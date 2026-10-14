package session

import (
	"bfp/security"
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestServerTCPBootstrapReplayNoResponse(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	go s.Serve(context.Background())
	attempt := randomID()
	hs, err := newHandshake(true, "new", "tcp", attempt, 0, cred, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := hs.WriteMessage(encodeJSON(defaultCapabilityOffer()))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealBoot(cred.Admission, boot{Version: wireVersion, Action: "init", Mode: "new", Attempt: attempt, Message: first}, 1200, true)
	if err != nil {
		t.Fatal(err)
	}
	original, err := net.DialTimeout("tcp", s.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	_ = original.SetDeadline(time.Now().Add(time.Second))
	if err = security.WriteBootstrap(original, wire); err != nil {
		t.Fatal(err)
	}
	plain, err := security.ReadBootstrap(original, cred.Admission)
	if err != nil {
		t.Fatal(err)
	}
	var reply boot
	if err = decodeJSON(plain, &reply); err != nil || reply.Action != "reply" || reply.Attempt != attempt {
		t.Fatalf("original authenticated INIT failed: action=%q err=%v", reply.Action, err)
	}
	s.mu.Lock()
	beforePending, beforeHandles, beforeAttempts := len(s.pending), len(s.handles), len(s.attempts)
	s.mu.Unlock()
	if beforePending != 1 || beforeHandles != 1 || beforeAttempts != 1 {
		t.Fatal("original INIT did not create exactly one candidate")
	}

	// An observer can replay these bytes without knowing any key. A new TCP
	// source port must not turn that captured INIT into another candidate.
	replayed, err := net.DialTimeout("tcp", s.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer replayed.Close()
	_ = replayed.SetDeadline(time.Now().Add(time.Second))
	if err = security.WriteBootstrap(replayed, wire); err != nil {
		t.Fatal(err)
	}
	if n, err := replayed.Read(make([]byte, 1201)); n != 0 || err == nil {
		t.Fatalf("captured TCP INIT emitted application response: bytes=%d err=%v", n, err)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("captured TCP INIT was not rejected promptly")
	}
	s.mu.Lock()
	pending, handles, attempts, sessions := len(s.pending), len(s.handles), len(s.attempts), len(s.sessions)
	s.mu.Unlock()
	if pending != beforePending || handles != beforeHandles || attempts != beforeAttempts || sessions != 0 {
		t.Fatalf("captured TCP INIT allocated state: pending=%d handles=%d attempts=%d sessions=%d", pending, handles, attempts, sessions)
	}
}

func TestServerCommittedUDPConfirmRejectsChangedProof(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	go s.Serve(context.Background())
	addr, err := net.ResolveUDPAddr("udp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	attempt := randomID()
	hs, err := newHandshake(true, "new", "udp", attempt, 0, cred, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := hs.WriteMessage(encodeJSON(defaultCapabilityOffer()))
	if err != nil {
		t.Fatal(err)
	}
	writeBoot := func(b boot) {
		t.Helper()
		wire, err := sealBoot(cred.Admission, b, 1200, true)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := conn.Write(wire); err != nil || n != len(wire) {
			t.Fatalf("UDP bootstrap write: bytes=%d err=%v", n, err)
		}
	}
	readBoot := func(budget time.Duration) (boot, error) {
		_ = conn.SetReadDeadline(time.Now().Add(budget))
		buf := make([]byte, 1201)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return boot{}, err
			}
			plain, err := security.OpenBootstrap(cred.Admission, buf[:n])
			if err != nil {
				// An established Session may send authenticated transport control;
				// only bootstrap responses belong to this admission assertion.
				continue
			}
			var b boot
			if err = decodeJSON(plain, &b); err == nil {
				return b, nil
			}
		}
	}
	writeBoot(boot{Version: wireVersion, Action: "init", Mode: "new", Attempt: attempt, Message: first})
	reply, err := readBoot(time.Second)
	if err != nil || reply.Action != "reply" || reply.Attempt != attempt {
		t.Fatalf("UDP INIT failed: action=%q err=%v", reply.Action, err)
	}
	plain, keys, err := hs.ReadMessage(reply.Message)
	if err != nil || keys == nil {
		t.Fatalf("UDP server proof failed: %v", err)
	}
	var info sessionInfo
	if err = decodeJSON(plain, &info); err != nil {
		t.Fatal(err)
	}
	var handle [16]byte
	copy(handle[:], info.Handle)
	tx, err := security.NewRecordCipher(keys.Send[:], handle, 0)
	if err != nil {
		t.Fatal(err)
	}
	proof, _, err := tx.Seal(encodeJSON(confirm{Challenge: info.Challenge, Binding: hs.ChannelBinding()}))
	if err != nil {
		t.Fatal(err)
	}
	confirmation := boot{Version: wireVersion, Action: "confirm", Attempt: attempt, Handle: info.Handle, Message: proof}
	writeBoot(confirmation)
	ready, err := readBoot(time.Second)
	if err != nil || ready.Action != "ready" || ready.Attempt != attempt {
		t.Fatalf("fresh UDP CONFIRM failed: action=%q err=%v", ready.Action, err)
	}
	rx, err := security.NewRecordCipher(keys.Receive[:], handle, 0)
	if err != nil {
		t.Fatal(err)
	}
	plain, _, err = rx.Open(ready.Message)
	if err != nil || !bytes.Equal(plain, []byte("ready")) {
		t.Fatalf("fresh UDP READY proof failed: %v", err)
	}
	changed := append([]byte(nil), proof...)
	changed[len(changed)-1] ^= 1
	for _, message := range [][]byte{nil, {1, 2, 3}, changed} {
		bad := confirmation
		bad.Message = message
		// Each envelope is freshly sealed; a raw-wire replay rejection cannot
		// conceal whether the committed candidate still validates its proof.
		writeBoot(bad)
		if response, err := readBoot(200 * time.Millisecond); err == nil {
			t.Fatalf("changed committed CONFIRM emitted bootstrap response: action=%q", response.Action)
		} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Fatalf("changed committed CONFIRM read failed unexpectedly: %v", err)
		}
	}

	// The exact authenticated proof remains retryable inside a fresh outer
	// envelope when READY was lost. Its record must not be decrypted twice.
	writeBoot(confirmation)
	retry, err := readBoot(time.Second)
	if err != nil || retry.Action != "ready" || !bytes.Equal(retry.Message, ready.Message) {
		t.Fatalf("same authenticated CONFIRM retry failed: action=%q err=%v", retry.Action, err)
	}
	s.mu.Lock()
	pending, handles, sessions := len(s.pending), len(s.handles), len(s.sessions)
	s.mu.Unlock()
	if pending != 1 || handles != 1 || sessions != 1 {
		t.Fatalf("CONFIRM retries changed state: pending=%d handles=%d sessions=%d", pending, handles, sessions)
	}
}
