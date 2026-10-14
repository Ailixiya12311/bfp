package session

import (
	"bfp/security"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// These tests retain the existing one-second bootstrap deadline. Cancellation
// must interrupt physical I/O well before it, rather than merely preventing
// attachment after the old deadline eventually wakes the handshake.
func TestNext11BootstrapCancelInterruptsBlockedTCP(t *testing.T) {
	for _, phase := range []string{"init-reply", "confirm-ready"} {
		t.Run(phase, func(t *testing.T) {
			s, cred := newSecurityTestServer(t)
			listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { listener.Close() })
			if err = listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			cfg := ClientConfig{Server: listener.Addr().String(), Credentials: cred, Options: Options{HandshakeTimeout: time.Second}}
			result := make(chan error, 1)
			go func() {
				car, _, err := establish(ctx, cfg, "tcp", randomID(), nil)
				if car != nil {
					car.close()
				}
				result <- err
			}()
			peer, err := listener.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { peer.Close() })
			if err = peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			stage := make(chan error, 1)
			physicalClose := make(chan error, 1)
			go func() {
				plain, err := security.ReadBootstrap(peer, cred.Admission)
				var init boot
				if err == nil {
					err = decodeJSON(plain, &init)
				}
				if err == nil && init.Action != "init" {
					err = errors.New("expected actual INIT")
				}
				if err == nil && phase == "confirm-ready" {
					var candidate *pending
					candidate, err = s.initialize(init, "tcp", peer, nil)
					if err == nil {
						err = security.WriteBootstrap(peer, candidate.reply)
					}
					if err == nil {
						plain, err = security.ReadBootstrap(peer, cred.Admission)
					}
					var proof boot
					if err == nil {
						err = decodeJSON(plain, &proof)
					}
					if err == nil && (proof.Action != "confirm" || proof.Attempt != init.Attempt) {
						err = errors.New("expected actual CONFIRM for INIT")
					}
				}
				stage <- err
				if err != nil {
					physicalClose <- err
					return
				}
				var next [1]byte
				n, err := peer.Read(next[:])
				if n != 0 || !errors.Is(err, io.EOF) {
					err = fmt.Errorf("expected physical EOF without another bootstrap byte: n=%d err=%w", n, err)
				} else {
					err = nil
				}
				physicalClose <- err
			}()
			select {
			case err = <-stage:
				if err != nil {
					t.Fatal("responder stage", err)
				}
			case <-time.After(time.Second):
				t.Fatal("bootstrap stage did not arrive within the existing deadline")
			}
			started := time.Now()
			cancel()
			select {
			case err = <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled bootstrap returned %v", err)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("cancellation did not interrupt blocked TCP bootstrap")
			}
			select {
			case err = <-physicalClose:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("peer did not observe physical socket close after cancellation")
			}
			t.Logf("%s: cancellation interrupted physical TCP I/O in %s with no later bootstrap byte", phase, time.Since(started))
		})
	}
}

func TestNext11BootstrapCancelStopsUDPAfterRetry(t *testing.T) {
	_, cred := newSecurityTestServer(t)
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	attempt := randomID()
	cfg := ClientConfig{Server: listener.LocalAddr().String(), Credentials: cred, Options: Options{HandshakeTimeout: time.Second}}
	result := make(chan error, 1)
	go func() {
		car, _, err := establish(ctx, cfg, "udp", attempt, nil)
		if car != nil {
			car.close()
		}
		result <- err
	}()
	buffer := make([]byte, 1201)
	if err = listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		n, _, err := listener.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal("expected initial packet and existing 350ms retry", err)
		}
		plain, err := security.OpenBootstrap(cred.Admission, buffer[:n])
		if err != nil {
			t.Fatal(err)
		}
		var b boot
		if decodeJSON(plain, &b) != nil || b.Action != "init" || b.Attempt != attempt {
			t.Fatal("unexpected bootstrap packet")
		}
	}
	started := time.Now()
	cancel()
	select {
	case err = <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled UDP bootstrap returned %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("cancellation waited for the next 350ms UDP read timeout")
	}
	elapsed := time.Since(started)
	if err = listener.SetReadDeadline(time.Now().Add(450 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, _, err := listener.ReadFromUDP(buffer)
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() || n != 0 {
		t.Fatalf("bootstrap retried after cancellation: n=%d err=%v", n, err)
	}
	t.Logf("UDP retry observed before cancel; pending read canceled in %s; no later packet for 450ms", elapsed)
}

func TestNext11BootstrapSuccessfulTransferSurvivesParentCancel(t *testing.T) {
	for _, kind := range []string{"udp", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			s, cred := newSecurityTestServer(t)
			serveDone := make(chan error, 1)
			go func() { serveDone <- s.Serve(context.Background()) }()
			t.Cleanup(func() {
				s.Close()
				select {
				case err := <-serveDone:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(time.Second):
					t.Error("bootstrap transfer server did not stop")
				}
			})
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			cfg := ClientConfig{Server: s.Addr().String(), Credentials: cred, Options: Options{HandshakeTimeout: time.Second}}
			car, _, err := establish(ctx, cfg, kind, randomID(), nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(car.close)
			cancel()
			// Observe beyond an asynchronous cancellation callback dispatch. Both
			// the actual socket deadline setter and empty write reject a closed
			// physical connection; carrier.closed alone would miss a raw Close.
			timer := time.NewTimer(100 * time.Millisecond)
			<-timer.C
			if err = car.conn.SetDeadline(time.Time{}); err != nil {
				t.Fatal("bootstrap cancellation closed transferred socket", err)
			}
			if n, err := car.conn.Write(nil); n != 0 || err != nil {
				t.Fatalf("transferred physical socket was unavailable: n=%d err=%v", n, err)
			}
			t.Log("authenticated carrier remained physically open after canceled bootstrap parent")
		})
	}
}
