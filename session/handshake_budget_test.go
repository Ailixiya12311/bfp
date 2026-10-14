package session

import (
	"bfp/security"
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// Observe actual establish traffic through a transparent UDP relay. This
// catches a missing padded=true at the CONFIRM call site deterministically,
// regardless of which random padding the cached READY happens to receive.
func TestUDPNewAndResumeConfirmFundsMaximumReady(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	serveDone := make(chan error, 1)
	go func() { serveDone <- s.Serve(context.Background()) }()
	t.Cleanup(func() {
		s.Close()
		select {
		case e := <-serveDone:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(time.Second):
			t.Error("budget test server did not stop")
		}
	})
	relay, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	upstream, e := net.DialUDP("udp", nil, s.udp.LocalAddr().(*net.UDPAddr))
	if e != nil {
		relay.Close()
		t.Fatal(e)
	}
	type observation struct {
		proof boot
		wire  int
		plain int
	}
	confirms := make(chan observation, 8)
	var peerMu sync.Mutex
	var peer *net.UDPAddr
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		buffer := make([]byte, 1201)
		for {
			n, from, e := relay.ReadFromUDP(buffer)
			if e != nil {
				return
			}
			peerMu.Lock()
			peer = from
			peerMu.Unlock()
			if plain, e := security.OpenBootstrap(cred.Admission, buffer[:n]); e == nil {
				var b boot
				if decodeJSON(plain, &b) == nil && b.Action == "confirm" {
					select {
					case confirms <- observation{b, n, len(plain)}:
					default:
					}
				}
			}
			if _, e = upstream.Write(buffer[:n]); e != nil {
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		buffer := make([]byte, 1201)
		for {
			n, e := upstream.Read(buffer)
			if e != nil {
				return
			}
			peerMu.Lock()
			to := peer
			peerMu.Unlock()
			if to != nil {
				if _, e = relay.WriteToUDP(buffer[:n], to); e != nil {
					return
				}
			}
		}
	}()
	t.Cleanup(func() { relay.Close(); upstream.Close(); workers.Wait() })
	cfg := ClientConfig{Server: relay.LocalAddr().String(), Credentials: cred, Options: Options{HandshakeTimeout: time.Second}}
	var previous *sessionInfo
	for _, mode := range []string{"new", "resume"} {
		attempt := randomID()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		car, info, e := establish(ctx, cfg, "udp", attempt, previous)
		cancel()
		if e != nil {
			t.Fatalf("%s actual handshake: %v", mode, e)
		}
		t.Cleanup(func() { car.close() })
		if previous != nil && (info.ID != previous.ID || info.Generation != previous.Generation+1) {
			t.Fatal("resume changed Session or failed to advance carrier generation")
		}
		var seen observation
		select {
		case seen = <-confirms:
		case <-time.After(time.Second):
			t.Fatal("actual CONFIRM was not observed")
		}
		if seen.proof.Attempt != attempt {
			t.Fatal("observed CONFIRM belongs to another attempt")
		}
		var handle [16]byte
		copy(handle[:], info.Handle)
		s.mu.Lock()
		p := s.handles[handle]
		s.mu.Unlock()
		if p == nil {
			t.Fatal("completed handshake has no committed candidate")
		}
		p.mu.Lock()
		ready := append([]byte(nil), p.ready...)
		p.mu.Unlock()
		readyPlain, e := security.OpenBootstrap(cred.Admission, ready)
		if e != nil {
			t.Fatal(e)
		}
		maximumReady := security.BootstrapOverhead + len(readyPlain) + 255
		minimumConfirm := security.BootstrapOverhead + seen.plain
		if minimumConfirm < maximumReady || seen.wire < minimumConfirm || seen.wire > 1200 {
			t.Fatalf("%s CONFIRM min=%d actual=%d cannot safely fund READY max=%d within UDP limit", mode, minimumConfirm, seen.wire, maximumReady)
		}
		// Removing the deliberate CONFIRM padding exposes the old deficit even
		// when this run's READY randomly receives a small outer envelope.
		pure := seen.proof
		pure.Padding = nil
		bareMinimum := security.BootstrapOverhead + len(encodeJSON(pure))
		if bareMinimum >= maximumReady {
			t.Fatal("regression case no longer exercises the former response budget deficit")
		}
		t.Logf("%s actual UDP handshake: CONFIRM minimum=%d actual=%d READY maximum=%d bare CONFIRM minimum=%d", mode, minimumConfirm, seen.wire, maximumReady, bareMinimum)
		previous = &info
	}
}
