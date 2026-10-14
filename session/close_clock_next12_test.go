package session

import (
	"bfp/obfuscation"
	"bfp/protocol"
	"bfp/security"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// A real actor owns a valid authenticated UDP carrier whose peer is only a
// datagram sink. No ACK can be produced. Business-clock injection happens at
// an actor barrier so that the test isolates close from ordinary expiry logic.
func TestNext12CloseClockNoAckSurvivesFrozenAndFutureTransportTime(t *testing.T) {
	for _, direction := range []string{"frozen-past", "jumped-future"} {
		for _, eligibility := range []string{"unbounded-eligibility", "future-lifetime-and-retention"} {
			t.Run(direction+"/"+eligibility, func(t *testing.T) {
				const closeTimeout = 150 * time.Millisecond
				receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = receiver.Close() })
				conn, err := net.DialUDP("udp", nil, receiver.LocalAddr().(*net.UDPAddr))
				if err != nil {
					t.Fatal(err)
				}
				var keys security.TransportKeys
				for i := range keys.Send {
					keys.Send[i], keys.Receive[i] = byte(i+1), byte(i+71)
				}
				var handle [16]byte
				copy(handle[:], []byte("next12-closeclk!"))
				carrier, err := makeCarrier("udp", 1, handle[:], &keys, conn, nil, nil)
				if err != nil {
					_ = conn.Close()
					t.Fatal(err)
				}
				parent, cancel := context.WithCancel(context.Background())
				owner := newSession(parent, sessionInfo{ID: "next12-close-clock"},
					Options{CloseTimeout: closeTimeout, RetainTimeout: 750 * time.Millisecond,
						ProbeInterval: time.Hour, KeyUpdateInterval: time.Hour}, true, nil)
				entered, release := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				t.Cleanup(func() {
					cancel()
					carrier.close()
					unblock()
					select {
					case <-owner.done:
					case <-time.After(time.Second):
						t.Error("owned close-clock actor failed local cleanup within fixed 1s")
					}
				})
				if err := owner.attach(carrier, 0); err != nil {
					t.Fatal(err)
				}
				businessTime := time.Unix(100, 0)
				if direction == "jumped-future" {
					businessTime = time.Now().Add(100 * 365 * 24 * time.Hour)
				}
				owner.post(func() {
					owner.transportNow = func() time.Time { return businessTime }
					if eligibility == "future-lifetime-and-retention" {
						owner.info.lifetimeUntil = time.Now().Add(750 * time.Millisecond)
						owner.suspendedAt = time.Now().Add(-25 * time.Millisecond)
					}
					close(entered)
					<-release
				})
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("actual actor did not enter close-clock barrier")
				}
				result := make(chan error, 1)
				started := time.Now()
				go func() { result <- owner.Close() }()
				intentDeadline := time.Now().Add(time.Second)
				for owner.closeIntent.Load() == nil {
					if time.Now().After(intentDeadline) {
						t.Fatal("Close did not publish its intent while the actor was paused")
					}
					time.Sleep(time.Millisecond)
				}
				unblock()
				select {
				case err := <-result:
					if !errors.Is(err, ErrCloseUnconfirmed) {
						t.Fatalf("UDP sink produced an unexplained confirmed result: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("frozen/future business time stopped the fixed actual close deadline")
				}
				elapsed := time.Since(started)
				if elapsed < 100*time.Millisecond || elapsed >= time.Second {
					t.Fatalf("150ms control drain ended immediately or exceeded fixed 1s: %v", elapsed)
				}
				if !owner.closed() || !owner.closing.localPublished || owner.closing.localAcked ||
					owner.closing.deadline.Sub(owner.closing.started) != closeTimeout {
					t.Fatalf("business clock corrupted publication/confirmation/deadline: %+v", owner.closing)
				}
				shadow, err := security.NewRecordCipher(keys.Send[:], handle, 0)
				if err != nil {
					t.Fatal(err)
				}
				if err := receiver.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				found := false
				for i := 0; i < 32 && !found; i++ {
					wire := make([]byte, security.MaxUDPRecordSize+1)
					n, _, err := receiver.ReadFromUDP(wire)
					if err != nil {
						t.Fatalf("sink never observed the actual authenticated close request: %v", err)
					}
					plain, _, err := shadow.Open(wire[:n])
					if err == nil {
						plain, err = obfuscation.Unpad(plain)
					}
					if err != nil {
						t.Fatal(err)
					}
					frames, err := protocol.Decode(plain)
					if err != nil {
						t.Fatal(err)
					}
					for _, frame := range frames {
						if frame.Kind == protocol.SessionClose {
							if !canonicalClose(frame) {
								t.Fatal("actual UDP request was not a canonical close")
							}
							found = true
						}
					}
				}
				if !found {
					t.Fatal("only ordinary traffic reached the sink")
				}
				t.Logf("actual UDP without ACK: business=%s eligibility=%s close=%v fixed timeout=%v published=%t; no remote confirmation", direction, eligibility, elapsed, closeTimeout, owner.closing.localPublished)
			})
		}
	}
}

// Both real encrypted actors freeze their business clocks after a target
// exchange. Capture each actor's current transport time: UDP history correctly
// rejects clock regression, and the first incoming Close is observed before
// its receiver becomes terminal. The frozen valid clock must not stop real
// control time, exactly-once target cleanup, or the responder's finite drain.
func TestNext12CloseClockAuthenticatedAckWithFrozenBusinessClocks(t *testing.T) {
	for _, kind := range []string{"udp", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			f := newCloseTestFixture(t, kind, 150*time.Millisecond, nil)
			f.flow(t)
			for _, owner := range f.sessions {
				if err := owner.call(context.Background(), func() {
					frozen := owner.transportTime()
					owner.transportNow = func() time.Time { return frozen }
				}); err != nil {
					t.Fatal(err)
				}
			}
			closeTestResult(t, f.sessions[0], nil, time.Second)
			if !f.sessions[0].closing.localAcked || f.backend.closed.Load() != 1 || f.backend.cleanups.Load() != 1 {
				t.Fatal("actual ACK did not follow exactly-once target and scope cleanup")
			}
			select {
			case <-f.sessions[1].done:
			case <-time.After(time.Second):
				t.Fatal("peer control actor remained alive with a frozen business clock")
			}
			closeAssertRecords(t, f.relay.selected(0, protocol.SessionClose), 1, maxCloseRequests)
			closeAssertRecords(t, f.relay.selected(1, protocol.SessionCloseAck), 1, maxCloseResponses)
		})
	}
}
