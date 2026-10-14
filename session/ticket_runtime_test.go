package session

import (
	"bfp/obfuscation"
	"bfp/protocol"
	"bfp/security"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type ticketDropConn struct {
	net.Conn
	shadow  *security.RecordCipher
	hold    *atomic.Bool
	dropped chan struct{}
	once    sync.Once
}

func ticketWireFrames(cipher *security.RecordCipher, wire []byte) []protocol.Frame {
	plain, _, e := cipher.Open(wire)
	if e != nil {
		return nil
	}
	plain, e = obfuscation.Unpad(plain)
	if e != nil {
		return nil
	}
	frames, _ := protocol.Decode(plain)
	return frames
}

func (c *ticketDropConn) Write(wire []byte) (int, error) {
	for _, f := range ticketWireFrames(c.shadow, wire) {
		if f.Kind == protocol.TicketRefreshAck && c.hold.Load() {
			c.once.Do(func() { close(c.dropped) })
			return len(wire), nil
		}
	}
	return c.Conn.Write(wire)
}

func ticketLossReader(t *testing.T, s *Session, c *carrier, dropFirst bool, dropped chan struct{}, observations *atomic.Uint64) {
	t.Helper()
	shadow, e := security.NewRecordCipher(c.keys.Receive[:], c.handle, 0)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			wire, e := c.read()
			if e != nil {
				select {
				case s.incoming <- packet{c: c, err: e}:
				case <-s.done:
				}
				return
			}
			drop := false
			for _, f := range ticketWireFrames(shadow, wire) {
				if f.Kind == protocol.TicketRefresh {
					count := observations.Add(1)
					if dropFirst && count == 1 {
						drop = true
						close(dropped)
					}
				}
			}
			if !drop {
				s.deliver(c, wire)
			}
		}
	}()
	t.Cleanup(func() {
		c.close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("ticket loss reader did not stop")
		}
	})
}

func TestRuntimeTicketRefreshLossAndInstalledAckLoss(t *testing.T) {
	for _, scenario := range []struct {
		name, kind string
		ackLoss    bool
	}{
		{"udp_refresh_lost", "udp", false}, {"tcp_refresh_lost", "tcp", false}, {"udp_install_ack_lost", "udp", true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			opts := Options{HandshakeTimeout: time.Second, ProbeInterval: 50 * time.Millisecond, FailureTimeout: 3 * time.Second, RetainTimeout: 5 * time.Second, TicketTTL: 2 * time.Second, TicketRefreshLead: 1400 * time.Millisecond, TicketOverlap: 400 * time.Millisecond, MaxSessionLifetime: 10 * time.Second}
			var hold atomic.Bool
			hold.Store(scenario.ackLoss)
			dropped := make(chan struct{})
			var observations atomic.Uint64
			f := newRuntimeFixtureWith(t, scenario.kind, opts, func(s *Session, c *carrier) {
				if scenario.ackLoss {
					shadow, e := security.NewRecordCipher(c.keys.Send[:], c.handle, 0)
					if e != nil {
						t.Fatal(e)
					}
					c.conn = &ticketDropConn{Conn: c.conn, shadow: shadow, hold: &hold, dropped: dropped}
				}
				ticketLossReader(t, s, c, !scenario.ackLoss, dropped, &observations)
			})
			flow := runtimeFlow(t, f)
			original, e := sessionSnapshot(f.client)
			if e != nil {
				t.Fatal(e)
			}
			runtimeExchange(t, flow, []byte("business before ticket refresh"))
			select {
			case <-dropped:
			case <-time.After(2 * time.Second):
				t.Fatal("expected control loss was not observed")
			}
			if scenario.ackLoss {
				installed, e := sessionSnapshot(f.client)
				if e != nil || installed.TicketSerial != 2 {
					t.Fatalf("ACK preceded installation: %v", e)
				}
				serverCredential, _ := sessionSnapshot(f.peer)
				runtimeWait(t, "logical retry while installation ACKs are lost", func() bool { return observations.Load() >= 2 })
				again, _ := sessionSnapshot(f.client)
				after, _ := sessionSnapshot(f.peer)
				if again.Ticket != installed.Ticket || again.ticketUntil.After(installed.ticketUntil) || after.Ticket != serverCredential.Ticket || !after.ticketUntil.Equal(serverCredential.ticketUntil) {
					t.Fatal("logical retries replaced or extended pending credentials")
				}
				var pending uint64
				_ = f.peer.call(context.Background(), func() { pending = f.peer.ticketPending })
				if pending != 2 {
					t.Fatal("packet ACK incorrectly completed installation")
				}
				f.server.mu.Lock()
				aliases := len(f.server.tickets)
				f.server.mu.Unlock()
				if aliases > 2 {
					t.Fatal("lost ACKs accumulated aliases")
				}
				hold.Store(false)
			}
			runtimeWait(t, "same credential installed and logically acknowledged", func() bool {
				a, _ := sessionSnapshot(f.client)
				b, _ := sessionSnapshot(f.peer)
				var pending uint64
				_ = f.peer.call(context.Background(), func() { pending = f.peer.ticketPending })
				return a.TicketSerial >= 2 && a.TicketSerial == b.TicketSerial && a.Ticket == b.Ticket && pending == 0
			})
			runtimeExchange(t, flow, []byte("business after lost credential control"))
			fresh, e := sessionSnapshot(f.client)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			car, info, e := establish(ctx, f.cfg, "tcp", randomID(), &fresh)
			cancel()
			if e != nil {
				t.Fatalf("refreshed ticket could not recover: %v", e)
			}
			if e = f.client.attach(car, fresh.Generation); e != nil {
				t.Fatal(e)
			}
			var mergeErr error
			_ = f.client.call(context.Background(), func() { mergeErr = f.client.mergeInfo(info) })
			if mergeErr != nil {
				t.Fatal(mergeErr)
			}
			f.client.startReader(car)
			f.client.activate(car)
			runtimeWait(t, "recovered carrier synchronization", func() bool { return runtimeReady(f.client) && runtimeReady(f.peer) })
			runtimeExchange(t, flow, []byte("original target after ticket rotation and TCP recovery"))
			if info.ID != original.ID || f.backend.dials.Load() != 1 {
				t.Fatal("ticket refresh or recovery rebuilt the temporary network/target socket")
			}
		})
	}
}
