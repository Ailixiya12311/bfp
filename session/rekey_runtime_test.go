package session

import (
	"bfp/obfuscation"
	"bfp/protocol"
	"bfp/security"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type runtimeBackend struct {
	dialer  net.Dialer
	dials   atomic.Int32
	written atomic.Int64
}
type runtimeCountConn struct {
	net.Conn
	written *atomic.Int64
}

func (c *runtimeCountConn) Write(data []byte) (int, error) {
	n, e := c.Conn.Write(data)
	c.written.Add(int64(n))
	return n, e
}
func (c *runtimeCountConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}
func (b *runtimeBackend) DialContext(ctx context.Context, kind, address string) (net.Conn, error) {
	c, e := b.dialer.DialContext(ctx, kind, address)
	if e != nil {
		return nil, e
	}
	b.dials.Add(1)
	return &runtimeCountConn{Conn: c, written: &b.written}, nil
}

type runtimeFixture struct {
	server       *Server
	client, peer *Session
	cfg          ClientConfig
	backend      *runtimeBackend
	target       string
}

func newRuntimeFixture(t *testing.T, kind string) *runtimeFixture {
	return newRuntimeFixtureWith(t, kind, Options{HandshakeTimeout: time.Second, ProbeInterval: 100 * time.Millisecond, FailureTimeout: 3 * time.Second, RetainTimeout: 5 * time.Second, KeyUpdateBytes: 1 << 30, KeyUpdateInterval: time.Hour}, nil)
}
func newRuntimeFixtureWith(t *testing.T, kind string, opts Options, reader func(*Session, *carrier)) *runtimeFixture {
	t.Helper()
	server, cred := newSecurityTestServer(t)
	backend := &runtimeBackend{}
	server.cfg.Backend = backend
	server.cfg.Options = opts.defaults()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background()) }()
	t.Cleanup(func() {
		server.Close()
		select {
		case e := <-serveDone:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(time.Second):
			t.Error("runtime server did not stop")
		}
	})
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var targetMu sync.Mutex
	targets := map[net.Conn]struct{}{}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			targetMu.Lock()
			targets[c] = struct{}{}
			targetMu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				defer func() { targetMu.Lock(); delete(targets, c); targetMu.Unlock() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		targetMu.Lock()
		for c := range targets {
			c.Close()
		}
		targetMu.Unlock()
		workers.Wait()
	})
	cfg := ClientConfig{Server: server.Addr().String(), TCPServer: server.Addr().String(), Credentials: cred, Options: opts}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	car, info, e := establish(ctx, cfg, kind, randomID(), nil)
	if e != nil {
		t.Fatal(e)
	}
	client := newSession(context.Background(), info, opts, true, nil)
	t.Cleanup(func() { client.Close() })
	if e = client.attach(car, 0); e != nil {
		t.Fatal(e)
	}
	if reader == nil {
		client.startReader(car)
	} else {
		reader(client, car)
	}
	client.activate(car)
	server.mu.Lock()
	peer := server.sessions[info.ID]
	server.mu.Unlock()
	if peer == nil {
		t.Fatal("real handshake did not commit server Session")
	}
	f := &runtimeFixture{server: server, client: client, peer: peer, cfg: cfg, backend: backend, target: listener.Addr().String()}
	runtimeWait(t, "initial bidirectional synchronization", func() bool { return runtimeReady(client) && runtimeReady(peer) })
	return f
}
func runtimeReady(s *Session) bool {
	ready := false
	_ = s.call(context.Background(), func() { ready = s.active && s.peerDone && s.localDoneAck })
	return ready
}
func runtimeWait(t *testing.T, description string, predicate func() bool) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(2 * time.Millisecond)
	defer poll.Stop()
	for {
		if predicate() {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("bounded wait expired: " + description)
		case <-poll.C:
		}
	}
}
func runtimeFlow(t *testing.T, f *runtimeFixture) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, e := f.client.DialContext(ctx, "tcp", f.target)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	return conn
}
func runtimeExchange(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	if err := runtimeExchangeErr(conn, payload); err != nil {
		t.Fatal(err)
	}
}
func runtimeExchangeErr(conn net.Conn, payload []byte) error {
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if n, e := conn.Write(payload); e != nil || n != len(payload) {
		return fmt.Errorf("write: %d %v", n, e)
	}
	got := make([]byte, len(payload))
	if _, e := io.ReadFull(conn, got); e != nil {
		return e
	}
	if !bytes.Equal(got, payload) {
		return errors.New("runtime echo byte mismatch")
	}
	return nil
}
func runtimeEpochs(s *Session) (send, receive uint32) {
	_ = s.call(context.Background(), func() { send = s.current.tx.Epoch(); receive = s.current.rx.Epoch() })
	return
}

func TestRuntimeBidirectionalRekeyPreservesBusinessAfterOldEpochRetirement(t *testing.T) {
	for _, kind := range []string{"udp", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			f := newRuntimeFixture(t, kind)
			flow := runtimeFlow(t, f)
			var clientKeys, serverKeys security.TransportKeys
			var clientHandle, serverHandle [16]byte
			_ = f.client.call(context.Background(), func() {
				clientKeys = f.client.current.keys
				clientHandle = f.client.current.handle
				f.client.opts.KeyUpdateBytes = 2048
			})
			_ = f.peer.call(context.Background(), func() {
				serverKeys = f.peer.current.keys
				serverHandle = f.peer.current.handle
				f.peer.opts.KeyUpdateBytes = 2048
			})
			if err := runtimeExchangeErr(flow, bytes.Repeat([]byte("key rotation in live business "), 160)); err != nil {
				t.Logf("exchange failure err=%v client=%+v peer=%+v", err, f.client.Stats(), f.peer.Stats())
				_ = f.client.call(context.Background(), func() {
					if f.client.udpPath != nil {
						t.Logf("client udp path live=%+v deadline=%v progress=%v health=%v pto=%d retries=%d refs=%d", f.client.udpPath.ledger.Snapshot(), f.client.udpPath.deadline, f.client.udpPath.lastProgress, f.client.udpPath.lastHealth, f.client.udpPath.pto.Rounds(), len(f.client.udpPath.retries), len(f.client.udpPath.refs))
					}
				})
				_ = f.peer.call(context.Background(), func() {
					if f.peer.udpPath != nil {
						t.Logf("peer udp path live=%+v deadline=%v progress=%v health=%v pto=%d retries=%d refs=%d", f.peer.udpPath.ledger.Snapshot(), f.peer.udpPath.deadline, f.peer.udpPath.lastProgress, f.peer.udpPath.lastHealth, f.peer.udpPath.pto.Rounds(), len(f.peer.udpPath.retries), len(f.peer.udpPath.refs))
					}
				})
				t.Fatal(err)
			}
			runtimeWait(t, "both transmit/receive epochs advance", func() bool {
				cs, cr := runtimeEpochs(f.client)
				ss, sr := runtimeEpochs(f.peer)
				return cs > 0 && cr > 0 && ss > 0 && sr > 0 && cs == sr && ss == cr
			})
			for _, endpoint := range []*Session{f.client, f.peer} {
				_ = endpoint.call(context.Background(), func() { endpoint.opts.KeyUpdateBytes = ^uint64(0); endpoint.opts.KeyUpdateInterval = time.Hour })
			}
			// Synthetic valid, previously unused epoch-0 PN tests retirement, rather
			// than relying on an already-seen handshake record's replay rejection.
			makeOld := func(key [32]byte, handle [16]byte) []byte {
				tx, e := security.NewRecordCipher(key[:], handle, 0)
				if e != nil {
					t.Fatal(e)
				}
				plain, e := protocol.Encode([]protocol.Frame{{Kind: protocol.Ping, Value: 99}})
				if e != nil {
					t.Fatal(e)
				}
				plain, e = obfuscation.Pad(plain, 1100)
				if e != nil {
					t.Fatal(e)
				}
				var wire []byte
				for i := 0; i <= 4096; i++ {
					wire, _, e = tx.Seal(plain)
					if e != nil {
						t.Fatal(e)
					}
				}
				return wire
			}
			oldClient, oldServer := makeOld(clientKeys.Send, clientHandle), makeOld(serverKeys.Send, serverHandle)
			for _, entry := range []struct {
				s    *Session
				wire []byte
			}{{f.peer, oldClient}, {f.client, oldServer}} {
				if e := entry.s.call(context.Background(), func() {
					if entry.s.udpPath != nil {
						t.Logf("before retire epoch=%d rxPrev=%v lastRX=%v", entry.s.current.rx.Epoch(), entry.s.udpPath.rxPrevious, entry.s.lastRXKey)
					}
					// Exercise the explicit drain gate rather than the removed
					// fixed five-second timer: the new epoch has already carried
					// business, and the old ACK scope is drained before retirement.
					entry.s.rxDrainAt = time.Now().Add(-6 * time.Second)
					entry.s.rxCurrentUsed = true
					if entry.s.udpPath != nil && entry.s.udpPath.history.PreviousPending() {
						scope := entry.s.udpPath.scope(entry.s.current.rx.Epoch() - 1)
						if snap, ok, snapErr := entry.s.udpPath.history.Snapshot(scope, entry.s.transportTime().Sub(entry.s.udpPath.origin)); snapErr == nil && ok {
							_ = entry.s.udpPath.history.MarkSent(scope, snap.Revision)
						}
					}
					entry.s.maintain(time.Now())
					if entry.s.udpPath != nil {
						t.Logf("after maintain epoch=%d rxPrev=%v lastRX=%v", entry.s.current.rx.Epoch(), entry.s.udpPath.rxPrevious, entry.s.lastRXKey)
					}
					if _, _, e := entry.s.current.rx.Open(entry.wire); !errors.Is(e, security.ErrAuthentication) {
						t.Errorf("retired epoch-0 record accepted or wrongly classified: %v", e)
					}
				}); e != nil {
					t.Fatal(e)
				}
			}
			runtimeExchange(t, flow, []byte("business after retirement"))
			if f.backend.dials.Load() != 1 {
				t.Fatal("key update rebuilt the target socket")
			}
		})
	}
}

// The test loop decodes with a separate cipher solely to choose loss events;
// the real receiver validates/replay-checks only records actually delivered.
func runtimeLossReader(t *testing.T, s *Session, c *carrier, hold *atomic.Bool, dropped chan struct{}) chan struct{} {
	t.Helper()
	shadow, e := security.NewRecordCipher(c.keys.Receive[:], c.handle, 0)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	var report sync.Once
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
			payload, _, e := shadow.Open(wire)
			if e == nil {
				if payload, e = obfuscation.Unpad(payload); e == nil {
					if frames, e := protocol.Decode(payload); e == nil {
						drop := false
						for _, frame := range frames {
							if frame.Kind == protocol.ResumeState && frame.Flags == 0 && hold.Load() {
								drop = true
							}
						}
						if drop {
							report.Do(func() { close(dropped) })
							continue
						}
					}
				}
			}
			s.deliver(c, wire)
		}
	}()
	return done
}
func TestRuntimeLossDuringCarrierRecoveryDoesNotReleaseBusinessEarly(t *testing.T) {
	for _, kind := range []string{"udp", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			f := newRuntimeFixture(t, "udp")
			flow := runtimeFlow(t, f)
			runtimeExchange(t, flow, []byte("before recovery"))
			original, e := sessionSnapshot(f.client)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			car, info, e := establish(ctx, f.cfg, kind, randomID(), &original)
			cancel()
			if e != nil {
				t.Fatal(e)
			}
			if e = f.client.attach(car, original.Generation); e != nil {
				t.Fatal(e)
			}
			_ = f.client.call(context.Background(), func() { f.client.info = info })
			var hold atomic.Bool
			hold.Store(true)
			dropped := make(chan struct{})
			readerDone := runtimeLossReader(t, f.client, car, &hold, dropped)
			t.Cleanup(func() {
				car.close()
				select {
				case <-readerDone:
				case <-time.After(time.Second):
					t.Error("loss reader did not exit")
				}
			})
			f.client.activate(car)
			select {
			case <-dropped:
			case <-time.After(time.Second):
				t.Fatal("no recovery snapshot traversed real carrier")
			}
			baseline := f.backend.written.Load()
			payload := []byte("queued during lost recovery control")
			if n, e := flow.Write(payload); e != nil || n != len(payload) {
				t.Fatalf("buffering during recovery: %d %v", n, e)
			}
			got := make([]byte, len(payload))
			received := make(chan error, 1)
			go func() { _, e := io.ReadFull(flow, got); received <- e }()
			_ = f.client.call(context.Background(), func() {
				f.client.flush()
				if f.client.peerDone {
					t.Error("missing snapshot prematurely marked peer complete")
				}
			})
			select {
			case e := <-received:
				t.Fatalf("business completed before snapshot loss was released: %v", e)
			case <-time.After(30 * time.Millisecond):
			}
			if f.backend.written.Load() != baseline {
				t.Fatal("target received new business before complete recovery synchronization")
			}
			hold.Store(false)
			select {
			case e := <-received:
				if e != nil {
					t.Fatal(e)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("business did not resume after snapshot retransmission")
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("recovery altered or repeated business bytes")
			}
			runtimeWait(t, "complete recovery synchronization", func() bool { return runtimeReady(f.client) && runtimeReady(f.peer) })
			if f.backend.dials.Load() != 1 {
				t.Fatal("recovery redialed the existing target")
			}
		})
	}
}

func TestRuntimeRepeatedCandidateAttachCannotExtendUnfinishedRetention(t *testing.T) {
	f := newRuntimeFixture(t, "udp")
	flow := runtimeFlow(t, f)
	runtimeExchange(t, flow, []byte("retain existing network"))
	original, e := sessionSnapshot(f.client)
	if e != nil {
		t.Fatal(e)
	}
	retainStart := time.Now().Add(-4 * time.Second)
	_ = f.client.call(context.Background(), func() { f.client.suspend(); f.client.suspendedAt = retainStart })
	previous := original
	for attempt := 0; attempt < 3; attempt++ {
		// Use real PSK handshakes and source-bound confirmation for each new
		// candidate, then withhold the activity reader so sync cannot complete.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		candidate, info, e := establish(ctx, f.cfg, "udp", randomID(), &previous)
		cancel()
		if e != nil {
			t.Fatal(e)
		}
		if e = f.client.attach(candidate, previous.Generation); e != nil {
			t.Fatal(e)
		}
		previous = info
		f.client.activate(candidate)
		if e = f.client.call(context.Background(), func() {
			if !f.client.suspendedAt.Equal(retainStart) {
				t.Errorf("candidate activation refreshed retention: %v", f.client.suspendedAt)
			}
			f.client.lastReceive = time.Now()
			f.client.lastProbe = time.Now()
			f.client.lastKey = time.Now()
		}); e != nil {
			t.Fatal(e)
		}
	}
	_ = f.client.call(context.Background(), func() { f.client.maintain(retainStart.Add(f.client.opts.RetainTimeout + time.Millisecond)) })
	select {
	case <-f.client.done:
	case <-time.After(time.Second):
		t.Fatal("repeated authenticated candidates extended unfinished session indefinitely")
	}
}
