package session

import (
	"bfp/obfuscation"
	"bfp/protocol"
	"bfp/scheduler"
	"bfp/security"
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// All carrier records remain the actual authenticated runtime records. The
// independent cipher only identifies a fragment at the deterministic cut point.
type next21CutConn struct {
	net.Conn
	owner         *Session
	shadow        *security.RecordCipher
	cutFirst      atomic.Bool
	blackholeRead atomic.Bool
	first         chan struct{}
}

func (c *next21CutConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err == nil && n == len(b) && c.cutFirst.Load() {
		plain, _, e := c.shadow.Open(b)
		if e == nil {
			plain, e = obfuscation.Unpad(plain)
		}
		var frames []protocol.Frame
		if e == nil {
			frames, e = protocol.Decode(plain)
		}
		if e == nil {
			for _, f := range frames {
				if f.Kind == protocol.Datagram && c.cutFirst.CompareAndSwap(true, false) {
					// Write executes on the Session owner: stop the subsequent
					// queued fragments before the next flush slot can commit them.
					c.blackholeRead.Store(true)
					c.owner.udpSuspect = true
					c.owner.beginRecoveryAttempt()
					close(c.first)
				}
			}
		}
	}
	return n, err
}

func (c *next21CutConn) Read(b []byte) (int, error) {
	for {
		n, err := c.Conn.Read(b)
		if err != nil || !c.blackholeRead.Load() {
			return n, err
		}
	}
}

func next21Fixture(t *testing.T) (*runtimeFixture, *next21CutConn, *Flow, *atomic.Int32) {
	t.Helper()
	var cut *next21CutConn
	opts := Options{HandshakeTimeout: time.Second, ProbeInterval: time.Hour, FailureTimeout: 10 * time.Second, UDPFailureBudget: 10 * time.Second, RetainTimeout: 5 * time.Second, KeyUpdateBytes: 1 << 30, KeyUpdateInterval: time.Hour}
	f := newRuntimeFixtureWith(t, "udp", opts, func(s *Session, c *carrier) {
		shadow, err := security.NewRecordCipher(c.keys.Send[:], c.handle, 0)
		if err != nil {
			t.Fatal(err)
		}
		cut = &next21CutConn{Conn: c.conn, owner: s, shadow: shadow, first: make(chan struct{})}
		c.conn = cut
		s.startReader(c)
	})
	address, received := transportUDPEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := f.client.DialContext(ctx, "udp", address)
	if err != nil {
		t.Fatal(err)
	}
	return f, cut, conn.(*Flow), received
}

func next21ResumeTCP(t *testing.T, f *runtimeFixture) {
	t.Helper()
	original, err := sessionSnapshot(f.client)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	car, info, err := establish(ctx, f.cfg, "tcp", randomID(), &original)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.client.attach(car, original.Generation); err != nil {
		car.close()
		t.Fatal(err)
	}
	if err = f.client.call(ctx, func() {
		if e := f.client.mergeInfo(info); e != nil {
			t.Error(e)
		}
		f.client.finishRecoveryAttempt(false)
	}); err != nil {
		t.Fatal(err)
	}
	f.client.startReader(car)
	f.client.activate(car)
	runtimeWait(t, "next21 TCP recovery synchronization", func() bool { return runtimeReady(f.client) && runtimeReady(f.peer) })
}

func next21Exchange(t *testing.T, flow *Flow, payload []byte) {
	t.Helper()
	flow.SetDeadline(time.Now().Add(time.Second))
	if n, err := flow.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write n=%d err=%v", n, err)
	}
	buf := make([]byte, 16<<10)
	if n, err := flow.Read(buf); err != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("echo n=%d err=%v", n, err)
	}
}

func TestDatagramTXNext21ZeroCommitMigratesOnceRealTCP(t *testing.T) {
	f, _, flow, received := next21Fixture(t)
	var originalTarget net.Conn
	f.peer.call(context.Background(), func() { originalTarget = f.peer.streams[flow.id].targetConn })
	f.client.call(context.Background(), func() { f.client.cwnd = 1 })
	payload := bytes.Repeat([]byte{7}, 1800)
	flow.SetDeadline(time.Now().Add(3 * time.Second))
	if n, err := flow.Write(payload); err != nil || n != len(payload) {
		t.Fatal(n, err)
	}
	f.client.call(context.Background(), func() {
		tx := f.client.streams[flow.id].txDatagrams[1]
		if tx == nil || tx.firstCommitted || tx.remaining != 2 {
			t.Error("message was not retained wholly uncommitted")
		}
		f.client.udpSuspect = true
	})
	next21ResumeTCP(t, f)
	buf := make([]byte, 4096)
	if n, err := flow.Read(buf); err != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("migrated echo n=%d err=%v", n, err)
	}
	if received.Load() != 1 || f.backend.dials.Load() != 1 {
		t.Fatal("migration duplicated target delivery or target socket")
	}
	f.peer.call(context.Background(), func() {
		if f.peer.streams[flow.id].targetConn != originalTarget {
			t.Error("target socket replaced")
		}
	})
	f.client.call(context.Background(), func() {
		if f.client.txDatagramReserved != 0 || f.client.txDatagramQueued != 0 || len(f.client.streams[flow.id].txDatagrams) != 0 {
			t.Error("fully sent migrated message retained reservations")
		}
	})
	next21Exchange(t, flow, []byte("same flow after migration"))
	if received.Load() != 2 || f.backend.dials.Load() != 1 {
		t.Fatal("original flow did not continue exactly once")
	}
}

func TestDatagramTXNext21PartialCommitMigratesOnRealTCP(t *testing.T) {
	f, cut, flow, received := next21Fixture(t)
	cut.cutFirst.Store(true)
	flow.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := flow.Write(bytes.Repeat([]byte{8}, 1800)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cut.first:
	case <-time.After(time.Second):
		t.Fatal("first real UDP fragment did not commit")
	}
	f.client.call(context.Background(), func() {
		tx := f.client.streams[flow.id].txDatagrams[1]
		if tx == nil || !tx.firstCommitted || tx.remaining != 1 {
			t.Error("partial message ownership missing")
		}
	})
	runtimeWait(t, "peer received first incomplete fragment", func() bool {
		found := false
		f.peer.call(context.Background(), func() { a := f.peer.streams[flow.id].datagrams[1]; found = a != nil && a.count == 900 })
		return found
	})
	next21ResumeTCP(t, f)
	f.client.call(context.Background(), func() {
		if len(f.client.streams[flow.id].txDatagrams) != 0 || f.client.txDatagramReserved != 0 {
			t.Error("partly submitted message retained after handover")
		}
	})
	buf := make([]byte, 4096)
	flow.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := flow.Read(buf); err != nil || !bytes.Equal(buf[:n], bytes.Repeat([]byte{8}, 1800)) {
		t.Fatalf("partial old message was not completed exactly once on new carrier: n=%d err=%v", n, err)
	}
	if received.Load() != 1 {
		t.Fatal("handover did not deliver the old datagram exactly once")
	}
	next21Exchange(t, flow, []byte("new message retains original association"))
	if received.Load() != 2 || f.backend.dials.Load() != 1 {
		t.Fatal("recovery replayed old message or recreated target")
	}
}

func TestDatagramTXNext21TargetReceivedReplyReplaysWithoutDuplicateTarget(t *testing.T) {
	f, cut, flow, received := next21Fixture(t)
	cut.blackholeRead.Store(true)
	flow.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := flow.Write([]byte("target executes once")); err != nil {
		t.Fatal(err)
	}
	runtimeWait(t, "target received original unknown-reply message", func() bool { return received.Load() == 1 })
	if _, err := flow.Read(make([]byte, 4096)); err == nil {
		t.Fatal("blackholed reply reached client")
	}
	f.client.call(context.Background(), func() { f.client.udpSuspect = true })
	next21ResumeTCP(t, f)
	flow.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4096)
	if n, err := flow.Read(buf); err != nil || !bytes.Equal(buf[:n], []byte("target executes once")) {
		t.Fatalf("old reply was not recovered on the new carrier: n=%d err=%v", n, err)
	}
	if received.Load() != 1 {
		t.Fatal("recovery reexecuted old target datagram")
	}
	next21Exchange(t, flow, []byte("new message after unknown outcome"))
	if received.Load() != 2 || f.backend.dials.Load() != 1 {
		t.Fatal("original association did not continue without replay")
	}
}

func TestDatagramTXNext21WaitKeepsOriginalDeadlineAndNoAdmission(t *testing.T) {
	for _, mode := range []string{"inactive", "suspect", "candidate"} {
		t.Run(mode, func(t *testing.T) {
			s, flow, st := transportUDPActor(t, 4096)
			s.call(context.Background(), func() {
				s.active = true
				s.peerDone = true
				s.current = &carrier{kind: "udp", generation: 1}
				if mode == "inactive" {
					s.active = false
				}
				if mode == "suspect" {
					s.udpSuspect = true
				}
				if mode == "candidate" {
					s.stats.TCPRecoveryInFlight = true
				}
			})
			flow.SetWriteDeadline(time.Now().Add(80 * time.Millisecond))
			start := time.Now()
			n, err := flow.Write([]byte("not silently discarded"))
			if n != 0 || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 400*time.Millisecond {
				t.Fatalf("wait result n=%d err=%v elapsed=%s", n, err, time.Since(start))
			}
			s.call(context.Background(), func() {
				if st.messageNext != 1 || s.queue.Len() != 0 || s.txDatagramReserved != 0 || s.stats.Dropped != 0 {
					t.Error("failed recovery wait changed message state")
				}
			})
		})
	}
}

func TestDatagramTXNext21ExpiryBudgetAndFECGeneration(t *testing.T) {
	s, flow, st := next15FECActor(t)
	flow.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := flow.Write(make([]byte, 901)); err != nil {
		t.Fatal(err)
	}
	s.call(context.Background(), func() {
		tx := st.txDatagrams[1]
		originalDeadline := tx.deadline
		oldCost := tx.reserved
		if s.pendingSendBytes() != oldCost || s.txDatagramQueued >= oldCost {
			t.Error("reservation double charged queued batch")
		}
		s.current = &carrier{kind: "udp", generation: 8}
		s.queue = scheduler.New[protocol.Frame](1200, s.opts.MaxSessionBuffer)
		s.rebindTXDatagrams(time.Now())
		if tx.generation != 8 || tx.deadline != originalDeadline || tx.firstCommitted {
			t.Error("rebind renewed deadline or lost ownership")
		}
		var parity protocol.Frame
		for {
			f, ok := s.nextSendFrame(3)
			if !ok {
				break
			}
			if f.Kind == protocol.DatagramRepairFrame {
				parity = f
			}
		}
		r, err := protocol.DecodeDatagramRepair(parity.Data)
		if err != nil || parity.Value != 8 || r.Meta.Generation != 8 {
			t.Error("FEC retained old generation")
		}
		// A fresh new-carrier queue can rebuild the same zero-commit message.
		s.current = &carrier{kind: "tcp", generation: 9}
		s.queue = scheduler.New[protocol.Frame](1200, s.opts.MaxSessionBuffer)
		s.rebindTXDatagrams(time.Now())
		if tx.remaining != 2 || tx.reserved >= oldCost || st.fecProfile != next15FECProfile() {
			t.Error("TCP parity/immutable contract wrong")
		}
		s.expireTXDatagrams(originalDeadline)
		if len(st.txDatagrams) != 0 || s.queue.Len() != 0 || s.txDatagramReserved != 0 || s.txDatagramQueued != 0 {
			t.Error("expired zero-commit batch retained cost or fragments")
		}
	})
}

func TestDatagramTXNext21SuspectAllowsControlStopsBusiness(t *testing.T) {
	for _, candidate := range []bool{false, true} {
		s, now, receiver := udpOwner(t)
		s.opts.MaxSessionBuffer = 65536
		s.udpSuspect = !candidate
		s.stats.TCPRecoveryInFlight = candidate
		business := protocol.Frame{Kind: protocol.Datagram, Flow: 1, Offset: 1, Value: uint64(3) << 32, Data: []byte("old")}
		if !s.enqueue(business, protocol.Normal) || !s.enqueue(protocol.Frame{Kind: protocol.Pong, Flow: 1, Value: 91}, protocol.Interactive) {
			t.Fatal("failed to queue fixture")
		}
		s.flushUDP()
		receiver.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		wire := make([]byte, security.MaxUDPRecordSize)
		n, _, err := receiver.ReadFromUDP(wire)
		if err != nil {
			t.Fatal("paused old UDP blocked necessary control", err)
		}
		rx, err := security.NewRecordCipher(s.current.keys.Send[:], s.current.handle, 0)
		if err != nil {
			t.Fatal(err)
		}
		plain, _, err := rx.Open(wire[:n])
		if err == nil {
			plain, err = obfuscation.Unpad(plain)
		}
		frames, decodeErr := protocol.Decode(plain)
		if err != nil || decodeErr != nil || len(frames) != 1 || frames[0].Kind != protocol.Pong {
			t.Fatal("paused path submitted business")
		}
		if s.queue.Len() != 1 {
			t.Fatal("old pending business lost while control passed")
		}
		*now = now.Add(time.Millisecond)
		if sent, err := s.udpSend(business, false, false, false); sent || err != nil {
			t.Fatal("direct old-carrier submission bypassed pause")
		}
	}
}

func TestDatagramTXNext21SessionFlowAndCardinalityBudget(t *testing.T) {
	for _, limit := range []string{"session", "flow", "count"} {
		t.Run(limit, func(t *testing.T) {
			s, flow, st := transportUDPActor(t, 65536)
			s.call(context.Background(), func() {
				s.active = true
				s.peerDone = true
				s.opts.MaxSessionBuffer = 1 << 20
				s.opts.MaxDatagramFlowBuffer = 1 << 20
				if limit == "session" {
					s.opts.MaxSessionBuffer = 1500
				}
				if limit == "flow" {
					s.opts.MaxDatagramFlowBuffer = 1500
				}
			})
			flow.SetWriteDeadline(time.Now().Add(time.Second))
			count := 1
			if limit == "count" {
				count = 32
			}
			for i := 0; i < count; i++ {
				if _, err := flow.Write(nil); err != nil {
					t.Fatal("first bounded admissions", i, err)
				}
			}
			var id uint64
			var reserved int
			s.call(context.Background(), func() {
				id = st.messageNext
				reserved = s.txDatagramReserved
				if reserved != st.txDatagramReserved || s.pendingSendBytes() != reserved {
					t.Error("whole-message cost not conserved")
				}
			})
			var err error
			if limit == "count" {
				_, err = flow.Write(nil)
			} else {
				_, err = flow.Write(make([]byte, 901))
			}
			if !errors.Is(err, ErrLimit) {
				t.Fatal("full-message budget not enforced", err)
			}
			s.call(context.Background(), func() {
				if st.messageNext != id || s.txDatagramReserved != reserved {
					t.Error("failed budget admission modified message id/reservation")
				}
				s.reset(st, ErrClosed, false)
				if s.txDatagramReserved != 0 || s.txDatagramQueued != 0 {
					t.Error("reset retained cost")
				}
			})
		})
	}
}

func TestDatagramTXNext21UnknownCarrierWriteCannotMigrate(t *testing.T) {
	s, flow, st := next15FECActor(t)
	flow.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := flow.Write(make([]byte, 901)); err != nil {
		t.Fatal(err)
	}
	s.call(context.Background(), func() {
		f, ok := s.nextSendFrame(3)
		if !ok {
			t.Fatal("no submitted candidate")
		}
		s.datagramWriteFailed(f)
		if len(st.txDatagrams) != 0 || s.queue.Len() != 0 || s.txDatagramReserved != 0 || s.txDatagramQueued != 0 {
			t.Error("unknown outcome retained replayable message")
		}
		s.current = &carrier{kind: "tcp", generation: 8}
		s.queue = scheduler.New[protocol.Frame](1200, s.opts.MaxSessionBuffer)
		s.rebindTXDatagrams(time.Now())
		if s.queue.Len() != 0 || st.messageNext != 2 {
			t.Error("unknown write replayed on next generation")
		}
	})
}

func TestDatagramTXNext21WaitingWriteContinuesOnSameFlow(t *testing.T) {
	f, _, flow, received := next21Fixture(t)
	f.client.call(context.Background(), func() { f.client.udpSuspect = true; f.client.beginRecoveryAttempt() })
	flow.SetDeadline(time.Now().Add(time.Second))
	payload := []byte("wait during recovery, original flow continues")
	done := make(chan error, 1)
	go func() {
		n, err := flow.Write(payload)
		if err == nil && n != len(payload) {
			err = errors.New("short datagram write")
		}
		done <- err
	}()
	f.client.call(context.Background(), func() {
		if len(f.client.streams[flow.id].txDatagrams) != 0 || f.client.streams[flow.id].messageNext != 1 {
			t.Error("paused write prematurely admitted")
		}
	})
	next21ResumeTCP(t, f)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting Write did not resume")
	}
	buf := make([]byte, 4096)
	if n, err := flow.Read(buf); err != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatal("waiting message was lost", n, err)
	}
	if received.Load() != 1 || f.backend.dials.Load() != 1 {
		t.Fatal("waiting message repeated or target replaced")
	}
}

func TestDatagramTXNext21WaitDeadlineCannotBeRenewed(t *testing.T) {
	s, flow, _ := transportUDPActor(t, 4096)
	s.call(context.Background(), func() { s.active = false })
	flow.SetWriteDeadline(time.Now().Add(80 * time.Millisecond))
	done := make(chan error, 1)
	started := time.Now()
	go func() { _, err := flow.Write([]byte("keep first cutoff")); done <- err }()
	// An actor barrier establishes that the first not-ready admission check
	// has run before a later setter attempts to renew its original budget.
	s.call(context.Background(), func() {})
	time.Sleep(15 * time.Millisecond)
	flow.SetWriteDeadline(time.Now().Add(time.Second))
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 400*time.Millisecond {
			t.Fatal("deadline renewed", err, time.Since(started))
		}
	case <-time.After(400 * time.Millisecond):
		t.Fatal("extended setter renewed in-flight UDP wait")
	}
}
