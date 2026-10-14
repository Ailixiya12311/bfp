package session

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"bfp/internal/classcontrol"
	"bfp/obfuscation"
	"bfp/protocol"
	"bfp/security"
)

// classBudgetConn completes writes into a buffer, or permits a real partial
// write before failing. It does not bypass the encrypted TCP record/framer path.
type classBudgetConn struct {
	wire      bytes.Buffer
	failAfter int
	closed    bool
}

func (c *classBudgetConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *classBudgetConn) Write(p []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	if c.failAfter >= 0 {
		remaining := c.failAfter - c.wire.Len()
		if remaining <= 0 {
			return 0, io.ErrClosedPipe
		}
		if remaining < len(p) {
			return c.wire.Write(p[:remaining])
		}
	}
	return c.wire.Write(p)
}
func (c *classBudgetConn) Close() error                     { c.closed = true; return nil }
func (c *classBudgetConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *classBudgetConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *classBudgetConn) SetDeadline(time.Time) error      { return nil }
func (c *classBudgetConn) SetReadDeadline(time.Time) error  { return nil }
func (c *classBudgetConn) SetWriteDeadline(time.Time) error { return nil }

func classBudgetTCP(t *testing.T) (*Session, *streamState, *time.Time, *classBudgetConn) {
	t.Helper()
	s, st := stateSession(t, "tcp")
	now := time.Unix(100, 0)
	s.transportNow = func() time.Time { return now }
	conn := &classBudgetConn{failAfter: -1}
	keys := &security.TransportKeys{}
	keys.Send[0], keys.Receive[0] = 1, 2
	c, err := makeCarrier("tcp", 1, bytes.Repeat([]byte{3}, 16), keys, conn, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.close)
	s.current, s.active, s.peerDone, s.localDoneAck = c, true, true, true
	s.rtt = 200 * time.Millisecond
	classBudgetInstall(t, s, st)
	return s, st, &now, conn
}

func classBudgetInstall(t *testing.T, s *Session, st *streamState) {
	t.Helper()
	if s.classTable == nil {
		var err error
		s.classTable, err = classcontrol.New(classcontrol.DefaultConfig())
		if err != nil {
			t.Fatal(err)
		}
	}
	if !s.startClassControl(st) {
		t.Fatal("class control did not start")
	}
	s.enableClassControl(st)
	if s.ctx.Err() != nil {
		t.Fatal(s.ctx.Err())
	}
}

func classBudgetView(t *testing.T, s *Session, flow uint64) classcontrol.Snapshot {
	t.Helper()
	view, err := s.classTable.Snapshot(flow)
	if err != nil {
		t.Fatal(err)
	}
	return view
}

func classBudgetTCPFrames(t *testing.T, s *Session, conn *classBudgetConn, count int) []protocol.Frame {
	t.Helper()
	peer, err := security.NewFramer(bytes.NewBuffer(conn.wire.Bytes()), s.current.keys.Receive[:], s.current.keys.Send[:])
	if err != nil {
		t.Fatal(err)
	}
	rx, err := security.NewRecordCipher(s.current.keys.Send[:], s.current.handle, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []protocol.Frame
	for i := 0; i < count; i++ {
		wire, err := peer.Read()
		if err != nil {
			t.Fatalf("TCP frame %d: %v", i, err)
		}
		plain, _, err := rx.Open(wire)
		if err != nil {
			t.Fatal(err)
		}
		plain, err = obfuscation.Unpad(plain)
		if err != nil {
			t.Fatal(err)
		}
		frames, err := protocol.Decode(plain)
		if err != nil || len(frames) != 1 {
			t.Fatalf("TCP decoded frames=%v err=%v", frames, err)
		}
		out = append(out, frames[0])
	}
	if _, err := peer.Read(); !errors.Is(err, io.EOF) {
		t.Fatalf("more than %d TCP records sent in one flush: %v", count, err)
	}
	return out
}

func classBudgetUDPFrames(t *testing.T, s *Session, receiver *net.UDPConn, count int) []protocol.Frame {
	t.Helper()
	rx, err := security.NewRecordCipher(s.current.keys.Send[:], s.current.handle, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var out []protocol.Frame
	for i := 0; i < count; i++ {
		wire := make([]byte, security.MaxUDPRecordSize)
		n, _, err := receiver.ReadFromUDP(wire)
		if err != nil {
			t.Fatalf("UDP frame %d: %v", i, err)
		}
		plain, _, err := rx.Open(wire[:n])
		if err != nil {
			t.Fatal(err)
		}
		plain, err = obfuscation.Unpad(plain)
		if err != nil {
			t.Fatal(err)
		}
		frames, err := protocol.Decode(plain)
		if err != nil || len(frames) != 1 {
			t.Fatalf("UDP decoded frames=%v err=%v", frames, err)
		}
		out = append(out, frames[0])
	}
	if got := s.current.tx.NextMeta().Number; got != uint64(count) {
		t.Fatalf("more than %d UDP records sent in one flush: next number=%d", count, got)
	}
	return out
}

func TestClassControlTCPPartialWriteDoesNotPublish(t *testing.T) {
	s, st, _, conn := classBudgetTCP(t)
	before := classBudgetView(t, s, st.flow.id)
	conn.failAfter = 7
	s.flush()
	after := classBudgetView(t, s, st.flow.id)
	if s.active || !conn.closed || conn.wire.Len() != 7 || s.stats.WireSent != 0 {
		t.Fatalf("TCP partial write did not suspend without success: active=%v closed=%v partial=%d stats=%+v", s.active, conn.closed, conn.wire.Len(), s.stats)
	}
	if after != before || !after.Pending || after.Published.Version != 0 || after.Attempts != 0 {
		t.Fatalf("failed TCP write published class state: before=%+v after=%+v", before, after)
	}
	if _, err := s.classTable.Ack(st.flow.id, before.Local.Version, before.Local.Class, s.classStamp()); !errors.Is(err, classcontrol.ErrAck) {
		t.Fatalf("failed TCP write acquired ACK proof: %v", err)
	}
}

func TestClassControlUDPAdmissionAndFailedWriteDoNotPublish(t *testing.T) {
	for _, mode := range []string{"cwnd", "pacer", "failed-write"} {
		t.Run(mode, func(t *testing.T) {
			s, _, _ := udpOwner(t)
			st := s.streams[1]
			classBudgetInstall(t, s, st)
			before := classBudgetView(t, s, 1)
			ledger := s.udpPath.ledger.Snapshot()
			meta := s.current.tx.NextMeta()
			switch mode {
			case "cwnd":
				s.cwnd = 1
			case "pacer":
				s.paceTokens = 0
			case "failed-write":
				_ = s.current.conn.Close()
			}
			sent, err := s.udpSend(classFrame(before.Local, 0), false, false, false)
			if sent || mode == "failed-write" && err == nil || mode != "failed-write" && err != nil {
				t.Fatalf("UDP admission %s sent=%v err=%v", mode, sent, err)
			}
			after := classBudgetView(t, s, 1)
			if after != before || s.udpPath.ledger.Snapshot() != ledger || len(s.udpPath.refs) != 0 || s.stats.WireSent != 0 {
				t.Fatalf("UDP %s published without complete admitted write: before=%+v after=%+v ledger=%+v", mode, before, after, s.udpPath.ledger.Snapshot())
			}
			if mode != "failed-write" && s.current.tx.NextMeta() != meta {
				t.Fatal("UDP cwnd/pacer rejection consumed a cipher nonce")
			}
		})
	}
}

func TestClassControlRecoveryGatesPreventPublication(t *testing.T) {
	for _, kind := range []string{"tcp", "udp"} {
		for _, gate := range []string{"peer-snapshot", "local-receipt"} {
			t.Run(kind+"/"+gate, func(t *testing.T) {
				var s *Session
				var conn *classBudgetConn
				if kind == "tcp" {
					s, _, _, conn = classBudgetTCP(t)
				} else {
					s, _, _ = udpOwner(t)
					classBudgetInstall(t, s, s.streams[1])
				}
				before := classBudgetView(t, s, 1)
				if gate == "peer-snapshot" {
					s.peerDone = false
				} else {
					s.localDoneAck = false
				}
				if f, ok := s.nextClassFrame(); ok {
					t.Fatalf("pre-sync class frame selected: %+v", f)
				}
				// A stale queued frame must also be suppressed by send preflight.
				frame := classFrame(before.Local, 0)
				if kind == "tcp" {
					if !s.enqueue(frame, protocol.Interactive) {
						t.Fatal("stale class fixture enqueue failed")
					}
					s.flush()
					if conn.wire.Len() != 0 {
						t.Fatal("TCP class frame escaped sync gate")
					}
				} else if consumed, err := s.udpSend(frame, false, false, false); err != nil || !consumed {
					t.Fatalf("UDP gated stale frame was not discarded: consumed=%v err=%v", consumed, err)
				}
				if after := classBudgetView(t, s, 1); after != before || s.stats.WireSent != 0 {
					t.Fatalf("sync gate modified publication state: before=%+v after=%+v", before, after)
				}
			})
		}
	}
}

func TestClassControlBypassesBulkFIFOAndSharesFourSendSlots(t *testing.T) {
	for _, kind := range []string{"tcp", "udp"} {
		t.Run(kind, func(t *testing.T) {
			var s *Session
			var conn *classBudgetConn
			var receiver *net.UDPConn
			if kind == "tcp" {
				s, _, _, conn = classBudgetTCP(t)
			} else {
				s, _, receiver = udpOwner(t)
				classBudgetInstall(t, s, s.streams[1])
			}
			st := s.streams[1]
			st.effectiveClass = protocol.Bulk
			s.updateClassControl(st)
			for id := uint64(2); id <= 4; id++ {
				flow := newFlow(s, id, "tcp")
				other := &streamState{flow: flow, effectiveClass: protocol.Bulk, openResult: "ok"}
				s.streams[id] = other
				classBudgetInstall(t, s, other)
			}
			for id := uint64(1); id <= 4; id++ {
				s.handleClassControl(protocol.Frame{Kind: protocol.ClassUpdate, Flow: id, Offset: 1, Value: uint64(protocol.Normal)})
			}
			for n := 0; n < 4; n++ {
				if !s.enqueue(protocol.Frame{Kind: protocol.StreamData, Flow: st.flow.id, Offset: uint64(n), Data: []byte{byte(n)}}, protocol.Bulk) {
					t.Fatal("Bulk FIFO fixture admission failed")
				}
			}
			s.flush()
			var frames []protocol.Frame
			if kind == "tcp" {
				frames = classBudgetTCPFrames(t, s, conn, 4)
			} else {
				frames = classBudgetUDPFrames(t, s, receiver, 4)
				if s.paceTokens != 4800-float64(s.stats.WireSent) || s.flight != int(s.stats.WireSent) || s.udpPath.ledger.Snapshot().Live != 4 {
					t.Fatalf("class controls bypassed complete UDP record cost: pace=%v flight=%d wire=%d ledger=%+v", s.paceTokens, s.flight, s.stats.WireSent, s.udpPath.ledger.Snapshot())
				}
			}
			if frames[0].Kind != protocol.ClassUpdate || frames[1].Kind != protocol.ClassUpdate ||
				frames[2].Kind != protocol.StreamData || frames[3].Kind != protocol.StreamData ||
				frames[2].Offset != 0 || frames[3].Offset != 1 || s.queue.Len() != 2 {
				t.Fatalf("class controls blocked by Bulk FIFO or exceeded 2/4 slots: frames=%+v queue=%d", frames, s.queue.Len())
			}
			if frames[0].Flags == frames[1].Flags {
				t.Fatalf("TX and peer ACK did not share class selection opportunities: %+v", frames[:2])
			}
			if s.classTable.Usage() != 4 || s.ctx.Err() != nil {
				t.Fatalf("slot test lost flow state: usage=%d ctx=%v", s.classTable.Usage(), s.ctx.Err())
			}
		})
	}
}

func TestClassControlUDPLossUsesLatestAndAckHasNoIndependentRetry(t *testing.T) {
	s, now, _ := udpOwner(t)
	st := s.streams[1]
	classBudgetInstall(t, s, st)
	first := classFrame(st.classTX, 0)
	if sent, err := s.udpSend(first, false, false, false); !sent || err != nil {
		t.Fatalf("first UDP publication sent=%v err=%v", sent, err)
	}
	*now = now.Add(time.Millisecond)
	st.effectiveClass = protocol.Bulk
	s.updateClassControl(st)
	before := classBudgetView(t, s, 1)
	s.queueRetry(makeRef(first))
	latest, ok := s.resolveRef(makeRef(first), *now)
	if !ok || latest.Offset != before.Local.Version || latest.Value != uint64(protocol.Bulk) || len(s.udpPath.retries) != 0 {
		t.Fatalf("UDP class loss retained stale state or unbounded retry ref: latest=%+v ok=%v refs=%d", latest, ok, len(s.udpPath.retries))
	}
	after := classBudgetView(t, s, 1)
	if after.Local != before.Local || after.Attempts != before.Attempts || after.Retries != before.Retries || after.Started != before.Started {
		t.Fatalf("loss reference consumed or renewed budget: before=%+v after=%+v", before, after)
	}
	peer := protocol.Frame{Kind: protocol.ClassUpdate, Flow: 1, Offset: 7, Value: uint64(protocol.Interactive)}
	s.handleClassControl(peer)
	ack := peer
	ack.Flags = 1
	if sent, err := s.udpSend(ack, false, false, false); !sent || err != nil {
		t.Fatalf("peer ACK UDP publication sent=%v err=%v", sent, err)
	}
	s.queueRetry(makeRef(ack))
	if _, ok := s.resolveRef(makeRef(ack), *now); ok {
		t.Fatal("ACK acquired an independent loss retry")
	}
	if view := classBudgetView(t, s, 1); view.AckPending || len(s.udpPath.retries) != 0 {
		t.Fatalf("lost ACK requeued itself: view=%+v retryRefs=%d", view, len(s.udpPath.retries))
	}
	s.handleClassControl(peer)
	if view := classBudgetView(t, s, 1); !view.AckPending || view.Ack.Version != peer.Offset || view.Ack.Class != protocol.Interactive {
		t.Fatalf("duplicate announcement did not requeue exact ACK: %+v", view)
	}
}

func TestClassControlTerminalCleanupAndExhaustionDoNotReviveFlow(t *testing.T) {
	for _, terminal := range []string{"reset", "exhausted", "fin"} {
		t.Run(terminal, func(t *testing.T) {
			s, st, now, _ := classBudgetTCP(t)
			s.handleClassControl(protocol.Frame{Kind: protocol.ClassUpdate, Flow: 1, Offset: 3, Value: uint64(protocol.Bulk)})
			if terminal == "reset" {
				s.reset(st, io.ErrClosedPipe, true)
			} else if terminal == "exhausted" {
				*now = now.Add(30 * time.Second)
				s.maintainClassControls()
			} else {
				final := uint64(0)
				st.localFinal, st.remoteFinal, st.finAck = &final, &final, true
				s.maintainClassControls()
			}
			if !st.terminal() || s.classTable.Usage() != 0 || terminal != "fin" && (!st.reset || !s.hasResetTombstone(1) || !st.resetPending) {
				t.Fatalf("terminal class state did not use bounded RESET cleanup: reset=%v tombstone=%v usage=%d pending=%v", st.reset, s.hasResetTombstone(1), s.classTable.Usage(), st.resetPending)
			}
			for _, flags := range []uint8{0, 1} {
				f := protocol.Frame{Kind: protocol.ClassUpdate, Flags: flags, Flow: 1, Offset: 3, Value: uint64(protocol.Bulk)}
				s.handleClassControl(f)
				if _, ok := s.resolveRef(makeRef(f), *now); ok {
					t.Fatal("terminal ClassUpdate reference was revived")
				}
			}
			if s.classTable.Usage() != 0 || s.ctx.Err() != nil {
				t.Fatalf("terminal class traffic recreated state or canceled healthy Session: usage=%d ctx=%v", s.classTable.Usage(), s.ctx.Err())
			}
		})
	}
}

func TestClassControlRecoverySnapshotDoesNotAckLocalPublication(t *testing.T) {
	s, now, _ := udpOwner(t)
	st := s.streams[1]
	classBudgetInstall(t, s, st)
	if sent, err := s.udpSend(classFrame(st.classTX, 0), false, false, false); !sent || err != nil {
		t.Fatalf("UDP publication sent=%v err=%v", sent, err)
	}
	frozen := s.flowSnapshot(st)
	*now = now.Add(5 * time.Second)
	st.effectiveClass = protocol.Bulk
	s.updateClassControl(st)
	before := classBudgetView(t, s, 1)
	if frozen.TXClass == nil || frozen.TXClass.Version != 1 || st.classTX.Version != 2 {
		t.Fatalf("local snapshot did not freeze pre-update class: frozen=%+v local=%+v", frozen.TXClass, st.classTX)
	}
	s.peerDone, s.localDoneAck = false, false
	s.syncReceived, s.syncAck = map[uint64]bool{}, map[uint64]bool{}
	s.peerSyncCount = -1
	s.syncFrames = []protocol.Frame{{Kind: protocol.ResumeState, Flow: 1, Value: 1, Data: encodeJSON(frozen)}}
	peer := flowSnapshot{ID: 1, Receive: 0, Max: 16, Result: "ok", TXClass: &classWireSnapshot{Version: 12, Class: uint64(protocol.Interactive)}}
	s.handle(protocol.Frame{Kind: protocol.ResumeState, Flow: 1, Value: 1, Data: encodeJSON(peer)})
	s.handle(protocol.Frame{Kind: protocol.ResumeState, Flags: 1, Flow: 1, Value: 1})
	if s.ctx.Err() != nil || !s.syncAck[1] || !s.syncReceived[1] {
		t.Fatalf("valid class recovery snapshot/receipt was not applied: ctx=%v local=%v peer=%v", s.ctx.Err(), s.syncAck, s.syncReceived)
	}
	after := classBudgetView(t, s, 1)
	if after.Local != before.Local || after.Published != before.Published || after.Acked != before.Acked ||
		!after.Pending || after.Started != before.Started || after.Attempts != before.Attempts || after.Retries != before.Retries || after.AckPending {
		t.Fatalf("snapshot or its receipt completed local exact ACK / changed budget: before=%+v after=%+v", before, after)
	}
	if !after.Peer.Known || after.Peer.State.Version != 12 || after.Peer.State.Class != protocol.Interactive || st.effectiveClass != protocol.Bulk {
		t.Fatalf("snapshot changed local TX policy or failed peer merge: view=%+v localClass=%v", after, st.effectiveClass)
	}
	// Replacing transport scope follows the attach glue without renewing the
	// semantic announcement lifetime; pre-sync selection remains closed.
	s.classTable.RebindCarrier()
	s.resetTransport(*now)
	if _, ok := s.nextClassFrame(); ok {
		t.Fatal("class announcement sent before recovery Done completion")
	}
	if rebound := classBudgetView(t, s, 1); rebound.Local != before.Local || rebound.Started != before.Started || rebound.Attempts != before.Attempts || rebound.Retries != before.Retries || !rebound.Pending {
		t.Fatalf("transport rebind renewed announcement budget: %+v", rebound)
	}
	s.peerDone, s.localDoneAck = true, true
	latest, ok := s.nextClassFrame()
	if !ok || latest.Flags != 0 || latest.Offset != 2 || latest.Value != uint64(protocol.Bulk) {
		t.Fatalf("recovery did not reselect current pending announcement: %+v, %v", latest, ok)
	}
}
