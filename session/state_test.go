package session

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"bfp/protocol"
	"bfp/scheduler"
)

// stateSession has no actor or sockets. These tests invoke state transitions in
// the same serialized order as Session.run and inspect the retained state.
func stateSession(t *testing.T, network string) (*Session, *streamState) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &Session{ctx: ctx, cancel: cancel, opts: Options{MaxFlowBuffer: 16, MaxSessionBuffer: 64}.defaults(), streams: map[uint64]*streamState{}, commands: make(chan func(), 128), done: make(chan struct{}), queue: scheduler.New[protocol.Frame](1200, 65536), peerDone: true}
	f := newFlow(s, 1, network)
	st := &streamState{flow: f, target: protocol.Target{Network: network, Address: "example.test:443", Domain: "example.test", RuleTag: "original-rule", Class: protocol.Normal}, effectiveClass: protocol.Normal, maxRemote: 16, segments: map[uint64][]byte{}, datagrams: map[uint64]*assembly{}, completed: map[uint64]bool{}, messageNext: 1, openResult: "ok"}
	s.streams[1] = st
	return s, st
}

func TestOldStreamAckDoesNotRewindOrClose(t *testing.T) {
	s, st := stateSession(t, "tcp")
	st.sendNext = 12
	st.sendAck = 4
	st.chunks = []chunk{{offset: 4, data: []byte("efgh")}, {offset: 8, data: []byte("ijkl")}}
	s.stats.TXBuffered = 8
	s.handle(protocol.Frame{Kind: protocol.StreamAck, Flow: 1, Offset: 2})
	if s.ctx.Err() != nil || st.sendAck != 4 || s.stats.TXBuffered != 8 || len(st.chunks) != 2 {
		t.Fatal("late duplicate STREAM_ACK corrupted current progress")
	}
	s.handle(protocol.Frame{Kind: protocol.StreamAck, Flow: 1, Offset: 8})
	if st.sendAck != 8 || s.stats.TXBuffered != 4 || len(st.chunks) != 1 {
		t.Fatal("new acknowledgement did not release exactly acknowledged bytes")
	}
	s.handle(protocol.Frame{Kind: protocol.StreamAck, Flow: 1, Offset: 8})
	if st.sendAck != 8 || s.stats.TXBuffered != 4 {
		t.Fatal("duplicate acknowledgement released buffers twice")
	}
	s.handle(protocol.Frame{Kind: protocol.StreamAck, Flow: 1, Offset: 13})
	if !errors.Is(s.ctx.Err(), context.Canceled) {
		t.Fatal("acknowledgement beyond submitted bytes was accepted")
	}
}

func TestStreamReceiveWindowOrderingDuplicatesAndConflict(t *testing.T) {
	s, st := stateSession(t, "tcp")
	s.data(st, protocol.Frame{Kind: protocol.StreamData, Flow: 1, Offset: 4, Data: []byte("efgh")})
	if st.receiveNext != 0 || len(st.segments) != 1 || s.stats.RXBuffered != 4 {
		t.Fatal("out-of-order bytes were delivered prematurely")
	}
	s.data(st, protocol.Frame{Kind: protocol.StreamData, Flow: 1, Offset: 4, Data: []byte("efgh")})
	if s.stats.RXBuffered != 4 {
		t.Fatal("duplicate segment consumed credit twice")
	}
	s.data(st, protocol.Frame{Kind: protocol.StreamData, Flow: 1, Offset: 0, Data: []byte("abcd")})
	if st.receiveNext != 8 || st.flow.buffer.String() != "abcdefgh" || s.stats.RXBuffered != 8 {
		t.Fatal("contiguous receive failed")
	}
	s.data(st, protocol.Frame{Kind: protocol.StreamData, Flow: 1, Offset: 0, Data: []byte("abcd")})
	if st.flow.buffer.String() != "abcdefgh" || s.stats.RXBuffered != 8 {
		t.Fatal("retransmission repeated downstream bytes")
	}
	s.data(st, protocol.Frame{Kind: protocol.StreamData, Flow: 1, Offset: 16, Data: []byte("x")})
	if s.ctx.Err() == nil {
		t.Fatal("out-of-window bytes were accepted")
	}
	conflict, other := stateSession(t, "tcp")
	conflict.data(other, protocol.Frame{Kind: protocol.StreamData, Flow: 1, Offset: 4, Data: []byte("efgh")})
	conflict.data(other, protocol.Frame{Kind: protocol.StreamData, Flow: 1, Offset: 4, Data: []byte("xxxx")})
	if conflict.ctx.Err() == nil {
		t.Fatal("conflicting retained overlap was accepted")
	}
}

func TestReceiveFINWaitsForBytesAndKeepsOtherDirection(t *testing.T) {
	s, st := stateSession(t, "tcp")
	s.handle(protocol.Frame{Kind: protocol.Fin, Flow: 1, Offset: 4})
	if st.flow.eof {
		t.Fatal("FIN took effect before its preceding bytes arrived")
	}
	s.data(st, protocol.Frame{Kind: protocol.StreamData, Flow: 1, Offset: 0, Data: []byte("data")})
	if !st.flow.eof || st.localFinal != nil || st.reset {
		t.Fatal("receive FIN closed both directions")
	}
	buffer := make([]byte, 4)
	n, err := st.flow.Read(buffer)
	if err != nil || n != 4 || string(buffer) != "data" {
		t.Fatalf("FIN discarded buffered data: n=%d err=%v", n, err)
	}
	if _, err := st.flow.Read(buffer); err != io.EOF {
		t.Fatalf("receive direction did not end: %v", err)
	}
	s.handle(protocol.Frame{Kind: protocol.Fin, Flow: 1, Offset: 4})
	if s.ctx.Err() != nil {
		t.Fatal("duplicate identical FIN closed session")
	}
	s.handle(protocol.Frame{Kind: protocol.Fin, Flow: 1, Offset: 5})
	if s.ctx.Err() == nil {
		t.Fatal("FIN final offset changed after commit")
	}
}

func TestDuplicateFINReissuesCommittedFinAck(t *testing.T) {
	s, st := stateSession(t, "tcp")
	s.handle(protocol.Frame{Kind: protocol.Fin, Flow: 1, Offset: 0})
	if !st.finAckSent {
		t.Fatal("initial FIN was not committed")
	}
	for {
		if f, ok := s.queue.Pop(); !ok {
			break
		} else if f.Kind == protocol.FinAck {
			break
		}
	}
	s.handle(protocol.Frame{Kind: protocol.Fin, Flow: 1, Offset: 0})
	found := false
	for {
		f, ok := s.queue.Pop()
		if !ok {
			break
		}
		if f.Kind == protocol.FinAck && f.Offset == 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("duplicate FIN did not regenerate the logical FinAck")
	}
}

func TestLegacyClassUpdateCannotChangeLocalClassOrOPENMetadata(t *testing.T) {
	s, st := stateSession(t, "tcp")
	original := st.target
	s.handle(protocol.Frame{Kind: protocol.ClassUpdate, Flow: 1, Value: uint64(protocol.Bulk)})
	if st.target != original || st.effectiveClass != protocol.Normal || s.classFor(1) != protocol.Normal {
		t.Fatal("legacy class update modified local policy or immutable OPEN identity")
	}
	s.handleOpen(protocol.Frame{Kind: protocol.Open, Flow: 1, Data: encodeJSON(original)})
	if s.ctx.Err() != nil {
		t.Fatal("duplicate original OPEN was rejected after class update")
	}
}

func TestInvalidClassValueCannotWrapToValidClass(t *testing.T) {
	s, st := stateSession(t, "tcp")
	s.handle(protocol.Frame{Kind: protocol.ClassUpdate, Flow: 1, Value: 256})
	if st.effectiveClass != protocol.Normal && s.ctx.Err() == nil {
		t.Fatal("out-of-range wire class wrapped to valid uint8 class")
	}
}

func fragment(id uint64, total, offset int, payload string) protocol.Frame {
	return protocol.Frame{Kind: protocol.Datagram, Flow: 1, Offset: id, Value: uint64(total)<<32 | uint64(offset), Data: []byte(payload)}
}

func TestDatagramFragmentsDuplicatesAndConflicts(t *testing.T) {
	s, st := stateSession(t, "udp")
	s.datagram(fragment(1, 8, 4, "efgh"))
	s.datagram(fragment(1, 8, 4, "efgh"))
	if len(st.flow.messages) != 0 || st.datagrams[1].count != 4 {
		t.Fatal("partial or duplicate fragments changed delivery")
	}
	s.datagram(fragment(1, 8, 0, "abcd"))
	if len(st.flow.messages) != 1 || string(st.flow.messages[0]) != "abcdefgh" || len(st.datagrams) != 0 {
		t.Fatal("complete datagram was not delivered once")
	}
	s.datagram(fragment(1, 8, 0, "abcdefgh"))
	if len(st.flow.messages) != 1 {
		t.Fatal("completed datagram was delivered twice")
	}
	s.datagram(fragment(2, 4, 0, "ab"))
	s.datagram(fragment(2, 4, 0, "xy"))
	s.datagram(fragment(2, 4, 0, "abcd"))
	if len(st.flow.messages) != 1 || !st.completed[2] {
		t.Fatal("conflicting overlap did not permanently reject message")
	}
	s.datagram(fragment(3, 0, 0, ""))
	if len(st.flow.messages) != 2 || len(st.flow.messages[1]) != 0 {
		t.Fatal("empty datagram boundary was lost")
	}
}

func TestDatagramBoundsRetirementAndAssemblyLimit(t *testing.T) {
	s, st := stateSession(t, "udp")
	for _, f := range []protocol.Frame{fragment(1, 16385, 0, "a"), fragment(1, 4, 5, ""), fragment(1, 4, 3, "ab")} {
		s.datagram(f)
	}
	if len(st.datagrams) != 0 || len(st.flow.messages) != 0 || s.stats.Dropped != 3 {
		t.Fatal("out-of-bounds fragment created state")
	}
	s.datagram(fragment(1, 1, 0, "a"))
	s.datagram(fragment(5000, 1, 0, "b"))
	s.datagram(fragment(1, 1, 0, "a"))
	if len(st.flow.messages) != 2 || st.completed[1] {
		t.Fatal("retired duplicate recreated state")
	}
	s.datagram(fragment(math.MaxUint64, 1, 0, "c"))
	s.datagram(fragment(5000, 1, 0, "b"))
	if len(st.flow.messages) != 3 {
		t.Fatal("retirement comparison overflow accepted an old message")
	}
	bounded, other := stateSession(t, "udp")
	for id := uint64(1); id <= 9; id++ {
		bounded.datagram(fragment(id, 4, 0, "a"))
	}
	if len(other.datagrams) != 8 || bounded.stats.Dropped != 1 {
		t.Fatal("assembly count exceeded limit")
	}
}

func TestDatagramLengthConflictCannotRestartMessage(t *testing.T) {
	s, st := stateSession(t, "udp")
	s.datagram(fragment(1, 4, 0, "ab"))
	s.datagram(fragment(1, 5, 2, "cd"))
	s.datagram(fragment(1, 4, 0, "abcd"))
	if len(st.flow.messages) != 0 {
		t.Fatal("inconsistent total length was forgotten and message later delivered")
	}
}

func TestExpiredDatagramCannotRestartItsReassemblyDeadline(t *testing.T) {
	s, st := stateSession(t, "udp")
	s.datagram(fragment(1, 4, 0, "ab"))
	now := time.Now()
	st.datagrams[1].created = now.Add(-2 * time.Second)
	s.active = true
	s.current = &carrier{kind: "tcp"}
	s.lastReceive = now
	s.lastProbe = now
	s.lastKey = now
	s.maintain(now)
	if len(st.datagrams) != 0 {
		t.Fatal("missing-fragment datagram did not expire")
	}
	s.datagram(fragment(1, 4, 0, "abcd"))
	if len(st.flow.messages) != 0 {
		t.Fatal("late fragments restarted an expired message and delivered it")
	}
}

type closeCounterConn struct {
	net.Conn
	closed atomic.Int32
}

func (c *closeCounterConn) Close() error { c.closed.Add(1); return nil }

func TestResetReclaimsUnreadBuffersAndDatagrams(t *testing.T) {
	s, st := stateSession(t, "tcp")
	st.chunks = []chunk{{offset: 0, data: []byte("send")}}
	s.stats.TXBuffered = 4
	s.data(st, protocol.Frame{Kind: protocol.StreamData, Flow: 1, Offset: 0, Data: []byte("unread")})
	s.data(st, protocol.Frame{Kind: protocol.StreamData, Flow: 1, Offset: 8, Data: []byte("gap")})
	st.flow.messages = [][]byte{[]byte("queued datagram")}
	s.stats.RXBuffered += len(st.flow.messages[0])
	st.datagrams[1] = &assembly{data: make([]byte, 100), seen: make([]bool, 100)}
	conn := &closeCounterConn{}
	st.targetConn = conn
	s.reset(st, io.ErrClosedPipe, true)
	s.reset(st, io.ErrClosedPipe, true)
	if s.stats.TXBuffered != 0 || s.stats.RXBuffered != 0 || st.flow.buffer.Len() != 0 || len(st.flow.messages) != 0 || len(st.datagrams) != 0 || len(st.chunks) != 0 || len(st.segments) != 0 || conn.closed.Load() != 1 {
		t.Fatalf("reset retained resources: TX=%d RX=%d unread=%d messages=%d assemblies=%d closes=%d", s.stats.TXBuffered, s.stats.RXBuffered, st.flow.buffer.Len(), len(st.flow.messages), len(st.datagrams), conn.closed.Load())
	}
}

func TestResetBeforeOpenLeavesTerminalTombstoneAndPreventsRedial(t *testing.T) {
	s, _ := stateSession(t, "tcp")
	// Flow 9 has no stream state yet. A reordered RESET must still reserve its
	// terminal decision before a later OPEN can reach the dialer.
	s.handle(protocol.Frame{Kind: protocol.Reset, Flow: 9})
	if !s.hasResetTombstone(9) {
		t.Fatal("unknown RESET did not create a terminal tombstone")
	}
	s.handleOpen(protocol.Frame{Kind: protocol.Open, Flow: 9, Data: encodeJSON(protocol.Target{Network: "tcp", Address: "late.example:443", Class: protocol.Normal})})
	if s.ctx.Err() != nil {
		t.Fatal("terminal tombstone caused the Session to fail")
	}
	if _, ok := s.streams[9]; ok {
		t.Fatal("OPEN after RESET allocated a new stream")
	}
	found := false
	for {
		f, ok := s.queue.Pop()
		if !ok {
			break
		}
		if f.Kind == protocol.OpenResult && f.Flow == 9 && string(f.Data) == "reset" {
			found = true
		}
	}
	if !found {
		t.Fatal("OPEN after RESET did not receive a terminal result")
	}
	// A duplicate RESET remains an idempotent acknowledgement and does not
	// remove the tombstone.
	s.handle(protocol.Frame{Kind: protocol.Reset, Flow: 9})
	if !s.hasResetTombstone(9) {
		t.Fatal("duplicate RESET removed the tombstone")
	}
}

func TestResumeSnapshotCarriesCurrentControlRevisions(t *testing.T) {
	s, _, st := actorFlow(t, 32)
	if err := s.call(context.Background(), func() {
		st.receiveNext = 7
		st.consumed = 3
		st.openResult = "ok"
		s.streamAckFrame(st)
		s.maxFlowFrame(st)
		s.openResultFrame(st)
		snap := s.flowSnapshot(st)
		if snap.Receive != 7 || snap.Max != 35 || snap.Result != "ok" {
			t.Fatalf("snapshot semantic state changed: %+v", snap)
		}
		if snap.AckRev == 0 || snap.MaxRev == 0 || snap.OpenRev == 0 {
			t.Fatalf("snapshot omitted latest-control revisions: %+v", snap)
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestResumeSnapshotRevisionLowerBoundsRejectConflicts(t *testing.T) {
	s, st := stateSession(t, "tcp")
	st.peerStreamAckRevision, st.peerStreamAckValue = 4, 8
	st.peerMaxFlowRevision, st.peerMaxFlowValue = 3, 32
	st.peerOpenResultRevision, st.peerOpenResultValue = 2, "ok"
	if !s.applyResumeControls(st, flowSnapshot{ID: 1, Receive: 7, Max: 31, Result: "ok", AckRev: 3, MaxRev: 2, OpenRev: 1}) {
		t.Fatal("a stale snapshot with the same semantic result was rejected")
	}
	if st.peerStreamAckRevision != 4 || st.peerStreamAckValue != 8 || st.peerMaxFlowRevision != 3 || st.peerMaxFlowValue != 32 || st.peerOpenResultRevision != 2 {
		t.Fatal("stale snapshot changed the installed lower bounds")
	}
	if !s.applyResumeControls(st, flowSnapshot{ID: 1, Receive: 8, Max: 32, Result: "ok", AckRev: 4, MaxRev: 3, OpenRev: 2}) {
		t.Fatal("identical snapshot revisions were rejected")
	}
	if s.applyResumeControls(st, flowSnapshot{ID: 1, Receive: 8, Max: 32, Result: "failed", AckRev: 4, MaxRev: 3, OpenRev: 2}) {
		t.Fatal("same revision with a different OPEN result was accepted")
	}
}
