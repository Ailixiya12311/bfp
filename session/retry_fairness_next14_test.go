package session

import (
	"net"
	"testing"
	"time"

	"bfp/obfuscation"
	"bfp/protocol"
	"bfp/security"
)

func retryFairnessFlow(s *Session, id uint64, class protocol.Class) *streamState {
	f := newFlow(s, id, "tcp")
	st := &streamState{
		flow:           f,
		target:         protocol.Target{Network: "tcp", Address: "example.test:443", Class: class},
		effectiveClass: class,
		chunks:         []chunk{{offset: 0, data: []byte{byte(id), 0xA7, 0x5C}}},
		maxRemote:      1 << 20,
		segments:       map[uint64][]byte{},
		datagrams:      map[uint64]*assembly{},
		completed:      map[uint64]bool{},
		openResult:     "ok",
	}
	s.streams[id] = st
	return st
}

func putRetry(s *Session, flow uint64) {
	f := protocol.Frame{Kind: protocol.StreamData, Flow: flow, Offset: 0}
	r := makeRef(f)
	s.udpPath.retries[r.key()] = r
}

func readRetryFrames(t *testing.T, s *Session, receiver *net.UDPConn, count int) []protocol.Frame {
	t.Helper()
	rx, err := security.NewRecordCipher(s.current.keys.Send[:], s.current.handle, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]protocol.Frame, 0, count)
	for i := 0; i < count; i++ {
		if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		wire := make([]byte, security.MaxUDPRecordSize)
		n, _, err := receiver.ReadFromUDP(wire)
		if err != nil {
			t.Fatalf("retry record %d: %v", i, err)
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
			t.Fatalf("retry record %d decoded frames=%v err=%v", i, frames, err)
		}
		out = append(out, frames[0])
	}
	return out
}

func TestUDPRetryFairnessUsesCurrentClassAndDoesNotStarveInteractiveFlow(t *testing.T) {
	s, now, receiver := udpOwner(t)
	b1 := retryFairnessFlow(s, 1, protocol.Bulk)
	b2 := retryFairnessFlow(s, 2, protocol.Bulk)
	i := retryFairnessFlow(s, 3, protocol.Normal)
	// The class is changed after the reference was created.  A retry must read
	// this current owner state, just as a newly queued StreamData frame does.
	i.effectiveClass = protocol.Interactive
	s.udpPath.retryClassCursor = 0
	s.udpPath.retryFlowCursor = [3]uint64{}
	s.cwnd, s.paceTokens = 1<<20, 1<<20
	for round := 0; round < 3; round++ {
		s.udpPath.retries = make(map[refKey]logicalRef)
		putRetry(s, b1.flow.id)
		putRetry(s, b2.flow.id)
		putRetry(s, i.flow.id)
		*now = now.Add(time.Millisecond)
		s.udpPath.retryClassCursor = 0
		s.udpPath.retryFlowCursor = [3]uint64{}
		s.flushUDP()
		frames := readRetryFrames(t, s, receiver, 2)
		if frames[0].Kind != protocol.StreamData || frames[0].Flow != i.flow.id {
			t.Fatalf("round %d interactive retry starved or stale class used: %+v", round, frames)
		}
		if frames[1].Kind != protocol.StreamData || frames[1].Flow != b1.flow.id {
			t.Fatalf("round %d first bulk retry order changed: %+v", round, frames)
		}
		if len(s.udpPath.retries) != 1 || s.udpPath.retries[makeRef(protocol.Frame{Kind: protocol.StreamData, Flow: b2.flow.id}).key()].flow != b2.flow.id {
			t.Fatalf("round %d retry slot/accounting changed: %v", round, s.udpPath.retries)
		}
	}
}

func TestUDPRetryStaleCleanupDoesNotConsumeRetrySlots(t *testing.T) {
	s, now, receiver := udpOwner(t)
	b := retryFairnessFlow(s, 1, protocol.Bulk)
	i := retryFairnessFlow(s, 3, protocol.Interactive)
	s.udpPath.retryClassCursor = 0
	s.udpPath.retryFlowCursor = [3]uint64{}
	s.cwnd, s.paceTokens = 1<<20, 1<<20
	stale := makeRef(protocol.Frame{Kind: protocol.StreamData, Flow: 99, Offset: 0})
	s.udpPath.retries[stale.key()] = stale
	putRetry(s, b.flow.id)
	putRetry(s, i.flow.id)
	*now = now.Add(time.Millisecond)
	s.flushUDP()
	frames := readRetryFrames(t, s, receiver, 2)
	if frames[0].Flow != i.flow.id || frames[1].Flow != b.flow.id {
		t.Fatalf("stale reference consumed a retry slot: %+v", frames)
	}
	if _, ok := s.udpPath.retries[stale.key()]; ok {
		t.Fatal("stale retry reference was retained")
	}
}

func TestUDPRetryWriteFailureRetainsReference(t *testing.T) {
	s, _, _ := udpOwner(t)
	st := retryFairnessFlow(s, 1, protocol.Interactive)
	putRetry(s, st.flow.id)
	if err := s.current.conn.Close(); err != nil {
		t.Fatal(err)
	}
	s.flushUDP()
	if _, ok := s.udpPath.retries[makeRef(protocol.Frame{Kind: protocol.StreamData, Flow: st.flow.id}).key()]; !ok {
		t.Fatal("failed retry write discarded ownership")
	}
}
