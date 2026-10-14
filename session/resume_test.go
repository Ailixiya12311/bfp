package session

import (
	"bfp/internal/latestcontrol"
	"bfp/protocol"
	"context"
	"testing"
	"time"
)

func TestResumeDoneCarriesSessionRevisionAndDirtyLatestControl(t *testing.T) {
	s, _, st := actorFlow(t, 64)
	defer s.Close()
	if err := s.call(context.Background(), func() {
		s.current = &carrier{kind: "tcp", generation: 7}
		s.resumeID = 3
		s.maxSessionFrame()
		s.resumeSessionRevision = s.maxSessionRevision
		s.resumeSessionValue = s.maxSessionValue
		s.syncFrames = []protocol.Frame{{Kind: protocol.ResumeState, Flow: st.flow.id, Value: 7, Data: encodeJSON(flowSnapshot{ID: st.flow.id})}}
		s.captureResumeBaseline()
		// This revision is created after the Flow snapshot boundary.
		st.receiveNext = 9
		s.streamAckFrame(st)
		frame, ok := s.resumeDoneFrame(0)
		if !ok {
			t.Fatal("resume done frame was not constructed")
		}
		state, legacy, err := decodeResumeDoneFrame(frame)
		if err != nil || legacy {
			t.Fatalf("decode resume done: legacy=%v err=%v", legacy, err)
		}
		if state.Generation != 7 || state.SnapshotID != 3 || state.SnapshotCount != 1 {
			t.Fatalf("wrong resume scope: %+v", state)
		}
		if state.SessionRevision == 0 || state.SessionValue == 0 {
			t.Fatalf("session credit revision missing: %+v", state)
		}
		if len(state.Dirty) != 1 || state.Dirty[0].Kind != protocol.StreamAck || state.Dirty[0].Flow != st.flow.id || state.Dirty[0].Value != 9 {
			t.Fatalf("dirty latest-control was not carried: %+v", state.Dirty)
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestResumeDoneAppliesDirtyStateAndEchoesSnapshotReceipt(t *testing.T) {
	s, _, st := actorFlow(t, 512)
	defer s.Close()
	if err := s.call(context.Background(), func() {
		s.current = &carrier{kind: "tcp", generation: 4}
		s.peerSyncCount = 0
		s.syncReceived = map[uint64]bool{}
		s.syncFrames = nil
		st.sendNext = 7
		st.chunks = []chunk{{offset: 0, data: []byte("payload")}}
		st.peerMaxFlowRevision, st.peerMaxFlowValue = 1, 64
		state := resumeDoneState{Version: resumeDoneVersion, Generation: 4, SnapshotID: 9, SnapshotCount: 0, SessionRevision: 1, SessionValue: 256,
			Dirty: []resumeDoneControl{{Kind: protocol.StreamAck, Flow: st.flow.id, Revision: 2, Value: 7}, {Kind: protocol.MaxFlowData, Flow: st.flow.id, Revision: 2, Value: 128}}}
		s.peerResumeDone = &state
		s.syncReceived = map[uint64]bool{}
		s.maybePeerSync()
		if !s.peerDone {
			t.Fatal("resume did not become peer-complete after the declared empty snapshot set")
		}
		if st.sendAck != 7 || st.peerStreamAckRevision != 2 || st.maxRemote < 128 || st.peerMaxFlowRevision != 2 {
			t.Fatalf("dirty state was not applied: sendAck=%d streamRev=%d maxRemote=%d maxRev=%d", st.sendAck, st.peerStreamAckRevision, st.maxRemote, st.peerMaxFlowRevision)
		}
		var ack protocol.Frame
		for {
			f, ok := s.queue.Pop()
			if !ok {
				break
			}
			if f.Kind == protocol.ResumeDone && f.Flags == 1 {
				ack = f
			}
		}
		if len(ack.Data) == 0 {
			t.Fatal("resume snapshot receipt did not carry its versioned state")
		}
		got, legacy, err := decodeResumeDoneFrame(ack)
		if err != nil || legacy || !resumeStateCovers(state, got) {
			t.Fatalf("invalid resume receipt: legacy=%v err=%v got=%+v want=%+v", legacy, err, got, state)
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestResumeDoneRejectsUnorderedOrUnknownDirtyControl(t *testing.T) {
	base := resumeDoneState{Version: resumeDoneVersion, Generation: 1, SnapshotID: 1, SnapshotCount: 0, SessionRevision: 1, SessionValue: 64}
	base.Dirty = []resumeDoneControl{{Kind: protocol.MaxFlowData, Flow: 1, Revision: 1, Value: 1}, {Kind: protocol.StreamAck, Flow: 1, Revision: 1, Value: 1}}
	if err := validateResumeDoneState(base); err == nil {
		t.Fatal("unordered dirty controls were accepted")
	}
	base.Dirty = []resumeDoneControl{{Kind: protocol.ControlReceipt, Flow: 1, Revision: 1}}
	if err := validateResumeDoneState(base); err == nil {
		t.Fatal("unsupported dirty control kind was accepted")
	}
}

func TestResumeDoneSessionCreditRejectsRevisionRollback(t *testing.T) {
	s, _, _ := actorFlow(t, 64)
	defer s.Close()
	if err := s.call(context.Background(), func() {
		s.current = &carrier{kind: "tcp", generation: 2}
		s.peerMaxSessionRevision, s.peerMaxSessionValue = 4, 256
		if s.applyResumeDoneState(resumeDoneState{Version: resumeDoneVersion, Generation: 2, SnapshotID: 1, SessionRevision: 3, SessionValue: 512}) {
			t.Fatal("resume accepted a lower revision with a larger credit")
		}
		if s.applyResumeDoneState(resumeDoneState{Version: resumeDoneVersion, Generation: 2, SnapshotID: 1, SessionRevision: 4, SessionValue: 256}) == false {
			t.Fatal("resume rejected an idempotent session credit")
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestResumeDoneDirtyBudgetFailsClosed(t *testing.T) {
	s, _, _ := actorFlow(t, 64)
	defer s.Close()
	if err := s.call(context.Background(), func() {
		s.current = &carrier{kind: "tcp", generation: 3}
		s.resumeID = 1
		s.maxSessionFrame()
		s.resumeSessionRevision = s.maxSessionRevision
		s.resumeSessionValue = s.maxSessionValue
		s.streams = make(map[uint64]*streamState, maxResumeDirtyControls)
		s.resumeBaseline = map[latestcontrol.Key]uint64{}
		for id := uint64(1); id <= 43; id++ {
			flow := newFlow(s, id, "tcp")
			s.streams[id] = &streamState{flow: flow}
			now := time.Duration((id-1)*3 + 1)
			if _, _, err := s.controlTable.Update(latestcontrol.Key{Kind: protocol.StreamAck, Flow: id}, id, nil, now); err != nil {
				t.Fatalf("stream ack update %d: %v", id, err)
			}
			if _, _, err := s.controlTable.Update(latestcontrol.Key{Kind: protocol.MaxFlowData, Flow: id}, id, nil, now+time.Nanosecond); err != nil {
				t.Fatalf("max flow update %d: %v", id, err)
			}
			if _, _, err := s.controlTable.Update(latestcontrol.Key{Kind: protocol.OpenResult, Flow: id}, 0, []byte("ok"), now+2*time.Nanosecond); err != nil {
				t.Fatalf("open result update %d: %v", id, err)
			}
		}
		if _, ok, err := s.resumeDoneState(); err == nil || ok {
			t.Fatalf("dirty budget was not rejected: ok=%v err=%v", ok, err)
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestResumeDoneDuplicateRequestReemitsReceipt(t *testing.T) {
	s, _, _ := actorFlow(t, 256)
	defer s.Close()
	if err := s.call(context.Background(), func() {
		s.current = &carrier{kind: "tcp", generation: 6}
		s.peerSyncCount = 0
		s.syncReceived = map[uint64]bool{}
		s.syncFrames = nil
		state := resumeDoneState{Version: resumeDoneVersion, Generation: 6, SnapshotID: 11, SnapshotCount: 0, SessionRevision: 1, SessionValue: 1024}
		s.peerResumeDone = &state
		s.peerDone = true
		s.maybePeerSync()
		for {
			if _, ok := s.queue.Pop(); !ok {
				break
			}
		}
		requestData := encodeResumeDoneState(state)
		s.handle(protocol.Frame{Kind: protocol.ResumeDone, Flow: 0, Offset: 6, Value: state.SessionValue, Data: requestData})
		var receipt protocol.Frame
		for {
			f, ok := s.queue.Pop()
			if !ok {
				break
			}
			if f.Kind == protocol.ResumeDone && f.Flags == 1 {
				receipt = f
			}
		}
		if len(receipt.Data) == 0 {
			t.Fatal("duplicate ResumeDone request did not re-emit receipt")
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestResumeDoneNewerDuplicateBarrierIsApplied(t *testing.T) {
	s, _, _ := actorFlow(t, 256)
	defer s.Close()
	if err := s.call(context.Background(), func() {
		s.current = &carrier{kind: "tcp", generation: 8}
		s.peerSyncCount = 0
		s.syncReceived = map[uint64]bool{}
		s.syncFrames = nil
		old := resumeDoneState{Version: resumeDoneVersion, Generation: 8, SnapshotID: 12, SnapshotCount: 0, SessionRevision: 1, SessionValue: 1024}
		s.peerResumeDone = &old
		s.peerDone = true
		s.maybePeerSync()
		for {
			if _, ok := s.queue.Pop(); !ok {
				break
			}
		}
		newer := resumeDoneState{Version: resumeDoneVersion, Generation: 8, SnapshotID: 12, SnapshotCount: 0, SessionRevision: 2, SessionValue: 2048}
		s.handle(protocol.Frame{Kind: protocol.ResumeDone, Flow: 0, Offset: 8, Value: newer.SessionValue, Data: encodeResumeDoneState(newer)})
		if s.peerResumeDone == nil || s.peerResumeDone.SessionRevision != 2 || s.peerMaxSessionRevision != 2 {
			t.Fatalf("newer duplicate barrier was not applied: peer=%+v revision=%d", s.peerResumeDone, s.peerMaxSessionRevision)
		}
		var receipt protocol.Frame
		for {
			f, ok := s.queue.Pop()
			if !ok {
				break
			}
			if f.Kind == protocol.ResumeDone && f.Flags == 1 {
				receipt = f
			}
		}
		got, legacy, err := decodeResumeDoneFrame(receipt)
		if err != nil || legacy || got.SessionRevision != 2 {
			t.Fatalf("newer barrier receipt mismatch: legacy=%v err=%v got=%+v", legacy, err, got)
		}
	}); err != nil {
		t.Fatal(err)
	}
}
