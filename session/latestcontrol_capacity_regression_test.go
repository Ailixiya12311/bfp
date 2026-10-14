package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"bfp/internal/latestcontrol"
	"bfp/protocol"
)

// Retired flow IDs remain in Session for its entire lifetime. Concurrent flow
// admission limits must not make that cumulative history outgrow the local
// publication table or turn the next refusal into a malformed OpenResult.
func TestSessionLatestControlLifetimeCapacity(t *testing.T) {
	s, existing, live := actorFlow(t, 1024)
	if err := s.call(context.Background(), func() {
		live.openResult = "ok"
		for id := uint64(1); id <= maxSessionFlowStates; id++ {
			st := live
			if id != live.flow.id {
				st = &streamState{flow: newFlow(s, id, "tcp"), target: protocol.Target{Network: "tcp"}, reset: true, openResult: "failed"}
				s.streams[id] = st
			}
			for _, frame := range []protocol.Frame{s.openResultFrame(st), s.streamAckFrame(st), s.maxFlowFrame(st)} {
				if _, revision, tracked := latestControlRevision(frame); !tracked || revision == 0 {
					t.Fatalf("flow %d lost its control revision after cumulative admission: %+v", id, frame)
				}
			}
		}
		s.nextFlow = maxSessionFlowStates + 1
		if frame := s.maxSessionFrame(); frame.Offset == 0 {
			t.Fatal("session credit has no publication revision")
		}
		keys, payloadBytes := s.controlTable.Usage()
		if keys != 3*maxSessionFlowStates+1 || keys <= latestcontrol.DefaultConfig().MaxKeys || payloadBytes > latestcontrol.DefaultConfig().MaxBytes {
			t.Fatalf("unexpected bounded lifetime usage: keys=%d bytes=%d", keys, payloadBytes)
		}

		// Force a producer beyond the fixed key budget. Even a stale frame
		// carrying a nonzero revision must not bypass the rejected Update.
		extra := protocol.Frame{Kind: protocol.OpenResult, Flow: maxSessionFlowStates + 1, Offset: 77, Data: []byte("limit")}
		if _, _, err := s.controlTable.Update(latestcontrol.Key{Kind: extra.Kind, Flow: extra.Flow}, 0, extra.Data, s.controlStamp(s.transportTime())); !errors.Is(err, latestcontrol.ErrLimit) {
			t.Fatalf("extra control key escaped the hard budget: %v", err)
		}
		before := s.queue.Len()
		if s.enqueue(extra, protocol.Interactive) || s.queue.Len() != before {
			t.Fatal("failed control admission queued a malformed OpenResult")
		}
		rejected := s.normalizeLatestControl(extra)
		if rejected.Offset != 0 {
			t.Fatal("failed normalization retained a stale nonzero revision")
		}
		if publication, skip, err := s.prepareLatestControl(rejected); err != nil || !skip || publication != nil {
			t.Fatalf("send preflight accepted unversioned control: pub=%v skip=%v err=%v", publication, skip, err)
		}

		// Previously allocated keys still publish and accept duplicate
		// receipts at capacity; rejecting new metadata cannot kill this flow.
		frame := s.streamAckFrame(live)
		publication, skip, err := s.prepareLatestControl(frame)
		if err != nil || skip || publication == nil {
			t.Fatalf("existing key cannot publish at capacity: skip=%v err=%v", skip, err)
		}
		if err := s.publishLatestControl(publication, 200*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		receipt := protocol.Frame{Kind: protocol.ControlReceipt, Flow: live.flow.id, Offset: frame.Value, Value: uint64(protocol.StreamAck)}
		s.handle(receipt)
		s.handle(receipt)
		view, err := s.controlTable.Snapshot(latestcontrol.Key{Kind: protocol.StreamAck, Flow: live.flow.id})
		if err != nil || view.Pending || view.Confirmed != frame.Value || s.ctx.Err() != nil {
			t.Fatalf("existing receipt state failed at capacity: %+v err=%v ctx=%v", view, err, s.ctx.Err())
		}
	}); err != nil {
		t.Fatal(err)
	}

	if conn, err := s.DialContext(context.Background(), "tcp", "extra.test:443"); conn != nil || !errors.Is(err, ErrLimit) {
		t.Fatalf("4097th flow was not locally refused: conn=%v err=%v", conn, err)
	}
	select {
	case <-s.BusinessDone():
		t.Fatal("local lifetime admission refusal ended the Session")
	default:
	}
	if err := existing.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := existing.Write([]byte("still alive")); err != nil || n != len("still alive") {
		t.Fatalf("existing flow failed after lifetime refusal: n=%d err=%v", n, err)
	}
	if err := s.call(context.Background(), func() {
		if len(s.streams) != maxSessionFlowStates || s.nextFlow != maxSessionFlowStates+1 || live.reset {
			t.Fatal("refusal changed retained stream identity or the existing flow")
		}
	}); err != nil {
		t.Fatal(err)
	}
}
