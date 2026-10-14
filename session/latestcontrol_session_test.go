package session

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"bfp/internal/latestcontrol"
	"bfp/protocol"
)

func TestSessionLatestControlPublishesOnlyAfterWriteAndInstallsReceipt(t *testing.T) {
	s, _, st := actorFlow(t, 1024)
	if err := s.call(context.Background(), func() {
		frame := s.streamAckFrame(st)
		if frame.Offset != 0 || frame.Value != 1 {
			t.Fatalf("unexpected first stream ack wire state: %+v", frame)
		}
		if !s.enqueue(frame, protocol.Interactive) {
			t.Fatal("stream ack was not queued")
		}
		key := latestcontrol.Key{Kind: protocol.StreamAck, Flow: st.flow.id}
		snap, err := s.controlTable.Snapshot(key)
		if err != nil || !snap.Pending || snap.State.Revision != 1 {
			t.Fatalf("queued state was not retained: %+v %v", snap, err)
		}
		pub, skip, err := s.prepareLatestControl(frame)
		if err != nil || skip || pub == nil {
			t.Fatalf("prepare: pub=%v skip=%v err=%v", pub, skip, err)
		}
		if _, err = s.controlTable.Receipt(key, 1, s.controlStamp(time.Now())); !errors.Is(err, latestcontrol.ErrReceipt) {
			t.Fatalf("unpublished receipt was accepted: %v", err)
		}
		if err = s.publishLatestControl(pub, 200*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if _, err = s.controlTable.Receipt(key, 1, s.controlStamp(time.Now())); err != nil {
			t.Fatal(err)
		}
		snap, err = s.controlTable.Snapshot(key)
		if err != nil || snap.Pending || snap.Confirmed != 1 {
			t.Fatalf("receipt did not install published state: %+v %v", snap, err)
		}
		// A duplicate receipt is harmless and cannot mutate the installed state.
		s.handle(protocol.Frame{Kind: protocol.ControlReceipt, Flow: st.flow.id, Offset: 1, Value: uint64(protocol.StreamAck)})
		snap, _ = s.controlTable.Snapshot(key)
		if snap.Pending || snap.Confirmed != 1 {
			t.Fatalf("duplicate receipt changed state: %+v", snap)
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSessionLatestControlCoalescesQueuedCredit(t *testing.T) {
	s, f, st := actorFlow(t, 1024)
	if err := s.call(context.Background(), func() {
		if !s.enqueue(s.maxFlowFrame(st), protocol.Interactive) {
			t.Fatal("initial credit was not queued")
		}
		st.consumed = 8
		if !s.enqueue(s.maxFlowFrame(st), protocol.Interactive) {
			t.Fatal("updated credit was not queued")
		}
		key := latestcontrol.Key{Kind: protocol.MaxFlowData, Flow: f.id}
		snap, err := s.controlTable.Snapshot(key)
		if err != nil || snap.State.Revision != 2 || snap.State.Value != 1032 || !snap.Pending {
			t.Fatalf("credit did not coalesce to latest revision: %+v %v", snap, err)
		}
		first, ok := s.queue.Pop()
		if !ok {
			t.Fatal("missing first credit frame")
		}
		first = s.normalizeLatestControl(first)
		if first.Offset != 2 || first.Value != 1032 {
			t.Fatalf("stale queued credit was not refreshed: %+v", first)
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeLatestControlReceiptAcrossCarriers(t *testing.T) {
	for _, kind := range []string{"udp", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			f := newRuntimeFixture(t, kind)
			flow := runtimeFlow(t, f)
			payload := bytes.Repeat([]byte("receipt integration "), 48)
			runtimeExchange(t, flow, payload)
			var key latestcontrol.Key
			runtimeWait(t, "stream ack receipt", func() bool {
				ready := false
				_ = f.client.call(context.Background(), func() {
					for id, st := range f.client.streams {
						if st.receiveNext < uint64(len(payload)) {
							continue
						}
						key = latestcontrol.Key{Kind: protocol.StreamAck, Flow: id}
						snap, err := f.client.controlTable.Snapshot(key)
						ready = err == nil && !snap.Pending && snap.Confirmed == snap.State.Revision && snap.State.Value >= uint64(len(payload))
						if ready {
							break
						}
					}
				})
				return ready
			})
			if key.Flow == 0 {
				t.Fatal("runtime did not retain a stream ack key")
			}
		})
	}
}
