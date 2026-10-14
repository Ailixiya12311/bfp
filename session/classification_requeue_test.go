package session

import (
	"bfp/internal/udptransport"
	"bfp/protocol"
	"bfp/scheduler"
	"bfp/security"
	"testing"
	"time"
)

func TestClassificationControlRequeueRetainsPriorityBudgets(t *testing.T) {
	for _, mode := range []string{"pre-sync", "congestion", "record-retransmit"} {
		t.Run(mode, func(t *testing.T) {
			s, st := stateSession(t, "tcp")
			st.effectiveClass = protocol.Bulk
			frame := protocol.Frame{Kind: protocol.MaxFlowData, Flow: 1, Value: 99}
			cost := frameCost(frame)
			s.queue = scheduler.NewWithLimits[protocol.Frame](1200, scheduler.Limits{MaxBytes: cost * 6, MaxClassBytes: cost})
			s.active = true
			s.peerDone = false
			s.current = &carrier{kind: "tcp"}
			now := time.Now()
			s.lastReceive, s.lastKey = now, now
			s.lastProbe, s.lastSync = now.Add(time.Hour), now.Add(time.Hour)
			s.rtt = time.Millisecond
			s.pending = map[security.RecordMeta]sentRecord{}
			s.paceTokens, s.paceTime = 4800, now
			if mode == "record-retransmit" {
				s.current.kind = "udp"
				s.current.generation = 1
				ledger, _ := udptransport.NewLedger(1, 0)
				s.udpPath = &udpPath{generation: 1, origin: now.Add(-time.Second), ledger: ledger, rtt: udptransport.NewRTT(), refs: map[security.RecordMeta]logicalRef{{}: makeRef(frame)}, retries: map[refKey]logicalRef{}}
				for n := uint64(0); n < 4; n++ {
					_, err := ledger.Commit(udptransport.Packet{Scope: udptransport.Scope{Generation: 1}, Number: n, Size: 100, AckEliciting: true})
					if err != nil {
						t.Fatal(err)
					}
				}
				_, err := ledger.ApplyACK(udptransport.Scope{Generation: 1}, udptransport.ACK{Largest: 3, Ranges: []udptransport.Range{{First: 1, Last: 3}}}, time.Millisecond, nil)
				if err != nil {
					t.Fatal(err)
				}
				s.detectUDPLoss(now)
				if len(s.udpPath.retries) != 1 {
					t.Fatal("record loss did not retain one logical reference")
				}
				for _, ref := range s.udpPath.retries {
					retry, ok := s.resolveRef(ref, now)
					if !ok || !s.enqueue(retry, s.classForFrame(retry)) {
						t.Fatal("control retry resolution")
					}
				}
			} else {
				if !s.enqueue(frame, protocol.Interactive) {
					t.Fatal("initial control admission")
				}
				if mode == "congestion" {
					s.current.kind = "udp"
					s.flight, s.cwnd = cost, cost
				}
				s.flush()
			}
			if s.queue.Len() != 1 || s.queue.Bytes() != cost {
				t.Fatal("requeue lost or duplicated control")
			}
			// Probe per-class budget rather than requiring the control to pass
			// earlier same-flow data: scheduler intentionally keeps flow FIFO.
			if s.enqueue(protocol.Frame{Kind: protocol.Fin, Flow: 1}, protocol.Interactive) {
				t.Fatal("requeued control did not occupy Interactive budget")
			}
			if !s.enqueue(protocol.Frame{Kind: protocol.StreamData, Flow: 1}, protocol.Bulk) {
				t.Fatal("requeued control occupied Bulk budget")
			}
			got, ok := s.queue.Pop()
			if !ok || got.Kind != frame.Kind {
				t.Fatal("requeue corrupted control/FIFO")
			}
			got, ok = s.queue.Pop()
			if !ok || got.Kind != protocol.StreamData {
				t.Fatal("requeue corrupted later data")
			}
		})
	}
}
