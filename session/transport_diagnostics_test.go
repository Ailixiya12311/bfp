package session

import (
	"bfp/internal/udptransport"
	"bfp/protocol"
	"bfp/security"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func diagnosticReceiveSize(t *testing.T, socket *net.UDPConn) int {
	t.Helper()
	if err := socket.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, security.MaxUDPRecordSize+1)
	n, _, err := socket.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestTransportDiagnosticsUDPCommittedWireCostAndRTT(t *testing.T) {
	s, now, receiver := udpOwner(t)
	defaults := s.snapshotStats(*now)
	if defaults.UDPRTTSamples != 0 || defaults.UDPRTTSmoothedUS != 200000 || defaults.UDPRTTVarianceUS != 100000 ||
		defaults.UDPRTTMinUS != 0 || defaults.UDPRTTLatestUS != 0 || defaults.UDPPathGeneration != 1 || !defaults.UDPPathActive {
		t.Fatalf("initial estimator gauges claim measured samples or wrong path: %+v", defaults)
	}
	frame := protocol.Frame{Kind: protocol.Ping, Value: 17}
	if sent, err := s.udpSend(frame, false, false, false); err != nil || !sent {
		t.Fatalf("ordinary committed record: sent=%v err=%v", sent, err)
	}
	ordinarySize := diagnosticReceiveSize(t, receiver)
	ordinary := s.snapshotStats(*now)
	if ordinary.UDPCommittedRecords != 1 || ordinary.UDPNonFeedbackRecords != 1 || ordinary.UDPFeedbackRecords != 0 ||
		ordinary.UDPCommittedWireBytes != uint64(ordinarySize) || ordinary.UDPNonFeedbackWireBytes != uint64(ordinarySize) ||
		ordinary.UDPFlightBytes != uint64(ordinarySize) || ordinary.UDPLastCommittedBytes != uint64(ordinarySize) ||
		ordinary.UDPPacerTokens != 4800-float64(ordinarySize) || ordinarySize < protocol.HeaderSize+security.RecordOverhead {
		t.Fatalf("diagnostics did not charge full observed encrypted datagram: bytes=%d stats=%+v", ordinarySize, ordinary)
	}
	feedback, err := udptransport.EncodeACK(udptransport.ACK{Epoch: 0, Largest: 0, Ranges: []udptransport.Range{{First: 0, Last: 0}}})
	if err != nil {
		t.Fatal(err)
	}
	if sent, err := s.udpSend(feedback, false, false, true); err != nil || !sent {
		t.Fatalf("feedback committed record: sent=%v err=%v", sent, err)
	}
	feedbackSize := diagnosticReceiveSize(t, receiver)
	combined := s.snapshotStats(*now)
	if combined.UDPCommittedRecords != 2 || combined.UDPFeedbackRecords != 1 || combined.UDPNonFeedbackRecords != 1 ||
		combined.UDPCommittedWireBytes != uint64(ordinarySize+feedbackSize) || combined.UDPFeedbackWireBytes != uint64(feedbackSize) ||
		combined.UDPNonFeedbackWireBytes != uint64(ordinarySize) || combined.UDPMaxCommittedRecordBytes != uint64(max(ordinarySize, feedbackSize)) ||
		combined.UDPLastCommittedBytes != uint64(feedbackSize) || combined.UDPFlightBytes != uint64(ordinarySize) ||
		combined.UDPFeedbackTokens != ackReserveBurst-float64(feedbackSize) {
		t.Fatalf("feedback and ordinary costs were mixed or approximated: ordinary=%d feedback=%d stats=%+v", ordinarySize, feedbackSize, combined)
	}
	*now = now.Add(25 * time.Millisecond)
	ownerACK(t, s, 0)
	measured := s.snapshotStats(*now)
	if measured.UDPRTTSamples != 1 || measured.UDPRTTMinUS != 25000 || measured.UDPRTTLatestUS != 25000 ||
		measured.UDPRTTSmoothedUS != 25000 || measured.UDPRTTVarianceUS != 12500 || measured.UDPFlightBytes != 0 {
		t.Fatalf("gauges did not copy the estimator's one eligible sample: %+v", measured)
	}
	rtt, deadline := s.udpPath.rtt.Snapshot(), s.udpPath.deadline
	_ = s.snapshotStats(now.Add(time.Second))
	if s.udpPath.rtt.Snapshot() != rtt || s.udpPath.deadline != deadline || s.opts.UDPFailureBudget != 15*time.Second {
		t.Fatal("diagnostic query sampled RTT, changed a deadline or changed default watchdog")
	}
}

type diagnosticShortWriteConn struct{ net.Conn }

func (c diagnosticShortWriteConn) Write(buf []byte) (int, error) { return len(buf) - 1, nil }

func TestTransportDiagnosticsFailedRecordDoesNotCountWireBytes(t *testing.T) {
	for _, failure := range []string{"closed-socket", "short-write"} {
		t.Run(failure, func(t *testing.T) {
			s, now, _ := udpOwner(t)
			if failure == "closed-socket" {
				s.current.conn.Close()
			} else {
				s.current.conn = diagnosticShortWriteConn{s.current.conn}
			}
			ledger := s.udpPath.ledger.Snapshot()
			sent, err := s.udpSend(protocol.Frame{Kind: protocol.Ping}, false, false, false)
			stats := s.snapshotStats(*now)
			if sent || err == nil || failure == "short-write" && err != io.ErrShortWrite || s.udpPath.ledger.Snapshot() != ledger ||
				stats.UDPCommittedRecords != 0 || stats.UDPCommittedWireBytes != 0 || stats.UDPNonFeedbackWireBytes != 0 ||
				stats.UDPFeedbackWireBytes != 0 || stats.UDPMaxCommittedRecordBytes != 0 || stats.UDPLastCommittedBytes != 0 || stats.WireSent != 0 {
				t.Fatalf("failed record acquired commit/cost evidence: sent=%v err=%v stats=%+v", sent, err, stats)
			}
			if s.current.tx.NextMeta().Number != 1 {
				t.Fatal("diagnostics changed the failed write's consumed encryption nonce")
			}
		})
	}
}

func TestTransportDiagnosticsExactAdmissionReasonsAndMergedEpisode(t *testing.T) {
	s, now, receiver := udpOwner(t)
	meta := s.current.tx.NextMeta()
	s.cwnd, s.paceTokens = 1, 4800
	if sent, err := s.udpSend(protocol.Frame{Kind: protocol.Ping}, false, false, false); sent || err != nil {
		t.Fatalf("cwnd denial: sent=%v err=%v", sent, err)
	}
	first := s.snapshotStats(*now)
	if first.UDPCwndAdmissionDenied != 1 || first.UDPPacerAdmissionDenied != 0 || !first.UDPBudgetBlocked || !first.UDPBlockedByCwnd || first.UDPBlockedByPacer {
		t.Fatalf("cwnd-only admission was misclassified: %+v", first)
	}
	*now = now.Add(50 * time.Millisecond)
	s.cwnd, s.paceTokens = 12000, 0
	if sent, err := s.udpSend(protocol.Frame{Kind: protocol.Ping}, false, false, false); sent || err != nil {
		t.Fatalf("pacer denial: sent=%v err=%v", sent, err)
	}
	*now = now.Add(50 * time.Millisecond)
	s.cwnd = 1
	if sent, err := s.udpSend(protocol.Frame{Kind: protocol.Ping}, false, false, false); sent || err != nil {
		t.Fatalf("overlapping denial: sent=%v err=%v", sent, err)
	}
	*now = now.Add(50 * time.Millisecond)
	start := s.udpPath.budgetBlockedSince
	projected := s.snapshotStats(*now)
	if projected.UDPCwndAdmissionDenied != 2 || projected.UDPPacerAdmissionDenied != 2 || projected.UDPBudgetBlockedMS != 150 ||
		projected.UDPBudgetBlockedMaxMS != 150 || !projected.UDPBlockedByCwnd || !projected.UDPBlockedByPacer ||
		s.udpBlockedTotal != 0 || s.udpBlockedMax != 0 || s.udpPath.budgetBlockedSince != start || s.current.tx.NextMeta() != meta {
		t.Fatalf("overlap doubled wait, snapshot mutated episode, or denied frame consumed a nonce: %+v", projected)
	}
	s.cwnd, s.paceTokens = 12000, 4800
	if sent, err := s.udpSend(protocol.Frame{Kind: protocol.Ping}, false, false, false); !sent || err != nil {
		t.Fatalf("budget reopens: sent=%v err=%v", sent, err)
	}
	_ = diagnosticReceiveSize(t, receiver)
	closed := s.snapshotStats(now.Add(time.Hour))
	if closed.UDPBudgetBlocked || closed.UDPBlockedByCwnd || closed.UDPBlockedByPacer || closed.UDPBudgetBlockedMS != 150 || closed.UDPBudgetBlockedMaxMS != 150 {
		t.Fatalf("successful non-feedback commit did not close the single episode: %+v", closed)
	}
}

func TestTransportDiagnosticsFlushGateReportsOnlyKnownQueuedWork(t *testing.T) {
	s, now, _ := udpOwner(t)
	s.paceTokens = 0
	s.flushUDP()
	if stats := s.snapshotStats(*now); stats.UDPFlushPacerGateDenied != 0 || stats.UDPBudgetBlocked {
		t.Fatalf("an idle flush was reported as queued work waiting: %+v", stats)
	}
	if !s.enqueue(protocol.Frame{Kind: protocol.Ping, Value: 1}, protocol.Interactive) {
		t.Fatal("queued fixture frame was rejected")
	}
	s.flushUDP()
	*now = now.Add(50 * time.Millisecond)
	s.paceTime = *now
	s.flight, s.cwnd, s.paceTokens = 12000, 12000, 4800
	s.flushUDP()
	stats := s.snapshotStats(*now)
	if stats.UDPFlushPacerGateDenied != 1 || stats.UDPFlushCwndGateDenied != 1 || stats.UDPCwndAdmissionDenied != 0 || stats.UDPPacerAdmissionDenied != 0 ||
		stats.UDPBudgetBlockedMS != 50 || !stats.UDPBlockedByCwnd || stats.UDPBlockedByPacer || s.queue.Len() != 1 || s.current.tx.NextMeta().Number != 0 {
		t.Fatalf("preselection gate invented an encoded-record denial or changed scheduling: %+v", stats)
	}
	_, _ = s.queue.Pop() // Model owner lifecycle dropping the pending work.
	*now = now.Add(50 * time.Millisecond)
	s.paceTime = *now
	s.flushUDP()
	stats = s.snapshotStats(now.Add(time.Hour))
	if stats.UDPBudgetBlocked || stats.UDPBudgetBlockedMS != 100 || stats.UDPBudgetBlockedMaxMS != 100 || stats.UDPFlushCwndGateDenied != 1 {
		t.Fatalf("empty queued work retained or renewed its observation episode: %+v", stats)
	}
}

func diagnosticActorCarrier(t *testing.T, kind string, generation uint64) *carrier {
	t.Helper()
	var conn net.Conn
	if kind == "udp" {
		receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { receiver.Close() })
		conn, err = net.DialUDP("udp", nil, receiver.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
	} else {
		left, right := net.Pipe()
		t.Cleanup(func() { right.Close() })
		conn = left
	}
	keys := &security.TransportKeys{}
	keys.Send[0], keys.Receive[0] = 1, 2
	c, err := makeCarrier(kind, generation, bytes.Repeat([]byte{byte(generation)}, 16), keys, conn, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.close)
	return c
}

func TestTransportDiagnosticsActorAttachSuspendAndCloseEndOldEpisode(t *testing.T) {
	for _, action := range []string{"attach-tcp", "attach-udp", "suspend", "close"} {
		t.Run(action, func(t *testing.T) {
			s := newSession(context.Background(), sessionInfo{ID: randomID()}, Options{}, true, nil)
			t.Cleanup(func() { s.Close() })
			clock := &atomic.Int64{}
			origin := time.Unix(100, 0)
			if err := s.call(context.Background(), func() { s.transportNow = func() time.Time { return origin.Add(time.Duration(clock.Load())) } }); err != nil {
				t.Fatal(err)
			}
			if err := s.attach(diagnosticActorCarrier(t, "udp", 1), 0); err != nil {
				t.Fatal(err)
			}
			if err := s.call(context.Background(), func() {
				s.cwnd = 1
				_, _ = s.udpSend(protocol.Frame{Kind: protocol.Ping}, false, false, false)
				s.stats.UDPCommittedRecords, s.stats.UDPCommittedWireBytes = 7, 1234
			}); err != nil {
				t.Fatal(err)
			}
			clock.Store(int64(50 * time.Millisecond))
			switch action {
			case "attach-tcp", "attach-udp":
				kind := "tcp"
				if action == "attach-udp" {
					kind = "udp"
				}
				if err := s.attach(diagnosticActorCarrier(t, kind, 2), 1); err != nil {
					t.Fatal(err)
				}
			case "suspend":
				if err := s.call(context.Background(), s.suspend); err != nil {
					t.Fatal(err)
				}
			case "close":
				s.Close()
			}
			clock.Store(int64(time.Hour))
			var stats Stats
			if action == "close" {
				// done establishes that the actor and its final episode closure
				// completed; reading retained owner state is now race-free.
				stats = s.snapshotStats(origin.Add(time.Hour))
			} else {
				stats = s.Stats()
			}
			if stats.UDPBudgetBlocked || stats.UDPBudgetBlockedMS != 50 || stats.UDPBudgetBlockedMaxMS != 50 ||
				stats.UDPCommittedRecords != 7 || stats.UDPCommittedWireBytes != 1234 {
				t.Fatalf("%s renewed/mixed old UDP wait or lost Session totals: %+v", action, stats)
			}
			if action == "attach-tcp" && (stats.UDPPathPresent || stats.UDPPathGeneration != 0 || stats.UDPCwndBytes != 0 || stats.UDPPacerTokens != 0 || stats.UDPRTTSamples != 0) {
				t.Fatalf("TCP inherited old UDP gauges: %+v", stats)
			}
			if action == "attach-udp" && (stats.UDPPathGeneration != 2 || stats.UDPFlightBytes != 0 || stats.UDPLastCommittedBytes != 0 || stats.UDPPacerTokens != 4800 || stats.UDPRTTSamples != 0) {
				t.Fatalf("new UDP path retained old transport gauges: %+v", stats)
			}
		})
	}
}

func TestTransportDiagnosticsConcurrentActorStatsRemainCopiedAndConsistent(t *testing.T) {
	s := newSession(context.Background(), sessionInfo{ID: randomID()}, Options{}, true, nil)
	t.Cleanup(func() { s.Close() })
	if err := s.attach(diagnosticActorCarrier(t, "udp", 1), 0); err != nil {
		t.Fatal(err)
	}
	clock := &atomic.Int64{}
	origin := time.Unix(100, 0)
	if err := s.call(context.Background(), func() {
		s.transportNow = func() time.Time { return origin.Add(time.Duration(clock.Load())) }
		s.resetTransport(origin)
	}); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for query := 0; query < 24; query++ {
				stats := s.Stats()
				if stats.UDPCommittedRecords != stats.UDPNonFeedbackRecords+stats.UDPFeedbackRecords ||
					stats.UDPCommittedWireBytes != stats.UDPNonFeedbackWireBytes+stats.UDPFeedbackWireBytes || stats.UDPPathGeneration != 1 {
					t.Errorf("actor snapshot mixed independently sampled totals/path: %+v", stats)
				}
				if _, err := json.Marshal(stats); err != nil {
					t.Errorf("diagnostic scalar snapshot cannot be serialized: %v", err)
				}
				stats.UDPCommittedRecords = math.MaxUint64 // A copy never writes back.
			}
		}()
	}
	for i := 0; i < 12; i++ {
		clock.Add(int64(time.Millisecond))
		if err := s.call(context.Background(), func() {
			s.flight, s.cwnd, s.paceTokens = 0, 12000, 4800
			if sent, err := s.udpSend(protocol.Frame{Kind: protocol.Ping, Value: uint64(i)}, false, false, false); !sent || err != nil {
				t.Errorf("concurrent fixture record sent=%v err=%v", sent, err)
			}
		}); err != nil {
			t.Fatal(err)
		}
	}
	workers.Wait()
	if stats := s.Stats(); stats.UDPCommittedRecords != 12 || stats.UDPNonFeedbackRecords != 12 {
		t.Fatalf("query copies corrupted cumulative owner state: %+v", stats)
	}
}

func TestTransportDiagnosticsCountersAndEpisodeDurationSaturate(t *testing.T) {
	s, now, receiver := udpOwner(t)
	s.stats.UDPCommittedRecords = math.MaxUint64
	s.stats.UDPCommittedWireBytes = math.MaxUint64 - 1
	s.stats.UDPNonFeedbackRecords = math.MaxUint64
	s.stats.UDPNonFeedbackWireBytes = math.MaxUint64 - 1
	s.udpBlockedTotal = time.Duration(math.MaxInt64) - time.Millisecond
	s.observeUDPBudgetDenial(*now, true, false)
	*now = now.Add(2 * time.Millisecond)
	if sent, err := s.udpSend(protocol.Frame{Kind: protocol.Ping}, false, false, false); err != nil || !sent {
		t.Fatalf("saturating commit: sent=%v err=%v", sent, err)
	}
	_ = diagnosticReceiveSize(t, receiver)
	stats := s.snapshotStats(*now)
	if stats.UDPCommittedRecords != math.MaxUint64 || stats.UDPCommittedWireBytes != math.MaxUint64 || stats.UDPNonFeedbackRecords != math.MaxUint64 ||
		stats.UDPNonFeedbackWireBytes != math.MaxUint64 || s.udpBlockedTotal != time.Duration(math.MaxInt64) || stats.UDPBudgetBlockedMaxMS != 2 {
		t.Fatalf("committed counters or cumulative episode duration wrapped: %+v total=%s", stats, s.udpBlockedTotal)
	}
}
