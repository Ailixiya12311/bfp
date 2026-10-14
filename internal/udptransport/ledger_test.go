package udptransport

import (
	"errors"
	"math"
	"reflect"
	"testing"
	"time"
)

func testLedger(t *testing.T) (*Ledger, Scope) {
	t.Helper()
	l, err := NewLedger(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	return l, Scope{1, 0}
}
func commit(t *testing.T, l *Ledger, s Scope, n uint64, at time.Duration, probe, retry bool) Packet {
	t.Helper()
	p, err := l.Commit(Packet{Scope: s, Number: n, Size: 100, SentAt: at, AckEliciting: true, Probe: probe, Retry: retry})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func singleACK(s Scope, n uint64) ACK {
	return ACK{Epoch: s.Epoch, Largest: n, Ranges: []Range{{n, n}}}
}
func copyLive(l *Ledger) map[packetKey]Packet {
	out := make(map[packetKey]Packet, len(l.live))
	for k, v := range l.live {
		out[k] = v
	}
	return out
}

func TestLedgerUnsentACKIsAtomicIncludingRTT(t *testing.T) {
	l, s := testLedger(t)
	for _, n := range []uint64{0, 2, 4} {
		commit(t, l, s, n, 0, false, false)
	}
	rtt := NewRTT()
	before := l.Snapshot()
	live := copyLive(l)
	rt := rtt.Snapshot()
	a := ACK{Epoch: 0, Largest: 4, Delay: time.Millisecond, Ranges: []Range{{4, 4}, {0, 2}}}
	if _, err := l.ApplyACK(s, a, time.Second, &rtt); !errors.Is(err, ErrUnsent) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, l.Snapshot()) || !reflect.DeepEqual(live, l.live) || !reflect.DeepEqual(rt, rtt.Snapshot()) {
		t.Fatal("partially applied invalid ACK")
	}
	if _, err := l.ApplyACK(s, singleACK(s, 5), time.Second, &rtt); !errors.Is(err, ErrUnsent) {
		t.Fatal(err)
	}
	valid := ACK{Epoch: 0, Largest: 4, Ranges: []Range{{4, 4}, {2, 2}, {0, 0}}}
	result, err := l.ApplyACK(s, valid, time.Second, &rtt)
	if err != nil || result.FlightReleased != 300 || len(result.Packets) != 3 || !result.SampleAccepted || !result.NewProgress || l.Snapshot().Flight != 0 {
		t.Fatalf("%+v %v", result, err)
	}
	result, err = l.ApplyACK(s, valid, 2*time.Second, &rtt)
	if err != nil || len(result.Packets) != 0 || result.SampleAccepted || result.NewProgress || result.FlightReleased != 0 {
		t.Fatalf("duplicate %+v %v", result, err)
	}
}

func TestLedgerAdmissionReservesAndOrdinalOverflow(t *testing.T) {
	l, s := testLedger(t)
	for n := uint64(0); n < OrdinaryPacketLimit; n++ {
		commit(t, l, s, n, 0, false, false)
	}
	before := l.Snapshot()
	if _, err := l.Commit(Packet{Scope: s, Number: 248, Size: 100, AckEliciting: true}); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	if l.Snapshot() != before {
		t.Fatal("rejection consumed ordinal")
	}
	for n := uint64(248); n < 256; n++ {
		commit(t, l, s, n, 0, true, false)
	}
	if _, err := l.Commit(Packet{Scope: s, Number: 256, Size: 100, AckEliciting: true, Probe: true}); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	if l.Snapshot().Live != 256 || l.Snapshot().Flight != 25600 {
		t.Fatal(l.Snapshot())
	}
	// A non-eliciting feedback record has no metadata or flight but still
	// occupies a sent-ledger number, and cannot be falsely acknowledged.
	if _, err := l.Commit(Packet{Scope: s, Number: 256, Size: 100}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.ApplyACK(s, singleACK(s, 256), time.Second, nil); !errors.Is(err, ErrNonEliciting) {
		t.Fatal(err)
	}
	l2, s2 := testLedger(t)
	l2.ordinal = math.MaxUint64
	if _, err := l2.Commit(Packet{Scope: s2, Number: 0, Size: 100, AckEliciting: true}); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	if l2.current.committed.initialized {
		t.Fatal("ordinal overflow committed record")
	}
}

func TestLedgerCommitPreflightAndRecordBoundary(t *testing.T) {
	l, s := testLedger(t)
	p := Packet{Scope: s, Number: MaxRecordNumber, Size: 1200, AckEliciting: true}
	if err := l.CheckCommit(p); err != nil {
		t.Fatal(err)
	}
	if l.Snapshot().Live != 0 || l.current.committed.initialized {
		t.Fatal("preflight mutated")
	}
	if _, err := l.Commit(p); err != nil {
		t.Fatal(err)
	}
	before := l.Snapshot()
	for _, p := range []Packet{{Scope: s, Number: MaxRecordNumber + 1, Size: 100, AckEliciting: true}, {Scope: s, Number: MaxRecordNumber, Size: 100, AckEliciting: true}, {Scope: Scope{2, 0}, Number: 0, Size: 100}, {Scope: s, Number: 0, Size: 0}, {Scope: s, Number: 0, Size: 1201}, {Scope: s, Number: 0, Size: 100, SentAt: -1}} {
		if _, err := l.Commit(p); err == nil {
			t.Fatal("accepted invalid commit")
		}
	}
	if l.Snapshot() != before {
		t.Fatal("invalid commit changed state")
	}
}

func TestLedgerLateACKBeyondWindowRetainsLiveEvidence(t *testing.T) {
	l, s := testLedger(t)
	commit(t, l, s, 0, 0, false, false)
	if _, err := l.Commit(Packet{Scope: s, Number: 10000, Size: 100, SentAt: time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	if l.current.committed.floor() != 5905 {
		t.Fatal(l.current.committed.floor())
	}
	result, err := l.ApplyACK(s, singleACK(s, 0), 2*time.Millisecond, nil)
	if err != nil || result.FlightReleased != 100 || len(result.Packets) != 1 {
		t.Fatalf("old live %+v %v", result, err)
	}
	result, err = l.ApplyACK(s, singleACK(s, 0), 3*time.Millisecond, nil)
	if err != nil || len(result.Packets) != 0 {
		t.Fatalf("forgotten old %+v %v", result, err)
	}
}

func TestLedgerHugeACKRangeIsBoundedAndForgottenFloorIgnored(t *testing.T) {
	l, s := testLedger(t)
	start := MaxRecordNumber - (HistoryBits - 1)
	for n := start; n < MaxRecordNumber; n++ {
		commit(t, l, s, n, 0, false, false)
		if _, err := l.ApplyACK(s, singleACK(s, n), time.Millisecond, nil); err != nil {
			t.Fatal(err)
		}
	}
	commit(t, l, s, MaxRecordNumber, 0, false, false)
	a := ACK{Epoch: 0, Largest: MaxRecordNumber, Ranges: []Range{{0, MaxRecordNumber}}}
	result, err := l.ApplyACK(s, a, time.Millisecond, nil)
	if err != nil || result.FlightReleased != 100 || l.Snapshot().Live != 0 {
		t.Fatalf("huge range %+v %v", result, err)
	}
}

func TestLedgerLossLateACKAndRepeatedLossDoNotDoubleFlight(t *testing.T) {
	l, s := testLedger(t)
	for n := uint64(0); n < 4; n++ {
		commit(t, l, s, n, 0, false, false)
	}
	a := ACK{Epoch: 0, Largest: 3, Ranges: []Range{{1, 3}}}
	if _, err := l.ApplyACK(s, a, time.Millisecond, nil); err != nil {
		t.Fatal(err)
	}
	lost, err := l.DetectLoss(time.Millisecond, NewRTT().Snapshot())
	if err != nil || len(lost) != 1 || lost[0].Number != 0 || l.Snapshot().Flight != 0 {
		t.Fatal(lost, err, l.Snapshot())
	}
	if _, ok := l.DeclareLost(s, 0); ok {
		t.Fatal("double loss")
	}
	rtt := NewRTT()
	rt := rtt.Snapshot()
	result, err := l.ApplyACK(s, singleACK(s, 0), time.Second, &rtt)
	if err != nil || len(result.Packets) != 1 || !result.Packets[0].WasLost || !result.NewProgress || result.FlightReleased != 0 || result.SampleAccepted || !reflect.DeepEqual(rt, rtt.Snapshot()) {
		t.Fatalf("late %+v %v", result, err)
	}
	if result, err = l.ApplyACK(s, singleACK(s, 0), 2*time.Second, &rtt); err != nil || len(result.Packets) != 0 || result.NewProgress {
		t.Fatal(result, err)
	}
}

func TestLedgerSilentPathUsesNoLossAndTimeNeedsLaterEvidence(t *testing.T) {
	l, s := testLedger(t)
	commit(t, l, s, 0, 0, false, false)
	rt := NewRTT().Snapshot()
	if lost, err := l.DetectLoss(10*time.Second, rt); err != nil || len(lost) != 0 {
		t.Fatal(lost, err)
	}
	commit(t, l, s, 1, 10*time.Second, false, false)
	if _, err := l.ApplyACK(s, singleACK(s, 1), 10*time.Second+time.Millisecond, nil); err != nil {
		t.Fatal(err)
	}
	if lost, err := l.DetectLoss(10*time.Second+time.Millisecond, rt); err != nil || len(lost) != 1 {
		t.Fatal(lost, err)
	}
}

func TestLedgerPacketThresholdCountsDistinctACKsRatherThanOrdinalGap(t *testing.T) {
	l, s := testLedger(t)
	for n := uint64(0); n < 10; n++ {
		commit(t, l, s, n, 0, false, false)
	}
	rt := NewRTT().Snapshot()
	for _, n := range []uint64{9, 9, 8} {
		if _, err := l.ApplyACK(s, singleACK(s, n), time.Millisecond, nil); err != nil {
			t.Fatal(err)
		}
		lost, err := l.DetectLoss(time.Millisecond, rt)
		if err != nil || len(lost) != 0 {
			t.Fatalf("ordinal gap or duplicate used as third successor: %v %v", lost, err)
		}
	}
	if _, err := l.ApplyACK(s, singleACK(s, 7), time.Millisecond, nil); err != nil {
		t.Fatal(err)
	}
	lost, err := l.DetectLoss(time.Millisecond, rt)
	if err != nil || len(lost) != 7 || lost[0].Number != 0 {
		t.Fatalf("three distinct successors: %v %v", lost, err)
	}
}

func TestLedgerKarnAndDelayFloorThroughACK(t *testing.T) {
	l, s := testLedger(t)
	rtt := NewRTT()
	commit(t, l, s, 0, 0, false, false)
	first, err := l.ApplyACK(s, singleACK(s, 0), 10*time.Millisecond, &rtt)
	if err != nil || !first.SampleAccepted {
		t.Fatal(first, err)
	}
	commit(t, l, s, 1, 20*time.Millisecond, false, true)
	before := rtt.Snapshot()
	result, err := l.ApplyACK(s, singleACK(s, 1), 40*time.Millisecond, &rtt)
	if err != nil || result.SampleAccepted || result.FlightReleased != 100 || !reflect.DeepEqual(before, rtt.Snapshot()) {
		t.Fatal(result, err, rtt.Snapshot())
	}
	commit(t, l, s, 2, 50*time.Millisecond, false, false)
	a := singleACK(s, 2)
	a.Delay = 20 * time.Millisecond
	result, err = l.ApplyACK(s, a, 65*time.Millisecond, &rtt)
	if err != nil || !result.SampleAccepted || rtt.Snapshot().Smoothed < 10*time.Millisecond {
		t.Fatal(result, err, rtt.Snapshot())
	}
}

func TestLedgerEpochGenerationRetirementIsolation(t *testing.T) {
	l, s := testLedger(t)
	commit(t, l, s, 0, 0, false, false)
	if err := l.AdvanceEpoch(1); err != nil {
		t.Fatal(err)
	}
	cur := Scope{1, 1}
	commit(t, l, cur, 0, time.Millisecond, false, false)
	if err := l.AdvanceEpoch(2); !errors.Is(err, ErrEpochBusy) {
		t.Fatal(err)
	}
	if err := l.RetirePrevious(); !errors.Is(err, ErrEpochBusy) {
		t.Fatal(err)
	}
	before := l.Snapshot()
	if _, err := l.ApplyACK(cur, singleACK(s, 0), 2*time.Millisecond, nil); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
	if _, err := l.ApplyACK(Scope{2, 1}, singleACK(cur, 0), 2*time.Millisecond, nil); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
	if l.Snapshot() != before {
		t.Fatal("wrong scope changed state")
	}
	result, err := l.ApplyACK(s, singleACK(s, 0), 2*time.Millisecond, nil)
	if err != nil || result.FlightReleased != 100 || l.Snapshot().Flight != 100 {
		t.Fatal(result, err, l.Snapshot())
	}
	if err := l.RetirePrevious(); err != nil {
		t.Fatal(err)
	}
	result, err = l.ApplyACK(s, singleACK(s, 0), 3*time.Millisecond, nil)
	if err != nil || !result.Ignored {
		t.Fatal(result, err)
	}
	fresh, _ := NewLedger(2, 0)
	before = fresh.Snapshot()
	result, err = fresh.ApplyACK(s, singleACK(s, 0), 4*time.Millisecond, nil)
	if err != nil || !result.Ignored || fresh.Snapshot() != before {
		t.Fatal(result, err)
	}
	maxEpoch, _ := NewLedger(1, math.MaxUint32)
	if err := maxEpoch.AdvanceEpoch(0); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
}

func TestLedgerLostTombstonesBoundedIncludingZeroKey(t *testing.T) {
	l, s := testLedger(t)
	for n := uint64(0); n < MaxLostPackets+1; n++ {
		commit(t, l, s, n, 0, false, false)
		if _, ok := l.DeclareLost(s, n); !ok {
			t.Fatal(n)
		}
	}
	if l.Snapshot().Lost != MaxLostPackets || l.Snapshot().Flight != 0 {
		t.Fatal(l.Snapshot())
	}
	if _, ok := l.lost[packetKey{0, 0}]; ok {
		t.Fatal("oldest tombstone not evicted")
	}
	for _, n := range []uint64{1, 256} {
		result, err := l.ApplyACK(s, singleACK(s, n), time.Second, nil)
		if err != nil || len(result.Packets) != 1 || !result.Packets[0].WasLost || result.FlightReleased != 0 {
			t.Fatal(result, err)
		}
	}
}
