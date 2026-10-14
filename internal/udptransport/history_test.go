package udptransport

import (
	"errors"
	"math"
	"reflect"
	"testing"
	"time"
)

func testHistory(t *testing.T) (*History, Scope) {
	t.Helper()
	h, err := NewHistory(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	return h, Scope{1, 0}
}
func observe(t *testing.T, h *History, s Scope, n uint64, at time.Duration, want bool) {
	t.Helper()
	got, err := h.Observe(s, n, at, true)
	if err != nil || got != want {
		t.Fatalf("observe %d got %v %v", n, got, err)
	}
}
func snapshot(t *testing.T, h *History, s Scope, at time.Duration) ACKSnapshot {
	t.Helper()
	got, ok, err := h.Snapshot(s, at)
	if err != nil || !ok {
		t.Fatalf("snapshot %v %v", ok, err)
	}
	if err = got.ACK.Validate(); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestHistoryDelayedACKAndFreshRecordThreshold(t *testing.T) {
	h, s := testHistory(t)
	observe(t, h, s, 0, 0, true)
	for _, at := range []time.Duration{0, 24 * time.Millisecond} {
		due, err := h.Due(s, at)
		if err != nil || due {
			t.Fatalf("early due %v %v", due, err)
		}
	}
	if due, _ := h.Due(s, 25*time.Millisecond); !due {
		t.Fatal("25ms deadline missing")
	}
	x := snapshot(t, h, s, 100*time.Millisecond)
	if x.ACK.Delay != MaxACKDelay {
		t.Fatal(x)
	}
	if err := h.MarkSent(s, x.Revision); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := h.Snapshot(s, 100*time.Millisecond); ok {
		t.Fatal("snapshot still pending")
	}
	observe(t, h, s, 0, 101*time.Millisecond, false)
	observe(t, h, s, 1, 101*time.Millisecond, true)
	observe(t, h, s, 2, 102*time.Millisecond, true)
	if due, _ := h.Due(s, 102*time.Millisecond); !due {
		t.Fatal("two-record threshold")
	}
	x = snapshot(t, h, s, 102*time.Millisecond)
	if !reflect.DeepEqual(x.ACK.Ranges, []Range{{0, 2}}) {
		t.Fatal(x)
	}
}

func TestHistoryACKOnlyNoFeedbackAndReordering(t *testing.T) {
	h, s := testHistory(t)
	if got, err := h.Observe(s, 0, 0, false); got || err != nil {
		t.Fatal(got, err)
	}
	if _, ok, _ := h.Snapshot(s, time.Second); ok {
		t.Fatal("ACK of ACK")
	}
	observe(t, h, s, 1, time.Second, true)
	first := snapshot(t, h, s, time.Second)
	_ = h.MarkSent(s, first.Revision)
	observe(t, h, s, 3, time.Second+time.Millisecond, true)
	x := snapshot(t, h, s, time.Second+2*time.Millisecond)
	if !reflect.DeepEqual(x.ACK.Ranges, []Range{{3, 3}, {1, 1}}) {
		t.Fatal(x)
	}
	if due, _ := h.Due(s, time.Second+2*time.Millisecond); !due {
		t.Fatal("gap not immediate")
	}
	observe(t, h, s, 2, time.Second+3*time.Millisecond, true)
	if err := h.MarkSent(s, x.Revision); err != nil {
		t.Fatal(err)
	}
	y := snapshot(t, h, s, time.Second+4*time.Millisecond)
	if !reflect.DeepEqual(y.ACK.Ranges, []Range{{1, 3}}) || y.ACK.Delay != 3*time.Millisecond {
		t.Fatal(y)
	}
	if _, _, err := h.Snapshot(s, time.Second+2*time.Millisecond); !errors.Is(err, ErrTime) {
		t.Fatal("backward clock accepted", err)
	}
	if err := h.MarkSent(s, y.Revision+1); !errors.Is(err, ErrSequence) {
		t.Fatal(err)
	}
}

func TestHistoryBoundedWindowMaxRangesAndLongJump(t *testing.T) {
	h, s := testHistory(t)
	for i := uint64(0); i < 100; i += 2 {
		observe(t, h, s, i, time.Duration(i)*time.Millisecond, true)
	}
	x := snapshot(t, h, s, 100*time.Millisecond)
	if len(x.ACK.Ranges) != MaxRanges || x.ACK.Ranges[31] != (Range{36, 36}) {
		t.Fatal(x)
	}
	observe(t, h, s, MaxRecordNumber, time.Second, true)
	x = snapshot(t, h, s, time.Second)
	if !reflect.DeepEqual(x.ACK.Ranges, []Range{{MaxRecordNumber, MaxRecordNumber}}) {
		t.Fatal(x)
	}
	observe(t, h, s, MaxRecordNumber-(HistoryBits-1), time.Second+time.Millisecond, true)
	observe(t, h, s, MaxRecordNumber-HistoryBits, time.Second+2*time.Millisecond, false)
	x = snapshot(t, h, s, time.Second+2*time.Millisecond)
	if len(x.ACK.Ranges) != 2 {
		t.Fatal(x)
	}
	if _, err := h.Observe(s, MaxRecordNumber+1, time.Second+3*time.Millisecond, true); !errors.Is(err, ErrSequence) {
		t.Fatal(err)
	}
}

func TestHistoryEpochGenerationAndPendingIsolation(t *testing.T) {
	h, s := testHistory(t)
	observe(t, h, s, 0, 0, true)
	if _, err := h.Observe(Scope{2, 0}, 0, 0, true); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
	if err := h.AdvanceEpoch(2); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
	if err := h.AdvanceEpoch(1); err != nil {
		t.Fatal(err)
	}
	observe(t, h, Scope{1, 1}, 0, time.Millisecond, true)
	if err := h.AdvanceEpoch(2); !errors.Is(err, ErrEpochBusy) {
		t.Fatal(err)
	}
	old := snapshot(t, h, s, 2*time.Millisecond)
	cur := snapshot(t, h, Scope{1, 1}, 2*time.Millisecond)
	if old.ACK.Epoch != 0 || cur.ACK.Epoch != 1 {
		t.Fatal(old, cur)
	}
	_ = h.MarkSent(s, old.Revision)
	if _, ok, _ := h.Snapshot(Scope{1, 1}, 2*time.Millisecond); !ok {
		t.Fatal("old ACK cleared new epoch")
	}
	h.RetirePrevious()
	if _, _, err := h.Snapshot(s, 2*time.Millisecond); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
	if err := h.AdvanceEpoch(2); err != nil {
		t.Fatal(err)
	}
	hMax, _ := NewHistory(1, math.MaxUint32)
	if err := hMax.AdvanceEpoch(0); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
	if _, err := NewHistory(0, 0); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
}

func TestHistoryInvalidTimeAndRevisionAreAtomic(t *testing.T) {
	h, s := testHistory(t)
	observe(t, h, s, 0, time.Second, true)
	before := *h.current
	if _, err := h.Observe(s, 1, -1, true); !errors.Is(err, ErrTime) {
		t.Fatal(err)
	}
	if _, err := h.Observe(s, 1, time.Millisecond, true); !errors.Is(err, ErrTime) {
		t.Fatal(err)
	}
	if _, _, err := h.Snapshot(s, time.Millisecond); !errors.Is(err, ErrTime) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, *h.current) {
		t.Fatal("invalid request mutated history")
	}
	h.current.revision = math.MaxUint64
	before = *h.current
	if _, err := h.Observe(s, 1, 2*time.Second, true); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, *h.current) {
		t.Fatal("revision overflow mutated history")
	}
}
