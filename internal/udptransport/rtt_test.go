package udptransport

import (
	"math"
	"math/big"
	"testing"
	"time"
)

func TestRTTInitialFirstSampleAndPTOClamp(t *testing.T) {
	r := NewRTT()
	if got := r.Snapshot(); got != (RTTSnapshot{Smoothed: 200 * time.Millisecond, Variance: 100 * time.Millisecond}) {
		t.Fatalf("initial estimator: %+v", got)
	}
	if got := r.BasePTO(); got != 625*time.Millisecond {
		t.Fatalf("initial PTO: %s", got)
	}
	if !r.Observe(80*time.Millisecond, 25*time.Millisecond, true) {
		t.Fatal("first valid sample rejected")
	}
	// The first raw sample is Min; subtracting delay would go below it.
	want := RTTSnapshot{Latest: 80 * time.Millisecond, Min: 80 * time.Millisecond, Smoothed: 80 * time.Millisecond, Variance: 40 * time.Millisecond, Samples: 1}
	if got := r.Snapshot(); got != want || r.BasePTO() != 265*time.Millisecond {
		t.Fatalf("first sample: %+v PTO=%s", got, r.BasePTO())
	}
	for _, tc := range []struct {
		raw, wantPTO time.Duration
	}{{time.Nanosecond, 200 * time.Millisecond}, {time.Second, 2 * time.Second}, {maxDuration, 2 * time.Second}} {
		r := NewRTT()
		if !r.Observe(tc.raw, 0, true) || r.BasePTO() != tc.wantPTO {
			t.Fatalf("PTO clamp raw=%s snapshot=%+v PTO=%s", tc.raw, r.Snapshot(), r.BasePTO())
		}
	}
}

func TestRTTEWMAUsesOldSmoothedAndBoundedDelay(t *testing.T) {
	r := NewRTT()
	r.Observe(100*time.Millisecond, 0, true)
	r.Observe(140*time.Millisecond, 20*time.Millisecond, true)
	want := RTTSnapshot{Latest: 140 * time.Millisecond, Min: 100 * time.Millisecond, Smoothed: 102500 * time.Microsecond, Variance: 42500 * time.Microsecond, Samples: 2}
	if got := r.Snapshot(); got != want {
		t.Fatalf("EWMA/subtract delay: %+v want %+v", got, want)
	}
	// raw-Min < delay: do not partially subtract/clamp delay to Min.
	r.Observe(110*time.Millisecond, MaxACKDelay, true)
	want.Latest, want.Smoothed, want.Variance, want.Samples = 110*time.Millisecond, 103437500*time.Nanosecond, 33750*time.Microsecond, 3
	if got := r.Snapshot(); got != want {
		t.Fatalf("min floor: %+v want %+v", got, want)
	}
	r.Observe(80*time.Millisecond, MaxACKDelay, true)
	if got := r.Snapshot(); got.Min != 80*time.Millisecond || got.Latest != 80*time.Millisecond || got.Smoothed < got.Min {
		t.Fatalf("new raw Min lost or delay went below it: %+v", got)
	}
	// Exactly raw-Min==delay is the inclusive subtraction boundary.
	boundary := NewRTT()
	boundary.Observe(100*time.Millisecond, 0, true)
	boundary.Observe(125*time.Millisecond, MaxACKDelay, true)
	if got := boundary.Snapshot(); got.Smoothed != 100*time.Millisecond || got.Variance != 37500*time.Microsecond {
		t.Fatalf("inclusive min floor: %+v", got)
	}
}

func TestRTTRejectsKarnAndInvalidInputsWithoutMutation(t *testing.T) {
	for _, seeded := range []bool{false, true} {
		r := NewRTT()
		if seeded {
			r.Observe(100*time.Millisecond, 0, true)
		}
		before := r.Snapshot()
		for _, tc := range []struct {
			raw, delay time.Duration
			eligible   bool
		}{
			{time.Second, 0, false},
			{0, 0, true},
			{-1, 0, true},
			{time.Second, -1, true},
			{time.Second, MaxACKDelay + 1, true},
			{maxDuration, maxDuration, true},
			{time.Duration(math.MinInt64), 0, true},
		} {
			if r.Observe(tc.raw, tc.delay, tc.eligible) || r.Snapshot() != before {
				t.Fatalf("rejected sample changed state: %+v", tc)
			}
		}
	}
}

func weightedOracle(a, b time.Duration, weight, divisor int64) time.Duration {
	var total, left, right, quotient big.Int
	left.Mul(big.NewInt(int64(a)), big.NewInt(weight))
	right.Mul(big.NewInt(int64(b)), big.NewInt(divisor-weight))
	total.Add(&left, &right)
	quotient.Quo(&total, big.NewInt(divisor))
	return time.Duration(quotient.Int64())
}

func TestRTTExactIntegerEWMAAndExtremeDurations(t *testing.T) {
	// An independent unbounded-integer oracle catches overflow and the
	// off-by-one from dividing weighted contributions separately.
	for _, pair := range [][2]time.Duration{
		{5, 6}, {maxDuration, maxDuration - 1}, {maxDuration, 1},
		{1, maxDuration}, {maxDuration - 7, maxDuration - 3},
	} {
		for _, ratio := range [][2]int64{{7, 8}, {3, 4}} {
			want := weightedOracle(pair[0], pair[1], ratio[0], ratio[1])
			if got := weightedDuration(pair[0], pair[1], ratio[0], ratio[1]); got != want {
				t.Fatalf("weighted mean %v ratio%v got=%d want=%d", pair, ratio, got, want)
			}
		}
	}
	r := NewRTT()
	r.Observe(maxDuration, 0, true)
	old := r.Snapshot()
	if !r.Observe(maxDuration-1, MaxACKDelay, true) {
		t.Fatal("extreme valid sample rejected")
	}
	got := r.Snapshot()
	if got.Latest != maxDuration-1 || got.Min != maxDuration-1 ||
		got.Smoothed != weightedOracle(old.Smoothed, maxDuration-1, 7, 8) ||
		got.Variance != weightedOracle(old.Variance, 1, 3, 4) || r.BasePTO() != 2*time.Second {
		t.Fatalf("overflow at extreme estimator: %+v", got)
	}
	// Near-Max Min with an added delay must not wrap the floor comparison.
	floor := NewRTT()
	floor.Observe(maxDuration-2, 0, true)
	floor.Observe(maxDuration, MaxACKDelay, true)
	if snap := floor.Snapshot(); snap.Smoothed < snap.Min || snap.Smoothed <= 0 {
		t.Fatalf("min+delay overflowed: %+v", snap)
	}
	r.samples = math.MaxUint64
	if !r.Observe(maxDuration, 0, true) || r.Snapshot().Samples != math.MaxUint64 {
		t.Fatal("sample counter wrapped")
	}
}
