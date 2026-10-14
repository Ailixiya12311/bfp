package udptransport

import (
	"math"
	"testing"
	"time"
)

func TestLossDelayRationalThresholdAndSaturation(t *testing.T) {
	for _, tc := range []struct {
		latest, smoothed, want time.Duration
	}{
		{0, 0, 10 * time.Millisecond},
		{-1, -1, 10 * time.Millisecond},
		{time.Millisecond, 0, 10 * time.Millisecond},
		{100 * time.Millisecond, 200 * time.Millisecond, 225 * time.Millisecond},
		{240 * time.Millisecond, 200 * time.Millisecond, 270 * time.Millisecond},
		{100*time.Millisecond + 7, 0, 112500*time.Microsecond + 7},
		{maxDuration, 0, maxDuration},
		{0, maxDuration, maxDuration},
	} {
		if got := LossDelay(tc.latest, tc.smoothed); got != tc.want {
			t.Fatalf("loss delay latest=%s srtt=%s got=%s want=%s", tc.latest, tc.smoothed, got, tc.want)
		}
	}
}

func TestLossEvidenceRequiresSuccessorAndMonotonicAge(t *testing.T) {
	threshold := 225 * time.Millisecond
	for _, tc := range []struct {
		higher int
		age    time.Duration
		want   bool
	}{
		{0, maxDuration, false},
		{-1, maxDuration, false},
		{1, threshold - 1, false},
		{1, threshold, true},
		{2, threshold, true},
		{2, 0, false},
		{3, 0, true},
		{math.MaxInt, 0, true},
		{3, -1, false},
	} {
		if got := LossEvidence(tc.higher, tc.age, 100*time.Millisecond, 200*time.Millisecond); got != tc.want {
			t.Fatalf("loss evidence %+v got=%t", tc, got)
		}
	}
	// Age may reach duration saturation, but without a later ACK it is PTO.
	if LossEvidence(0, maxDuration, maxDuration, maxDuration) ||
		!LossEvidence(1, maxDuration, maxDuration, maxDuration) ||
		LossEvidence(1, maxDuration-1, maxDuration, maxDuration) {
		t.Fatal("extreme age/threshold confused evidence")
	}
}

func TestPTOBackoffClampsBaseCapsAndResets(t *testing.T) {
	p := NewPTO()
	base := NewRTT()
	want := []time.Duration{625 * time.Millisecond, 1250 * time.Millisecond, 2500 * time.Millisecond, 5 * time.Second, 8 * time.Second, 8 * time.Second}
	for round, interval := range want {
		if p.Rounds() != uint8(round) || p.Interval(base.BasePTO()) != interval {
			t.Fatalf("round%d interval=%s want=%s", p.Rounds(), p.Interval(base.BasePTO()), interval)
		}
		// Asking for a deadline must not advance no-progress state.
		if p.Interval(base.BasePTO()) != interval || p.Rounds() != uint8(round) {
			t.Fatal("Interval mutated backoff")
		}
		p.Expire()
	}
	for n := 0; n < 300; n++ {
		p.Expire()
	}
	if p.Rounds() != 63 || p.Interval(maxDuration) != 8*time.Second || p.Interval(1) != 8*time.Second {
		t.Fatal("round/interval saturation wrapped")
	}
	p.Progress()
	if p.Rounds() != 0 || p.Interval(base.BasePTO()) != 625*time.Millisecond {
		t.Fatal("new acknowledged progress failed to reset")
	}
	for _, tc := range []struct{ input, want time.Duration }{
		{time.Duration(math.MinInt64), 200 * time.Millisecond},
		{-1, 200 * time.Millisecond},
		{0, 200 * time.Millisecond},
		{1, 200 * time.Millisecond},
		{2 * time.Second, 2 * time.Second},
		{maxDuration, 2 * time.Second},
	} {
		if got := p.Interval(tc.input); got != tc.want {
			t.Fatalf("base clamp input=%s got=%s want=%s", tc.input, got, tc.want)
		}
	}
	// Zero-value counter has the same usable initial state as NewPTO.
	var zero PTO
	if zero.Rounds() != 0 || zero.Interval(time.Second) != time.Second {
		t.Fatal("zero counter differs from constructor")
	}
}
