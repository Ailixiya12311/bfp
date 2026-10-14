package udptransport

import (
	"math"
	"time"
)

const (
	initialSmoothedRTT = 200 * time.Millisecond
	initialRTTVariance = 100 * time.Millisecond
	timerGranularity   = 10 * time.Millisecond
	minBasePTO         = 200 * time.Millisecond
	maxBasePTO         = 2 * time.Second
	maxDuration        = time.Duration(math.MaxInt64)
)

// RTT is an owner-confined estimator. Observe receives an already validated
// elapsed sample; the caller determines sampling eligibility (including Karn,
// ACK scope, the newly acknowledged largest record, and retry lineage).
// It never reads a clock or observes record/stream delivery on its own.
type RTT struct {
	latest, minimum, smoothed, variance time.Duration
	samples                             uint64
}

type RTTSnapshot struct {
	Latest, Min, Smoothed, Variance time.Duration
	Samples                         uint64
}

func NewRTT() RTT {
	return RTT{smoothed: initialSmoothedRTT, variance: initialRTTVariance}
}

// Observe rejects ineligible, nonpositive raw, negative delay, and delay above
// the fixed bound without any mutation. Latest/Min retain raw network samples.
// Delay is subtracted only in full when doing so cannot go below raw Min.
func (r *RTT) Observe(raw, delay time.Duration, eligible bool) bool {
	if !eligible || raw <= 0 || delay < 0 || delay > MaxACKDelay {
		return false
	}
	minimum := r.minimum
	if r.samples == 0 || raw < minimum {
		minimum = raw
	}
	adjusted := raw
	// Subtract before comparing rather than computing minimum+delay, which
	// can overflow at the duration bound.
	if raw-minimum >= delay {
		adjusted = raw - delay
	}
	if r.samples == 0 {
		r.smoothed = adjusted
		r.variance = adjusted / 2
	} else {
		difference := r.smoothed - adjusted
		if difference < 0 {
			difference = -difference // Both terms are positive, so no MinInt64.
		}
		r.variance = weightedDuration(r.variance, difference, 3, 4)
		r.smoothed = weightedDuration(r.smoothed, adjusted, 7, 8)
	}
	r.latest, r.minimum = raw, minimum
	if r.samples < math.MaxUint64 {
		r.samples++
	}
	return true
}

func (r RTT) Snapshot() RTTSnapshot {
	return RTTSnapshot{Latest: r.latest, Min: r.minimum, Smoothed: r.smoothed, Variance: r.variance, Samples: r.samples}
}

// BasePTO uses the fixed candidate revision constants. Saturation happens
// before clamping, so an extreme sample cannot wrap into a short timeout.
func (r RTT) BasePTO() time.Duration {
	variation := max(saturatingDurationScale(r.variance, 4), timerGranularity)
	base := saturatingDurationAdd(saturatingDurationAdd(r.smoothed, variation), MaxACKDelay)
	return max(minBasePTO, min(base, maxBasePTO))
}

// weightedDuration returns floor((weight*a + (divisor-weight)*b)/divisor)
// exactly for nonnegative durations. Splitting quotients and remainders avoids
// overflow without independently truncating the two weighted contributions.
func weightedDuration(a, b time.Duration, weight, divisor int64) time.Duration {
	d := time.Duration(divisor)
	other := time.Duration(divisor - weight)
	w := time.Duration(weight)
	return a/d*w + b/d*other + (a%d*w+b%d*other)/d
}

func saturatingDurationAdd(a, b time.Duration) time.Duration {
	if a > maxDuration-b {
		return maxDuration
	}
	return a + b
}

func saturatingDurationScale(value time.Duration, factor time.Duration) time.Duration {
	if value > maxDuration/factor {
		return maxDuration
	}
	return value * factor
}
