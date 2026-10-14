package udptransport

import "time"

const (
	maxPTOInterval = 8 * time.Second
	maxPTORounds   = uint8(63)
)

// LossDelay is a duration threshold, not a timer and not proof of loss.
// Invalid negative estimator inputs are treated as absent observations.
func LossDelay(latest, smoothed time.Duration) time.Duration {
	sample := max(time.Duration(0), latest, smoothed)
	return max(timerGranularity, saturatingDurationAdd(sample, sample/8))
}

// LossEvidence requires later acknowledged ack-eliciting ordinals. Without
// such evidence, age alone is never loss; the Session owner must use PTO.
// Negative age denotes an invalid monotonic observation and cannot prove loss.
func LossEvidence(higherACKs int, age, latest, smoothed time.Duration) bool {
	if higherACKs <= 0 || age < 0 {
		return false
	}
	return higherACKs >= 3 || age >= LossDelay(latest, smoothed)
}

// PTO is only a bounded no-progress backoff counter. Its owner decides when
// outstanding records arm a deadline, when actual probes commit, which fresh
// ACK/Pong is progress, and when to recover the carrier. It performs none of
// those actions and has no clock, outstanding set, or per-path health state.
type PTO struct{ rounds uint8 }

func NewPTO() PTO { return PTO{} }

// Interval clamps base to the candidate BasePTO range before applying 2^rounds.
// It returns at most 8s without shifting an overflowing signed duration.
func (p PTO) Interval(base time.Duration) time.Duration {
	base = max(minBasePTO, min(base, maxBasePTO))
	if base > maxPTOInterval>>p.rounds {
		return maxPTOInterval
	}
	return base << p.rounds
}

func (p *PTO) Expire() {
	if p.rounds < maxPTORounds {
		p.rounds++
	}
}

func (p *PTO) Progress()    { p.rounds = 0 }
func (p PTO) Rounds() uint8 { return p.rounds }
