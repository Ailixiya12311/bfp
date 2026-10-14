package classification

import (
	"fmt"
	"math"
	"math/bits"
	"time"

	"bfp/protocol"
)

// BehaviorConfig describes a conservative bucketed sliding window. The oldest
// partial bucket is discarded, so retained history can be up to Bucket shorter
// than Window; the rate denominator always remains Window. No sample is spread
// into unobserved past time. Window/Bucket must be between 2 and 1024.
type BehaviorConfig struct {
	Enabled            bool
	Window             time.Duration
	Bucket             time.Duration
	MinTotalBytes      uint64
	BulkBytesPerSecond uint64
	BulkSustain        time.Duration
	// ActivityGap is the longest gap between new-byte observations allowed to
	// continue a bulk candidate. BulkSustain must exceed it, so one burst cannot
	// qualify merely by remaining in a large sliding window.
	ActivityGap           time.Duration
	Restore               bool
	RestoreBytesPerSecond uint64
	RestoreSustain        time.Duration
	Cooldown              time.Duration
}

func DefaultBehaviorConfig() BehaviorConfig {
	return BehaviorConfig{
		Enabled: true, Window: 4 * time.Second, Bucket: 250 * time.Millisecond,
		MinTotalBytes: 1 << 20, BulkBytesPerSecond: 256 << 10,
		BulkSustain: 3 * time.Second, ActivityGap: time.Second,
		Restore: true, RestoreBytesPerSecond: 64 << 10,
		RestoreSustain: 8 * time.Second, Cooldown: 5 * time.Second,
	}
}

func validateBehavior(b BehaviorConfig) (uint64, uint64, error) {
	if b.Bucket <= 0 || b.Window <= 0 || b.Window > time.Minute || b.Window%b.Bucket != 0 || b.Window/b.Bucket < 2 || b.Window/b.Bucket > 1024 {
		return 0, 0, fmt.Errorf("%w: window/bucket", ErrConfig)
	}
	if b.MinTotalBytes == 0 || b.BulkBytesPerSecond == 0 || b.ActivityGap < b.Bucket || b.BulkSustain <= b.ActivityGap || b.Cooldown < 0 {
		return 0, 0, fmt.Errorf("%w: bulk/cooldown thresholds", ErrConfig)
	}
	if b.Restore && (b.RestoreBytesPerSecond >= b.BulkBytesPerSecond || b.RestoreSustain <= 0) {
		return 0, 0, fmt.Errorf("%w: restore hysteresis", ErrConfig)
	}
	high, ok := rateThreshold(b.BulkBytesPerSecond, b.Window, true)
	if !ok {
		return 0, 0, fmt.Errorf("%w: bulk rate overflow", ErrConfig)
	}
	low, ok := rateThreshold(b.RestoreBytesPerSecond, b.Window, false)
	if !ok {
		return 0, 0, fmt.Errorf("%w: restore rate overflow", ErrConfig)
	}
	return high, low, nil
}

func rateThreshold(rate uint64, window time.Duration, roundUp bool) (uint64, bool) {
	hi, lo := bits.Mul64(rate, uint64(window))
	denominator := uint64(time.Second)
	if hi >= denominator {
		return 0, false
	}
	q, rem := bits.Div64(hi, lo, denominator)
	if roundUp && rem != 0 {
		if q == math.MaxUint64 {
			return 0, false
		}
		q++
	}
	return q, true
}

type Reason string

const (
	ReasonBulk    Reason = "sustained_bulk"
	ReasonRestore Reason = "sustained_low"
)

type Snapshot struct {
	Baseline    Decision
	Class       protocol.Class
	Elapsed     time.Duration
	TotalBytes  uint64
	WindowBytes uint64
}

type Update struct {
	Previous protocol.Class
	Snapshot Snapshot
	Changed  bool
	Reason   Reason
}

type Flow struct {
	decision                    Decision
	behavior                    BehaviorConfig
	class                       protocol.Class
	opened, now, lastChange     time.Duration
	lastActivity                time.Duration
	hasActivity                 bool
	total, window               uint64
	buckets                     []uint64
	tick                        int64
	bulkThreshold, lowThreshold uint64
	bulkSince, lowSince         time.Duration
	bulkCandidate, lowCandidate bool
}

func (f *Flow) Snapshot() Snapshot {
	return Snapshot{Baseline: f.decision, Class: f.class, Elapsed: f.now, TotalBytes: f.total, WindowBytes: f.window}
}

// Tick expires history and evaluates idle/low-rate restoration. The session
// owner should call it periodically even without writes. A large time jump takes
// at most Window/Bucket work and does not assume traffic in unobserved time.
func (f *Flow) Tick(elapsed time.Duration) (Update, error) {
	return f.Observe(elapsed, 0)
}

// Observe counts newly accepted application bytes in this sending direction,
// exactly once. Exclude record headers, padding, ACK/control, FEC, replayed bytes,
// and recovery retransmissions. Equal timestamps are allowed; clock rollback
// returns ErrTime without changing any state. Counters saturate, never wrap.
// The returned change is applied by the caller to the effective scheduling class;
// queued frames, wire CLASS_UPDATE, and receiver policy remain owner concerns.
func (f *Flow) Observe(elapsed time.Duration, newAppBytes uint64) (Update, error) {
	previous := f.class
	if elapsed < 0 || elapsed < f.now {
		return Update{Previous: previous, Snapshot: f.Snapshot()}, ErrTime
	}
	if len(f.buckets) == 0 {
		f.now = elapsed
		f.total = saturatingAdd(f.total, newAppBytes)
		return Update{Previous: previous, Snapshot: f.Snapshot()}, nil
	}
	f.advance(elapsed)
	f.now = elapsed
	if newAppBytes != 0 {
		if f.hasActivity && elapsed-f.lastActivity > f.behavior.ActivityGap {
			f.bulkCandidate = false
		}
		f.hasActivity = true
		f.lastActivity = elapsed
		index := f.tick % int64(len(f.buckets))
		old := f.buckets[index]
		f.buckets[index] = saturatingAdd(old, newAppBytes)
		f.window = saturatingAdd(f.window, f.buckets[index]-old)
		f.total = saturatingAdd(f.total, newAppBytes)
	}
	f.updateCandidates(elapsed)
	reason := f.evaluate(elapsed)
	return Update{Previous: previous, Snapshot: f.Snapshot(), Changed: previous != f.class, Reason: reason}, nil
}

func saturatingAdd(a, b uint64) uint64 {
	if b > math.MaxUint64-a {
		return math.MaxUint64
	}
	return a + b
}

func (f *Flow) advance(elapsed time.Duration) {
	next := int64(elapsed / f.behavior.Bucket)
	steps := next - f.tick
	if steps >= int64(len(f.buckets)) {
		clear(f.buckets)
		f.window = 0
		f.tick = next
		f.bulkCandidate = false
		// The caller did not observe the intervening low-rate duration. Start
		// a fresh restoration candidate at this observation, conservatively.
		f.lowCandidate = false
		return
	}
	for f.tick < next {
		f.tick++
		index := f.tick % int64(len(f.buckets))
		removed := f.buckets[index]
		f.buckets[index] = 0
		if f.window == math.MaxUint64 {
			f.window = 0
			for _, n := range f.buckets {
				f.window = saturatingAdd(f.window, n)
			}
		} else {
			f.window -= removed
		}
		// Expiry of the final bucket and the current sample form one atomic
		// observation. Evaluate earlier crossed buckets to catch a rate gap,
		// but do not reset a candidate just before adding same-step new bytes.
		if f.tick < next {
			f.updateCandidates(time.Duration(f.tick) * f.behavior.Bucket)
		}
	}
}

func (f *Flow) updateCandidates(elapsed time.Duration) {
	active := f.hasActivity && elapsed-f.lastActivity <= f.behavior.ActivityGap
	high := elapsed-f.opened >= f.behavior.Window && f.total >= f.behavior.MinTotalBytes && f.window >= f.bulkThreshold && active
	if f.class != protocol.Bulk && high {
		if !f.bulkCandidate {
			f.bulkSince = elapsed
			f.bulkCandidate = true
		}
	} else {
		f.bulkCandidate = false
	}
	if f.class == protocol.Bulk && f.behavior.Restore && f.window <= f.lowThreshold {
		if !f.lowCandidate {
			f.lowSince = elapsed
			f.lowCandidate = true
		}
	} else {
		f.lowCandidate = false
	}
}

func (f *Flow) evaluate(elapsed time.Duration) Reason {
	if elapsed-f.lastChange < f.behavior.Cooldown {
		return ""
	}
	var reason Reason
	if f.class != protocol.Bulk && f.bulkCandidate && elapsed-f.bulkSince >= f.behavior.BulkSustain {
		f.class = protocol.Bulk
		reason = ReasonBulk
	} else if f.class == protocol.Bulk && f.lowCandidate && elapsed-f.lowSince >= f.behavior.RestoreSustain {
		f.class = f.decision.Class
		reason = ReasonRestore
	}
	if reason != "" {
		f.lastChange = elapsed
		f.bulkCandidate, f.lowCandidate = false, false
	}
	return reason
}
