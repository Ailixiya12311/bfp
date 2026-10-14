package classification

import (
	"errors"
	"math"
	"testing"
	"time"

	"bfp/protocol"
)

func behaviorConfig() Config {
	cfg := DefaultConfig()
	cfg.Behavior = BehaviorConfig{
		Enabled: true, Window: 4 * time.Second, Bucket: time.Second,
		MinTotalBytes: 1000, BulkBytesPerSecond: 1000,
		BulkSustain: 3 * time.Second, ActivityGap: time.Second,
		Restore: true, RestoreBytesPerSecond: 100,
		RestoreSustain: 3 * time.Second, Cooldown: 5 * time.Second,
	}
	return cfg
}

func newFlow(t *testing.T, cfg Config, elapsed time.Duration) *Flow {
	t.Helper()
	f, err := newClassifier(t, cfg).NewFlow(meta("tcp", "", ""), elapsed)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func observe(t *testing.T, f *Flow, elapsed time.Duration, n uint64) Update {
	t.Helper()
	u, err := f.Observe(elapsed, n)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestBurstDoesNotBecomeBulkWithoutContinuedActivity(t *testing.T) {
	f := newFlow(t, behaviorConfig(), 0)
	for second := 0; second < 4; second++ {
		observe(t, f, time.Duration(second)*time.Second, 0)
	}
	observe(t, f, 4*time.Second, 1<<20)
	for second := 5; second < 20; second++ {
		u := observe(t, f, time.Duration(second)*time.Second, 0)
		if u.Changed || u.Snapshot.Class != protocol.Normal {
			t.Fatalf("single burst downgraded at %d: %+v", second, u)
		}
	}
	if f.Snapshot().TotalBytes != 1<<20 || f.Snapshot().WindowBytes != 0 {
		t.Fatalf("counters/expiry: %+v", f.Snapshot())
	}
}

func TestSustainedBulkAndIdleRestoreToBaseline(t *testing.T) {
	f := newFlow(t, behaviorConfig(), 0)
	for second := 0; second <= 6; second++ {
		u := observe(t, f, time.Duration(second)*time.Second, 2000)
		if u.Changed {
			t.Fatalf("downgraded too early at %d: %+v", second, u)
		}
	}
	u := observe(t, f, 7*time.Second, 2000)
	if !u.Changed || u.Reason != ReasonBulk || u.Previous != protocol.Normal || u.Snapshot.Class != protocol.Bulk {
		t.Fatalf("sustained traffic not downgraded: %+v", u)
	}
	for second := 8; second <= 13; second++ {
		u = observe(t, f, time.Duration(second)*time.Second, 0)
		if u.Changed {
			t.Fatalf("restored too early at %d: %+v", second, u)
		}
	}
	u = observe(t, f, 14*time.Second, 0)
	if !u.Changed || u.Reason != ReasonRestore || u.Snapshot.Class != protocol.Normal || u.Snapshot.Baseline.Class != protocol.Normal {
		t.Fatalf("idle restoration: %+v", u)
	}
	if u.Snapshot.TotalBytes != 16000 || u.Snapshot.WindowBytes != 0 {
		t.Fatalf("unique counters: %+v", u)
	}
}

func TestExactThresholdSamplesAtBucketBoundary(t *testing.T) {
	f := newFlow(t, behaviorConfig(), 0)
	for second := 0; second <= 6; second++ {
		if u := observe(t, f, time.Duration(second)*time.Second, 1000); u.Changed {
			t.Fatalf("high candidate matured early: %+v", u)
		}
	}
	if u := observe(t, f, 7*time.Second, 1000); !u.Changed || u.Reason != ReasonBulk {
		t.Fatalf("atomic expiry/sample broke sustained threshold: %+v", u)
	}
}

func TestMinimumTotalWarmupAndCooldown(t *testing.T) {
	cfg := behaviorConfig()
	cfg.Behavior.MinTotalBytes = 25000
	cfg.Behavior.Cooldown = 15 * time.Second
	f := newFlow(t, cfg, 0)
	for second := 0; second < 15; second++ {
		u := observe(t, f, time.Duration(second)*time.Second, 2000)
		if u.Changed {
			t.Fatalf("minimum total/cooldown bypassed at %d: %+v", second, u)
		}
	}
	u := observe(t, f, 15*time.Second, 2000)
	if !u.Changed || u.Reason != ReasonBulk {
		t.Fatalf("candidate failed after cumulative threshold and cooldown: %+v", u)
	}
	// A long cooldown must also constrain restoration, even though the low
	// candidate can begin before cooldown expires.
	for second := 16; second < 30; second++ {
		u = observe(t, f, time.Duration(second)*time.Second, 0)
		if u.Changed {
			t.Fatalf("restore cooldown bypassed at %d: %+v", second, u)
		}
	}
	u = observe(t, f, 30*time.Second, 0)
	if !u.Changed || u.Snapshot.Class != protocol.Normal {
		t.Fatalf("restore after cooldown: %+v", u)
	}
}

func TestHysteresisAndGapResetCandidates(t *testing.T) {
	f := newFlow(t, behaviorConfig(), 0)
	for second := 0; second <= 5; second++ {
		observe(t, f, time.Duration(second)*time.Second, 2000)
	}
	// Missing more than ActivityGap resets an in-progress high candidate.
	u := observe(t, f, 7*time.Second, 2000)
	if u.Changed || !f.bulkCandidate || f.bulkSince != 7*time.Second {
		t.Fatalf("activity gap did not restart sustain: %+v since=%v", u, f.bulkSince)
	}
	for second := 8; second < 10; second++ {
		if observe(t, f, time.Duration(second)*time.Second, 2000).Changed {
			t.Fatal("candidate gap counted as sustained traffic")
		}
	}
	if !observe(t, f, 10*time.Second, 2000).Changed {
		t.Fatal("restarted high candidate did not mature")
	}
	// 400 B/s is above restore threshold but below bulk threshold. It must
	// retain Bulk instead of flapping to the baseline.
	for second := 11; second <= 24; second++ {
		if u = observe(t, f, time.Duration(second)*time.Second, 400); u.Changed || u.Snapshot.Class != protocol.Bulk {
			t.Fatalf("hysteresis band restored: %+v", u)
		}
	}
	for second := 25; second <= 27; second++ {
		observe(t, f, time.Duration(second)*time.Second, 0)
	}
	// One low bucket opens the candidate, then fresh 2000B cancels it.
	observe(t, f, 28*time.Second, 0)
	if !f.lowCandidate {
		t.Fatal("low candidate not started")
	}
	u = observe(t, f, 29*time.Second, 2000)
	if u.Changed || f.lowCandidate {
		t.Fatalf("new traffic failed to cancel restore: %+v", u)
	}
}

func TestLockedDisabledAndBulkBaseline(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cfg   Config
		hint  *ClassHint
		class protocol.Class
	}{
		{"locked", behaviorConfig(), &ClassHint{Class: protocol.Interactive, Trusted: true, Locked: true}, protocol.Interactive},
		{"bulk-baseline", behaviorConfig(), &ClassHint{Class: protocol.Bulk, Trusted: true}, protocol.Bulk},
		{"disabled", Config{DefaultClass: protocol.Normal}, nil, protocol.Normal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newClassifier(t, tc.cfg)
			m := meta("tcp", "", "")
			m.Hint = tc.hint
			f, err := c.NewFlow(m, 0)
			if err != nil {
				t.Fatal(err)
			}
			for second := 0; second < 30; second++ {
				u := observe(t, f, time.Duration(second)*time.Second, 1<<20)
				if u.Changed || u.Snapshot.Class != tc.class {
					t.Fatalf("fixed class changed: %+v", u)
				}
			}
			if len(f.buckets) != 0 || f.Snapshot().TotalBytes != 30<<20 {
				t.Fatalf("disabled accounting/state: %+v", f.Snapshot())
			}
		})
	}
}

func TestRollbackEqualTimesAndLargeJump(t *testing.T) {
	f := newFlow(t, behaviorConfig(), 500*time.Millisecond)
	observe(t, f, time.Second, 100)
	observe(t, f, time.Second, 200)
	before := f.Snapshot()
	if _, err := f.Observe(time.Second-time.Nanosecond, 9999); !errors.Is(err, ErrTime) || f.Snapshot() != before {
		t.Fatalf("rollback mutated state: %+v, %v", f.Snapshot(), err)
	}
	if _, err := f.Tick(-1); !errors.Is(err, ErrTime) || f.Snapshot() != before {
		t.Fatal("negative elapsed accepted")
	}
	u := observe(t, f, time.Duration(math.MaxInt64), 10)
	if u.Changed || u.Snapshot.TotalBytes != 310 || u.Snapshot.WindowBytes != 10 || len(f.buckets) != 4 {
		t.Fatalf("unbounded/invalid large jump: %+v", u)
	}
	if _, err := newClassifier(t, behaviorConfig()).NewFlow(meta("tcp", "", ""), -1); !errors.Is(err, ErrTime) {
		t.Fatal("negative initial elapsed accepted")
	}
}

func TestHugeObservationDoesNotWrapOrCorruptWindow(t *testing.T) {
	f := newFlow(t, behaviorConfig(), 0)
	observe(t, f, 0, math.MaxUint64-1)
	u := observe(t, f, time.Second, 100)
	if u.Snapshot.TotalBytes != math.MaxUint64 || u.Snapshot.WindowBytes != math.MaxUint64 {
		t.Fatalf("counters wrapped: %+v", u)
	}
	u = observe(t, f, 4*time.Second, 0)
	if u.Snapshot.WindowBytes != 100 || u.Snapshot.TotalBytes != math.MaxUint64 {
		t.Fatalf("saturated-window expiry corrupted small remaining bucket: %+v", u)
	}
	observe(t, f, 4*time.Second, math.MaxUint64)
	observe(t, f, 4*time.Second, 1) // Saturated single bucket stays saturated.
	u = observe(t, f, 8*time.Second, 0)
	if u.Snapshot.WindowBytes != 0 {
		t.Fatalf("saturated bucket failed to expire: %+v", u)
	}
}

func TestBucketBoundaryConservativeExpiry(t *testing.T) {
	f := newFlow(t, behaviorConfig(), 0)
	observe(t, f, time.Second-time.Nanosecond, 100)
	u := observe(t, f, 4*time.Second-time.Nanosecond, 200)
	if u.Snapshot.WindowBytes != 300 {
		t.Fatalf("bucket expired before boundary: %+v", u)
	}
	u = observe(t, f, 4*time.Second, 0)
	if u.Snapshot.WindowBytes != 200 {
		t.Fatalf("oldest bucket not expired at boundary: %+v", u)
	}
}

func TestLowSustainNotInferredAcrossUnobservedLongGap(t *testing.T) {
	f := newFlow(t, behaviorConfig(), 0)
	for second := 0; second <= 7; second++ {
		observe(t, f, time.Duration(second)*time.Second, 2000)
	}
	u := observe(t, f, time.Hour, 0)
	if u.Changed || u.Snapshot.Class != protocol.Bulk || !f.lowCandidate || f.lowSince != time.Hour {
		t.Fatalf("unobserved low duration inferred: %+v", u)
	}
	for second := 1; second < 3; second++ {
		if observe(t, f, time.Hour+time.Duration(second)*time.Second, 0).Changed {
			t.Fatal("low sustain too short after long gap")
		}
	}
	if !observe(t, f, time.Hour+3*time.Second, 0).Changed {
		t.Fatal("low candidate did not restore after observed sustain")
	}
}

func TestInvalidBehaviorConfig(t *testing.T) {
	base := behaviorConfig()
	for _, mutate := range []func(*BehaviorConfig){
		func(b *BehaviorConfig) { b.Bucket = 0 },
		func(b *BehaviorConfig) { b.Window = 0 },
		func(b *BehaviorConfig) { b.Window = time.Hour },
		func(b *BehaviorConfig) { b.Bucket = 3 * time.Second },
		func(b *BehaviorConfig) { b.Window = b.Bucket },
		func(b *BehaviorConfig) { b.Bucket = time.Nanosecond },
		func(b *BehaviorConfig) { b.MinTotalBytes = 0 },
		func(b *BehaviorConfig) { b.BulkBytesPerSecond = 0 },
		func(b *BehaviorConfig) { b.ActivityGap = 500 * time.Millisecond },
		func(b *BehaviorConfig) { b.BulkSustain = b.ActivityGap },
		func(b *BehaviorConfig) { b.RestoreBytesPerSecond = b.BulkBytesPerSecond },
		func(b *BehaviorConfig) { b.RestoreSustain = 0 },
		func(b *BehaviorConfig) { b.Cooldown = -1 },
		func(b *BehaviorConfig) { b.BulkBytesPerSecond = math.MaxUint64 },
	} {
		cfg := base
		mutate(&cfg.Behavior)
		if _, err := New(cfg); !errors.Is(err, ErrConfig) {
			t.Fatalf("invalid behavior accepted: %+v, %v", cfg.Behavior, err)
		}
	}
}

func TestRateThresholdRounding(t *testing.T) {
	if n, ok := rateThreshold(3, 500*time.Millisecond, true); !ok || n != 2 {
		t.Fatalf("high ceiling: %d %v", n, ok)
	}
	if n, ok := rateThreshold(3, 500*time.Millisecond, false); !ok || n != 1 {
		t.Fatalf("low floor: %d %v", n, ok)
	}
	if n, ok := rateThreshold(math.MaxUint64, time.Second, true); !ok || n != math.MaxUint64 {
		t.Fatalf("representable boundary: %d %v", n, ok)
	}
	if _, ok := rateThreshold(math.MaxUint64, time.Second+1, true); ok {
		t.Fatal("unrepresentable threshold accepted")
	}
}
