package operation

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"bfp/protocol"
)

func opKey(kind protocol.Kind, flow, serial uint64) Key {
	return Key{Kind: kind, Flow: flow, Serial: serial}
}

func newTable(t *testing.T) *Table {
	t.Helper()
	x, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func publish(t *testing.T, x *Table, k Key, at time.Duration, gen uint64) State {
	t.Helper()
	p, err := x.Prepare(k, at)
	if err != nil {
		t.Fatal(err)
	}
	if err = x.Publish(p, at, gen); err != nil {
		t.Fatal(err)
	}
	s, err := x.Snapshot(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOperationNeedsActualWriteBeforeReceipt(t *testing.T) {
	x := newTable(t)
	k := opKey(protocol.Open, 7, 1)
	if _, err := x.Start(k, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := x.Ack(k, time.Millisecond); !errors.Is(err, ErrAckBeforeSend) {
		t.Fatal(err)
	}
	state := publish(t, x, k, 0, 1)
	if state.Attempts != 1 || state.Retries != 0 || state.CarrierGen != 1 || !state.Pending {
		t.Fatal(state)
	}
	r, err := x.Ack(k, 2*time.Millisecond)
	if err != nil || !r.Progress || !r.Completed {
		t.Fatal(r, err)
	}
	r, err = x.Ack(k, 3*time.Millisecond)
	if err != nil || !r.Ignored || r.Progress {
		t.Fatal(r, err)
	}
}

func TestRetryBudgetAndNoProgressAreBounded(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxRetries = 2
	cfg.NoProgress = time.Minute
	x, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	k := opKey(protocol.Fin, 3, 99)
	if _, err = x.Start(k, 0); err != nil {
		t.Fatal(err)
	}
	publish(t, x, k, 0, 1)
	x.RebindCarrier(2)
	publish(t, x, k, time.Millisecond, 2)
	x.RebindCarrier(3)
	publish(t, x, k, 2*time.Millisecond, 3)
	s, _ := x.Snapshot(k)
	if s.Retries != 2 || s.Attempts != 3 {
		t.Fatal(s)
	}
	ready, dead, err := x.Ready(s.NextSend, 4)
	if err != nil || len(ready) != 0 || len(dead) != 1 || dead[0] != k {
		t.Fatal(ready, dead, err)
	}
	if _, err = x.Prepare(k, s.NextSend); !errors.Is(err, ErrExhausted) {
		t.Fatal(err)
	}
	if err = x.Fail(k, s.NextSend); err != nil {
		t.Fatal(err)
	}
	if ready, dead, err = x.Ready(s.NextSend, 4); err != nil || len(ready) != 0 || len(dead) != 0 {
		t.Fatal(ready, dead, err)
	}
}

func TestCarrierRebindDoesNotRenewLifetime(t *testing.T) {
	x := newTable(t)
	k := opKey(protocol.Reset, 4, 1)
	if _, err := x.Start(k, 0); err != nil {
		t.Fatal(err)
	}
	publish(t, x, k, 0, 1)
	before, _ := x.Snapshot(k)
	for i := 1; i <= 29; i++ {
		x.RebindCarrier(uint64(i + 1))
		ready, dead, err := x.Ready(time.Duration(i)*time.Second, 1)
		if err != nil || len(dead) != 0 || len(ready) != 1 {
			t.Fatal(i, ready, dead, err)
		}
		publish(t, x, k, time.Duration(i)*time.Second, uint64(i+1))
	}
	after, _ := x.Snapshot(k)
	if after.Started != before.Started || after.Attempts != 30 || after.Retries != 29 {
		t.Fatal(before, after)
	}
	_, dead, err := x.Ready(30*time.Second, 1)
	if err != nil || len(dead) != 1 || dead[0] != k {
		t.Fatal(dead, err)
	}
}

func TestImmutableKeysCannotBeReusedOrCrossAcknowledged(t *testing.T) {
	x := newTable(t)
	a := opKey(protocol.KeyUpdate, 0, 2)
	b := opKey(protocol.KeyUpdate, 0, 3)
	if _, err := x.Start(a, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := x.Start(a, 0); !errors.Is(err, ErrDuplicate) {
		t.Fatal(err)
	}
	if _, err := x.Start(b, 0); err != nil {
		t.Fatal(err)
	}
	publish(t, x, a, 0, 1)
	if _, err := x.Ack(b, time.Millisecond); !errors.Is(err, ErrAckBeforeSend) {
		t.Fatal(err)
	}
	if _, err := x.Ack(a, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, err := x.Snapshot(b); err != nil {
		t.Fatal(err)
	}
}

func TestFailedPublicationHasNoSideEffectAndMonotonicTimeIsAtomic(t *testing.T) {
	x := newTable(t)
	k := opKey(protocol.TicketRefresh, 0, 9)
	if _, err := x.Start(k, time.Second); err != nil {
		t.Fatal(err)
	}
	p, err := x.Prepare(k, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := x.Snapshot(k)
	if err = x.Publish(p, 900*time.Millisecond, 1); !errors.Is(err, ErrTime) {
		t.Fatal(err)
	}
	after, _ := x.Snapshot(k)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed publication mutated state", before, after)
	}
	if _, err = x.Prepare(k, 500*time.Millisecond); !errors.Is(err, ErrTime) {
		t.Fatal(err)
	}
	if _, err = x.Start(opKey(protocol.TicketRefresh, 0, 10), 500*time.Millisecond); !errors.Is(err, ErrTime) {
		t.Fatal(err)
	}
}

func TestReadyDoesNotConsumeRetryAndRebindMakesItImmediate(t *testing.T) {
	x := newTable(t)
	k := opKey(protocol.ResumeState, 8, 1)
	if _, err := x.Start(k, 0); err != nil {
		t.Fatal(err)
	}
	publish(t, x, k, 0, 1)
	ready, dead, err := x.Ready(1*time.Millisecond, 1)
	if err != nil || len(ready) != 0 || len(dead) != 0 {
		t.Fatal(ready, dead, err)
	}
	x.RebindCarrier(2)
	ready, dead, err = x.Ready(1*time.Millisecond, 1)
	if err != nil || len(ready) != 1 || len(dead) != 0 || ready[0].Retries != 0 {
		t.Fatal(ready, dead, err)
	}
	// Preparing without publishing is safe and does not consume the retry.
	p, err := x.Prepare(k, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err = x.Publish(p, 2*time.Millisecond, 2); err != nil {
		t.Fatal(err)
	}
	s, _ := x.Snapshot(k)
	if s.Retries != 1 || s.Attempts != 2 {
		t.Fatal(s)
	}
}

func TestForgetWhereDropsSupersededCarrierOperations(t *testing.T) {
	x := newTable(t)
	old := opKey(protocol.ResumeState, 7, 1)
	keep := opKey(protocol.ResumeState, 7, 2)
	other := opKey(protocol.Fin, 7, 1)
	for _, k := range []Key{old, keep, other} {
		if _, err := x.Start(k, 0); err != nil {
			t.Fatal(err)
		}
	}
	if removed := x.ForgetWhere(func(k Key, _ State) bool {
		return (k.Kind == protocol.ResumeState || k.Kind == protocol.ResumeDone) && k.Serial != 2
	}); removed != 1 {
		t.Fatalf("removed %d operations, want one", removed)
	}
	if x.Has(old) {
		t.Fatal("superseded recovery operation remained")
	}
	if !x.Has(keep) || !x.Has(other) {
		t.Fatal("predicate removed an unrelated operation")
	}
}
