package latestcontrol

import (
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"bfp/protocol"
)

func newTable(t *testing.T) *Table {
	t.Helper()
	x, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return x
}
func update(t *testing.T, x *Table, k Key, v uint64, data []byte, at time.Duration) State {
	t.Helper()
	s, changed, err := x.Update(k, v, data, at)
	if err != nil || !changed {
		t.Fatalf("update changed=%v err=%v", changed, err)
	}
	return s
}
func publish(t *testing.T, x *Table, s State, at time.Duration) {
	t.Helper()
	p, err := x.Prepare(s.Key, s.Revision, at)
	if err != nil {
		t.Fatal(err)
	}
	if err = x.Publish(p, at, 200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
}

func TestFinalStateRetriesWithoutNewBusinessUntilInstalled(t *testing.T) {
	x := newTable(t)
	k := Key{protocol.StreamAck, 1}
	s := update(t, x, k, 900, nil, 0)
	publish(t, x, s, 0)
	ready, exhausted, err := x.Ready(199*time.Millisecond, 1)
	if err != nil || len(ready) != 0 || len(exhausted) != 0 {
		t.Fatal(ready, exhausted, err)
	}
	ready, _, err = x.Ready(200*time.Millisecond, 1)
	if err != nil || len(ready) != 1 || ready[0].Value != 900 {
		t.Fatal(ready, err)
	}
	publish(t, x, ready[0], 200*time.Millisecond)
	r, err := x.Receipt(k, 1, 250*time.Millisecond)
	if err != nil || !r.Progress || !r.Installed {
		t.Fatal(r, err)
	}
	ready, exhausted, err = x.Ready(time.Minute, 1)
	if err != nil || len(ready) != 0 || len(exhausted) != 0 {
		t.Fatal(ready, exhausted, err)
	}
	r, err = x.Receipt(k, 1, time.Minute)
	if err != nil || !r.Ignored || r.Progress {
		t.Fatal(r, err)
	}
}

func TestCoalescingAndOldReceiptCannotInstallNewRevision(t *testing.T) {
	x := newTable(t)
	k := Key{protocol.MaxFlowData, 7}
	a := update(t, x, k, 100, nil, 0)
	publish(t, x, a, 0)
	b := update(t, x, k, 200, nil, time.Millisecond)
	if b.Revision != 2 {
		t.Fatal(b)
	}
	r, err := x.Receipt(k, 1, 2*time.Millisecond)
	if err != nil || !r.Progress || r.Installed {
		t.Fatal(r, err)
	}
	s, _ := x.Snapshot(k)
	if !s.Pending || s.State.Value != 200 || s.Confirmed != 1 {
		t.Fatal(s)
	}
	ready, _, err := x.Ready(2*time.Millisecond, 2)
	if err != nil || len(ready) != 1 || ready[0].Revision != 2 {
		t.Fatal(ready, err)
	}
	publish(t, x, b, 3*time.Millisecond)
	r, err = x.Receipt(k, 2, 4*time.Millisecond)
	if err != nil || !r.Installed {
		t.Fatal(r, err)
	}
}

func TestUnpublishedHoleAndFutureReceiptRejectAtomically(t *testing.T) {
	x := newTable(t)
	k := Key{protocol.MaxSessionData, 0}
	update(t, x, k, 100, nil, 0) // revision 1 never submitted
	s := update(t, x, k, 200, nil, 0)
	publish(t, x, s, 0)
	before, _ := x.Snapshot(k)
	for _, revision := range []uint64{0, 1, 3, math.MaxUint64} {
		if _, err := x.Receipt(k, revision, time.Second); !errors.Is(err, ErrReceipt) {
			t.Fatal(revision, err)
		}
		after, _ := x.Snapshot(k)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("invalid receipt mutated state")
		}
	}
}

func TestPublicationFollowsActualWriteAndRecordsDeadlineCrossing(t *testing.T) {
	x := newTable(t)
	k := Key{protocol.StreamAck, 9}
	s := update(t, x, k, 1, nil, 0)
	p, err := x.Prepare(k, s.Revision, 29*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Failed I/O discards a preparation: no publication or retry side effect.
	before, _ := x.Snapshot(k)
	if before.Published != 0 || before.Retries != 0 {
		t.Fatal(before)
	}
	if _, err = x.Receipt(k, 1, 29*time.Second); !errors.Is(err, ErrReceipt) {
		t.Fatal(err)
	}
	// A successful write crossing the deadline still requires publication.
	if err = x.Publish(p, 31*time.Second, time.Second); err != nil {
		t.Fatal(err)
	}
	ready, dead, err := x.Ready(31*time.Second, 1)
	if err != nil || len(ready) != 0 || len(dead) != 1 {
		t.Fatal(ready, dead, err)
	}
	if err = x.Publish(p, 32*time.Second, time.Second); !errors.Is(err, ErrStale) {
		t.Fatal("reused publication", err)
	}
	r, err := x.Receipt(k, 1, 32*time.Second)
	if err != nil || !r.Installed {
		t.Fatal(r, err)
	}
}

func TestStaleSnapshotCannotPublishAfterCoalescingOrReceipt(t *testing.T) {
	x := newTable(t)
	k := Key{protocol.MaxFlowData, 1}
	a := update(t, x, k, 10, nil, 0)
	p, err := x.Prepare(k, a.Revision, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := update(t, x, k, 20, nil, 0)
	if err = x.Publish(p, 0, time.Second); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	if _, err = x.Prepare(k, a.Revision, 0); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	publish(t, x, b, 0)
	p, err = x.Prepare(k, b.Revision, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = x.Receipt(k, b.Revision, time.Second); err != nil {
		t.Fatal(err)
	}
	if err = x.Publish(p, time.Second, time.Second); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
}

func TestNewValuesAndCarrierRebindDoNotRenewNoProgressLifetime(t *testing.T) {
	x := newTable(t)
	k := Key{protocol.MaxFlowData, 1}
	s := update(t, x, k, 10, nil, 0)
	publish(t, x, s, 0)
	for i := 1; i <= 29; i++ {
		s = update(t, x, k, uint64(10+i), nil, time.Duration(i)*time.Second)
		publish(t, x, s, time.Duration(i)*time.Second)
		x.RebindCarrier()
	}
	snap, _ := x.Snapshot(k)
	if snap.Started != 0 {
		t.Fatal("latest update renewed deadline", snap)
	}
	ready, dead, err := x.Ready(30*time.Second, 1)
	if err != nil || len(ready) != 0 || len(dead) != 1 {
		t.Fatal(ready, dead, err)
	}
	if _, err = x.Prepare(k, s.Revision, 30*time.Second); !errors.Is(err, ErrExhausted) {
		t.Fatal(err)
	}
}

func TestActualRetryLimitAndRebindRetryLineage(t *testing.T) {
	x := newTable(t)
	k := Key{protocol.StreamAck, 1}
	s := update(t, x, k, 1, nil, 0)
	publish(t, x, s, 0)
	for i := 1; i <= 8; i++ {
		x.RebindCarrier() // recovery is a retry, not another initial publication
		ready, dead, err := x.Ready(time.Duration(i)*time.Millisecond, 1)
		if err != nil || len(ready) != 1 || len(dead) != 0 {
			t.Fatal(i, ready, dead, err)
		}
		publish(t, x, s, time.Duration(i)*time.Millisecond)
	}
	snap, _ := x.Snapshot(k)
	if snap.Retries != 8 {
		t.Fatal(snap)
	}
	ready, dead, err := x.Ready(9*time.Millisecond, 1)
	if err != nil || len(ready) != 0 || len(dead) != 0 {
		t.Fatal(ready, dead, err)
	}
	if _, err = x.Prepare(k, 1, 9*time.Millisecond); !errors.Is(err, ErrNotDue) {
		t.Fatal(err)
	}
	ready, dead, err = x.Ready(snap.NextSend, 1)
	if err != nil || len(ready) != 0 || len(dead) != 1 {
		t.Fatal(ready, dead, err)
	}
	r, err := x.Receipt(k, 1, 10*time.Millisecond)
	if err != nil || !r.Installed {
		t.Fatal(r, err)
	}
}

func TestPublishedHistoryRetirementIgnoresOldWithoutClearingCurrent(t *testing.T) {
	x := newTable(t)
	k := Key{protocol.StreamAck, 1}
	for i := 1; i <= 40; i++ {
		s := update(t, x, k, uint64(i), nil, 0)
		publish(t, x, s, 0)
	}
	before, _ := x.Snapshot(k)
	if before.RetiredThrough != 24 || before.Published != 40 {
		t.Fatal(before)
	}
	for _, revision := range []uint64{1, 20, 24} {
		r, err := x.Receipt(k, revision, 0)
		if err != nil || !r.Ignored || r.Progress {
			t.Fatal(r, err)
		}
	}
	after, _ := x.Snapshot(k)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("forgotten receipt changed current")
	}
	r, err := x.Receipt(k, 25, 0)
	if err != nil || !r.Progress || r.Installed {
		t.Fatal(r, err)
	}
	r, err = x.Receipt(k, 40, 0)
	if err != nil || !r.Installed {
		t.Fatal(r, err)
	}
}

func TestImmutableResultAndCopyOnlySnapshots(t *testing.T) {
	x := newTable(t)
	k := Key{protocol.OpenResult, 1}
	data := []byte("ok")
	s := update(t, x, k, 0, data, 0)
	data[0] = 'x'
	s.Data[0] = 'y'
	snap, _ := x.Snapshot(k)
	if string(snap.State.Data) != "ok" {
		t.Fatal(snap)
	}
	snap.State.Data[0] = 'z'
	if _, changed, err := x.Update(k, 0, []byte("ok"), 0); err != nil || changed {
		t.Fatal(changed, err)
	}
	if _, _, err := x.Update(k, 0, []byte("denied"), 0); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	ready, _, _ := x.Ready(0, 1)
	ready[0].Data[0] = 'w'
	snap, _ = x.Snapshot(k)
	if string(snap.State.Data) != "ok" {
		t.Fatal(snap)
	}
}

func TestBudgetsAndMonotonicErrorsHaveNoSideEffects(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxKeys = 1
	cfg.MaxBytes = 2
	cfg.MaxResultBytes = 2
	x, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	k := Key{protocol.OpenResult, 1}
	s := update(t, x, k, 0, []byte("ok"), time.Second)
	before, _ := x.Snapshot(k)
	if _, _, err = x.Update(Key{protocol.StreamAck, 2}, 1, nil, time.Second); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	if _, _, err = x.Update(k, 0, []byte("ok"), 0); !errors.Is(err, ErrTime) {
		t.Fatal(err)
	}
	after, _ := x.Snapshot(k)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failure mutated state")
	}
	if _, err = x.Prepare(k, s.Revision, 0); !errors.Is(err, ErrTime) {
		t.Fatal(err)
	}
	if _, _, err = x.Ready(0, 1); !errors.Is(err, ErrTime) {
		t.Fatal(err)
	}
	x.Forget(k)
	if keys, used := x.Usage(); keys != 0 || used != 0 {
		t.Fatal(keys, used)
	}
	update(t, x, Key{protocol.StreamAck, 2}, 1, nil, time.Second)
}

func TestStateScopeMonotonicValueAndRevisionOverflow(t *testing.T) {
	x := newTable(t)
	for _, k := range []Key{{protocol.StreamData, 1}, {protocol.StreamAck, 0}, {protocol.MaxSessionData, 1}, {protocol.OpenResult, 0}} {
		if _, _, err := x.Update(k, 1, nil, 0); !errors.Is(err, ErrState) {
			t.Fatal(k, err)
		}
	}
	k := Key{protocol.StreamAck, 1}
	update(t, x, k, 5, nil, 0)
	if _, _, err := x.Update(k, 4, nil, 0); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	x.entries[k].state.Revision = math.MaxUint64
	before, _ := x.Snapshot(k)
	if _, _, err := x.Update(k, 6, nil, 0); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	after, _ := x.Snapshot(k)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("revision wrap changed state")
	}
}
