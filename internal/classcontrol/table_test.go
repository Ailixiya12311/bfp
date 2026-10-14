package classcontrol

import (
	"errors"
	"math"
	"testing"
	"time"

	"bfp/protocol"
)

func testTable(t *testing.T) *Table {
	t.Helper()
	table, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return table
}

func startEnabled(t *testing.T, table *Table, flow uint64, class protocol.Class, now time.Duration) State {
	t.Helper()
	state, err := table.Start(flow, class, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := table.Enable(flow, now); err != nil {
		t.Fatal(err)
	}
	return state
}

func publish(t *testing.T, table *Table, state State, now time.Duration) {
	t.Helper()
	p, err := table.Prepare(state.Flow, state.Version, state.Class, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.State(); got != state {
		t.Fatalf("prepared state = %+v, want %+v", got, state)
	}
	if err := table.Publish(p, now, 200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
}

func snapshot(t *testing.T, table *Table, flow uint64) Snapshot {
	t.Helper()
	s, err := table.Snapshot(flow)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLocalVersionAndGatePermitClassDecrease(t *testing.T) {
	table := testTable(t)
	initial, err := table.Start(1, protocol.Bulk, 0)
	if err != nil || initial.Version != 1 {
		t.Fatalf("start = %+v, %v", initial, err)
	}
	for _, class := range []protocol.Class{protocol.Normal, protocol.Interactive} {
		changed, didChange, err := table.Update(1, class, 0)
		if err != nil || !didChange || changed.Class != class {
			t.Fatalf("decreasing class = %+v, %v, %v", changed, didChange, err)
		}
	}
	if same, changed, err := table.Update(1, protocol.Interactive, time.Second); err != nil || changed || same.Version != 3 {
		t.Fatalf("same-class update = %+v, %v, %v", same, changed, err)
	}
	ready, dead, err := table.Ready(40*time.Second, 1)
	if err != nil || len(ready) != 0 || len(dead) != 0 {
		t.Fatalf("gated readiness = %+v, %v, %v", ready, dead, err)
	}
	if _, err := table.Prepare(1, 3, protocol.Interactive, 40*time.Second); !errors.Is(err, ErrNotDue) {
		t.Fatalf("gated prepare = %v", err)
	}
	if err := table.Enable(1, 40*time.Second); err != nil {
		t.Fatal(err)
	}
	table.RebindCarrier()
	ready, dead, err = table.Ready(40*time.Second, 1)
	if err != nil || len(ready) != 1 || ready[0].Version != 3 || len(dead) != 0 {
		t.Fatalf("enabled readiness = %+v, %v, %v", ready, dead, err)
	}
	s := snapshot(t, table, 1)
	if s.Local.Version != 3 || s.Started != 40*time.Second || s.Attempts != 0 || s.Published.Version != 0 {
		t.Fatalf("query/rebind changed local semantic state: %+v", s)
	}
}

func TestFailedWriteAndExactPublicationProof(t *testing.T) {
	table := testTable(t)
	state := startEnabled(t, table, 1, protocol.Bulk, 0)
	p, err := table.Prepare(1, 1, protocol.Bulk, 0)
	if err != nil {
		t.Fatal(err)
	}
	// A partial/failed carrier write discards p without calling Publish.
	if _, err := table.Ack(1, 1, protocol.Bulk, 0); !errors.Is(err, ErrAck) {
		t.Fatalf("unpublished acknowledgement = %v", err)
	}
	if s := snapshot(t, table, 1); s.Published.Version != 0 || s.Attempts != 0 || !s.Pending {
		t.Fatalf("prepare published failed I/O: %+v", s)
	}
	if err := table.Publish(p, time.Millisecond, 200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, err := table.Ack(1, 1, protocol.Interactive, time.Millisecond); !errors.Is(err, ErrAck) {
		t.Fatalf("wrong exact class acknowledgement = %v", err)
	}
	if _, err := table.Ack(1, 2, protocol.Bulk, time.Millisecond); !errors.Is(err, ErrAck) {
		t.Fatalf("future acknowledgement = %v", err)
	}
	result, err := table.Ack(state.Flow, state.Version, state.Class, time.Millisecond)
	if err != nil || !result.Installed || !result.Progress || snapshot(t, table, 1).Pending {
		t.Fatalf("exact acknowledgement = %+v, %v", result, err)
	}
	if _, err := table.Ack(1, 1, protocol.Interactive, time.Millisecond); !errors.Is(err, ErrAck) {
		t.Fatalf("wrong class duplicate was accepted: %v", err)
	}
	if result, err := table.Ack(1, 1, protocol.Bulk, time.Millisecond); err != nil || !result.Ignored {
		t.Fatalf("exact duplicate = %+v, %v", result, err)
	}
	if err := table.Publish(p, time.Millisecond, 200*time.Millisecond); !errors.Is(err, ErrStale) {
		t.Fatalf("token published twice = %v", err)
	}
}

func TestSupersededAckCannotClearLatestOrRenewBudget(t *testing.T) {
	table := testTable(t)
	first := startEnabled(t, table, 1, protocol.Bulk, 0)
	publish(t, table, first, 0)
	latest, _, err := table.Update(1, protocol.Interactive, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	publish(t, table, latest, time.Second)
	before := snapshot(t, table, 1)
	result, err := table.Ack(1, first.Version, first.Class, 2*time.Second)
	if err != nil || !result.Progress || result.Installed {
		t.Fatalf("previous acknowledgement = %+v, %v", result, err)
	}
	after := snapshot(t, table, 1)
	if !after.Pending || after.Local != latest || after.Started != before.Started || after.Retries != before.Retries || after.Attempts != before.Attempts {
		t.Fatalf("older acknowledgement renewed or cleared latest: before=%+v after=%+v", before, after)
	}
	result, err = table.Ack(1, latest.Version, latest.Class, 2*time.Second)
	if err != nil || !result.Installed {
		t.Fatalf("latest acknowledgement = %+v, %v", result, err)
	}
	changed, _, err := table.Update(1, protocol.Normal, 3*time.Second)
	if err != nil || changed.Version != 3 {
		t.Fatalf("next episode update = %+v, %v", changed, err)
	}
	s := snapshot(t, table, 1)
	if s.Started != 3*time.Second || s.Retries != 0 || s.Attempts != 0 || !s.Pending {
		t.Fatalf("new acknowledged episode did not get new budget: %+v", s)
	}
}

func TestUpdateAndRebindCannotBypassRetryBudget(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxRetries = 2
	table, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	state := startEnabled(t, table, 1, protocol.Bulk, 0)
	publish(t, table, state, 0)
	state, _, err = table.Update(1, protocol.Interactive, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	publish(t, table, state, time.Second)
	table.RebindCarrier()
	publish(t, table, state, 2*time.Second)
	s := snapshot(t, table, 1)
	if s.Retries != 2 || s.Attempts != 3 || s.Started != 0 {
		t.Fatalf("rebind/update changed fixed pending budget: %+v", s)
	}
	state, _, err = table.Update(1, protocol.Normal, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	table.RebindCarrier()
	if _, err := table.Prepare(1, state.Version, state.Class, 2*time.Second); !errors.Is(err, ErrNotDue) {
		t.Fatalf("fresh version bypassed retry ceiling = %v", err)
	}
	ready, dead, err := table.Ready(s.NextSend, 1)
	if err != nil || len(ready) != 0 || len(dead) != 1 || dead[0] != 1 {
		t.Fatalf("retry exhaustion = %+v, %v, %v", ready, dead, err)
	}
	if _, err := table.Prepare(1, state.Version, state.Class, s.NextSend); !errors.Is(err, ErrExhausted) {
		t.Fatalf("exhausted retry = %v", err)
	}
}

func TestUpdatesAndLostReferencesPreserveNoProgressDeadline(t *testing.T) {
	table := testTable(t)
	first := startEnabled(t, table, 1, protocol.Normal, time.Second)
	publish(t, table, first, time.Second)
	latest, _, err := table.Update(1, protocol.Bulk, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := table.RequestRetry(1); err != nil {
		t.Fatal(err)
	}
	ready, _, err := table.Ready(20*time.Second, 1)
	if err != nil || len(ready) != 1 || ready[0] != latest {
		t.Fatalf("lost old reference did not resolve latest: %+v, %v", ready, err)
	}
	table.RebindCarrier()
	if err := table.Enable(1, 25*time.Second); err != nil {
		t.Fatal(err)
	}
	if s := snapshot(t, table, 1); s.Started != time.Second || s.Attempts != 1 || s.Retries != 0 {
		t.Fatalf("readiness/retry/rebind/gate reset budget: %+v", s)
	}
	ready, dead, err := table.Ready(31*time.Second, 1)
	if err != nil || len(ready) != 0 || len(dead) != 1 {
		t.Fatalf("deadline exhaustion = %+v, %v, %v", ready, dead, err)
	}
	if _, _, err := table.Update(1, protocol.Interactive, 31*time.Second); !errors.Is(err, ErrExhausted) {
		t.Fatalf("post-deadline update = %v", err)
	}
}

func TestWriteCompletionAcrossDeadlineRetainsProof(t *testing.T) {
	table := testTable(t)
	state := startEnabled(t, table, 1, protocol.Interactive, 0)
	p, err := table.Prepare(1, 1, protocol.Interactive, 29*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := table.Publish(p, 31*time.Second, 200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if got := snapshot(t, table, 1).Published; got != state {
		t.Fatalf("completed write lost evidence: %+v", got)
	}
	_, dead, err := table.Ready(31*time.Second, 1)
	if err != nil || len(dead) != 1 {
		t.Fatalf("completed expired write escaped deadline: %v, %v", dead, err)
	}
	if result, err := table.Ack(1, 1, protocol.Interactive, 31*time.Second); err != nil || !result.Installed {
		t.Fatalf("actual completed write acknowledgement = %+v, %v", result, err)
	}
}

func TestPeerMergeDoesNotChangeLocalDirection(t *testing.T) {
	table := testTable(t)
	local := startEnabled(t, table, 1, protocol.Bulk, 0)
	publish(t, table, local, 0)
	before := snapshot(t, table, 1)
	newer := State{Flow: 1, Version: 9, Class: protocol.Interactive}
	if result, err := table.MergePeer(newer); err != nil || !result.Updated {
		t.Fatalf("new peer view = %+v, %v", result, err)
	}
	if result, err := table.MergePeer(State{Flow: 1, Version: 2, Class: protocol.Bulk}); err != nil || !result.Ignored {
		t.Fatalf("older peer view = %+v, %v", result, err)
	}
	if result, err := table.MergePeer(newer); err != nil || !result.Duplicate {
		t.Fatalf("duplicate peer view = %+v, %v", result, err)
	}
	if _, err := table.MergePeer(State{Flow: 1, Version: 9, Class: protocol.Bulk}); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting peer view = %v", err)
	}
	after := snapshot(t, table, 1)
	if !after.Peer.Known || after.Peer.State != newer {
		t.Fatalf("peer view = %+v", after.Peer)
	}
	after.Peer = before.Peer
	if after != before {
		t.Fatalf("peer merge modified local direction: before=%+v after=%+v", before, after)
	}
}

func TestSnapshotDoesNotSynthesizeFutureAckAndStaleInputIsExact(t *testing.T) {
	table := testTable(t)
	startEnabled(t, table, 1, protocol.Normal, 0)
	if _, err := table.MergePeer(State{Flow: 1, Version: 10, Class: protocol.Interactive}); err != nil {
		t.Fatal(err)
	}
	if acks, err := table.ReadyAcks(1); err != nil || len(acks) != 0 {
		t.Fatalf("snapshot synthesized ACK: %+v, %v", acks, err)
	}
	old := State{Flow: 1, Version: 3, Class: protocol.Bulk}
	if result, err := table.MergePeer(old); err != nil || !result.Ignored {
		t.Fatalf("stale announcement merge = %+v, %v", result, err)
	}
	if err := table.QueueAck(old); err != nil {
		t.Fatal(err)
	}
	acks, err := table.ReadyAcks(1)
	if err != nil || len(acks) != 1 || acks[0] != old {
		t.Fatalf("stale announcement ACK substituted snapshot state: %+v, %v", acks, err)
	}
	// A failed carrier write leaves this exact slot; repeated queries coalesce.
	if acks, err := table.ReadyAcks(1); err != nil || len(acks) != 1 || acks[0] != old {
		t.Fatalf("failed ACK write consumed slot: %+v, %v", acks, err)
	}
	if err := table.AckSent(old); err != nil {
		t.Fatal(err)
	}
	if err := table.QueueAck(old); err != nil {
		t.Fatal(err)
	}
	if acks, err := table.ReadyAcks(1); err != nil || len(acks) != 1 || acks[0] != old {
		t.Fatalf("duplicate announcement did not re-ACK: %+v, %v", acks, err)
	}
}

func TestAckSlotCoalescesAndOldWriteCannotClearNewAck(t *testing.T) {
	table := testTable(t)
	startEnabled(t, table, 1, protocol.Normal, 0)
	old := State{Flow: 1, Version: 3, Class: protocol.Bulk}
	latest := State{Flow: 1, Version: 4, Class: protocol.Interactive}
	for _, state := range []State{old, latest, old, latest} {
		if _, err := table.MergePeer(state); err != nil {
			t.Fatal(err)
		}
		if err := table.QueueAck(state); err != nil {
			t.Fatal(err)
		}
	}
	if err := table.AckSent(old); !errors.Is(err, ErrStale) {
		t.Fatalf("old ACK write cleared current slot = %v", err)
	}
	if got, err := table.ReadyAcks(1); err != nil || len(got) != 1 || got[0] != latest {
		t.Fatalf("ACK coalescing = %+v, %v", got, err)
	}
	if err := table.QueueAck(State{Flow: 1, Version: 4, Class: protocol.Bulk}); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting ACK slot = %v", err)
	}
	if err := table.QueueAck(State{Flow: 1, Version: 5, Class: protocol.Normal}); !errors.Is(err, ErrState) {
		t.Fatalf("ACK without peer merge = %v", err)
	}
}

func TestPublicationHistoryBoundsExactClassProofAndHoles(t *testing.T) {
	table := testTable(t)
	state := startEnabled(t, table, 1, protocol.Normal, 0)
	for n := 0; n < PublishedHistory+4; n++ {
		at := time.Duration(n) * time.Millisecond
		publish(t, table, state, at)
		if result, err := table.Ack(1, state.Version, state.Class, at); err != nil || !result.Installed {
			t.Fatalf("iteration %d ACK = %+v, %v", n, result, err)
		}
		// Deliberately coalesce away one version to produce publication holes.
		_, _, err := table.Update(1, protocol.Class((uint8(state.Class)+1)%3), at)
		if err != nil {
			t.Fatal(err)
		}
		state, _, err = table.Update(1, protocol.Class((uint8(state.Class)+2)%3), at)
		if err != nil {
			t.Fatal(err)
		}
	}
	s := snapshot(t, table, 1)
	if s.RetiredThrough == 0 || table.entries[1].publicationCount != PublishedHistory {
		t.Fatalf("publication history not bounded: %+v", s)
	}
	if result, err := table.Ack(1, 1, protocol.Bulk, 30*time.Millisecond); err != nil || !result.Ignored || result.Progress || result.Installed {
		t.Fatalf("retired unprovable ACK was installed: %+v, %v", result, err)
	}
	last := s.Published
	if _, err := table.Ack(1, last.Version-1, last.Class, 30*time.Millisecond); !errors.Is(err, ErrAck) {
		t.Fatalf("retained publication hole = %v", err)
	}
	if _, err := table.Ack(1, last.Version, protocol.Class((uint8(last.Class)+1)%3), 30*time.Millisecond); !errors.Is(err, ErrAck) {
		t.Fatalf("retained same version different class = %v", err)
	}
}

func TestBoundedEntriesAndTerminalRemovalCannotAllocateFromPeer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxEntries = 1
	table, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	startEnabled(t, table, 1, protocol.Normal, 0)
	if _, err := table.Start(2, protocol.Bulk, 0); !errors.Is(err, ErrLimit) {
		t.Fatalf("entry overflow = %v", err)
	}
	peer := State{Flow: 1, Version: 1, Class: protocol.Bulk}
	if _, err := table.MergePeer(peer); err != nil {
		t.Fatal(err)
	}
	if err := table.QueueAck(peer); err != nil {
		t.Fatal(err)
	}
	table.Forget(1)
	if table.Usage() != 0 {
		t.Fatalf("forget kept metadata: %d", table.Usage())
	}
	if _, err := table.MergePeer(peer); !errors.Is(err, ErrUnknown) {
		t.Fatalf("terminal merge = %v", err)
	}
	if err := table.QueueAck(peer); !errors.Is(err, ErrUnknown) {
		t.Fatalf("terminal queued ACK = %v", err)
	}
	if _, _, err := table.Update(1, protocol.Interactive, 0); !errors.Is(err, ErrUnknown) {
		t.Fatalf("terminal local update = %v", err)
	}
	if err := table.RequestRetry(1); !errors.Is(err, ErrUnknown) {
		t.Fatalf("terminal lost reference = %v", err)
	}
	if _, err := table.Ack(1, 1, protocol.Normal, 0); !errors.Is(err, ErrUnknown) {
		t.Fatalf("terminal received ACK = %v", err)
	}
	table.RebindCarrier()
	ready, dead, err := table.Ready(0, 1)
	acks, ackErr := table.ReadyAcks(1)
	if err != nil || ackErr != nil || len(ready) != 0 || len(dead) != 0 || len(acks) != 0 || table.Usage() != 0 {
		t.Fatalf("terminal state reappeared: ready=%v dead=%v acks=%v usage=%d errors=%v,%v", ready, dead, acks, table.Usage(), err, ackErr)
	}
	// The owner can allocate a different durable flow identity after removal.
	if _, err := table.Start(2, protocol.Interactive, 0); err != nil {
		t.Fatal(err)
	}
}

func TestVersionOverflowDoesNotWrap(t *testing.T) {
	table := testTable(t)
	startEnabled(t, table, 1, protocol.Bulk, 0)
	table.entries[1].local.Version = math.MaxUint64
	before := snapshot(t, table, 1)
	if _, changed, err := table.Update(1, protocol.Interactive, 0); !errors.Is(err, ErrVersion) || changed {
		t.Fatalf("version overflow = %v, %v", changed, err)
	}
	if after := snapshot(t, table, 1); after != before {
		t.Fatalf("version overflow mutated state: before=%+v after=%+v", before, after)
	}
	if _, changed, err := table.Update(1, protocol.Bulk, 0); err != nil || changed {
		t.Fatalf("no-op at maximum version = %v, %v", changed, err)
	}
}

func TestOwnerTimeValidationAndStalePublicationTokens(t *testing.T) {
	table := testTable(t)
	state := startEnabled(t, table, 1, protocol.Bulk, time.Second)
	p, err := table.Prepare(1, 1, protocol.Bulk, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := table.Ready(0, 1); !errors.Is(err, ErrTime) {
		t.Fatalf("backward query time = %v", err)
	}
	latest, _, err := table.Update(1, protocol.Interactive, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := table.Publish(p, 2*time.Second, 200*time.Millisecond); !errors.Is(err, ErrStale) {
		t.Fatalf("superseded token = %v", err)
	}
	if _, err := table.Prepare(1, state.Version, state.Class, 2*time.Second); !errors.Is(err, ErrStale) {
		t.Fatalf("old reference exact prepare = %v", err)
	}
	p, err = table.Prepare(1, latest.Version, latest.Class, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	table.RebindCarrier()
	if err := table.Publish(p, 2*time.Second, 200*time.Millisecond); !errors.Is(err, ErrStale) {
		t.Fatalf("previous carrier token already marked for resend = %v", err)
	}
	p, err = table.Prepare(1, latest.Version, latest.Class, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	table.Forget(1)
	if err := table.Publish(p, 2*time.Second, 200*time.Millisecond); !errors.Is(err, ErrStale) {
		t.Fatalf("terminal token = %v", err)
	}
}

func TestInvalidBudgetsAndInputDoNotAllocate(t *testing.T) {
	for _, cfg := range []Config{
		{}, {MaxEntries: MaxEntries + 1, MaxRetries: 8, NoProgress: time.Second},
		{MaxEntries: 1, MaxRetries: 9, NoProgress: time.Second},
		{MaxEntries: 1, MaxRetries: 8, NoProgress: 31 * time.Second},
	} {
		if _, err := New(cfg); !errors.Is(err, ErrConfig) {
			t.Fatalf("invalid config %+v = %v", cfg, err)
		}
	}
	table := testTable(t)
	for _, state := range []State{
		{Flow: 0, Version: 1, Class: protocol.Normal},
		{Flow: 1, Version: 0, Class: protocol.Normal},
		{Flow: 1, Version: 1, Class: protocol.Class(3)},
	} {
		if _, err := table.MergePeer(state); !errors.Is(err, ErrState) {
			t.Fatalf("invalid peer state %+v = %v", state, err)
		}
		if err := table.QueueAck(state); !errors.Is(err, ErrState) {
			t.Fatalf("invalid ACK state %+v = %v", state, err)
		}
	}
	if table.Usage() != 0 {
		t.Fatalf("invalid input allocated %d entries", table.Usage())
	}
}
