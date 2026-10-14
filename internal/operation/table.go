// Package operation owns the lifetime of one logical protocol operation.
//
// The table is deliberately owner-confined: it has no goroutines, I/O, or
// wall-clock reads.  A Session actor supplies a monotonic time value and calls
// Publish only after a complete authenticated carrier write.  A carrier
// change can therefore make an outstanding operation immediately eligible
// without renewing its no-progress lifetime.
package operation

import (
	"errors"
	"math"
	"sort"
	"time"

	"bfp/protocol"
)

var (
	ErrConfig        = errors.New("operation: invalid budget")
	ErrTime          = errors.New("operation: non-monotonic time")
	ErrLimit         = errors.New("operation: operation budget exhausted")
	ErrDuplicate     = errors.New("operation: immutable key already exists")
	ErrUnknown       = errors.New("operation: unknown key")
	ErrStale         = errors.New("operation: stale publication")
	ErrNotDue        = errors.New("operation: retry is not due")
	ErrExhausted     = errors.New("operation: retry or no-progress budget exhausted")
	ErrCompleted     = errors.New("operation: already completed")
	ErrAckBeforeSend = errors.New("operation: acknowledgement before publication")
)

// Key is the immutable identity of a logical operation.  Serial carries a
// final offset, key epoch, ticket serial, or other operation-specific value;
// Epoch is reserved for operations whose identity includes both a serial and
// a transport epoch.  Flags separates a request from its recovery snapshot
// acknowledgement without making the carrier generation part of identity.
type Key struct {
	Kind   protocol.Kind
	Flags  uint8
	Flow   uint64
	Serial uint64
	Epoch  uint32
}

// Config bounds both attempts and the time spent without a terminal receipt.
type Config struct {
	MaxOperations int
	MaxRetries    uint8
	NoProgress    time.Duration
	BaseRetry     time.Duration
	MaxRetry      time.Duration
}

func DefaultConfig() Config {
	return Config{MaxOperations: 8192, MaxRetries: 8, NoProgress: 30 * time.Second,
		BaseRetry: 200 * time.Millisecond, MaxRetry: 8 * time.Second}
}

// State is a read-only copy of an operation's owner state.  Attempts counts
// successful carrier publications; Retries counts publications after the
// first.  Failed and Completed are terminal and never become pending again.
type State struct {
	Key        Key
	Started    time.Duration
	LastSent   time.Duration
	NextSend   time.Duration
	Attempts   uint8
	Retries    uint8
	Pending    bool
	Resend     bool
	Completed  bool
	Failed     bool
	CarrierGen uint64
}

type entry struct {
	state State
	// sent is distinct from Attempts: an operation may be queued before the
	// first complete carrier write and must still be eligible immediately.
	sent bool
}

type Table struct {
	cfg      Config
	entries  map[Key]*entry
	lastTime time.Duration
}

type Snapshot = State

func New(cfg Config) (*Table, error) {
	if cfg.MaxOperations < 1 || cfg.MaxOperations > 1<<20 || cfg.MaxRetries < 1 ||
		cfg.NoProgress <= 0 || cfg.NoProgress > 24*time.Hour ||
		cfg.BaseRetry <= 0 || cfg.MaxRetry < cfg.BaseRetry || cfg.MaxRetry > 24*time.Hour {
		return nil, ErrConfig
	}
	return &Table{cfg: cfg, entries: make(map[Key]*entry)}, nil
}

func (t *Table) checkTime(now time.Duration) error {
	if now < 0 || now < t.lastTime {
		return ErrTime
	}
	return nil
}

func copyState(s State) State { return s }

// Start creates an operation.  Keys are never reused, including after a
// terminal result; flow ids and operation serials therefore remain a durable
// anti-confusion boundary across carrier changes.
func (t *Table) Start(k Key, now time.Duration) (State, error) {
	if err := t.checkTime(now); err != nil {
		return State{}, err
	}
	if k.Kind == 0 {
		return State{}, ErrUnknown
	}
	if _, ok := t.entries[k]; ok {
		return State{}, ErrDuplicate
	}
	if len(t.entries) >= t.cfg.MaxOperations {
		return State{}, ErrLimit
	}
	e := &entry{state: State{Key: k, Started: now, Pending: true}}
	t.entries[k] = e
	t.lastTime = now
	return copyState(e.state), nil
}

// Ensure is idempotent for retransmission scheduling.  It returns created so
// callers can distinguish the first logical request from a duplicate enqueue.
func (t *Table) Ensure(k Key, now time.Duration) (state State, created bool, err error) {
	if err = t.checkTime(now); err != nil {
		return State{}, false, err
	}
	if e := t.entries[k]; e != nil {
		t.lastTime = now
		return copyState(e.state), false, nil
	}
	state, err = t.Start(k, now)
	return state, err == nil, err
}

func (t *Table) Snapshot(k Key) (State, error) {
	e := t.entries[k]
	if e == nil {
		return State{}, ErrUnknown
	}
	return copyState(e.state), nil
}

func (t *Table) Has(k Key) bool { _, ok := t.entries[k]; return ok }

func (t *Table) exhausted(e *entry, now time.Duration) bool {
	return now-e.state.Started >= t.cfg.NoProgress || e.state.Retries >= t.cfg.MaxRetries && e.sent && now >= e.state.NextSend
}

// Ready returns operations that may be prepared now and operations whose
// bounded lifetime is exhausted.  It never consumes an attempt.
func (t *Table) Ready(now time.Duration, limit int) ([]State, []Key, error) {
	if err := t.checkTime(now); err != nil {
		return nil, nil, err
	}
	if limit < 0 || limit > t.cfg.MaxOperations {
		return nil, nil, ErrLimit
	}
	keys := make([]Key, 0, len(t.entries))
	for k := range t.entries {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Flow != b.Flow {
			return a.Flow < b.Flow
		}
		if a.Serial != b.Serial {
			return a.Serial < b.Serial
		}
		if a.Epoch != b.Epoch {
			return a.Epoch < b.Epoch
		}
		return a.Flags < b.Flags
	})
	ready := make([]State, 0, min(limit, len(keys)))
	dead := make([]Key, 0)
	for _, k := range keys {
		e := t.entries[k]
		if e.state.Completed || e.state.Failed {
			continue
		}
		if t.exhausted(e, now) {
			dead = append(dead, k)
			continue
		}
		if len(ready) >= limit {
			continue
		}
		if !e.sent || e.state.Resend || now >= e.state.NextSend {
			ready = append(ready, copyState(e.state))
		}
	}
	t.lastTime = now
	return ready, dead, nil
}

func retryDelay(cfg Config, retries uint8) time.Duration {
	shift := retries
	if shift > 30 {
		shift = 30
	}
	d := cfg.BaseRetry
	if d > time.Duration(math.MaxInt64>>shift) {
		d = time.Duration(math.MaxInt64)
	} else {
		d <<= shift
	}
	if d > cfg.MaxRetry {
		d = cfg.MaxRetry
	}
	return d
}

// Publication is an immutable preflight token.  Only a successful complete
// carrier write may consume it through Publish.
type Publication struct {
	table     *Table
	entry     *entry
	state     State
	checkedAt time.Duration
	consumed  bool
}

func (t *Table) Prepare(k Key, now time.Duration) (*Publication, error) {
	if err := t.checkTime(now); err != nil {
		return nil, err
	}
	e := t.entries[k]
	if e == nil {
		return nil, ErrUnknown
	}
	if e.state.Completed {
		return nil, ErrCompleted
	}
	if e.state.Failed {
		return nil, ErrExhausted
	}
	if t.exhausted(e, now) {
		return nil, ErrExhausted
	}
	if e.sent && !e.state.Resend && now < e.state.NextSend {
		return nil, ErrNotDue
	}
	return &Publication{table: t, entry: e, state: e.state, checkedAt: now}, nil
}

func (t *Table) Publish(p *Publication, now time.Duration, carrierGen uint64) error {
	if p == nil || p.table != t || p.consumed {
		return ErrStale
	}
	if err := t.checkTime(now); err != nil {
		return err
	}
	if now < p.checkedAt {
		return ErrTime
	}
	e := p.entry
	if t.entries[e.state.Key] != e || e.state != p.state {
		return ErrStale
	}
	if e.sent {
		if e.state.Retries == math.MaxUint8 {
			return ErrLimit
		}
		e.state.Retries++
	}
	if e.state.Attempts == math.MaxUint8 {
		return ErrLimit
	}
	e.state.Attempts++
	e.state.Pending = true
	e.state.Resend = false
	e.state.CarrierGen = carrierGen
	e.state.LastSent = now
	e.state.NextSend = now + retryDelay(t.cfg, e.state.Retries)
	e.sent = true
	t.lastTime = now
	p.consumed = true
	return nil
}

type AckResult struct {
	Progress  bool
	Completed bool
	Ignored   bool
}

// Ack completes exactly the immutable key that was published.  A duplicate
// acknowledgement after completion is harmless; an acknowledgement for an
// operation that has never reached the wire is rejected.
func (t *Table) Ack(k Key, now time.Duration) (AckResult, error) {
	if err := t.checkTime(now); err != nil {
		return AckResult{}, err
	}
	e := t.entries[k]
	if e == nil {
		return AckResult{}, ErrUnknown
	}
	if e.state.Completed {
		t.lastTime = now
		return AckResult{Ignored: true}, nil
	}
	if e.state.Failed {
		return AckResult{}, ErrExhausted
	}
	if !e.sent {
		return AckResult{}, ErrAckBeforeSend
	}
	e.state.Pending = false
	e.state.Resend = false
	e.state.Completed = true
	t.lastTime = now
	return AckResult{Progress: true, Completed: true}, nil
}

// Fail is an explicit terminal failure.  It is used when a flow or Session
// decides that exhaustion cannot be recovered by a new carrier.
func (t *Table) Fail(k Key, now time.Duration) error {
	if err := t.checkTime(now); err != nil {
		return err
	}
	e := t.entries[k]
	if e == nil {
		return ErrUnknown
	}
	if e.state.Completed {
		return ErrCompleted
	}
	e.state.Pending = false
	e.state.Resend = false
	e.state.Failed = true
	t.lastTime = now
	return nil
}

// RebindCarrier makes pending operations eligible on the new authenticated
// carrier immediately, preserving Started and therefore the original lifetime
// budget.  It does not create an attempt and does not revive terminal state.
func (t *Table) RebindCarrier(carrierGen uint64) {
	for _, e := range t.entries {
		if e.state.Pending && !e.state.Completed && !e.state.Failed {
			e.state.Resend = true
		}
	}
}

func (t *Table) Forget(k Key) { delete(t.entries, k) }

// ForgetWhere removes operations that have been superseded by a newer
// protocol generation.  The table is owner-confined, so the predicate may
// inspect the immutable key and its last state without additional locking.
// Forgetting is intentionally different from Fail: a carrier-bound
// operation that can no longer be represented on the new carrier must not
// consume the Session's no-progress budget or turn into a false Session
// failure later.
func (t *Table) ForgetWhere(predicate func(Key, State) bool) int {
	if predicate == nil {
		return 0
	}
	removed := 0
	for k, e := range t.entries {
		if e != nil && predicate(k, copyState(e.state)) {
			delete(t.entries, k)
			removed++
		}
	}
	return removed
}

func (t *Table) Usage() int { return len(t.entries) }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
