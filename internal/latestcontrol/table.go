// Package latestcontrol owns bounded, coalesced local TX control state.
// It does no I/O and reads no clock. The Session owner authenticates receipt
// frames, applies peer state before issuing receipts, and serializes all calls.
package latestcontrol

import (
	"bytes"
	"errors"
	"math"
	"sort"
	"time"

	"bfp/protocol"
)

const PublishedHistory = 16

var (
	ErrConfig    = errors.New("latestcontrol: invalid budget")
	ErrState     = errors.New("latestcontrol: invalid control state")
	ErrLimit     = errors.New("latestcontrol: metadata budget exhausted")
	ErrTime      = errors.New("latestcontrol: invalid monotonic time")
	ErrUnknown   = errors.New("latestcontrol: unknown control key")
	ErrStale     = errors.New("latestcontrol: stale send snapshot")
	ErrReceipt   = errors.New("latestcontrol: receipt for unpublished state")
	ErrExhausted = errors.New("latestcontrol: retry or no-progress budget exhausted")
	ErrNotDue    = errors.New("latestcontrol: retry is not due")
)

// Key describes this endpoint's sending direction. A separate receive-side
// application table is required; peer announcements are never local TX policy.
type Key struct {
	Kind protocol.Kind
	Flow uint64
}

// State is semantic, unencrypted control data. Value is receiveNext or an
// absolute credit; OpenResult uses Data and requires Value=0. Revision is local.
type State struct {
	Key      Key
	Revision uint64
	Value    uint64
	Data     []byte
}

type Config struct {
	MaxKeys        int
	MaxBytes       int
	MaxResultBytes int
	MaxRetries     uint8
	NoProgress     time.Duration
}

func DefaultConfig() Config {
	return Config{MaxKeys: 1024, MaxBytes: 64 << 10, MaxResultBytes: 4096,
		MaxRetries: 8, NoProgress: 30 * time.Second}
}

type entry struct {
	state                                State
	confirmed, published, retiredThrough uint64
	publication                          [PublishedHistory]uint64
	publicationCount, publicationNext    int
	pending                              bool
	started, lastSent, nextSend          time.Duration
	retries                              uint8
	currentSent                          bool
	resend                               bool
}

type Table struct {
	cfg      Config
	entries  map[Key]*entry
	bytes    int
	lastTime time.Duration
}

type Snapshot struct {
	State                                State
	Confirmed, Published, RetiredThrough uint64
	Pending                              bool
	Started, LastSent, NextSend          time.Duration
	Retries                              uint8
}

func New(cfg Config) (*Table, error) {
	if cfg.MaxKeys < 1 || cfg.MaxKeys > 16384 || cfg.MaxBytes < 1 ||
		cfg.MaxBytes > 64<<20 || cfg.MaxResultBytes < 1 ||
		cfg.MaxResultBytes > cfg.MaxBytes || cfg.MaxRetries < 1 ||
		cfg.NoProgress <= 0 || cfg.NoProgress > time.Hour {
		return nil, ErrConfig
	}
	return &Table{cfg: cfg, entries: make(map[Key]*entry)}, nil
}

func validKey(k Key) bool {
	switch k.Kind {
	case protocol.StreamAck, protocol.MaxFlowData, protocol.OpenResult:
		return k.Flow != 0
	case protocol.MaxSessionData:
		return k.Flow == 0
	default:
		return false
	}
}

func copyState(s State) State { s.Data = append([]byte(nil), s.Data...); return s }
func (t *Table) checkTime(now time.Duration) error {
	if now < 0 || now < t.lastTime {
		return ErrTime
	}
	return nil
}

// Update coalesces a semantic latest value. It never renews an outstanding
// no-progress deadline or resets retries merely because the value changed.
// Equal values are no-ops; OpenResult is immutable after its initial result.
func (t *Table) Update(k Key, value uint64, data []byte, now time.Duration) (State, bool, error) {
	if !validKey(k) || k.Kind != protocol.OpenResult && len(data) != 0 ||
		k.Kind == protocol.OpenResult && (value != 0 || len(data) == 0 || len(data) > t.cfg.MaxResultBytes) {
		return State{}, false, ErrState
	}
	if err := t.checkTime(now); err != nil {
		return State{}, false, err
	}
	e := t.entries[k]
	if e == nil {
		if len(t.entries) >= t.cfg.MaxKeys || len(data) > t.cfg.MaxBytes-t.bytes {
			return State{}, false, ErrLimit
		}
		e = &entry{state: State{Key: k, Revision: 1, Value: value, Data: append([]byte(nil), data...)},
			pending: true, started: now}
		t.entries[k] = e
		t.bytes += len(data)
		t.lastTime = now
		return copyState(e.state), true, nil
	}
	if value == e.state.Value && bytes.Equal(data, e.state.Data) {
		t.lastTime = now
		return copyState(e.state), false, nil
	}
	if k.Kind == protocol.OpenResult || value < e.state.Value {
		return State{}, false, ErrState
	}
	if e.state.Revision == math.MaxUint64 {
		return State{}, false, ErrLimit
	}
	if !e.pending {
		e.started, e.retries = now, 0
	}
	e.state.Revision++
	e.state.Value = value
	e.pending, e.currentSent = true, false
	t.lastTime = now
	return copyState(e.state), true, nil
}

func (t *Table) Snapshot(k Key) (Snapshot, error) {
	e := t.entries[k]
	if e == nil {
		return Snapshot{}, ErrUnknown
	}
	return Snapshot{State: copyState(e.state), Confirmed: e.confirmed, Published: e.published,
		RetiredThrough: e.retiredThrough, Pending: e.pending, Started: e.started,
		LastSent: e.lastSent, NextSend: e.nextSend, Retries: e.retries}, nil
}

func (t *Table) exhausted(e *entry, now time.Duration) bool {
	return now-e.started >= t.cfg.NoProgress || e.retries >= t.cfg.MaxRetries && now >= e.nextSend
}

// Ready returns at most limit latest snapshots, plus exhausted keys. Queries
// do not publish a revision, consume a retry or mutate a no-progress deadline.
// The owner must apply independent control/wire/CPU send budgets.
func (t *Table) Ready(now time.Duration, limit int) ([]State, []Key, error) {
	if err := t.checkTime(now); err != nil {
		return nil, nil, err
	}
	if limit < 0 || limit > t.cfg.MaxKeys {
		return nil, nil, ErrLimit
	}
	keys := make([]Key, 0, len(t.entries))
	for k, e := range t.entries {
		if e.pending {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Kind != keys[j].Kind {
			return keys[i].Kind < keys[j].Kind
		}
		return keys[i].Flow < keys[j].Flow
	})
	var ready []State
	var exhausted []Key
	for _, k := range keys {
		e := t.entries[k]
		if t.exhausted(e, now) {
			exhausted = append(exhausted, k)
			continue
		}
		if e.retries < t.cfg.MaxRetries && len(ready) < limit && (!e.currentSent || e.resend || now >= e.nextSend) {
			ready = append(ready, copyState(e.state))
		}
	}
	return ready, exhausted, nil
}

func cappedInterval(base time.Duration, retries uint8) time.Duration {
	base = max(200*time.Millisecond, min(base, 2*time.Second))
	if retries >= 6 || base > (8*time.Second>>retries) {
		return 8 * time.Second
	}
	return min(base<<retries, 8*time.Second)
}

func addDuration(a, b time.Duration) time.Duration {
	if a > time.Duration(math.MaxInt64)-b {
		return time.Duration(math.MaxInt64)
	}
	return a + b
}

// Publication is an opaque preflight result. It can be committed once, after
// a successful full carrier write. Failed I/O discards it without mutation.
type Publication struct {
	table                          *Table
	entry                          *entry
	revision, published, confirmed uint64
	retries                        uint8
	checkedAt, started             time.Duration
	currentSent, resend, consumed  bool
}

// Prepare must precede carrier I/O. The immutable revision snapshot must be
// encoded from the same State, with no intervening owner mutation.
func (t *Table) Prepare(k Key, revision uint64, now time.Duration) (*Publication, error) {
	if err := t.checkTime(now); err != nil {
		return nil, err
	}
	e := t.entries[k]
	if e == nil {
		return nil, ErrUnknown
	}
	if revision != e.state.Revision || !e.pending {
		return nil, ErrStale
	}
	if t.exhausted(e, now) {
		return nil, ErrExhausted
	}
	if e.retries >= t.cfg.MaxRetries || e.currentSent && !e.resend && now < e.nextSend {
		return nil, ErrNotDue
	}
	return &Publication{table: t, entry: e, revision: revision, published: e.published,
		confirmed: e.confirmed, retries: e.retries, checkedAt: now, started: e.started,
		currentSent: e.currentSent, resend: e.resend}, nil
}

// Publish records actual successful I/O, even if that write completed after
// the no-progress deadline. A subsequent Ready reports exhaustion. Dropping
// evidence for a write that crossed the deadline would misclassify receipts.
func (t *Table) Publish(p *Publication, now, base time.Duration) error {
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
	if t.entries[e.state.Key] != e || !e.pending || e.state.Revision != p.revision ||
		e.published != p.published || e.confirmed != p.confirmed || e.retries != p.retries ||
		e.started != p.started || e.currentSent != p.currentSent || e.resend != p.resend {
		return ErrStale
	}
	revision := p.revision
	if e.currentSent {
		e.retries++
	}
	if revision > e.published {
		if e.publicationCount == PublishedHistory {
			e.retiredThrough = e.publication[e.publicationNext]
		} else {
			e.publicationCount++
		}
		e.publication[e.publicationNext] = revision
		e.publicationNext = (e.publicationNext + 1) % PublishedHistory
		e.published = revision
	}
	e.currentSent, e.resend = true, false
	e.lastSent, e.nextSend = now, addDuration(now, cappedInterval(base, e.retries))
	t.lastTime = now
	p.consumed = true
	return nil
}

type ReceiptResult struct{ Progress, Installed, Ignored bool }

// Receipt confirms a revision that was actually published. Forgotten old
// receipts are harmless and cannot clear current pending state. A hole among
// retained revisions or a future receipt is an authenticated protocol error.
func (t *Table) Receipt(k Key, revision uint64, now time.Duration) (ReceiptResult, error) {
	if err := t.checkTime(now); err != nil {
		return ReceiptResult{}, err
	}
	e := t.entries[k]
	if e == nil {
		return ReceiptResult{}, ErrUnknown
	}
	if revision == 0 || revision > e.published {
		return ReceiptResult{}, ErrReceipt
	}
	if revision <= e.confirmed || revision <= e.retiredThrough {
		return ReceiptResult{Ignored: true}, nil
	}
	known := false
	for _, r := range e.publication {
		if r == revision {
			known = true
			break
		}
	}
	if !known {
		return ReceiptResult{}, ErrReceipt
	}
	e.confirmed = revision
	e.retries = 0
	e.started = now // Genuine installation progress may start a new no-progress interval.
	installed := revision == e.state.Revision
	if installed {
		e.pending = false
	}
	t.lastTime = now
	return ReceiptResult{Progress: true, Installed: installed}, nil
}

// RebindCarrier preserves semantic revision, publication evidence and original
// no-progress lifetime. Pending state becomes immediately eligible to send on
// the new authenticated carrier. The Session rejects stale-carrier receipts.
func (t *Table) RebindCarrier() {
	for _, e := range t.entries {
		if e.pending {
			e.resend = true
		}
	}
}

// Forget requires local lifecycle authorization. The owner must keep terminal
// operation tombstones until duplicate peer commands no longer need a result.
func (t *Table) Forget(k Key) {
	if e := t.entries[k]; e != nil {
		t.bytes -= len(e.state.Data)
		delete(t.entries, k)
	}
}

func (t *Table) Usage() (keys, payloadBytes int) { return len(t.entries), t.bytes }
