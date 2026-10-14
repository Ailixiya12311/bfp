// Package classcontrol owns bounded local TX announcements and peer TX views.
// It has no I/O, goroutines, or clock reads. The Session actor serializes calls,
// authenticates inputs, and supplies elapsed monotonic time. Class values may
// decrease; only the version is monotonic. Peer views never select local policy.
package classcontrol

import (
	"errors"
	"math"
	"sort"
	"time"

	"bfp/protocol"
)

const (
	MaxEntries       = 4096
	PublishedHistory = 16
)

var (
	ErrConfig    = errors.New("classcontrol: invalid budget")
	ErrState     = errors.New("classcontrol: invalid class state")
	ErrLimit     = errors.New("classcontrol: metadata budget exhausted")
	ErrTime      = errors.New("classcontrol: non-monotonic time")
	ErrUnknown   = errors.New("classcontrol: unknown flow")
	ErrDuplicate = errors.New("classcontrol: flow already registered")
	ErrVersion   = errors.New("classcontrol: TX version exhausted")
	ErrStale     = errors.New("classcontrol: stale publication")
	ErrAck       = errors.New("classcontrol: acknowledgement for unpublished state")
	ErrConflict  = errors.New("classcontrol: peer version has conflicting classes")
	ErrNotDue    = errors.New("classcontrol: announcement is gated or not due")
	ErrExhausted = errors.New("classcontrol: retry or no-progress budget exhausted")
)

// State describes one endpoint's TX direction. Version zero is never valid on
// the wire. Published/Acked snapshots use zero only to indicate no known state.
type State struct {
	Flow    uint64
	Version uint64
	Class   protocol.Class
}

func (s State) Valid() bool { return s.Flow != 0 && s.Version != 0 && s.Class.Valid() }

type PeerView struct {
	Known bool
	State State
}

type Config struct {
	MaxEntries int
	MaxRetries uint8
	NoProgress time.Duration
}

func DefaultConfig() Config {
	return Config{MaxEntries: MaxEntries, MaxRetries: 8, NoProgress: 30 * time.Second}
}

type entry struct {
	local, published, acked State
	peer                    PeerView
	ack                     State
	ackPending              bool
	publication             [PublishedHistory]State
	publicationCount        int
	publicationNext         int
	retiredThrough          uint64
	enabled, pending        bool
	started, lastSent       time.Duration
	nextSend                time.Duration
	attempts                uint8
	retries                 uint8
	resend                  bool
	mutation                uint64
}

// Table is owner-confined. Start is a local lifecycle operation, never an
// allocation path for a received announcement, acknowledgement, or snapshot.
type Table struct {
	cfg      Config
	entries  map[uint64]*entry
	lastTime time.Duration
}

type Snapshot struct {
	Local, Published, Acked     State
	Peer                        PeerView
	Pending, Enabled            bool
	Started, LastSent, NextSend time.Duration
	Attempts, Retries           uint8
	RetiredThrough              uint64
	Ack                         State
	AckPending                  bool
}

func New(cfg Config) (*Table, error) {
	if cfg.MaxEntries < 1 || cfg.MaxEntries > MaxEntries || cfg.MaxRetries < 1 ||
		cfg.MaxRetries > 8 || cfg.NoProgress <= 0 || cfg.NoProgress > 30*time.Second {
		return nil, ErrConfig
	}
	return &Table{cfg: cfg, entries: make(map[uint64]*entry)}, nil
}

func (t *Table) checkTime(now time.Duration) error {
	if now < 0 || now < t.lastTime {
		return ErrTime
	}
	return nil
}

// Start records initial version 1, with sending gated until Enable. Class
// changes before successful OPEN installation still receive versions, but the
// announcement lifetime begins only when the owner opens that gate. The owner
// must never reuse a flow ID, including after Forget and terminal tombstoning.
func (t *Table) Start(flow uint64, class protocol.Class, now time.Duration) (State, error) {
	if flow == 0 || !class.Valid() {
		return State{}, ErrState
	}
	if err := t.checkTime(now); err != nil {
		return State{}, err
	}
	if t.entries[flow] != nil {
		return State{}, ErrDuplicate
	}
	if len(t.entries) >= t.cfg.MaxEntries {
		return State{}, ErrLimit
	}
	e := &entry{local: State{Flow: flow, Version: 1, Class: class}, pending: true}
	t.entries[flow] = e
	t.lastTime = now
	return e.local, nil
}

// Enable is idempotent. The Session calls it only after proving successful OPEN
// installation. Repeated calls cannot renew an outstanding lifetime.
func (t *Table) Enable(flow uint64, now time.Duration) error {
	if err := t.checkTime(now); err != nil {
		return err
	}
	e := t.entries[flow]
	if e == nil {
		return ErrUnknown
	}
	if !e.enabled {
		e.enabled, e.started = true, now
		e.mutation++
	}
	t.lastTime = now
	return nil
}

// Update increments the version only for an actual local class change. An
// outstanding pending episode keeps its original lifetime and all consumed
// retries, even if the replacement has never been sent. A new episode starts
// only after the previous latest state was exactly acknowledged.
func (t *Table) Update(flow uint64, class protocol.Class, now time.Duration) (State, bool, error) {
	if !class.Valid() {
		return State{}, false, ErrState
	}
	if err := t.checkTime(now); err != nil {
		return State{}, false, err
	}
	e := t.entries[flow]
	if e == nil {
		return State{}, false, ErrUnknown
	}
	if class == e.local.Class {
		t.lastTime = now
		return e.local, false, nil
	}
	if e.local.Version == math.MaxUint64 {
		return State{}, false, ErrVersion
	}
	if e.pending && e.enabled && t.exhausted(e, now) {
		return State{}, false, ErrExhausted
	}
	if !e.pending {
		e.started, e.attempts, e.retries = now, 0, 0
	}
	e.local.Version++
	e.local.Class = class
	e.pending, e.resend = true, true
	e.mutation++
	t.lastTime = now
	return e.local, true, nil
}

func (t *Table) Snapshot(flow uint64) (Snapshot, error) {
	e := t.entries[flow]
	if e == nil {
		return Snapshot{}, ErrUnknown
	}
	return Snapshot{Local: e.local, Published: e.published, Acked: e.acked,
		Peer: e.peer, Pending: e.pending, Enabled: e.enabled, Started: e.started,
		LastSent: e.lastSent, NextSend: e.nextSend, Attempts: e.attempts,
		Retries: e.retries, RetiredThrough: e.retiredThrough,
		Ack: e.ack, AckPending: e.ackPending}, nil
}

func (t *Table) exhausted(e *entry, now time.Duration) bool {
	return now-e.started >= t.cfg.NoProgress ||
		e.attempts != 0 && e.retries >= t.cfg.MaxRetries && now >= e.nextSend
}

func (t *Table) due(e *entry, now time.Duration) bool {
	return e.attempts == 0 || e.resend || now >= e.nextSend
}

func (t *Table) orderedFlows() []uint64 {
	flows := make([]uint64, 0, len(t.entries))
	for flow := range t.entries {
		flows = append(flows, flow)
	}
	sort.Slice(flows, func(i, j int) bool { return flows[i] < flows[j] })
	return flows
}

// Ready returns bounded latest snapshots and all exhausted pending flows.
// Queries consume no attempts or publication evidence. The owner shares these
// frames with the existing finite control, record, pacer, cwnd and CPU budgets.
func (t *Table) Ready(now time.Duration, limit int) ([]State, []uint64, error) {
	if err := t.checkTime(now); err != nil {
		return nil, nil, err
	}
	if limit < 0 || limit > t.cfg.MaxEntries {
		return nil, nil, ErrLimit
	}
	ready := make([]State, 0, min(limit, len(t.entries)))
	var exhausted []uint64
	for _, flow := range t.orderedFlows() {
		e := t.entries[flow]
		if !e.enabled || !e.pending {
			continue
		}
		if t.exhausted(e, now) {
			exhausted = append(exhausted, flow)
			continue
		}
		if len(ready) < limit && t.due(e, now) && (e.attempts == 0 || e.retries < t.cfg.MaxRetries) {
			ready = append(ready, e.local)
		}
	}
	t.lastTime = now
	return ready, exhausted, nil
}

// Publication is an opaque preflight token. Abandon it after partial or failed
// I/O. Only a complete authenticated carrier write may consume it via Publish.
type Publication struct {
	table     *Table
	entry     *entry
	state     State
	mutation  uint64
	checkedAt time.Duration
	consumed  bool
}

func (p *Publication) State() State {
	if p == nil {
		return State{}
	}
	return p.state
}

// Prepare requires the exact current version and class that will be encoded.
// No intervening TX mutation is allowed between preparation and completion.
func (t *Table) Prepare(flow, version uint64, class protocol.Class, now time.Duration) (*Publication, error) {
	if version == 0 || !class.Valid() {
		return nil, ErrState
	}
	if err := t.checkTime(now); err != nil {
		return nil, err
	}
	e := t.entries[flow]
	if e == nil {
		return nil, ErrUnknown
	}
	if version != e.local.Version || class != e.local.Class || !e.pending {
		return nil, ErrStale
	}
	if !e.enabled {
		return nil, ErrNotDue
	}
	if t.exhausted(e, now) {
		return nil, ErrExhausted
	}
	if !t.due(e, now) || e.attempts != 0 && e.retries >= t.cfg.MaxRetries {
		return nil, ErrNotDue
	}
	t.lastTime = now
	return &Publication{table: t, entry: e, state: e.local,
		mutation: e.mutation, checkedAt: now}, nil
}

func cappedInterval(base time.Duration, retries uint8) time.Duration {
	base = max(200*time.Millisecond, min(base, 2*time.Second))
	if retries >= 6 || base > 8*time.Second>>retries {
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

// Publish preserves evidence for a successful write even if completion crosses
// its no-progress deadline. The next Ready reports exhaustion. Every additional
// successful send in the pending episode consumes a retry, including a send of
// a newly superseding version and an immediate send after carrier replacement.
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
	if t.entries[p.state.Flow] != e || e.local != p.state || e.mutation != p.mutation ||
		!e.pending || !e.enabled {
		return ErrStale
	}
	if e.attempts != 0 {
		e.retries++
	}
	e.attempts++
	if p.state.Version > e.published.Version {
		if e.publicationCount == PublishedHistory {
			e.retiredThrough = e.publication[e.publicationNext].Version
		} else {
			e.publicationCount++
		}
		e.publication[e.publicationNext] = p.state
		e.publicationNext = (e.publicationNext + 1) % PublishedHistory
		e.published = p.state
	}
	e.resend = false
	e.lastSent, e.nextSend = now, addDuration(now, cappedInterval(base, e.retries))
	e.mutation++
	t.lastTime = now
	p.consumed = true
	return nil
}

type AckResult struct {
	Progress  bool
	Installed bool
	Ignored   bool
}

// Ack requires exact publication proof, including class. An older proven ACK
// can update the acknowledged view but cannot clear the latest pending state
// or renew its lifetime/retries. Evicted old ACKs are ignored without claiming
// installation; holes/future versions and wrong retained classes are errors.
func (t *Table) Ack(flow, version uint64, class protocol.Class, now time.Duration) (AckResult, error) {
	if version == 0 || !class.Valid() {
		return AckResult{}, ErrState
	}
	if err := t.checkTime(now); err != nil {
		return AckResult{}, err
	}
	e := t.entries[flow]
	if e == nil {
		return AckResult{}, ErrUnknown
	}
	if version > e.published.Version {
		return AckResult{}, ErrAck
	}
	if version <= e.retiredThrough {
		t.lastTime = now
		return AckResult{Ignored: true}, nil
	}
	want := State{Flow: flow, Version: version, Class: class}
	known := false
	for _, published := range e.publication {
		if published == want {
			known = true
			break
		}
	}
	if !known {
		return AckResult{}, ErrAck
	}
	if version <= e.acked.Version {
		t.lastTime = now
		return AckResult{Ignored: true}, nil
	}
	e.acked = want
	installed := e.local == want
	if installed {
		e.pending, e.resend = false, false
	}
	e.mutation++
	t.lastTime = now
	return AckResult{Progress: true, Installed: installed}, nil
}

type MergeResult struct {
	Updated   bool
	Duplicate bool
	Ignored   bool
}

// MergePeer is shared by authenticated announcements and recovery snapshots.
// It never allocates a flow, changes local TX, or creates an ACK. In particular,
// learning a state from a snapshot provides no ClassUpdate publication proof.
func (t *Table) MergePeer(state State) (MergeResult, error) {
	if !state.Valid() {
		return MergeResult{}, ErrState
	}
	e := t.entries[state.Flow]
	if e == nil {
		return MergeResult{}, ErrUnknown
	}
	if !e.peer.Known || state.Version > e.peer.State.Version {
		e.peer = PeerView{Known: true, State: state}
		return MergeResult{Updated: true}, nil
	}
	if state.Version < e.peer.State.Version {
		return MergeResult{Ignored: true}, nil
	}
	if state.Class != e.peer.State.Class {
		return MergeResult{}, ErrConflict
	}
	return MergeResult{Duplicate: true}, nil
}

// QueueAck is called only for a received ClassUpdate after successful merge.
// The one bounded ACK slot preserves exact input state, including stale input;
// it never substitutes a newer view learned only from a recovery snapshot.
// Multiple announcements coalesce to the highest actually received version.
func (t *Table) QueueAck(state State) error {
	if !state.Valid() {
		return ErrState
	}
	e := t.entries[state.Flow]
	if e == nil {
		return ErrUnknown
	}
	if !e.peer.Known || state.Version > e.peer.State.Version {
		return ErrState
	}
	if state.Version == e.peer.State.Version && state.Class != e.peer.State.Class {
		return ErrConflict
	}
	if e.ackPending {
		if state.Version < e.ack.Version {
			return nil
		}
		if state.Version == e.ack.Version {
			if state.Class != e.ack.Class {
				return ErrConflict
			}
			return nil
		}
	}
	e.ack, e.ackPending = state, true
	return nil
}

// ReadyAcks returns copies without consuming a slot. Failed writes leave ACKs
// pending. ACKs have no independent retry timer; a repeated announcement after
// successful AckSent queues another exact response.
func (t *Table) ReadyAcks(limit int) ([]State, error) {
	if limit < 0 || limit > t.cfg.MaxEntries {
		return nil, ErrLimit
	}
	acks := make([]State, 0, min(limit, len(t.entries)))
	for _, flow := range t.orderedFlows() {
		e := t.entries[flow]
		if e.ackPending && len(acks) < limit {
			acks = append(acks, e.ack)
		}
	}
	return acks, nil
}

// AckSent clears only the exact slot written successfully. A superseded ACK
// write cannot discard a newer queued response.
func (t *Table) AckSent(state State) error {
	if !state.Valid() {
		return ErrState
	}
	e := t.entries[state.Flow]
	if e == nil {
		return ErrUnknown
	}
	if !e.ackPending || e.ack != state {
		return ErrStale
	}
	e.ackPending = false
	return nil
}

// RequestRetry makes the latest pending state immediately eligible after a
// UDP loss/PTO reference. It does not preserve the obsolete referenced class,
// consume a publication, or refresh the pending episode's lifetime or retries.
func (t *Table) RequestRetry(flow uint64) error {
	e := t.entries[flow]
	if e == nil {
		return ErrUnknown
	}
	if e.pending && e.enabled && !e.resend {
		e.resend = true
		e.mutation++
	}
	return nil
}

// RebindCarrier keeps local/peer versions, publication proof, ACK slots and the
// original pending budget. It marks only pending TX for an immediate new send.
func (t *Table) RebindCarrier() {
	for _, e := range t.entries {
		if e.pending && e.enabled {
			e.resend = true
			// A prepared token belongs to the previous carrier even if an
			// update or loss had already made this state immediately due.
			e.mutation++
		}
	}
}

// Forget requires owner lifecycle authorization. The Session retains its
// bounded terminal tombstone and must not call Start again for this flow ID.
func (t *Table) Forget(flow uint64) { delete(t.entries, flow) }

func (t *Table) Usage() int { return len(t.entries) }
