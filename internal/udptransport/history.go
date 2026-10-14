package udptransport

import (
	"math"
	"time"
)

// numberWindow is a fixed circular bitmap. Advancing by an arbitrary integer
// takes at most HistoryBits steps, never the distance supplied by a peer.
type numberWindow struct {
	bits        [HistoryBits / 64]uint64
	largest     uint64
	initialized bool
}

func (w *numberWindow) floor() uint64 {
	if w.largest >= HistoryBits-1 {
		return w.largest - (HistoryBits - 1)
	}
	return 0
}
func (w *numberWindow) advance(n uint64) {
	if !w.initialized {
		w.initialized = true
		w.largest = n
		return
	}
	if n <= w.largest {
		return
	}
	d := n - w.largest
	if d >= HistoryBits {
		w.bits = [HistoryBits / 64]uint64{}
	} else {
		for i := uint64(1); i <= d; i++ {
			slot := (w.largest + i) % HistoryBits
			w.bits[slot/64] &^= uint64(1) << (slot % 64)
		}
	}
	w.largest = n
}
func (w *numberWindow) has(n uint64) bool {
	if !w.initialized || n > w.largest || n < w.floor() {
		return false
	}
	slot := n % HistoryBits
	return w.bits[slot/64]&(uint64(1)<<(slot%64)) != 0
}
func (w *numberWindow) add(n uint64) bool {
	w.advance(n)
	if n < w.floor() || w.has(n) {
		return false
	}
	slot := n % HistoryBits
	w.bits[slot/64] |= uint64(1) << (slot % 64)
	return true
}
func (w *numberWindow) ranges() []Range {
	if !w.initialized {
		return nil
	}
	out := make([]Range, 0, MaxRanges)
	var active bool
	var r Range
	for i := uint64(0); i <= w.largest-w.floor(); i++ {
		n := w.largest - i
		if w.has(n) {
			if !active {
				r = Range{n, n}
				active = true
			} else {
				r.First = n
			}
		} else if active {
			out = append(out, r)
			active = false
			if len(out) == MaxRanges {
				return out
			}
		}
	}
	if active && len(out) < MaxRanges {
		out = append(out, r)
	}
	return out
}

type rxEpoch struct {
	epoch                        uint32
	window                       numberWindow
	largestAt, pendingAt, lastAt time.Duration
	revision                     uint64
	fresh                        uint8
	pending, immediate           bool
}
type History struct {
	generation        uint64
	current, previous *rxEpoch
}
type ACKSnapshot struct {
	ACK      ACK
	Revision uint64
}

func NewHistory(generation uint64, epoch uint32) (*History, error) {
	if generation == 0 {
		return nil, ErrScope
	}
	return &History{generation: generation, current: &rxEpoch{epoch: epoch}}, nil
}
func (h *History) find(scope Scope) (*rxEpoch, error) {
	if scope.Generation != h.generation {
		return nil, ErrScope
	}
	if h.current != nil && scope.Epoch == h.current.epoch {
		return h.current, nil
	}
	if h.previous != nil && scope.Epoch == h.previous.epoch {
		return h.previous, nil
	}
	return nil, ErrScope
}

// AdvanceEpoch requires an explicit retirement gate before a third epoch.
func (h *History) AdvanceEpoch(epoch uint32) error {
	if h.previous != nil {
		return ErrEpochBusy
	}
	if h.current.epoch == math.MaxUint32 || epoch != h.current.epoch+1 {
		return ErrScope
	}
	h.previous = h.current
	h.current = &rxEpoch{epoch: epoch}
	return nil
}

// PreviousPending reports whether the retained old epoch still has an ACK
// obligation. The key-lifecycle owner must keep this scope until the ACK has
// actually been written or its bounded drain policy deliberately suspends
// the carrier.
func (h *History) PreviousPending() bool { return h.previous != nil && h.previous.pending }

// RetirePrevious is called only after the key-lifecycle owner permits it.
func (h *History) RetirePrevious() { h.previous = nil }

// Observe takes authenticated, fully decoded record metadata exactly once.
// ACK-only/padding records use ackEliciting=false and create no ACK intent.
func (h *History) Observe(scope Scope, number uint64, now time.Duration, ackEliciting bool) (bool, error) {
	e, err := h.find(scope)
	if err != nil {
		return false, err
	}
	if number > MaxRecordNumber {
		return false, ErrSequence
	}
	if now < 0 {
		return false, ErrTime
	}
	if !ackEliciting || e.window.initialized && (number < e.window.floor() || e.window.has(number)) {
		return false, nil
	}
	if e.revision == math.MaxUint64 {
		return false, ErrLimit
	}
	if e.window.initialized && now < e.lastAt {
		return false, ErrTime
	}
	gap := e.window.initialized && (number < e.window.largest || number-e.window.largest > 1)
	if !e.pending {
		e.pendingAt = now
	}
	if !e.window.initialized || number > e.window.largest {
		e.largestAt = now
	}
	e.window.add(number)
	e.lastAt = now
	e.revision++
	e.pending = true
	e.immediate = e.immediate || gap
	if e.fresh < 2 {
		e.fresh++
	}
	return true, nil
}
func (h *History) Due(scope Scope, now time.Duration) (bool, error) {
	e, err := h.find(scope)
	if err != nil {
		return false, err
	}
	if now < 0 || e.window.initialized && now < e.lastAt {
		return false, ErrTime
	}
	return e.pending && (e.immediate || e.fresh >= 2 || now-e.pendingAt >= MaxACKDelay), nil
}

// Snapshot does not clear the pending intention. MarkSent only clears exactly
// the revision actually written, so a stale snapshot cannot erase new work.
func (h *History) Snapshot(scope Scope, now time.Duration) (ACKSnapshot, bool, error) {
	e, err := h.find(scope)
	if err != nil {
		return ACKSnapshot{}, false, err
	}
	if now < 0 || e.window.initialized && now < e.lastAt {
		return ACKSnapshot{}, false, ErrTime
	}
	if !e.pending {
		return ACKSnapshot{}, false, nil
	}
	delay := min(now-e.largestAt, MaxACKDelay)
	delay -= delay % time.Microsecond
	return ACKSnapshot{ACK: ACK{Epoch: e.epoch, Largest: e.window.largest, Delay: delay, Ranges: e.window.ranges()}, Revision: e.revision}, true, nil
}
func (h *History) MarkSent(scope Scope, revision uint64) error {
	e, err := h.find(scope)
	if err != nil {
		return err
	}
	if revision == 0 || revision > e.revision {
		return ErrSequence
	}
	if revision == e.revision {
		e.pending = false
		e.immediate = false
		e.fresh = 0
	}
	return nil
}
