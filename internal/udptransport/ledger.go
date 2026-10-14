package udptransport

import (
	"math"
	"sort"
	"time"
)

// Packet contains transport metadata only; it never retains a payload/chunk.
// Retry marks logical retry lineage for conservative Karn filtering. Ordinal
// is assigned by Commit and remains carrier-wide across key epochs.
type Packet struct {
	Scope                      Scope
	Number                     uint64
	Size                       uint32
	SentAt                     time.Duration
	AckEliciting, Retry, Probe bool
	Ordinal                    uint64
}
type packetKey struct {
	epoch  uint32
	number uint64
}
type sentEpoch struct {
	epoch                uint32
	committed, eliciting numberWindow
}
type Ledger struct {
	generation        uint64
	current, previous *sentEpoch
	live              map[packetKey]Packet
	lost              map[packetKey]Packet
	lostOrder         [MaxLostPackets]packetKey
	lostNext          int
	lostUsed          int
	flight, ordinal   uint64
	highestACKs       [3]uint64
}
type LedgerSnapshot struct {
	Flight      uint64
	Live, Lost  int
	LastOrdinal uint64
	HighestACKs [3]uint64
}
type Acknowledged struct {
	Packet  Packet
	WasLost bool
}
type ACKResult struct {
	Packets                 []Acknowledged
	FlightReleased          uint64
	SampleAccepted, Ignored bool
	// NewProgress is true only for a first ACK of retained live/lost metadata.
	// A late ACK may provide progress with zero flight release; owners must
	// not infer congestion growth from the sum of Packets' sizes.
	NewProgress bool
}

func NewLedger(generation uint64, epoch uint32) (*Ledger, error) {
	if generation == 0 {
		return nil, ErrScope
	}
	return &Ledger{generation: generation, current: &sentEpoch{epoch: epoch}, live: make(map[packetKey]Packet), lost: make(map[packetKey]Packet)}, nil
}
func (l *Ledger) find(scope Scope) (*sentEpoch, error) {
	if scope.Generation != l.generation {
		return nil, ErrScope
	}
	if scope.Epoch == l.current.epoch {
		return l.current, nil
	}
	if l.previous != nil && scope.Epoch == l.previous.epoch {
		return l.previous, nil
	}
	return nil, ErrScope
}
func (l *Ledger) AdvanceEpoch(epoch uint32) error {
	if l.previous != nil {
		return ErrEpochBusy
	}
	if l.current.epoch == math.MaxUint32 || epoch != l.current.epoch+1 {
		return ErrScope
	}
	l.previous = l.current
	l.current = &sentEpoch{epoch: epoch}
	return nil
}
func (l *Ledger) RetirePrevious() error {
	if l.previous == nil {
		return nil
	}
	for k := range l.live {
		if k.epoch == l.previous.epoch {
			return ErrEpochBusy
		}
	}
	for k := range l.lost {
		if k.epoch == l.previous.epoch {
			delete(l.lost, k)
		}
	}
	l.previous = nil
	return nil
}

// CheckCommit must run before carrier I/O. Commit runs only after an actual
// successful write, with no intervening owner mutation. Failed writes consume
// no ledger/ordinal/flight state; skipped record numbers remain unsent holes.
func (l *Ledger) CheckCommit(p Packet) error {
	if p.Scope.Generation != l.generation || p.Scope.Epoch != l.current.epoch {
		return ErrScope
	}
	if p.Number > MaxRecordNumber || p.Ordinal != 0 || l.current.committed.initialized && p.Number <= l.current.committed.largest {
		return ErrSequence
	}
	if p.SentAt < 0 {
		return ErrTime
	}
	if p.Size == 0 || p.Size > MaxWireBytes || p.Probe && !p.AckEliciting {
		return ErrLimit
	}
	if p.AckEliciting {
		if len(l.live) >= MaxLivePackets || l.ordinal == math.MaxUint64 {
			return ErrLimit
		}
		probes := 0
		for _, live := range l.live {
			if live.Probe {
				probes++
			}
		}
		if p.Probe && probes >= MaxProbePackets || !p.Probe && len(l.live)-probes >= OrdinaryPacketLimit {
			return ErrLimit
		}
	}
	return nil
}
func (l *Ledger) Commit(p Packet) (Packet, error) {
	if err := l.CheckCommit(p); err != nil {
		return Packet{}, err
	}
	e := l.current
	e.committed.add(p.Number)
	e.eliciting.advance(p.Number)
	if p.AckEliciting {
		e.eliciting.add(p.Number)
		l.ordinal++
		p.Ordinal = l.ordinal
		l.live[packetKey{p.Scope.Epoch, p.Number}] = p
		l.flight += uint64(p.Size)
	}
	return p, nil
}
func (l *Ledger) Snapshot() LedgerSnapshot {
	return LedgerSnapshot{l.flight, len(l.live), len(l.lost), l.ordinal, l.highestACKs}
}

func (l *Ledger) validateACK(e *sentEpoch, a ACK) error {
	if !e.committed.initialized || a.Largest > e.committed.largest {
		return ErrUnsent
	}
	// Ranges are disjoint. Total window iteration is <=4096, independent of
	// numeric interval lengths; old forgotten numbers are ignored.
	for _, r := range a.Ranges {
		lo := max(r.First, e.committed.floor())
		hi := min(r.Last, e.committed.largest)
		if lo > hi {
			continue
		}
		for n := lo; n <= hi; n++ {
			if !e.committed.has(n) {
				return ErrUnsent
			}
			if !e.eliciting.has(n) {
				return ErrNonEliciting
			}
		}
	}
	return nil
}

// ApplyACK validates the entire ACK before mutating any flight, packet, RTT or
// progress state. Past generations/retired epochs are harmless; future scope
// is an error. The ACK's own outer sending epoch must never be passed here.
func (l *Ledger) ApplyACK(scope Scope, a ACK, now time.Duration, rtt *RTT) (ACKResult, error) {
	if err := a.Validate(); err != nil {
		return ACKResult{}, err
	}
	if now < 0 {
		return ACKResult{}, ErrTime
	}
	if a.Epoch != scope.Epoch {
		return ACKResult{}, ErrScope
	}
	if scope.Generation < l.generation || scope.Generation == l.generation && scope.Epoch < l.current.epoch && (l.previous == nil || scope.Epoch != l.previous.epoch) {
		return ACKResult{Ignored: true}, nil
	}
	e, err := l.find(scope)
	if err != nil {
		return ACKResult{}, err
	}
	if err = l.validateACK(e, a); err != nil {
		return ACKResult{}, err
	}
	result := ACKResult{}
	for k, p := range l.live {
		if k.epoch == scope.Epoch && includes(a.Ranges, k.number) {
			result.Packets = append(result.Packets, Acknowledged{Packet: p})
			result.FlightReleased += uint64(p.Size)
		}
	}
	for k, p := range l.lost {
		if k.epoch == scope.Epoch && includes(a.Ranges, k.number) {
			result.Packets = append(result.Packets, Acknowledged{Packet: p, WasLost: true})
		}
	}
	// Deterministic result order aids owner queue processing and test vectors.
	sort.Slice(result.Packets, func(i, j int) bool { return result.Packets[i].Packet.Ordinal < result.Packets[j].Packet.Ordinal })
	result.NewProgress = len(result.Packets) > 0
	for _, ap := range result.Packets {
		p := ap.Packet
		k := packetKey{p.Scope.Epoch, p.Number}
		if ap.WasLost {
			delete(l.lost, k)
		} else {
			delete(l.live, k)
		}
		l.noteACK(p.Ordinal)
		if p.Number == a.Largest && rtt != nil {
			result.SampleAccepted = rtt.Observe(now-p.SentAt, a.Delay, !p.Retry && !ap.WasLost)
		}
	}
	l.flight -= result.FlightReleased
	return result, nil
}
func (l *Ledger) noteACK(ordinal uint64) {
	for i := range l.highestACKs {
		if ordinal == l.highestACKs[i] {
			return
		}
		if ordinal > l.highestACKs[i] {
			for j := len(l.highestACKs) - 1; j > i; j-- {
				l.highestACKs[j] = l.highestACKs[j-1]
			}
			l.highestACKs[i] = ordinal
			return
		}
	}
}

// DeclareLost releases flight once and retains only bounded late-ACK metadata.
// It does not request a payload retry or reduce cwnd: the owner chooses those.
func (l *Ledger) DeclareLost(scope Scope, number uint64) (Packet, bool) {
	if _, err := l.find(scope); err != nil {
		return Packet{}, false
	}
	k := packetKey{scope.Epoch, number}
	p, ok := l.live[k]
	if !ok {
		return Packet{}, false
	}
	delete(l.live, k)
	l.flight -= uint64(p.Size)
	if l.lostUsed == MaxLostPackets {
		old := l.lostOrder[l.lostNext]
		delete(l.lost, old)
	} else {
		l.lostUsed++
	}
	l.lostOrder[l.lostNext] = k
	l.lostNext = (l.lostNext + 1) % MaxLostPackets
	l.lost[k] = p
	return p, true
}

// DetectLoss uses authenticated ACK evidence, not a fixed timeout. With no
// later ACK evidence, a silent path is handled by a separate PTO owner.
func (l *Ledger) DetectLoss(now time.Duration, rtt RTTSnapshot) ([]Packet, error) {
	if now < 0 {
		return nil, ErrTime
	}
	candidates := make([]Packet, 0, len(l.live))
	for _, p := range l.live {
		if now < p.SentAt {
			continue
		}
		higher := 0
		for _, ord := range l.highestACKs {
			if ord > p.Ordinal {
				higher++
			}
		}
		if LossEvidence(higher, now-p.SentAt, rtt.Latest, rtt.Smoothed) {
			candidates = append(candidates, p)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Ordinal < candidates[j].Ordinal })
	for _, p := range candidates {
		l.DeclareLost(p.Scope, p.Number)
	}
	return candidates, nil
}
