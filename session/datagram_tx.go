package session

import (
	"bfp/protocol"
	"bfp/scheduler"
	"sort"
	"time"
)

// A datagram is still best-effort while a carrier is healthy.  During a
// carrier handover, however, a complete encrypted record may have been
// written to the old UDP socket without the peer's transport ACK reaching us.
// Keep a bounded copy of those logical datagram frames so the new carrier can
// finish the same message.  The receiver's flow/message tombstones make this
// replay idempotent at the BFP boundary.
const maxHandoverDatagrams = 512

type datagramHandoverKey struct {
	kind         protocol.Kind
	flow, offset uint64
	value        uint64
	flags        uint8
}

func handoverKey(f protocol.Frame) datagramHandoverKey {
	return datagramHandoverKey{kind: f.Kind, flow: f.Flow, offset: f.Offset, value: f.Value, flags: f.Flags}
}

func cloneHandoverFrame(f protocol.Frame) protocol.Frame {
	f.Data = append([]byte(nil), f.Data...)
	return f
}

func (s *Session) rememberHandoverDatagram(f protocol.Frame) {
	if f.Kind != protocol.Datagram || f.Flow == 0 || s.streams[f.Flow] == nil || s.streams[f.Flow].reset {
		return
	}
	if s.handoverDatagrams == nil {
		s.handoverDatagrams = make(map[datagramHandoverKey]protocol.Frame)
	}
	k := handoverKey(f)
	if _, exists := s.handoverDatagrams[k]; exists {
		return
	}
	if len(s.handoverDatagrams) >= maxHandoverDatagrams {
		return
	}
	s.handoverDatagrams[k] = cloneHandoverFrame(f)
}

// captureHandoverDatagrams runs before the old carrier is closed.  Transport
// references cover records already written; a txDatagram with only some of
// its fragments written supplies the complete message so an uncommitted tail
// cannot be stranded by the queue reset in attach.
func (s *Session) captureHandoverDatagrams(now time.Time) {
	if s.current == nil || s.current.kind != "udp" || s.udpPath == nil {
		return
	}
	for _, r := range s.udpPath.refs {
		if r.kind != protocol.Datagram {
			continue
		}
		s.rememberHandoverDatagram(protocol.Frame{Kind: r.kind, Flow: r.flow, Offset: r.offset, Value: r.value, Flags: r.flags, Data: r.data})
	}
	for _, st := range s.streams {
		if st == nil || st.reset {
			continue
		}
		for id, tx := range st.txDatagrams {
			if tx == nil || !tx.firstCommitted || !now.Before(tx.deadline) {
				continue
			}
			batch, err := s.datagramBatch(st, id, tx.data)
			if err != nil {
				continue
			}
			for _, item := range batch {
				if item.Value.Kind == protocol.Datagram {
					s.rememberHandoverDatagram(item.Value)
				}
			}
		}
	}
}

// requeueHandoverDatagrams installs the retained logical frames on the new
// carrier.  They remain in the map until a complete new-carrier write
// succeeds, so a second failure can capture/requeue them again.
func (s *Session) requeueHandoverDatagrams() {
	if len(s.handoverDatagrams) == 0 {
		return
	}
	keys := make([]datagramHandoverKey, 0, len(s.handoverDatagrams))
	for k := range s.handoverDatagrams {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.flow != b.flow {
			return a.flow < b.flow
		}
		if a.offset != b.offset {
			return a.offset < b.offset
		}
		if a.value != b.value {
			return a.value < b.value
		}
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		return a.flags < b.flags
	})
	for _, k := range keys {
		f := s.handoverDatagrams[k]
		st := s.streams[f.Flow]
		if st == nil || st.reset {
			delete(s.handoverDatagrams, k)
			continue
		}
		if !s.enqueue(f, st.effectiveClass) {
			// Keep the frame for a later carrier attempt.  The queue is empty at
			// the normal attach boundary; failure here means the session is already
			// at its bounded admission limit.
			continue
		}
	}
}

func (s *Session) handoverDatagramCommitted(f protocol.Frame) {
	if f.Kind != protocol.Datagram || len(s.handoverDatagrams) == 0 {
		return
	}
	delete(s.handoverDatagrams, handoverKey(f))
}

// The per-flow write gate bounds recovery waiters to one retained payload per
// flow. The operation keeps its original deadline; setters may only tighten it.
func (f *Flow) writeDatagram(b []byte, op *datagramWriteOperation) (int, error) {
	for {
		f.mu.Lock()
		err := op.check()
		f.mu.Unlock()
		if err != nil {
			return 0, err
		}
		accepted := false
		var result error
		err = f.s.businessCall(op.ctx, func() {
			f.mu.Lock()
			result = op.check()
			f.mu.Unlock()
			if result != nil {
				return
			}
			st := f.s.streams[f.id]
			if st == nil || st.reset {
				result = ErrClosed
				return
			}
			if !f.s.datagramWriteReady() {
				return
			}
			if st.messageNext == ^uint64(0) {
				result = ErrLimit
				return
			}
			// While waiting, borrow the caller's buffer under Write's normal
			// contract. Create owned immutable storage only for actual admission;
			// its whole-message reservation includes this one shared copy.
			data := append([]byte(nil), b...)
			id := st.messageNext
			batch, batchErr := f.s.datagramBatch(st, id, data)
			if batchErr != nil {
				result = batchErr
				return
			}
			cost := datagramReservation(batch)
			if len(st.txDatagrams) >= 32 || cost > f.s.opts.defaults().MaxDatagramFlowBuffer-st.txDatagramReserved {
				result = ErrLimit
				return
			}
			if cost > f.s.opts.MaxSessionBuffer-f.s.pendingSendBytes() || cost > f.s.opts.MaxSessionBuffer-f.s.stats.TXBuffered-f.s.txDatagramReserved {
				result = ErrLimit
				return
			}
			// Serialize the final cutoff check and whole-message admission with
			// deadline setters. A setter that wins cannot be bypassed by a stale
			// captured limit; one that follows admission cannot revoke it.
			f.mu.Lock()
			if result = op.check(); result != nil {
				f.mu.Unlock()
				return
			}
			if f.s.queue.PushBatch(f.id, st.effectiveClass, batch) != nil {
				result = ErrLimit
				f.mu.Unlock()
				return
			}
			if st.txDatagrams == nil {
				st.txDatagrams = make(map[uint64]*txDatagram)
			}
			gen := uint64(0)
			if f.s.current != nil {
				gen = f.s.current.generation
			}
			st.txDatagrams[id] = &txDatagram{data: data, deadline: op.deadline, generation: gen, remaining: len(batch), reserved: cost}
			f.s.txDatagramReserved += cost
			st.txDatagramReserved += cost
			f.s.txDatagramQueued += batchCost(batch)
			st.messageNext++
			accepted = true
			f.mu.Unlock()
			// Classification accounts only the completed admission. It may
			// invoke Session cancellation, so do not hold the flow lock here.
			f.s.observeTX(st, uint64(len(data)))
		})
		if err != nil {
			if op.ctx.Err() != nil {
				return 0, deadlineError("write")
			}
			return 0, err
		}
		if result != nil {
			return 0, result
		}
		if accepted {
			return len(b), nil
		}
		if err = f.waitDatagramWrite(op); err != nil {
			return 0, err
		}
	}
}

// txDatagram owns a whole message until its queued fragments have been sent or
// retired. firstCommitted never becomes false. A failed carrier write has an
// unknown delivery outcome and is conservatively retired, never migrated.
// Data is shared with the batch fragments, not copied for each record.
type txDatagram struct {
	data           []byte
	deadline       time.Time
	generation     uint64
	firstCommitted bool
	remaining      int
	reserved       int
}

func isBusinessFrame(f protocol.Frame) bool {
	return f.Kind == protocol.StreamData || f.Kind == protocol.Datagram || f.Kind == protocol.DatagramRepairFrame || f.Kind == protocol.Open
}

func isDatagramFrame(f protocol.Frame) bool {
	return f.Kind == protocol.Datagram || f.Kind == protocol.DatagramRepairFrame
}

func (s *Session) oldUDPBusinessPaused() bool {
	return s.current != nil && s.current.kind == "udp" && (s.udpSuspect || s.stats.TCPRecoveryInFlight)
}

func (s *Session) datagramWriteReady() bool {
	return s.active && s.peerDone && !s.oldUDPBusinessPaused()
}

func (s *Session) signalFlows() {
	for _, st := range s.streams {
		st.flow.signal()
	}
}

// Queued datagram costs already belong to their whole-message reservation.
// Charge them once, while keeping the full reservation for partly sent messages.
func (s *Session) pendingSendBytes() int {
	if s.queue == nil {
		return s.txDatagramReserved
	}
	return s.queue.Bytes() + s.txDatagramReserved - s.txDatagramQueued
}

func (s *Session) txMessage(f protocol.Frame) *txDatagram {
	if !isDatagramFrame(f) {
		return nil
	}
	if st := s.streams[f.Flow]; st != nil {
		return st.txDatagrams[f.Offset]
	}
	return nil
}

func (s *Session) datagramPopped(f protocol.Frame) {
	if s.txMessage(f) != nil {
		s.txDatagramQueued -= frameCost(f)
	}
}

func (s *Session) datagramRequeued(f protocol.Frame) {
	if s.txMessage(f) != nil {
		s.txDatagramQueued += frameCost(f)
	}
}

func (s *Session) retireTXDatagram(st *streamState, id uint64, dropped bool) {
	tx := st.txDatagrams[id]
	if tx == nil {
		return
	}
	if s.queue != nil {
		cost, _ := s.queue.DropMatching(st.flow.id, func(f protocol.Frame) bool { return isDatagramFrame(f) && f.Offset == id })
		s.txDatagramQueued -= cost
	}
	s.txDatagramReserved -= tx.reserved
	st.txDatagramReserved -= tx.reserved
	delete(st.txDatagrams, id)
	if dropped {
		s.stats.Dropped++
	}
	s.signalFlows()
}

func (s *Session) expireTXDatagrams(now time.Time) {
	for _, st := range s.streams {
		for id, tx := range st.txDatagrams {
			if !tx.firstCommitted && !now.Before(tx.deadline) {
				s.retireTXDatagram(st, id, true)
			}
		}
	}
}

// Check again after queue selection and immediately before any carrier write.
// The local deadline controls only uncommitted work; already submitted data is
// not revoked and never becomes eligible for replay after its deadline.
func (s *Session) datagramCanSend(f protocol.Frame, now time.Time) bool {
	tx := s.txMessage(f)
	if tx == nil {
		return true
	} // internal fixtures/legacy direct frames
	st := s.streams[f.Flow]
	if s.current == nil || tx.generation != s.current.generation || !tx.firstCommitted && !now.Before(tx.deadline) {
		s.retireTXDatagram(st, f.Offset, true)
		return false
	}
	return true
}

func (s *Session) datagramWriteDeadline(f protocol.Frame) time.Time {
	if tx := s.txMessage(f); tx != nil && !tx.firstCommitted {
		return tx.deadline
	}
	return time.Time{}
}

func (s *Session) datagramCommitted(f protocol.Frame) {
	tx := s.txMessage(f)
	if tx == nil {
		return
	}
	tx.firstCommitted = true
	tx.remaining--
	if tx.remaining == 0 {
		s.retireTXDatagram(s.streams[f.Flow], f.Offset, false)
	}
}

func (s *Session) datagramWriteFailed(f protocol.Frame) {
	if tx := s.txMessage(f); tx != nil {
		tx.firstCommitted = true // carrier failure may follow a partial/full write
		s.retireTXDatagram(s.streams[f.Flow], f.Offset, true)
	}
}

func batchCost(batch []scheduler.Item[protocol.Frame]) int {
	n := 0
	for _, item := range batch {
		n += item.Cost
	}
	return n
}

// Payload storage is shared between the owner and queued fragments. Record
// envelope costs also reserve parity payload. Additional fixed charges cover
// the TX owner/map and conservative slice, frame, queue-capacity and temporary
// batch metadata. These are logical upper allowances, not an RSS measurement.
func datagramReservation(batch []scheduler.Item[protocol.Frame]) int {
	n := batchCost(batch) + 256 + 192*len(batch)
	for _, item := range batch {
		if item.Value.Kind == protocol.DatagramRepairFrame {
			n += len(item.Value.Data)
		}
	}
	return n
}

// Called after installation of the new carrier and retirement of its old queue.
// Rebuild only complete, never-submitted messages. FEC metadata is generated
// for the new generation; TCP omits parity without changing the OPEN contract.
func (s *Session) rebindTXDatagrams(now time.Time) {
	s.txDatagramQueued = 0
	for _, st := range s.streams {
		ids := make([]uint64, 0, len(st.txDatagrams))
		for id := range st.txDatagrams {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			tx := st.txDatagrams[id]
			if tx.firstCommitted || !now.Before(tx.deadline) || st.reset {
				s.retireTXDatagram(st, id, true)
				continue
			}
			batch, err := s.datagramBatch(st, id, tx.data)
			cost := datagramReservation(batch)
			if err != nil || cost > s.opts.MaxSessionBuffer-(s.pendingSendBytes()-tx.reserved) || s.queue.PushBatch(st.flow.id, st.effectiveClass, batch) != nil {
				s.retireTXDatagram(st, id, true)
				continue
			}
			s.txDatagramReserved += cost - tx.reserved
			st.txDatagramReserved += cost - tx.reserved
			tx.reserved, tx.remaining, tx.generation = cost, len(batch), s.current.generation
			s.txDatagramQueued += batchCost(batch)
		}
	}
}
