package session

import (
	"context"
	"math"
	"sort"
	"time"

	"bfp/internal/operation"
	"bfp/internal/udptransport"
	"bfp/obfuscation"
	"bfp/protocol"
	"bfp/security"
)

const ackReserveBurst = 2400
const ackReserveRate = 64 << 10

type logicalRef struct {
	kind                protocol.Kind
	flow, offset, value uint64
	flags               uint8
	data                []byte
}
type refKey struct {
	kind                protocol.Kind
	flow, offset, value uint64
	flags               uint8
}

func (r logicalRef) key() refKey {
	k := refKey{kind: r.kind, flow: r.flow, flags: r.flags}
	if r.kind == protocol.StreamData || r.kind == protocol.Fin || r.kind == protocol.FinAck {
		k.offset = r.offset
	}
	if r.kind == protocol.KeyUpdate || r.kind == protocol.KeyUpdateAck || r.kind == protocol.TicketRefresh || r.kind == protocol.TicketRefreshAck {
		k.value = r.value
	}
	return k
}

type udpPath struct {
	generation                                 uint64
	origin                                     time.Time
	history                                    *udptransport.History
	ledger                                     *udptransport.Ledger
	rtt                                        udptransport.RTT
	pto                                        udptransport.PTO
	refs                                       map[security.RecordMeta]logicalRef
	retries                                    map[refKey]logicalRef
	lastHealth, lastProgress, healthAtDeadline time.Time
	deadline                                   time.Time
	noResponseDeadlines                        uint8
	probeRemaining                             int
	probeSerial                                uint64
	freshTokens                                map[uint64]bool
	ackTokens                                  float64
	ackTime                                    time.Time
	rxPrevious, txPrevious                     *uint32
	recoveryEnd                                uint64
	avoidanceRemainder                         uint64
	lastCommittedBytes                         uint64
	budgetBlocked                              bool
	budgetBlockedSince                         time.Time
	blockedByCwnd, blockedByPacer              bool
	// Retry scheduling is separate from the normal pending queue.  A lost
	// record reference is owned by the UDP path until it is successfully
	// written, so the scheduler keeps only bounded cursors rather than a
	// second queue or any payload copies.  The class cursor follows the same
	// 4:2:1 category weights as scheduler.Queue; the per-class cursor gives
	// flows a round-robin opportunity within that category.
	retryClassCursor int
	retryFlowCursor  [3]uint64
}

func addTransportCounter(dst *uint64, amount uint64) {
	if amount > math.MaxUint64-*dst {
		*dst = math.MaxUint64
		return
	}
	*dst += amount
}

func addTransportDuration(a, b time.Duration) time.Duration {
	if b > time.Duration(math.MaxInt64)-a {
		return time.Duration(math.MaxInt64)
	}
	return a + b
}

// One fixed-size owner record merges overlapping cwnd/pacer observations. The
// supplied clock is observational only and is never used for transport policy.
func (s *Session) observeUDPBudgetDenial(now time.Time, cwnd, pacer bool) {
	p := s.udpPath
	if p == nil || !cwnd && !pacer {
		return
	}
	if !p.budgetBlocked {
		p.budgetBlocked, p.budgetBlockedSince = true, now
	}
	p.blockedByCwnd, p.blockedByPacer = cwnd, pacer
}

func (s *Session) finishUDPBudgetEpisode(now time.Time) {
	p := s.udpPath
	if p == nil || !p.budgetBlocked {
		return
	}
	elapsed := max(time.Duration(0), now.Sub(p.budgetBlockedSince))
	s.udpBlockedTotal = addTransportDuration(s.udpBlockedTotal, elapsed)
	s.udpBlockedMax = max(s.udpBlockedMax, elapsed)
	p.budgetBlocked, p.blockedByCwnd, p.blockedByPacer = false, false, false
	p.budgetBlockedSince = time.Time{}
}

func (s *Session) recordUDPCommit(size int, feedback bool) {
	bytes := uint64(size)
	addTransportCounter(&s.stats.UDPCommittedRecords, 1)
	addTransportCounter(&s.stats.UDPCommittedWireBytes, bytes)
	s.stats.UDPMaxCommittedRecordBytes = max(s.stats.UDPMaxCommittedRecordBytes, bytes)
	s.udpPath.lastCommittedBytes = bytes
	if feedback {
		addTransportCounter(&s.stats.UDPFeedbackRecords, 1)
		addTransportCounter(&s.stats.UDPFeedbackWireBytes, bytes)
	} else {
		addTransportCounter(&s.stats.UDPNonFeedbackRecords, 1)
		addTransportCounter(&s.stats.UDPNonFeedbackWireBytes, bytes)
	}
}

func (s *Session) transportTime() time.Time {
	if s.transportNow != nil {
		return s.transportNow()
	}
	return time.Now()
}
func (p *udpPath) scope(epoch uint32) udptransport.Scope {
	return udptransport.Scope{Generation: p.ledgerGeneration(), Epoch: epoch}
}

// Generation is immutable for a path; kept explicitly rather than reading an
// ACK's outer epoch or a mutable sessionInfo from a different carrier.
func (p *udpPath) ledgerGeneration() uint64 { return p.generation }

func (s *Session) resetTransport(now time.Time) {
	s.finishUDPBudgetEpisode(now)
	if s.recoveryCancel != nil {
		s.recoveryCancel()
		s.recoveryCancel = nil
	}
	s.udpSuspect = false
	s.udpPath = nil
	s.flight = 0
	s.cwnd = 12000
	s.ssthresh = 1 << 20
	s.rtt = 200 * time.Millisecond
	s.paceTokens = 4800
	s.paceTime = now
	s.lastProbe = now
	if s.current == nil || s.current.kind != "udp" {
		return
	}
	h, _ := udptransport.NewHistory(s.current.generation, s.current.rx.Epoch())
	l, _ := udptransport.NewLedger(s.current.generation, s.current.tx.Epoch())
	s.udpPath = &udpPath{generation: s.current.generation, origin: now, history: h, ledger: l, rtt: udptransport.NewRTT(), pto: udptransport.NewPTO(), refs: map[security.RecordMeta]logicalRef{}, retries: map[refKey]logicalRef{}, lastHealth: now, lastProgress: now, healthAtDeadline: now, ackTokens: ackReserveBurst, ackTime: now, freshTokens: map[uint64]bool{}}
}
func makeRef(f protocol.Frame) logicalRef {
	r := logicalRef{kind: f.Kind, flow: f.Flow, offset: f.Offset, value: f.Value, flags: f.Flags}
	// Stream payload belongs to retained chunks, not each packet metadata.
	// Datagram payload is copied because a carrier handover may need to replay
	// the logical frame after its original queue owner has retired. Frozen
	// resume JSON is owned once by syncFrames; these references alias immutable
	// storage. Latest-state refs are reconstructed below.
	if f.Kind == protocol.Datagram {
		r.data = append([]byte(nil), f.Data...)
	} else if f.Kind == protocol.ResumeState || f.Kind == protocol.ResumeDone {
		r.data = f.Data
	}
	return r
}
func (s *Session) resolveRef(r logicalRef, now time.Time) (protocol.Frame, bool) {
	f := protocol.Frame{Kind: r.kind, Flow: r.flow, Offset: r.offset, Value: r.value, Flags: r.flags}
	st := s.streams[r.flow]
	switch r.kind {
	case protocol.Datagram, protocol.DatagramRepairFrame, protocol.PacketAck:
		return f, false
	case protocol.ClassUpdate:
		if r.flags != 0 || s.classTable == nil || st == nil || st.terminal() {
			return f, false
		}
		view, err := s.classTable.Snapshot(r.flow)
		if err != nil || !view.Pending || !view.Enabled {
			return f, false
		}
		_ = s.classTable.RequestRetry(r.flow)
		f = classFrame(view.Local, 0)
	case protocol.StreamData:
		if st == nil || st.reset {
			return f, false
		}
		for _, ch := range st.chunks {
			if ch.offset == r.offset {
				f.Data = ch.data
				return f, true
			}
		}
		return f, false
	case protocol.StreamAck:
		if st == nil || st.reset {
			return f, false
		}
		f = s.streamAckFrame(st)
	case protocol.MaxFlowData:
		if st == nil || st.reset {
			return f, false
		}
		f = s.maxFlowFrame(st)
	case protocol.MaxSessionData:
		f = s.maxSessionFrame()
	case protocol.Open:
		if st == nil || !st.opening {
			return f, false
		}
		f.Data = encodeJSON(st.target)
	case protocol.OpenResult:
		if st == nil || st.openResult == "" {
			return f, false
		}
		f = s.openResultFrame(st)
	case protocol.Fin:
		if st == nil || st.reset || st.localFinal == nil || st.finAck {
			return f, false
		}
		f.Offset = *st.localFinal
	case protocol.FinAck:
		if st == nil || st.remoteFinal == nil {
			return f, false
		}
		f.Offset = *st.remoteFinal
	case protocol.Reset:
		if st == nil || !st.resetPending || st.resetAcked {
			return f, false
		}
	case protocol.KeyUpdate:
		if !s.keyPending || r.value != uint64(s.current.tx.Epoch())+1 {
			return f, false
		}
	case protocol.KeyUpdateAck:
		if r.value != uint64(s.current.rx.Epoch()) {
			return f, false
		}
	case protocol.TicketRefresh:
		if s.ticketPending == 0 || r.value != s.info.TicketSerial {
			return f, false
		}
		f.Offset = remainingMS(s.info.ticketUntil, now)
		if f.Offset == 0 {
			return f, false
		}
		f.Data = []byte(s.info.Ticket)
	case protocol.ResumeState:
		f.Data = r.data
		if f.Flags == 0 && s.syncAck[f.Flow] {
			return f, false
		}
	case protocol.ResumeDone:
		if f.Flags == 0 && s.localDoneAck {
			return f, false
		}
		f.Offset = s.current.generation
		if f.Flags == 0 {
			if frame, ok := s.resumeDoneFrame(0); ok {
				f = frame
			} else {
				return f, false
			}
		} else if frame, ok := s.resumeDoneFrame(1); ok {
			f = frame
		}
	}
	return f, true
}
func (s *Session) queueRetry(r logicalRef) {
	p := s.udpPath
	if r.kind == protocol.ClassUpdate {
		if r.flags == 0 && s.classTable != nil {
			_ = s.classTable.RequestRetry(r.flow)
		}
		return
	}
	if r.kind == protocol.Datagram || r.kind == protocol.DatagramRepairFrame || r.kind == protocol.Ping || r.kind == protocol.Pong {
		return
	}
	k := r.key()
	if _, ok := p.retries[k]; !ok && len(p.retries) >= udptransport.MaxLivePackets {
		s.transportStalled()
		return
	}
	p.retries[k] = r
}

// retryClass returns the current scheduling class for a retry reference.  A
// StreamData retry deliberately reads the live flow state: a behavior
// reclassification made after loss must affect the next retry.  All control
// references remain Interactive, matching their normal queue treatment.
func (s *Session) retryClass(r logicalRef) protocol.Class {
	if r.kind == protocol.StreamData {
		return s.classFor(r.flow)
	}
	return protocol.Interactive
}

var retryClassSchedule = [...]protocol.Class{
	protocol.Interactive, protocol.Interactive, protocol.Interactive, protocol.Interactive,
	protocol.Normal, protocol.Normal,
	protocol.Bulk,
}

func retryKeyLess(a, b refKey) bool {
	if a.flow != b.flow {
		return a.flow < b.flow
	}
	if a.kind != b.kind {
		return a.kind < b.kind
	}
	if a.offset != b.offset {
		return a.offset < b.offset
	}
	if a.value != b.value {
		return a.value < b.value
	}
	return a.flags < b.flags
}

// pickRetry selects one pending retry without consuming it.  Stale references
// are removed by flushUDP after resolveRef; blocked pre-sync references are
// excluded only for this flush.  The returned class/flow cursors are advanced
// by flushUDP only after resolveRef confirms a live frame, so stale cleanup and
// an ineligible reference do not consume one of the two retry opportunities.
func (s *Session) pickRetry(skip map[refKey]bool) (refKey, logicalRef, bool) {
	p := s.udpPath
	if p == nil || len(p.retries) == 0 {
		return refKey{}, logicalRef{}, false
	}
	var byClass [3][]refKey
	for k, r := range p.retries {
		if skip != nil && skip[k] {
			continue
		}
		class := s.retryClass(r)
		if !class.Valid() {
			class = protocol.Interactive
		}
		byClass[class] = append(byClass[class], k)
	}
	for class := range byClass {
		sort.Slice(byClass[class], func(i, j int) bool { return retryKeyLess(byClass[class][i], byClass[class][j]) })
	}
	for step := 0; step < len(retryClassSchedule); step++ {
		idx := (p.retryClassCursor + step) % len(retryClassSchedule)
		class := retryClassSchedule[idx]
		keys := byClass[class]
		if len(keys) == 0 {
			continue
		}
		cursor := p.retryFlowCursor[class]
		chosen := keys[0]
		for _, k := range keys {
			if k.flow > cursor {
				chosen = k
				break
			}
		}
		return chosen, p.retries[chosen], true
	}
	return refKey{}, logicalRef{}, false
}

func (s *Session) advanceRetryCursor(class protocol.Class, flow uint64) {
	p := s.udpPath
	if p == nil || !class.Valid() {
		return
	}
	p.retryFlowCursor[class] = flow
	for i := 0; i < len(retryClassSchedule); i++ {
		idx := (p.retryClassCursor + i) % len(retryClassSchedule)
		if retryClassSchedule[idx] == class {
			p.retryClassCursor = (idx + 1) % len(retryClassSchedule)
			return
		}
	}
}
func (s *Session) transportStalled() {
	if s.current != nil && s.current.kind == "udp" {
		s.stats.UDPStalled++
	}
	s.suspend()
}
func (s *Session) retryLineage(f protocol.Frame) bool {
	if f.Kind == protocol.ClassUpdate {
		if f.Flags == 1 || s.classTable == nil {
			return false
		}
		view, err := s.classTable.Snapshot(f.Flow)
		return err == nil && view.Attempts != 0
	}
	if f.Kind == protocol.Ping || f.Kind == protocol.Pong || f.Kind == protocol.Datagram || f.Kind == protocol.DatagramRepairFrame {
		return false
	}
	if f.Kind == protocol.StreamData {
		if st := s.streams[f.Flow]; st != nil {
			for _, ch := range st.chunks {
				if ch.offset == f.Offset {
					return ch.sentGeneration == s.current.generation
				}
			}
		}
		return true
	}
	// Operation frames remain on the Session retry path. Latest-control state
	// frames are coalesced by their semantic key and reconstructed at send time;
	// all such frames conservatively skip RTT sampling, including first sends.
	return true
}
func (s *Session) udpSend(f protocol.Frame, retry, probe, feedback bool) (bool, error) {
	if s.oldUDPBusinessPaused() && isBusinessFrame(f) {
		return false, nil
	}
	if !s.datagramCanSend(f, time.Now()) {
		return true, nil
	}
	if s.terminating() {
		return false, nil
	}
	p := s.udpPath
	now := s.transportTime()
	f = s.normalizeLatestControl(f)
	operationPublication, operationSkip, operationErr := s.prepareOperation(f)
	if operationErr == operation.ErrNotDue {
		return false, nil
	}
	if operationErr != nil {
		return false, operationErr
	}
	if operationSkip {
		return true, nil
	}
	publication, skip, err := s.prepareLatestControl(f)
	if err != nil {
		return false, err
	}
	if skip {
		return true, nil
	}
	classPublication, classSkip, classErr := s.prepareClassControl(f)
	if classErr != nil {
		return false, classErr
	}
	if classSkip {
		return true, nil
	}
	plain, err := protocol.Encode([]protocol.Frame{f})
	if err != nil {
		return false, err
	}
	if feedback {
		plain, err = obfuscation.PadBounded(plain, security.MaxUDPRecordSize-security.RecordOverhead, 66)
	} else {
		plain, err = obfuscation.Pad(plain, security.MaxUDPRecordSize-security.RecordOverhead)
	}
	if err != nil {
		return false, err
	}
	size := len(plain) + security.RecordOverhead
	meta := s.current.tx.NextMeta()
	candidate := udptransport.Packet{Scope: p.scope(meta.Epoch), Number: meta.Number, Size: uint32(size), SentAt: now.Sub(p.origin), AckEliciting: !feedback, Retry: retry, Probe: probe}
	if err = p.ledger.CheckCommit(candidate); err != nil {
		if err == udptransport.ErrLimit {
			return false, nil
		}
		return false, err
	}
	if feedback {
		if p.ackTokens < float64(size) {
			s.stats.UDPACKCoalesced++
			return false, nil
		}
	} else if probe {
		if s.paceTokens-float64(size) < -2400 {
			return false, nil
		}
	} else {
		cwndDenied, pacerDenied := s.flight+size > s.cwnd, s.paceTokens < float64(size)
		if cwndDenied || pacerDenied {
			if cwndDenied {
				addTransportCounter(&s.stats.UDPCwndAdmissionDenied, 1)
			}
			if pacerDenied {
				addTransportCounter(&s.stats.UDPPacerAdmissionDenied, 1)
			}
			s.observeUDPBudgetDenial(now, cwndDenied, pacerDenied)
			return false, nil
		}
	}
	wire, actual, err := s.current.tx.Seal(plain)
	if err != nil {
		return false, err
	}
	if actual != meta {
		return false, ErrState
	}
	if s.terminating() {
		return false, nil
	}
	if err = s.current.writeUntil(wire, s.datagramWriteDeadline(f)); err != nil {
		s.datagramWriteFailed(f)
		return false, err
	}
	s.datagramCommitted(f)
	s.handoverDatagramCommitted(f)
	if !s.txDrainAt.IsZero() && meta.Epoch == s.current.tx.Epoch() {
		s.txCurrentUsed = true
	}
	if err = s.publishOperation(operationPublication); err != nil {
		return false, err
	}
	if err = s.publishLatestControl(publication, p.rtt.BasePTO()); err != nil {
		return false, err
	}
	if err = s.publishClassControl(f, classPublication, p.rtt.BasePTO()); err != nil {
		return false, err
	}
	// Write success is an indivisible owner commit; no ACK can interleave.
	committedAt := s.transportTime()
	candidate.SentAt = committedAt.Sub(p.origin)
	if _, err = p.ledger.Commit(candidate); err != nil {
		return false, err
	}
	s.recordUDPCommit(len(wire), feedback)
	if !feedback {
		s.finishUDPBudgetEpisode(committedAt)
	}
	s.stats.WireSent += uint64(len(wire))
	if f.Kind == protocol.DatagramRepairFrame {
		s.stats.FECRepairSent++
	}
	s.bytesSinceKey += uint64(len(wire))
	if feedback {
		p.ackTokens -= float64(len(wire))
		s.stats.UDPACKSent++
	} else {
		s.paceTokens -= float64(len(wire))
		p.refs[meta] = makeRef(f)
		if f.Kind == protocol.StreamData {
			if st := s.streams[f.Flow]; st != nil {
				for i := range st.chunks {
					if st.chunks[i].offset == f.Offset {
						st.chunks[i].sentGeneration = s.current.generation
					}
				}
			}
		}
		if p.deadline.IsZero() {
			p.deadline = committedAt.Add(p.pto.Interval(p.rtt.BasePTO()))
			p.lastProgress = committedAt
			p.healthAtDeadline = p.lastHealth
		}
	}
	s.flight = int(p.ledger.Snapshot().Flight)
	return true, nil
}
func (s *Session) flushUDP() {
	if s.terminating() {
		return
	}
	p := s.udpPath
	if p == nil {
		return
	}
	now := s.transportTime()
	if now.Before(p.ackTime) || now.Before(s.paceTime) {
		s.transportStalled()
		return
	}
	p.ackTokens = min(ackReserveBurst, p.ackTokens+now.Sub(p.ackTime).Seconds()*ackReserveRate)
	p.ackTime = now
	s.paceTokens = min(4800, s.paceTokens+now.Sub(s.paceTime).Seconds()*float64(s.cwnd)/max(p.rtt.Snapshot().Smoothed.Seconds(), .001))
	s.paceTime = now
	epochs := []uint32{s.current.rx.Epoch()}
	if p.rxPrevious != nil {
		epochs = append(epochs, *p.rxPrevious)
	}
	for _, epoch := range epochs {
		scope := p.scope(epoch)
		due, err := p.history.Due(scope, now.Sub(p.origin))
		if err != nil {
			continue
		}
		if !due {
			continue
		}
		snap, ok, err := p.history.Snapshot(scope, now.Sub(p.origin))
		if err != nil || !ok {
			continue
		}
		f, err := udptransport.EncodeACK(snap.ACK)
		if err != nil {
			s.cancel()
			return
		}
		sent, err := s.udpSend(f, false, false, true)
		if err != nil {
			s.suspend()
			return
		}
		if sent {
			_ = p.history.MarkSent(scope, snap.Revision)
		}
	}
	// An expiry grants this finite probe opportunity exactly once. Fresh Ping
	// never retransmits an application Datagram or releases a retained chunk.
	if p.probeRemaining > 0 {
		if p.probeSerial == math.MaxUint64 {
			s.transportStalled()
			return
		}
		token := p.probeSerial + 1
		sent, err := s.udpSend(protocol.Frame{Kind: protocol.Ping, Value: token}, false, true, false)
		if err != nil {
			s.suspend()
			return
		}
		if !sent {
			s.transportStalled()
			return
		}
		p.probeSerial = token
		p.freshTokens[token] = true
		p.probeRemaining = 0
		s.stats.UDPProbeSent++
		p.deadline = s.transportTime().Add(p.pto.Interval(p.rtt.BasePTO()))
	}
	// Retries have their own bounded two-slot budget, but must still respect
	// category and flow fairness.  Do not count stale or pre-sync references as
	// slots: resolving/removing one must not prevent a live Interactive flow
	// from using this flush.  A failed admission/write keeps the reference and
	// advances only the fairness cursor; no retry ownership is discarded.
	skipped := make(map[refKey]bool, len(p.retries))
	for slots := 0; slots < 2; {
		k, r, ok := s.pickRetry(skipped)
		if !ok {
			break
		}
		f, ok := s.resolveRef(r, now)
		if !ok {
			delete(p.retries, k)
			continue
		}
		if s.oldUDPBusinessPaused() && isBusinessFrame(f) {
			skipped[k] = true
			continue
		}
		if (!s.peerDone || !s.localDoneAck) && !syncAllowed(f) {
			skipped[k] = true
			continue
		}
		class := s.retryClass(r)
		s.advanceRetryCursor(class, k.flow)
		slots++
		sent, err := s.udpSend(f, true, false, false)
		if err != nil {
			s.suspend()
			return
		}
		if sent {
			delete(p.retries, k)
			s.stats.Retransmissions++
		}
	}
	for count := 0; count < 4; count++ {
		if s.paceTokens < 1200 || s.flight >= s.cwnd {
			if s.queue.Len() > 0 || len(p.retries) > 0 {
				cwndDenied, pacerDenied := s.flight >= s.cwnd, s.paceTokens < 1200
				if cwndDenied {
					addTransportCounter(&s.stats.UDPFlushCwndGateDenied, 1)
				}
				if pacerDenied {
					addTransportCounter(&s.stats.UDPFlushPacerGateDenied, 1)
				}
				s.observeUDPBudgetDenial(now, cwndDenied, pacerDenied)
			} else {
				s.finishUDPBudgetEpisode(now)
			}
			return
		}
		f, ok := s.nextSendFrame(count)
		if !ok {
			if s.queue.Len() == 0 && len(p.retries) == 0 {
				s.finishUDPBudgetEpisode(now)
			}
			return
		}
		f = s.normalizeLatestControl(f)
		if key, revision, tracked := latestControlRevision(f); tracked {
			ck := controlReceiptKey{kind: key.Kind, flow: key.Flow}
			if s.controlQueued[ck] == revision {
				delete(s.controlQueued, ck)
			}
		}
		if (!s.peerDone || !s.localDoneAck) && !syncAllowed(f) {
			s.enqueue(f, s.classForFrame(f))
			return
		}
		sent, err := s.udpSend(f, s.retryLineage(f), false, false)
		if err != nil {
			s.suspend()
			return
		}
		if !sent {
			if f.Kind != protocol.ClassUpdate {
				s.enqueue(f, s.classForFrame(f))
			}
			return
		}
	}
}
func syncAllowed(f protocol.Frame) bool {
	return f.Kind == protocol.ResumeState || f.Kind == protocol.ResumeDone || f.Kind == protocol.Ping || f.Kind == protocol.Pong || f.Kind == protocol.PacketAck
}
func (s *Session) observeUDPRecord(meta security.RecordMeta, frames []protocol.Frame, now time.Time) bool {
	p := s.udpPath
	if p == nil {
		s.cancel()
		return false
	}
	eliciting := false
	for _, f := range frames {
		if f.Kind != protocol.PacketAck {
			eliciting = true
		}
	}
	if _, err := p.history.Observe(p.scope(meta.Epoch), meta.Number, now.Sub(p.origin), eliciting); err != nil {
		s.cancel()
		return false
	}
	p.lastHealth = now
	return true
}
func (s *Session) udpProgress(now time.Time) {
	p := s.udpPath
	p.lastProgress = now
	p.pto.Progress()
	p.noResponseDeadlines = 0
	p.healthAtDeadline = p.lastHealth
	p.probeRemaining = 0
	p.freshTokens = map[uint64]bool{}
	s.stats.UDPTransportProgress++
	s.udpSuspect = false
	s.signalFlows()
	if s.recoveryCancel != nil {
		s.recoveryCancel()
		s.recoveryCancel = nil
	}
	if p.ledger.Snapshot().Live == 0 {
		p.deadline = time.Time{}
	} else {
		p.deadline = now.Add(p.pto.Interval(p.rtt.BasePTO()))
	}
}
func (s *Session) receiveUDPPong(token uint64, now time.Time) {
	if p := s.udpPath; p != nil && p.freshTokens[token] {
		s.udpProgress(now)
	}
}
func (s *Session) receiveUDPACK(f protocol.Frame) {
	if s.current == nil || s.current.kind != "udp" || s.udpPath == nil {
		s.stats.Dropped++
		return
	}
	a, err := udptransport.DecodeACK(f)
	if err != nil {
		s.cancel()
		return
	}
	p := s.udpPath
	now := s.transportTime()
	result, err := p.ledger.ApplyACK(p.scope(a.Epoch), a, now.Sub(p.origin), &p.rtt)
	if err != nil {
		s.cancel()
		return
	}
	s.stats.UDPACKReceived++
	s.flight = int(p.ledger.Snapshot().Flight)
	s.rtt = p.rtt.Snapshot().Smoothed
	for _, ap := range result.Packets {
		delete(p.refs, security.RecordMeta{Epoch: ap.Packet.Scope.Epoch, Number: ap.Packet.Number})
		if ap.WasLost || ap.Packet.Ordinal <= p.recoveryEnd {
			continue
		}
		size := uint64(ap.Packet.Size)
		if s.cwnd < s.ssthresh {
			s.cwnd += int(size)
		} else {
			p.avoidanceRemainder += 1200 * size
			denominator := uint64(s.cwnd)
			s.cwnd += int(p.avoidanceRemainder / denominator)
			p.avoidanceRemainder %= denominator
		}
		s.cwnd = min(s.cwnd, 256*1200)
	}
	if result.NewProgress {
		s.udpProgress(now)
	}
	s.detectUDPLoss(now)
}
func (s *Session) detectUDPLoss(now time.Time) {
	p := s.udpPath
	lost, err := p.ledger.DetectLoss(now.Sub(p.origin), p.rtt.Snapshot())
	if err != nil {
		s.transportStalled()
		return
	}
	for _, packet := range lost {
		if packet.Ordinal > p.recoveryEnd {
			s.ssthresh = max(2400, s.cwnd/2)
			s.cwnd = s.ssthresh
			p.avoidanceRemainder = 0
			p.recoveryEnd = p.ledger.Snapshot().LastOrdinal
		}
		meta := security.RecordMeta{Epoch: packet.Scope.Epoch, Number: packet.Number}
		if r, ok := p.refs[meta]; ok {
			s.queueRetry(r)
			delete(p.refs, meta)
		}
	}
	s.flight = int(p.ledger.Snapshot().Flight)
	if p.ledger.Snapshot().Live == 0 {
		p.deadline = time.Time{}
	}
}
func (s *Session) maintainUDP(now time.Time) {
	p := s.udpPath
	if p == nil {
		return
	}
	s.detectUDPLoss(now)
	if !s.active {
		return
	}
	if p.ledger.Snapshot().Live == 0 {
		p.deadline = time.Time{}
		return
	}
	if now.Sub(p.lastProgress) >= s.opts.UDPFailureBudget {
		s.transportStalled()
		return
	}
	if p.deadline.IsZero() || now.Before(p.deadline) || p.probeRemaining > 0 {
		return
	}
	if p.lastHealth.After(p.healthAtDeadline) {
		p.noResponseDeadlines = 0
	} else if p.noResponseDeadlines < 3 {
		p.noResponseDeadlines++
	}
	p.healthAtDeadline = p.lastHealth
	p.pto.Expire()
	p.probeRemaining = 1
	p.freshTokens = map[uint64]bool{}
	s.stats.UDPPTODue++
	// A busy reliable flow can keep the normal send queue cwnd-blocked while
	// probes still make progress.  In that case waiting for a fourth deadline
	// after the third PTO leaves the application-level recovery window to race
	// its own read deadline.  Two consecutive no-response deadlines plus a
	// third PTO and an active cwnd-block episode are sufficient to enter the
	// recovery candidate state.  The ordinary idle path retains the original
	// three-deadline rule, so a late authenticated health response cannot be
	// reclassified merely because the PTO counter advanced.
	if p.noResponseDeadlines >= 3 || p.noResponseDeadlines >= 2 && p.pto.Rounds() >= 3 && p.blockedByCwnd {
		s.udpSuspect = true
	}
}

// Kept here as an explicit consumer seam: the Client owner installs a
// cancellation callback only during this generation's suspect candidate.
func (s *Session) setRecoveryCancel(cancel context.CancelFunc) { s.recoveryCancel = cancel }
