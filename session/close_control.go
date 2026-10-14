package session

import (
	"bfp/obfuscation"
	"bfp/protocol"
	"bfp/security"
	"bytes"
	"context"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

const (
	maxCloseRequests      = 5
	maxCloseResponses     = 8
	maxCloseRecordBytes   = protocol.HeaderSize + obfuscation.MaxOverhead + security.RecordOverhead
	maxCloseWireBytes     = (maxCloseRequests + maxCloseResponses) * maxCloseRecordBytes
	closeResponseInterval = 200 * time.Millisecond
)

// Intent is immutable and visible before business cancellation or actor work.
// Admission commits and its publication share admissionMu; it never holds that
// gate while waiting for the actor, closing a target, or writing a carrier.
type closeIntent struct{ started time.Time }

// Exactly one request slot and one responder slot survive business cleanup.
// Attempts (including failed writes) and successful publication are separate.
type closeState struct {
	started, deadline               time.Time
	localPublished, localAcked      bool
	peerRequested, ackPending       bool
	requestAttempts, ackAttempts    int
	attemptedBytes, successfulBytes int
	nextRequest, nextAck            time.Time
}

func (s *Session) terminating() bool {
	return s.closeIntent.Load() != nil || s.ctx != nil && s.ctx.Err() != nil
}

// The lifetime of a graceful control drain is independent of a frozen or
// advanced transport-diagnostic clock. Production time.Now retains Go's
// monotonic component; owner-only transition fixtures may opt into a separate
// immutable virtual close clock before any actor or caller starts.
func (s *Session) closeTime() time.Time {
	if s.closeNow != nil {
		return s.closeNow()
	}
	return time.Now()
}

// Synthetic transition fixtures have only ctx. Production always has two
// independent contexts derived from the same parent.
func (s *Session) controlContext() context.Context {
	if s.controlCtx != nil {
		return s.controlCtx
	}
	return s.businessContext()
}

func (s *Session) businessContext() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

func (s *Session) requestClose(local bool, now time.Time) {
	s.admissionMu.Lock()
	if s.closeIntent.Load() == nil {
		// Publish the first graceful intent's origin before stopBusiness can
		// wake observers. An earlier abort retains its existing source; this
		// diagnostic neither changes the intent nor serializes cancellation.
		origin := "peer_close"
		if local {
			origin = "local_close"
		}
		source := origin + "@unknown"
		if _, file, line, ok := runtime.Caller(1); ok {
			source = origin + "@" + filepath.Base(file) + ":" + strconv.Itoa(line)
		}
		s.terminationSource.CompareAndSwap(nil, &source)
		s.markBackendTerminal()
		s.localClose.Store(local)
		s.closeIntent.Store(&closeIntent{started: now})
	}
	s.admissionMu.Unlock()
	if s.stopBusiness != nil {
		s.stopBusiness()
	}
	// The carrier pointer is published only after an admission-gated attach.
	// Tighten an already-running private TCP write without reading actor state;
	// a shared server UDP socket never receives a per-Session deadline.
	if c := s.boundCarrier.Load(); c != nil {
		c.limitWrite(s.closeIntent.Load().started.Add(s.opts.CloseTimeout))
	}
	select {
	case s.closeWake <- struct{}{}:
	default:
	}
}

// This gate is for bounded actor admission commits. Read-only/admin calls and
// late backend completion retain call(), so late sockets can still be closed.
func (s *Session) businessCall(ctx context.Context, fn func()) error {
	if s.terminating() {
		return ErrClosed
	}
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(s.businessContext(), cancel)
	defer stop()
	denied := false
	err := s.call(work, func() {
		s.admissionMu.RLock()
		defer s.admissionMu.RUnlock()
		if s.terminating() {
			denied = true
			return
		}
		fn()
	})
	if denied || err != nil && s.terminating() {
		return ErrClosed
	}
	return err
}

// No RESET, credit publication or other business output is generated here.
// A noncooperative custom Backend/Conn may outlive cancellation, but any result
// can only release its retained resources, never refill or install a target.
func (s *Session) cleanupBusiness(now time.Time) {
	if s.businessCleaned {
		return
	}
	s.businessCleaned = true
	if s.dialResults != nil {
		s.dialResults.retire()
	}
	if s.closeBackend != nil {
		s.closeBackend()
	}
	if s.closeLocalAddressScope != nil {
		s.closeLocalAddressScope()
	}
	s.finishUDPBudgetEpisode(now)
	if s.recoveryCancel != nil {
		s.recoveryCancel()
		s.recoveryCancel = nil
	}
	s.stats.TCPRecoveryInFlight = false
	for _, st := range s.streams {
		st.reset = true
		if st.dialCancel != nil {
			st.dialCancel()
			st.dialCancel = nil
		}
		if st.targetConn != nil {
			_ = st.targetConn.Close()
			st.targetConn = nil
		}
		st.chunks, st.segments, st.datagrams, st.completed = nil, nil, nil, nil
		st.txDatagrams = nil
		st.txDatagramReserved = 0
		st.txClassifier = nil
		st.target = protocol.Target{}
		st.flow.mu.Lock()
		st.flow.buffer = bytes.Buffer{}
		st.flow.messages = nil
		st.flow.mu.Unlock()
		st.flow.fail(ErrClosed)
	}
	s.streams, s.resetTombstones = nil, nil
	s.queue, s.pending = nil, nil
	s.txDatagramReserved, s.txDatagramQueued = 0, 0
	s.controlTable, s.operations, s.classTable = nil, nil, nil
	s.controlReceipts, s.controlQueued = nil, nil
	s.syncFrames, s.syncAck, s.syncReceived = nil, nil, nil
	s.resumeBaseline, s.peerResumeDone = nil, nil
	s.udpPath = nil // drop retained business references, no fabricated cwnd reset
	s.active, s.synced, s.udpSuspect = false, false, false
	s.stats.TXBuffered, s.stats.RXBuffered = 0, 0
	s.info.Secret, s.info.Ticket, s.info.Challenge = nil, "", nil
	s.info.Handle = nil
	s.ticketPending = 0
	// Dial workers captured their backend before launch, and their typed result
	// mailbox is retired. A retained closed Session need not pin that backend.
	s.backend, s.closeBackend = nil, nil
	s.localAddressScope, s.closeLocalAddressScope = nil, nil
	s.dialing = 0
}

func (s *Session) beginCloseControl(now time.Time) {
	intent := s.closeIntent.Load()
	if intent == nil || !s.closing.started.IsZero() {
		return
	}
	s.closing.started = intent.started
	s.closing.deadline = intent.started.Add(s.opts.CloseTimeout)
	if !s.info.lifetimeUntil.IsZero() {
		s.closing.deadline = earlier(s.closing.deadline, s.info.lifetimeUntil)
	}
	if !s.suspendedAt.IsZero() {
		s.closing.deadline = earlier(s.closing.deadline, s.suspendedAt.Add(s.opts.RetainTimeout))
	}
	// Transport accounting keeps its own clock and must not turn a fixed 50ms
	// diagnostic episode into the difference between wall time and its origin.
	s.cleanupBusiness(s.transportTime())
}

func canonicalClose(f protocol.Frame) bool {
	return (f.Kind == protocol.SessionClose || f.Kind == protocol.SessionCloseAck) &&
		f.Flags == 0 && f.Flow == 0 && f.Offset == 0 && f.Value == 0 && len(f.Data) == 0
}

func (s *Session) handleCloseControl(f protocol.Frame, now time.Time) {
	if s.controlContext().Err() != nil {
		return
	}
	if !canonicalClose(f) {
		s.cancel()
		return
	}
	if !s.closing.deadline.IsZero() && !now.Before(s.closing.deadline) {
		s.stopCloseControl()
		return
	}
	if f.Kind == protocol.SessionClose {
		s.requestClose(false, now)
		s.beginCloseControl(now)
		s.closing.peerRequested = true
		if s.closing.ackAttempts < maxCloseResponses {
			s.closing.ackPending = true
		}
		return
	}
	// receive() has already enforced the current carrier and AEAD replay scope.
	// Write success is the local publication proof; enqueue/Seal/PacketAck are
	// insufficient and an unsolicited ACK must not terminate an open Session.
	if s.localClose.Load() && s.closing.localPublished {
		s.closing.localAcked = true
		s.closeErr = nil
		if !s.closing.peerRequested {
			s.stopCloseControl()
		}
	}
}

func closeRetryDelay(attempt int) time.Duration {
	switch attempt {
	case 1:
		return 200 * time.Millisecond
	case 2:
		return 400 * time.Millisecond
	case 3:
		return 800 * time.Millisecond
	default:
		return time.Second
	}
}

func (s *Session) stopCloseControl() {
	if s.closing.localAcked || !s.localClose.Load() && s.closing.peerRequested {
		s.closeErr = nil
	} else {
		s.closeErr = ErrCloseUnconfirmed
	}
	if s.stopControl != nil {
		s.stopControl()
	} else if s.cancel != nil {
		s.cancel()
	}
}

func (s *Session) closeTick(now time.Time) {
	if s.closeIntent.Load() == nil {
		return
	}
	s.beginCloseControl(now)
	if s.controlContext().Err() != nil {
		return
	}
	if !now.Before(s.closing.deadline) || s.authority != nil && s.authority.revoked.Load() {
		s.stopCloseControl()
		return
	}
	if !closeCarrierAvailable(s.current) {
		s.stopCloseControl()
		return
	}
	// A reply is owed only to authenticated requests. Floods coalesce into one
	// bit; successful or failed attempts share the same fixed budget/deadline.
	// An unconfirmed local request must precede its reply in one record. Wait
	// for the original request retry time rather than letting peer requests
	// consume all five local attempts at the response interval.
	// If that retry cannot occur before the fixed deadline, the owed reply may
	// carry one early request instead of withholding its ACK until expiry.
	localRequestPending := s.localClose.Load() && !s.closing.localAcked && s.closing.requestAttempts < maxCloseRequests
	if s.closing.ackPending && s.closing.ackAttempts < maxCloseResponses && !now.Before(s.closing.nextAck) &&
		(!localRequestPending || s.closePairReady(now)) {
		s.closing.ackPending = false
		if !s.sendCloseControl(protocol.SessionCloseAck, now) {
			return
		}
		s.closing.nextAck = now.Add(closeResponseInterval)
	}
	if s.localClose.Load() && !s.closing.localAcked && s.closing.requestAttempts < maxCloseRequests && !now.Before(s.closing.nextRequest) {
		if !s.sendCloseControl(protocol.SessionClose, now) {
			return
		}
		s.closing.nextRequest = now.Add(closeRetryDelay(s.closing.requestAttempts))
	}
}

func (s *Session) closePairReady(now time.Time) bool {
	return !now.Before(s.closing.nextRequest) || !s.closing.nextRequest.Before(s.closing.deadline)
}

// A transport label alone cannot authorize a close publication. Some owner
// transition tests intentionally use unbound carriers, and an incomplete
// binding has neither authenticated response state nor a usable write path.
func closeCarrierAvailable(c *carrier) bool {
	if c == nil || c.tx == nil || c.rx == nil {
		return false
	}
	if c.closed != nil {
		select {
		case <-c.closed:
			return false
		default:
		}
	}
	switch c.kind {
	case "tcp":
		return c.conn != nil && c.framer != nil
	case "udp":
		if c.udp != nil {
			return c.remote != nil
		}
		return c.conn != nil
	default:
		return false
	}
}

func (s *Session) sendCloseControl(kind protocol.Kind, now time.Time) bool {
	if !now.Before(s.closing.deadline) || !closeCarrierAvailable(s.current) {
		s.stopCloseControl()
		return false
	}
	frames := []protocol.Frame{{Kind: kind}}
	// During simultaneous close, a standalone ACK can overtake our request:
	// the peer would stop its control owner before seeing the request it owes
	// an ACK for. Put the pending local request before that ACK in one record.
	// AEAD authenticates the complete ordered transaction, so UDP cannot
	// reorder the two controls. Both consume their existing fixed budgets.
	paired := kind == protocol.SessionCloseAck && s.localClose.Load() &&
		!s.closing.localAcked && s.closing.requestAttempts < maxCloseRequests && s.closePairReady(now)
	if paired {
		frames = []protocol.Frame{{Kind: protocol.SessionClose}, {Kind: protocol.SessionCloseAck}}
	}
	plain, err := protocol.Encode(frames)
	if err == nil {
		// Pairing cannot enlarge the original per-record or cumulative budget.
		plain, err = obfuscation.Pad(plain, maxCloseRecordBytes-security.RecordOverhead)
	}
	if err != nil {
		s.cancel()
		return false
	}
	wire, _, err := s.current.tx.Seal(plain)
	if err != nil || len(wire) > maxCloseRecordBytes || s.closing.attemptedBytes+len(wire) > maxCloseWireBytes {
		s.cancel()
		return false
	}
	// Charging occurs BEFORE any physical write, including a partial/failing
	// write. Publication occurs only after the complete write returns success.
	if kind == protocol.SessionClose || paired {
		s.closing.requestAttempts++
	}
	if kind == protocol.SessionCloseAck {
		s.closing.ackAttempts++
	}
	s.closing.attemptedBytes += len(wire)
	if err = s.current.writeUntil(wire, s.closing.deadline); err != nil {
		s.stopCloseControl()
		return false
	}
	s.closing.successfulBytes += len(wire)
	s.stats.WireSent += uint64(len(wire))
	if kind == protocol.SessionClose || paired {
		s.closing.localPublished = true
		if paired {
			s.closing.nextRequest = now.Add(closeRetryDelay(s.closing.requestAttempts))
		}
	}
	return true
}
