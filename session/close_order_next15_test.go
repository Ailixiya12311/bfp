package session

import (
	"bfp/obfuscation"
	"bfp/protocol"
	"bfp/security"
	"errors"
	"reflect"
	"testing"
	"time"
)

func closeOrderDecodeNext15(t *testing.T, shadow *security.RecordCipher, wire []byte) ([]protocol.Frame, security.RecordMeta) {
	t.Helper()
	plain, meta, err := shadow.Open(wire)
	if err == nil {
		plain, err = obfuscation.Unpad(plain)
	}
	if err != nil {
		t.Fatal(err)
	}
	frames, err := protocol.Decode(plain)
	if err != nil {
		t.Fatal(err)
	}
	for _, frame := range frames {
		if !canonicalClose(frame) {
			t.Fatalf("close record contained noncanonical frame kind %d", frame.Kind)
		}
	}
	return frames, meta
}

func closeOrderPeerWireNext15(t *testing.T, s *Session, frames ...protocol.Frame) []byte {
	t.Helper()
	peer, err := security.NewRecordCipher(s.current.keys.Receive[:], s.current.handle, 0)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := protocol.Encode(frames)
	if err == nil {
		plain, err = obfuscation.Pad(plain, maxCloseRecordBytes-security.RecordOverhead)
	}
	if err != nil {
		t.Fatal(err)
	}
	wire, _, err := peer.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestCloseOrderPairedReceiveRegistersPeerBeforeLocalAckNext15(t *testing.T) {
	s, conn, shadow, start := closeOwnerFixture(t, false)
	s.requestClose(true, start)
	s.closeTick(start)
	if !s.closing.localPublished || len(conn.writes) != 1 {
		t.Fatal("fixture did not completely publish its own Close")
	}
	frames, _ := closeOrderDecodeNext15(t, shadow, conn.writes[0])
	if len(frames) != 1 || frames[0].Kind != protocol.SessionClose {
		t.Fatal("fixture initial request changed")
	}
	deadline := s.closing.deadline
	// The two canonical frames occupy one AEAD plaintext. receive must process
	// Close before its associated ACK, so the ACK cannot retire the control
	// owner in the gap before it learns that the peer also requested Close.
	wire := closeOrderPeerWireNext15(t, s, protocol.Frame{Kind: protocol.SessionClose}, protocol.Frame{Kind: protocol.SessionCloseAck})
	s.receive(packet{c: s.current, wire: wire})
	if !s.closing.peerRequested || !s.closing.ackPending || !s.closing.localAcked || s.closeErr != nil || s.controlContext().Err() != nil {
		t.Fatalf("paired receive lost an owed ACK: peer=%t pending=%t localAck=%t controlErr=%v result=%v", s.closing.peerRequested, s.closing.ackPending, s.closing.localAcked, s.controlContext().Err(), s.closeErr)
	}
	if s.closing.started != start || s.closing.deadline != deadline {
		t.Fatal("paired receive renewed the first close deadline")
	}
	s.closeTick(start.Add(10 * time.Millisecond))
	if len(conn.writes) != 2 || s.closing.ackAttempts != 1 || s.closing.requestAttempts != 1 || !s.closing.localPublished {
		t.Fatal("confirmed local request failed to send exactly one standalone peer ACK")
	}
	frames, _ = closeOrderDecodeNext15(t, shadow, conn.writes[1])
	if len(frames) != 1 || frames[0].Kind != protocol.SessionCloseAck {
		t.Fatal("already confirmed local request was retransmitted with peer ACK")
	}
	before := len(conn.writes)
	s.closeTick(deadline)
	if s.controlContext().Err() == nil || s.closeErr != nil {
		t.Fatal("confirmed simultaneous close did not stop at its original deadline")
	}
	s.handleCloseControl(protocol.Frame{Kind: protocol.SessionClose}, deadline.Add(time.Hour))
	s.closeTick(deadline.Add(time.Hour))
	if len(conn.writes) != before || s.closing.deadline != deadline {
		t.Fatal("late peer Close revived publication or renewed the original deadline")
	}
}

func TestCloseOrderPairedPublicationChargesBothKindsOnceNext15(t *testing.T) {
	for _, publishedFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial-pair", true: "after-own-publication"}[publishedFirst], func(t *testing.T) {
			s, conn, shadow, start := closeOwnerFixture(t, false)
			s.requestClose(true, start)
			if publishedFirst {
				s.closeTick(start)
				frames, _ := closeOrderDecodeNext15(t, shadow, conn.writes[0])
				if len(frames) != 1 || frames[0].Kind != protocol.SessionClose {
					t.Fatal("fixture did not publish its initial canonical Close")
				}
			}
			s.handleCloseControl(protocol.Frame{Kind: protocol.SessionClose}, start)
			requests, responses := s.closing.requestAttempts, s.closing.ackAttempts
			attempted, successful, wireSent := s.closing.attemptedBytes, s.closing.successfulBytes, s.stats.WireSent
			before := len(conn.writes)
			publicationTime := start
			if publishedFirst {
				s.closeTick(start)
				if len(conn.writes) != before || !s.closing.ackPending || s.closing.requestAttempts != requests || s.closing.ackAttempts != responses {
					t.Fatal("pending ACK bypassed the next local request backoff")
				}
				publicationTime = start.Add(200 * time.Millisecond)
			}
			s.closeTick(publicationTime)
			if len(conn.writes) != before+1 {
				t.Fatal("paired Close/Ack split into records or emitted a same-tick extra request")
			}
			wire := conn.writes[before]
			frames, _ := closeOrderDecodeNext15(t, shadow, wire)
			got := make([]protocol.Kind, len(frames))
			for i, frame := range frames {
				got[i] = frame.Kind
			}
			if !reflect.DeepEqual(got, []protocol.Kind{protocol.SessionClose, protocol.SessionCloseAck}) {
				t.Fatalf("paired AEAD frame order=%v want [Close,Ack]", got)
			}
			if s.closing.requestAttempts != requests+1 || s.closing.ackAttempts != responses+1 || !s.closing.localPublished {
				t.Fatal("paired publication did not charge both logical attempt budgets or retain successful request proof")
			}
			if s.closing.attemptedBytes-attempted != len(wire) || s.closing.successfulBytes-successful != len(wire) || s.stats.WireSent-wireSent != uint64(len(wire)) {
				t.Fatal("paired transaction charged its physical record bytes more or less than once")
			}
			if len(wire) > maxCloseRecordBytes || s.closing.deadline != start.Add(s.opts.CloseTimeout) || s.closing.nextRequest != publicationTime.Add(closeRetryDelay(s.closing.requestAttempts)) {
				t.Fatal("paired transaction enlarged the record/deadline bound or ignored the request backoff")
			}
			s.closeTick(publicationTime)
			if len(conn.writes) != before+1 {
				t.Fatal("same-tick close processing repeated the paired request")
			}
		})
	}
}

func TestCloseOrderPairedShortWriteCannotPublishEitherResultNext15(t *testing.T) {
	s, conn, shadow, start := closeOwnerFixture(t, true)
	s.requestClose(true, start)
	s.handleCloseControl(protocol.Frame{Kind: protocol.SessionClose}, start)
	s.closeTick(start)
	if len(conn.writes) != 1 {
		t.Fatal("short-writing pair did not make exactly one physical attempt")
	}
	frames, _ := closeOrderDecodeNext15(t, shadow, conn.writes[0])
	if len(frames) != 2 || frames[0].Kind != protocol.SessionClose || frames[1].Kind != protocol.SessionCloseAck {
		t.Fatal("short-writing pair attempted a different canonical frame sequence")
	}
	if s.closing.requestAttempts != 1 || s.closing.ackAttempts != 1 || s.closing.attemptedBytes != len(conn.writes[0]) || s.closing.successfulBytes != 0 || s.stats.WireSent != 0 || s.closing.localPublished || s.closing.localAcked {
		t.Fatal("short-writing pair created complete publication/ACK proof or incorrect physical attempt accounting")
	}
	if !errors.Is(s.closeErr, ErrCloseUnconfirmed) || s.controlContext().Err() == nil {
		t.Fatal("failed paired write reported a confirmed close result")
	}
	s.handleCloseControl(protocol.Frame{Kind: protocol.SessionCloseAck}, start.Add(time.Millisecond))
	if s.closing.localAcked || !errors.Is(s.closeErr, ErrCloseUnconfirmed) {
		t.Fatal("late ACK after failed initial pair confirmed an unpublished request")
	}
}

func TestCloseOrderPairingRespectsExhaustedAndPeerFirstBudgetsNext15(t *testing.T) {
	for _, mode := range []string{"peer-first", "request-budget-exhausted", "local-already-acked"} {
		t.Run(mode, func(t *testing.T) {
			s, conn, shadow, start := closeOwnerFixture(t, false)
			if mode != "peer-first" {
				s.requestClose(true, start)
			}
			s.handleCloseControl(protocol.Frame{Kind: protocol.SessionClose}, start)
			if mode == "request-budget-exhausted" {
				s.closing.requestAttempts = maxCloseRequests
				s.closing.localPublished = true
			} else if mode == "local-already-acked" {
				s.closing.localAcked = true
				s.closing.localPublished = true
				s.closeErr = nil
			}
			requests := s.closing.requestAttempts
			s.closeTick(start)
			if len(conn.writes) != 1 {
				t.Fatal("standalone ACK path made an unexpected number of records")
			}
			frames, _ := closeOrderDecodeNext15(t, shadow, conn.writes[0])
			if len(frames) != 1 || frames[0].Kind != protocol.SessionCloseAck || s.closing.requestAttempts != requests || s.closing.ackAttempts != 1 {
				t.Fatal("ACK upgraded a peer-first intent or exceeded its own request budget")
			}
			if mode == "peer-first" && s.localClose.Load() {
				t.Fatal("peer-first close was upgraded to a local request")
			}
		})
	}
}

func TestCloseOrderPairedFloodRetainsOriginalDeadlineAndByteBudgetNext15(t *testing.T) {
	s, conn, shadow, start := closeOwnerFixture(t, false)
	s.requestClose(true, start)
	s.handleCloseControl(protocol.Frame{Kind: protocol.SessionClose}, start)
	s.closeTick(start)
	deadline := start.Add(s.opts.CloseTimeout)
	for step := 1; step <= 29; step++ {
		now := start.Add(time.Duration(step) * 100 * time.Millisecond)
		for flood := 0; flood < 25; flood++ {
			s.handleCloseControl(protocol.Frame{Kind: protocol.SessionClose}, now)
		}
		s.closeTick(now)
		if s.closing.started != start || s.closing.deadline != deadline {
			t.Fatal("repeated peer requests renewed paired close's original deadline")
		}
	}
	requestFrames, ackFrames, bytes := 0, 0, 0
	metas := make(map[security.RecordMeta]bool)
	for _, wire := range conn.writes {
		frames, meta := closeOrderDecodeNext15(t, shadow, wire)
		if len(frames) < 1 || len(frames) > 2 || len(frames) == 2 && (frames[0].Kind != protocol.SessionClose || frames[1].Kind != protocol.SessionCloseAck) {
			t.Fatal("bounded flood emitted an unordered or unsupported close transaction")
		}
		for _, frame := range frames {
			if frame.Kind == protocol.SessionClose {
				requestFrames++
			} else {
				ackFrames++
			}
		}
		if len(wire) > maxCloseRecordBytes || metas[meta] {
			t.Fatal("paired flood exceeded the original per-record limit or reused a record number")
		}
		metas[meta] = true
		bytes += len(wire)
	}
	if requestFrames != maxCloseRequests || ackFrames < 1 || ackFrames > maxCloseResponses || len(conn.writes) > maxCloseRequests+maxCloseResponses || bytes > maxCloseWireBytes || bytes != s.closing.attemptedBytes || bytes != s.closing.successfulBytes || s.stats.WireSent != uint64(bytes) {
		t.Fatalf("paired flood changed logical or physical budgets: requests=%d ACKs=%d records=%d actualBytes=%d attempted=%d successful=%d", requestFrames, ackFrames, len(conn.writes), bytes, s.closing.attemptedBytes, s.closing.successfulBytes)
	}
	s.closeTick(deadline)
	before := len(conn.writes)
	if s.controlContext().Err() == nil || !errors.Is(s.closeErr, ErrCloseUnconfirmed) {
		t.Fatal("unconfirmed paired flood failed to terminate at its original deadline")
	}
	s.handleCloseControl(protocol.Frame{Kind: protocol.SessionClose}, deadline.Add(time.Hour))
	s.closeTick(deadline.Add(time.Hour))
	if len(conn.writes) != before || s.closing.deadline != deadline {
		t.Fatal("late flood revived paired close publication or extended its deadline")
	}
}

func TestCloseOrderPendingACKPreservesOriginalRequestBackoffNext15(t *testing.T) {
	s, conn, shadow, start := closeOwnerFixture(t, false)
	s.requestClose(true, start)
	s.handleCloseControl(protocol.Frame{Kind: protocol.SessionClose}, start)
	// Each timestamp is an original request retry opportunity. Fresh peer
	// requests before it must coalesce without accelerating this schedule.
	for i, delay := range []time.Duration{0, 200 * time.Millisecond, 600 * time.Millisecond, 1400 * time.Millisecond, 2400 * time.Millisecond} {
		due := start.Add(delay)
		if i > 0 {
			beforeDue := due.Add(-time.Nanosecond)
			s.handleCloseControl(protocol.Frame{Kind: protocol.SessionClose}, beforeDue)
			s.closeTick(beforeDue)
			if len(conn.writes) != i || s.closing.requestAttempts != i || s.closing.ackAttempts != i || !s.closing.ackPending {
				t.Fatalf("peer request accelerated retry %d before its original opportunity", i+1)
			}
		}
		s.closeTick(due)
		if len(conn.writes) != i+1 || s.closing.requestAttempts != i+1 || s.closing.ackAttempts != i+1 {
			t.Fatalf("original retry opportunity %v did not emit one paired transaction", delay)
		}
		frames, _ := closeOrderDecodeNext15(t, shadow, conn.writes[i])
		if len(frames) != 2 || frames[0].Kind != protocol.SessionClose || frames[1].Kind != protocol.SessionCloseAck {
			t.Fatalf("pending ACK was not ordered behind the request at %v", delay)
		}
		if s.closing.deadline != start.Add(s.opts.CloseTimeout) || s.closing.nextRequest != due.Add(closeRetryDelay(i+1)) {
			t.Fatal("paired retry changed the original deadline or backoff state")
		}
	}
	// After all five request opportunities, the ACK-only reserve can still
	// respond at its original 200ms minimum interval.
	s.handleCloseControl(protocol.Frame{Kind: protocol.SessionClose}, start.Add(2600*time.Millisecond))
	s.closeTick(start.Add(2600 * time.Millisecond))
	frames, _ := closeOrderDecodeNext15(t, shadow, conn.writes[5])
	if len(frames) != 1 || frames[0].Kind != protocol.SessionCloseAck || s.closing.requestAttempts != maxCloseRequests || s.closing.ackAttempts != 6 {
		t.Fatal("exhausted requests starved the independent remaining ACK budget")
	}
}

func TestCloseOrderPeerFirstFloodCanUseOriginalEightACKReserveNext15(t *testing.T) {
	s, conn, shadow, start := closeOwnerFixture(t, false)
	s.handleCloseControl(protocol.Frame{Kind: protocol.SessionClose}, start)
	s.closeTick(start)
	for i := 1; i < maxCloseResponses; i++ {
		due := start.Add(time.Duration(i) * closeResponseInterval)
		s.handleCloseControl(protocol.Frame{Kind: protocol.SessionClose}, due.Add(-time.Nanosecond))
		s.closeTick(due.Add(-time.Nanosecond))
		if len(conn.writes) != i {
			t.Fatal("peer-first ACK bypassed its original 200ms minimum interval")
		}
		s.closeTick(due)
	}
	if len(conn.writes) != maxCloseResponses || s.closing.ackAttempts != maxCloseResponses || s.closing.requestAttempts != 0 || s.localClose.Load() || s.closing.localPublished {
		t.Fatal("peer-first responder changed the original eight-ACK reserve or upgraded intent")
	}
	bytes := 0
	for _, wire := range conn.writes {
		frames, _ := closeOrderDecodeNext15(t, shadow, wire)
		if len(frames) != 1 || frames[0].Kind != protocol.SessionCloseAck || len(wire) > maxCloseRecordBytes {
			t.Fatal("peer-first responder emitted a request or exceeded its original record bound")
		}
		bytes += len(wire)
	}
	if bytes != s.closing.attemptedBytes || bytes != s.closing.successfulBytes || bytes > maxCloseWireBytes {
		t.Fatal("peer-first ACK physical byte accounting changed")
	}
	s.handleCloseControl(protocol.Frame{Kind: protocol.SessionClose}, start.Add(2*time.Second))
	s.closeTick(start.Add(2 * time.Second))
	if len(conn.writes) != maxCloseResponses || s.closing.deadline != start.Add(s.opts.CloseTimeout) {
		t.Fatal("exhausted peer-first ACK reserve sent an extra record or renewed its deadline")
	}
}

func TestCloseOrderShortEffectiveDeadlineDoesNotStarvePendingACKNext15(t *testing.T) {
	for _, mode := range []string{"close-timeout", "immutable-lifetime", "suspended-retention"} {
		t.Run(mode, func(t *testing.T) {
			s, conn, shadow, start := closeOwnerFixture(t, false)
			deadline := start.Add(150 * time.Millisecond)
			switch mode {
			case "close-timeout":
				s.opts.CloseTimeout = 150 * time.Millisecond
			case "immutable-lifetime":
				s.info.lifetimeUntil = deadline
			case "suspended-retention":
				s.suspendedAt = deadline.Add(-s.opts.RetainTimeout)
			}
			s.requestClose(true, start)
			s.closeTick(start)
			initial, _ := closeOrderDecodeNext15(t, shadow, conn.writes[0])
			if len(initial) != 1 || initial[0].Kind != protocol.SessionClose || !s.closing.localPublished || s.closing.nextRequest != start.Add(200*time.Millisecond) || s.closing.deadline != deadline {
				t.Fatal("short cutoff fixture did not begin with its original successful request/backoff")
			}
			attempted, successful, wireSent := s.closing.attemptedBytes, s.closing.successfulBytes, s.stats.WireSent
			arrival := start.Add(10 * time.Millisecond)
			s.handleCloseControl(protocol.Frame{Kind: protocol.SessionClose}, arrival)
			s.closeTick(arrival)
			if len(conn.writes) != 2 || s.closing.requestAttempts != 2 || s.closing.ackAttempts != 1 || s.closing.ackPending {
				t.Fatal("pending ACK was delayed to a retry opportunity beyond the immutable cutoff")
			}
			frames, _ := closeOrderDecodeNext15(t, shadow, conn.writes[1])
			if len(frames) != 2 || frames[0].Kind != protocol.SessionClose || frames[1].Kind != protocol.SessionCloseAck {
				t.Fatal("short-window exception omitted atomic Close-before-ACK ordering")
			}
			wireBytes := len(conn.writes[1])
			if s.closing.attemptedBytes-attempted != wireBytes || s.closing.successfulBytes-successful != wireBytes || s.stats.WireSent-wireSent != uint64(wireBytes) || wireBytes > maxCloseRecordBytes || s.closing.attemptedBytes > maxCloseWireBytes {
				t.Fatal("short-window exception charged paired physical bytes incorrectly")
			}
			if s.closing.started != start || s.closing.deadline != deadline || s.closing.nextRequest != arrival.Add(closeRetryDelay(2)) {
				t.Fatal("short-window exception renewed the original cutoff or failed to charge its next retry")
			}
			s.closeTick(deadline)
			if s.controlContext().Err() == nil || !errors.Is(s.closeErr, ErrCloseUnconfirmed) {
				t.Fatal("unacknowledged short-window close did not stop honestly at its original cutoff")
			}
			s.handleCloseControl(protocol.Frame{Kind: protocol.SessionClose}, deadline.Add(time.Hour))
			s.closeTick(deadline.Add(time.Hour))
			if len(conn.writes) != 2 || s.closing.deadline != deadline {
				t.Fatal("late request revived or renewed the expired short-window pair")
			}
		})
	}
}
