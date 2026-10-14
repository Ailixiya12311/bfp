package session

import (
	"bfp/protocol"
	"bfp/security"
	"context"
	"errors"
	"testing"
)

// These tests exercise the Session boundary around operation receipts.  The
// operation table itself tests retry arithmetic; this layer proves that a
// receipt cannot complete a different logical request before frame semantics
// and the current carrier generation have been checked.

func TestTerminalAckMismatchDoesNotCompleteFINOperation(t *testing.T) {
	s, _, st := actorFlow(t, 32)
	defer s.Close()
	if err := s.call(context.Background(), func() {
		final := uint64(5)
		st.localFinal = &final
		request := protocol.Frame{Kind: protocol.Fin, Flow: st.flow.id, Offset: final}
		if !s.ensureOperation(request) {
			t.Fatal("failed to create FIN operation")
		}
		key, ok := requestOperationKey(request)
		if !ok {
			t.Fatal("FIN operation key missing")
		}
		s.handle(protocol.Frame{Kind: protocol.FinAck, Flow: st.flow.id, Offset: final - 1})
		state, err := s.operations.Snapshot(key)
		if err != nil {
			t.Fatal(err)
		}
		if state.Completed {
			t.Fatal("mismatched FIN_ACK completed the FIN operation")
		}
	}); err != nil && !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if s.ctx.Err() == nil {
		t.Fatal("mismatched FIN_ACK did not fail the authenticated Session")
	}
}

func TestTerminalAckMismatchDoesNotCompleteRESETOperation(t *testing.T) {
	s, _, st := actorFlow(t, 32)
	defer s.Close()
	if err := s.call(context.Background(), func() {
		st.resetPending = true
		request := protocol.Frame{Kind: protocol.Reset, Flow: st.flow.id}
		if !s.ensureOperation(request) {
			t.Fatal("failed to create RESET operation")
		}
		key, ok := requestOperationKey(request)
		if !ok {
			t.Fatal("RESET operation key missing")
		}
		s.handle(protocol.Frame{Kind: protocol.ResetAck, Flow: st.flow.id, Flags: 1})
		state, err := s.operations.Snapshot(key)
		if err != nil {
			t.Fatal(err)
		}
		if state.Completed {
			t.Fatal("malformed RESET_ACK completed the RESET operation")
		}
		if st.resetAcked || !st.resetPending {
			t.Fatal("malformed RESET_ACK changed reset state")
		}
	}); err != nil && !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if s.ctx.Err() == nil {
		t.Fatal("malformed RESET_ACK did not fail the authenticated Session")
	}
}

func TestFutureKeyUpdateAckDoesNotCompleteCurrentOperation(t *testing.T) {
	s, _, _ := actorFlow(t, 32)
	defer s.Close()
	var key [32]byte
	var handle [16]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	tx, err := security.NewRecordCipher(key[:], handle, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.call(context.Background(), func() {
		s.current = &carrier{kind: "tcp", generation: 1, tx: tx}
		s.keyPending = true
		request := protocol.Frame{Kind: protocol.KeyUpdate, Value: 1}
		if !s.ensureOperation(request) {
			t.Fatal("failed to create KEY_UPDATE operation")
		}
		key, ok := requestOperationKey(request)
		if !ok {
			t.Fatal("KEY_UPDATE operation key missing")
		}
		s.handle(protocol.Frame{Kind: protocol.KeyUpdateAck, Value: 2})
		state, err := s.operations.Snapshot(key)
		if err != nil {
			t.Fatal(err)
		}
		if state.Completed {
			t.Fatal("future KEY_UPDATE_ACK completed the current key operation")
		}
	}); err != nil && !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if s.ctx.Err() == nil {
		t.Fatal("future KEY_UPDATE_ACK did not fail the authenticated Session")
	}
}

func TestTicketAckOnlyClearsMatchingPendingIssue(t *testing.T) {
	s, _, _ := actorFlow(t, 32)
	defer s.Close()
	if err := s.call(context.Background(), func() {
		s.client = false
		s.ticketPending = 7
		request := protocol.Frame{Kind: protocol.TicketRefresh, Value: 7}
		if !s.ensureOperation(request) {
			t.Fatal("failed to create ticket operation")
		}
		key, ok := acknowledgementOperationKey(protocol.Frame{Kind: protocol.TicketRefreshAck, Value: 7})
		if !ok {
			t.Fatal("ticket acknowledgement key missing")
		}
		stamp := s.operationStamp(s.transportTime())
		publication, err := s.operations.Prepare(key, stamp)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.operations.Publish(publication, stamp, 1); err != nil {
			t.Fatal(err)
		}
		s.handle(protocol.Frame{Kind: protocol.TicketRefreshAck, Value: 8})
		if s.ticketPending != 7 {
			t.Fatal("future ticket ACK cleared the pending issue")
		}
		state, err := s.operations.Snapshot(key)
		if err != nil {
			t.Fatal(err)
		}
		if state.Completed {
			t.Fatal("future ticket ACK completed the pending issue")
		}
		s.handle(protocol.Frame{Kind: protocol.TicketRefreshAck, Value: 7})
		if s.ticketPending != 0 {
			t.Fatal("matching ticket ACK did not clear the pending issue")
		}
		state, err = s.operations.Snapshot(key)
		if err != nil {
			t.Fatal(err)
		}
		if !state.Completed {
			t.Fatal("matching ticket ACK did not complete its operation")
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestResumeDoneAckMustMatchDeclaredSnapshotCount(t *testing.T) {
	s, _, st := actorFlow(t, 32)
	defer s.Close()
	if err := s.call(context.Background(), func() {
		s.current = &carrier{kind: "tcp", generation: 4}
		s.syncFrames = []protocol.Frame{{Kind: protocol.ResumeState, Flow: st.flow.id, Value: 4, Data: []byte(`{"i":1}`)}}
		s.syncAck = map[uint64]bool{st.flow.id: true}
		s.localDoneAck = false
		request := protocol.Frame{Kind: protocol.ResumeDone, Flow: 1, Offset: 4, Value: 64}
		if !s.ensureOperation(request) {
			t.Fatal("failed to create RESUME_DONE operation")
		}
		key, ok := requestOperationKey(request)
		if !ok {
			t.Fatal("RESUME_DONE operation key missing")
		}
		s.handle(protocol.Frame{Kind: protocol.ResumeDone, Flags: 1, Flow: 2, Offset: 4})
		state, err := s.operations.Snapshot(key)
		if err != nil {
			t.Fatal(err)
		}
		if state.Completed {
			t.Fatal("wrong RESUME_DONE count completed the operation")
		}
		if s.localDoneAck {
			t.Fatal("wrong RESUME_DONE count marked recovery complete")
		}
	}); err != nil && !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if s.ctx.Err() == nil {
		t.Fatal("wrong RESUME_DONE count did not fail the authenticated Session")
	}
}

func TestOpenResultForUnknownFlowCannotCompleteOpenOperation(t *testing.T) {
	s, _, st := actorFlow(t, 32)
	defer s.Close()
	if err := s.call(context.Background(), func() {
		s.client = true
		st.opening = true
		request := protocol.Frame{Kind: protocol.Open, Flow: st.flow.id}
		if !s.ensureOperation(request) {
			t.Fatal("failed to create OPEN operation")
		}
		key, ok := requestOperationKey(request)
		if !ok {
			t.Fatal("OPEN operation key missing")
		}
		s.handle(protocol.Frame{Kind: protocol.OpenResult, Flow: st.flow.id + 1, Offset: 1, Data: []byte("ok")})
		state, err := s.operations.Snapshot(key)
		if err != nil {
			t.Fatal(err)
		}
		if state.Completed {
			t.Fatal("unknown-flow OPEN_RESULT completed the OPEN operation")
		}
	}); err != nil && !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if s.ctx.Err() == nil {
		t.Fatal("unknown-flow OPEN_RESULT did not fail the authenticated Session")
	}
}
