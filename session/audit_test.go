package session

import (
	"bfp/internal/operation"
	"bfp/protocol"
	"bfp/scheduler"
	"bfp/security"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestAuditCarrierAttachDropsSupersededRecoveryOperations(t *testing.T) {
	s := newSession(context.Background(), sessionInfo{ID: "resume-generation"}, Options{}, true, nil)
	defer s.Close()
	if err := s.call(context.Background(), func() {
		s.current = &carrier{kind: "tcp", generation: 1}
		now := s.operationStamp(time.Now())
		for _, key := range []operation.Key{
			{Kind: protocol.ResumeState, Flow: 1, Serial: 1},
			{Kind: protocol.ResumeDone, Serial: 1},
			{Kind: protocol.KeyUpdate, Serial: 1},
			{Kind: protocol.Open, Flow: 1},
		} {
			if _, err := s.operations.Start(key, now); err != nil {
				t.Fatal(err)
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.attach(&carrier{kind: "tcp", generation: 2}, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.call(context.Background(), func() {
		if s.operations.Has(operation.Key{Kind: protocol.ResumeState, Flow: 1, Serial: 1}) || s.operations.Has(operation.Key{Kind: protocol.ResumeDone, Serial: 1}) || s.operations.Has(operation.Key{Kind: protocol.KeyUpdate, Serial: 1}) {
			t.Fatal("old carrier recovery operation remained after attach")
		}
		if !s.operations.Has(operation.Key{Kind: protocol.Open, Flow: 1}) {
			t.Fatal("non-recovery operation was removed during attach")
		}
		if _, created, err := s.operations.Ensure(operation.Key{Kind: protocol.KeyUpdate, Serial: 1}, s.operationStamp(time.Now())); err != nil || !created {
			t.Fatalf("new carrier could not start its first key update: created=%v err=%v", created, err)
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAuditTCPControlRetryUsesOperationDeadline(t *testing.T) {
	s, st := stateSession(t, "tcp")
	ops, err := operation.New(operation.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1700000000, 0)
	s.operations = ops
	s.current = &carrier{kind: "tcp", generation: 1}
	s.active, s.peerDone, s.localDoneAck = true, true, true
	s.lastReceive, s.lastProbe, s.lastKey, s.lastSync = base, base, base, base
	s.transportNow = func() time.Time { return base }
	st.opening, s.client = true, true
	open := protocol.Frame{Kind: protocol.Open, Flow: st.flow.id, Data: encodeJSON(st.target)}
	if !s.ensureOperation(open) {
		t.Fatal("could not create OPEN operation")
	}
	key, _ := requestOperationKey(open)
	p, err := ops.Prepare(key, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = ops.Publish(p, 0, 1); err != nil {
		t.Fatal(err)
	}
	// The default operation backoff is 200 ms. A stable TCP carrier must not
	// inject the legacy 500 ms copy or spin a queued duplicate earlier.
	s.transportNow = func() time.Time { return base.Add(100 * time.Millisecond) }
	s.maintain(base.Add(100 * time.Millisecond))
	if f, ok := s.queue.Pop(); ok && f.Kind == protocol.Open {
		t.Fatal("OPEN was requeued before its operation deadline")
	}
	s.transportNow = func() time.Time { return base.Add(200 * time.Millisecond) }
	s.maintain(base.Add(200 * time.Millisecond))
	f, ok := s.queue.Pop()
	if !ok || f.Kind != protocol.Open {
		t.Fatalf("OPEN was not requeued at operation deadline: %+v %v", f, ok)
	}
}

func TestAuditKeyDrainRequiresNewEpochUseBeforeRetirement(t *testing.T) {
	s, _ := stateSession(t, "tcp")
	base := time.Unix(1700000100, 0)
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	var handle [16]byte
	for i := range handle {
		handle[i] = byte(31 - i)
	}
	rxSender, err := security.NewRecordCipher(key[:], handle, 0)
	if err != nil {
		t.Fatal(err)
	}
	oldWire1, _, err := rxSender.Seal([]byte("old-1"))
	if err != nil {
		t.Fatal(err)
	}
	oldWire2, _, err := rxSender.Seal([]byte("old-2"))
	if err != nil {
		t.Fatal(err)
	}
	rx, err := security.NewRecordCipher(key[:], handle, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := rx.UpdateKey(1); err != nil {
		t.Fatal(err)
	}
	s.current = &carrier{kind: "tcp", generation: 1, rx: rx}
	s.active = true
	s.opts.KeyDrainTimeout = 2 * time.Second
	s.rtt = 200 * time.Millisecond
	s.rxDrainAt = base
	s.transportNow = func() time.Time { return base }
	if _, _, err := s.current.rx.Open(oldWire1); err != nil {
		t.Fatalf("old epoch was retired before new epoch use: %v", err)
	}
	s.transportNow = func() time.Time { return base.Add(500 * time.Millisecond) }
	if !s.maintainKeyDrain(base.Add(500 * time.Millisecond)) {
		t.Fatal("key drain unexpectedly suspended before its timeout")
	}
	if _, _, err := s.current.rx.Open(oldWire2); err != nil {
		t.Fatalf("old epoch was not retained without a new-epoch proof: %v", err)
	}
	// A valid current-epoch record is the installation proof.
	if err := rxSender.UpdateKey(1); err != nil {
		t.Fatal(err)
	}
	newWire, _, err := rxSender.Seal([]byte("new"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.current.rx.Open(newWire); err != nil {
		t.Fatal("new epoch proof was rejected: ", err)
	}
	s.rxCurrentUsed = true
	if !s.maintainKeyDrain(base.Add(500 * time.Millisecond)) {
		t.Fatal("key drain failed after installation proof")
	}
	if _, _, err := s.current.rx.Open(oldWire2); !errors.Is(err, security.ErrAuthentication) {
		t.Fatalf("retired old epoch accepted or returned wrong error: %v", err)
	}
}

func TestAuditResetReturnsDiscardedUniqueReceiveCreditOnce(t *testing.T) {
	s, _, st := actorFlow(t, 16)
	if e := s.call(context.Background(), func() {
		s.data(st, protocol.Frame{Kind: protocol.StreamData, Flow: 1, Offset: 0, Data: []byte("abc")})
		// Exact duplicate does not consume a second receive-credit allocation.
		s.data(st, protocol.Frame{Kind: protocol.StreamData, Flow: 1, Offset: 0, Data: []byte("abc")})
		s.data(st, protocol.Frame{Kind: protocol.StreamData, Flow: 1, Offset: 6, Data: []byte("xyz")})
		if s.stats.RXBuffered != 6 {
			t.Errorf("unexpected unique receive bytes %d", s.stats.RXBuffered)
		}
		s.reset(st, io.ErrClosedPipe, false)
		if s.stats.RXBuffered != 0 {
			t.Errorf("RESET did not release receive memory: %d", s.stats.RXBuffered)
		}
		if s.totalConsumed != 6 {
			t.Errorf("RESET discarded six bytes but released cumulative session credit %d", s.totalConsumed)
		}
		s.reset(st, io.ErrClosedPipe, false)
		if s.totalConsumed != 6 {
			t.Errorf("repeat RESET changed returned credit: %d", s.totalConsumed)
		}
	}); e != nil {
		t.Fatal(e)
	}
}

func TestAuditTimedOutQueuedWriteDoesNotCommitLater(t *testing.T) {
	s, f, st := actorFlow(t, 16)
	started, release := make(chan struct{}), make(chan struct{})
	s.post(func() { close(started); <-release })
	<-started
	f.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
	n, e := f.Write([]byte("business payload"))
	close(release)
	if n != 0 || !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("expected an uncommitted timeout, got %d %v", n, e)
	}
	if e = s.call(context.Background(), func() {
		if st.sendNext != 0 || s.totalSent != 0 || len(st.chunks) != 0 {
			t.Errorf("write reported zero+timeout but committed later: next=%d total=%d chunks=%d", st.sendNext, s.totalSent, len(st.chunks))
		}
	}); e != nil {
		t.Fatal(e)
	}
}

func TestAuditPacketAckRejectsEpochTruncation(t *testing.T) {
	s, _, _ := actorFlow(t, 16)
	if e := s.call(context.Background(), func() {
		meta := security.RecordMeta{Epoch: 0, Number: 77}
		s.pending[meta] = sentRecord{size: 100, sent: time.Now()}
		s.flight = 100
		s.handle(protocol.Frame{Kind: protocol.PacketAck, Value: uint64(1) << 32, Offset: 77})
		if _, ok := s.pending[meta]; !ok {
			t.Error("out-of-range ACK epoch truncated to a valid epoch")
		}
		if s.flight != 100 {
			t.Errorf("invalid ACK released congestion accounting: %d", s.flight)
		}
	}); e != nil {
		t.Fatal(e)
	}
}

func TestAuditDatagramAssemblyUsesSessionMemoryBudget(t *testing.T) {
	s, f, st := actorFlow(t, 8) // only 32 bytes of session receive-memory allowance
	if e := s.call(context.Background(), func() {
		st.target.Network = "udp"
		f.network = "udp"
		s.datagram(protocol.Frame{Kind: protocol.Datagram, Flow: 1, Offset: 1, Value: uint64(16<<10) << 32, Data: []byte{1}})
		if len(st.datagrams) != 0 {
			t.Error("one authenticated fragment allocated a 16-KiB assembly above session memory budget")
		}
	}); e != nil {
		t.Fatal(e)
	}
}

type auditDelayedBackend struct {
	started   chan struct{}
	release   chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

type auditCancelBackend struct{ started, canceled chan struct{} }

func (b *auditCancelBackend) DialContext(ctx context.Context, _ string, _ string) (net.Conn, error) {
	close(b.started)
	<-ctx.Done()
	close(b.canceled)
	return nil, ctx.Err()
}
func TestAuditResetCancelsPendingTargetDial(t *testing.T) {
	backend := &auditCancelBackend{started: make(chan struct{}), canceled: make(chan struct{})}
	s := newSession(context.Background(), sessionInfo{ID: "cancel-dial"}, Options{}, false, backend)
	defer s.Close()
	if e := s.call(context.Background(), func() {
		s.peerDone = true
		s.handleOpen(protocol.Frame{Kind: protocol.Open, Flow: 1, Data: encodeJSON(protocol.Target{Network: "tcp", Address: "example.test:80", Class: protocol.Normal})})
	}); e != nil {
		t.Fatal(e)
	}
	select {
	case <-backend.started:
	case <-time.After(time.Second):
		t.Fatal("dial not started")
	}
	if e := s.call(context.Background(), func() { s.handle(protocol.Frame{Kind: protocol.Reset, Flow: 1}) }); e != nil {
		t.Fatal(e)
	}
	select {
	case <-backend.canceled:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("RESET released flow quota without canceling its pending target dial")
	}
}

type auditRecordBackend struct{ called chan struct{} }

func (b *auditRecordBackend) DialContext(context.Context, string, string) (net.Conn, error) {
	b.called <- struct{}{}
	return nil, errors.New("test dial refused")
}
func TestAuditRejectedOpenCannotBecomeNewDial(t *testing.T) {
	s, _, st := actorFlow(t, 16)
	backend := &auditRecordBackend{called: make(chan struct{}, 4)}
	target := protocol.Target{Network: "tcp", Address: "example.test:80", Class: protocol.Normal}
	if e := s.call(context.Background(), func() {
		s.client = false
		s.peerDone = true
		s.backend = backend
		s.opts.MaxFlows = 1
		s.handleOpen(protocol.Frame{Kind: protocol.Open, Flow: 2, Data: encodeJSON(target)})
		s.reset(st, io.ErrClosedPipe, false)
		s.handleOpen(protocol.Frame{Kind: protocol.Open, Flow: 2, Data: encodeJSON(target)})
	}); e != nil {
		t.Fatal(e)
	}
	select {
	case <-backend.called:
		t.Fatal("previously rejected OPEN retried later created a target socket")
	case <-time.After(30 * time.Millisecond):
	}
}

func (b *auditDelayedBackend) DialContext(context.Context, string, string) (net.Conn, error) {
	close(b.started)
	<-b.release
	left, right := net.Pipe()
	// The observer is separate from the Session. A discarded asynchronous result
	// must close the returned connection even when its actor has already exited.
	go func() {
		defer right.Close()
		var one [1]byte
		_, _ = right.Read(one[:])
		b.closeOnce.Do(func() { close(b.closed) })
	}()
	return left, nil
}
func TestAuditDialResultAfterSessionCloseIsReleased(t *testing.T) {
	backend := &auditDelayedBackend{started: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	s := newSession(context.Background(), sessionInfo{ID: "late-dial"}, Options{}, false, backend)
	if e := s.call(context.Background(), func() {
		s.peerDone = true
		s.handleOpen(protocol.Frame{Kind: protocol.Open, Flow: 1, Data: encodeJSON(protocol.Target{Network: "tcp", Address: "example.test:80", Class: protocol.Normal})})
	}); e != nil {
		t.Fatal(e)
	}
	select {
	case <-backend.started:
	case <-time.After(time.Second):
		t.Fatal("target dial never started")
	}
	s.Close()
	close(backend.release)
	select {
	case <-backend.closed:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("target socket returned after actor exit was leaked")
	}
}

func TestAuditFinAckWaitsForReceiveConsumption(t *testing.T) {
	s, _, st := actorFlow(t, 16)
	if e := s.call(context.Background(), func() {
		s.data(st, protocol.Frame{Kind: protocol.StreamData, Flow: 1, Data: []byte("abc")})
		s.handle(protocol.Frame{Kind: protocol.Fin, Flow: 1, Offset: 3})
		found := false
		for {
			frame, ok := s.queue.Pop()
			if !ok {
				break
			}
			if frame.Kind == protocol.FinAck {
				found = true
			}
		}
		if found {
			t.Error("FIN acknowledged while preceding bytes remain unread in the receive buffer")
		}
	}); e != nil {
		t.Fatal(e)
	}
}

func TestAuditZeroLengthOutOfOrderStreamFramesDoNotAllocateSegments(t *testing.T) {
	s, _, st := actorFlow(t, 128)
	if e := s.call(context.Background(), func() {
		for offset := uint64(1); offset < 100; offset++ {
			s.data(st, protocol.Frame{Kind: protocol.StreamData, Flow: 1, Offset: offset})
		}
		if len(st.segments) != 0 {
			t.Errorf("empty frames retained %d segment objects without consuming byte credit", len(st.segments))
		}
	}); e != nil {
		t.Fatal(e)
	}
}

func TestAuditResumeDoneCannotOvertakeMissingSnapshot(t *testing.T) {
	s, st := stateSession(t, "tcp")
	s.peerDone = false
	s.current = &carrier{kind: "udp", generation: 1}
	s.peerSyncCount = -1
	s.syncReceived = map[uint64]bool{}
	s.syncAck = map[uint64]bool{}
	st.sendNext = 9
	// A lossy/reordered UDP record can bring DONE before this flow's snapshot.
	// Completion must depend on the declared snapshot set, not record arrival.
	s.handle(protocol.Frame{Kind: protocol.ResumeDone, Flow: 1, Value: 64, Offset: 1})
	if s.peerDone {
		t.Fatal("resume marked complete before its declared flow snapshot arrived")
	}
	s.handle(protocol.Frame{Kind: protocol.ResumeState, Flow: 1, Value: 1, Data: encodeJSON(flowSnapshot{ID: 1, Receive: 0, Max: 16})})
	if !s.peerDone {
		t.Fatal("resume did not complete after its declared missing snapshot arrived")
	}
}

func TestAuditFailedSnapshotEnqueueCannotMarkSyncComplete(t *testing.T) {
	s, _, _ := actorFlow(t, 16)
	if e := s.call(context.Background(), func() {
		s.queue = scheduler.New[protocol.Frame](32, 32)
		s.current = &carrier{kind: "udp", generation: 1}
		s.syncAck = map[uint64]bool{}
		s.syncReceived = map[uint64]bool{}
		s.peerSyncCount = -1
		s.paceTokens = 0
		s.cwnd = 0
		s.lastReceive = time.Now()
		s.lastProbe = time.Now()
		s.lastKey = time.Now()
	}); e != nil {
		t.Fatal(e)
	}
	s.activate()
	_ = s.call(context.Background(), func() {
		s.maintain(time.Now())
		if len(s.syncFrames) != 1 {
			t.Error("test failed to create a concrete snapshot candidate")
		}
		if s.synced {
			t.Error("resume was marked synced after every snapshot/control enqueue failed")
		}
	})
}

func TestAuditStreamDataCannotPopulateDatagramFlowBuffer(t *testing.T) {
	s, st := stateSession(t, "udp")
	s.handle(protocol.Frame{Kind: protocol.StreamData, Flow: 1, Data: []byte("reliable bytes in a datagram association")})
	if st.flow.buffer.Len() != 0 {
		t.Fatal("STREAM_DATA was retained in a buffer that datagram Read cannot consume")
	}
}

func TestAuditUnknownRecoverySnapshotsHaveBoundedState(t *testing.T) {
	s, _ := stateSession(t, "tcp")
	s.current = &carrier{kind: "udp", generation: 1}
	s.syncReceived = map[uint64]bool{}
	s.peerSyncCount = -1
	for id := uint64(2); id <= 4098 && s.ctx.Err() == nil; id++ {
		s.handle(protocol.Frame{Kind: protocol.ResumeState, Flow: id, Value: 1, Data: encodeJSON(flowSnapshot{ID: id, Reset: true})})
	}
	if len(s.syncReceived) > 4096 {
		t.Fatalf("authenticated recovery snapshots retained %d unknown flow identifiers", len(s.syncReceived))
	}
}

func TestAuditCompletedDatagramsRemainChargedToSessionBudget(t *testing.T) {
	s, st := stateSession(t, "udp") // 64 bytes total receive allowance
	for id := uint64(1); id <= 3; id++ {
		s.datagram(protocol.Frame{Kind: protocol.Datagram, Flow: 1, Offset: id, Value: uint64(32) << 32, Data: make([]byte, 32)})
	}
	queued := 0
	for _, message := range st.flow.messages {
		queued += len(message)
	}
	if queued > s.opts.MaxSessionBuffer {
		t.Fatalf("completed datagrams queued %d bytes above %d-byte session budget", queued, s.opts.MaxSessionBuffer)
	}
}

func TestAuditRepeatedCarrierActivationIsIdempotent(t *testing.T) {
	s, _, _ := actorFlow(t, 16)
	if e := s.call(context.Background(), func() {
		s.current = &carrier{kind: "udp", generation: 1}
		s.syncAck = map[uint64]bool{}
		s.syncReceived = map[uint64]bool{}
		s.peerSyncCount = -1
		s.paceTokens = 0
		s.cwnd = 0
		s.lastReceive = time.Now()
		s.lastProbe = time.Now()
		s.lastKey = time.Now()
	}); e != nil {
		t.Fatal(e)
	}
	s.activate()
	s.activate()
	if e := s.call(context.Background(), func() {
		if len(s.syncFrames) != 1 {
			t.Errorf("same carrier activation appended %d copies of one snapshot", len(s.syncFrames))
		}
	}); e != nil {
		t.Fatal(e)
	}
}
