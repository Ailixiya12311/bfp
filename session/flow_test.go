package session

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"bfp/protocol"
)

func actorFlow(t *testing.T, buffer int) (*Session, *Flow, *streamState) {
	t.Helper()
	s := newSession(context.Background(), sessionInfo{ID: "unit"}, Options{MaxFlowBuffer: buffer, MaxSessionBuffer: buffer * 4}, true, nil)
	t.Cleanup(func() { s.Close() })
	f := newFlow(s, 1, "tcp")
	st := &streamState{flow: f, target: protocol.Target{Network: "tcp", Address: "example.test:80", Class: protocol.Normal}, effectiveClass: protocol.Normal, maxRemote: uint64(buffer), segments: map[uint64][]byte{}, datagrams: map[uint64]*assembly{}, completed: map[uint64]bool{}}
	if err := s.call(context.Background(), func() { s.streams[1] = st }); err != nil {
		t.Fatal(err)
	}
	return s, f, st
}

func TestFlowWriteHonorsCreditAndResumesAfterAdvance(t *testing.T) {
	s, f, st := actorFlow(t, 8)
	f.SetWriteDeadline(time.Now().Add(time.Second))
	if n, err := f.Write([]byte("abcdefgh")); n != 8 || err != nil {
		t.Fatalf("initial write: %d %v", n, err)
	}
	done := make(chan error, 1)
	go func() {
		n, err := f.Write([]byte("ij"))
		if n != 2 && err == nil {
			err = io.ErrShortWrite
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("write exceeded current receive credit: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if err := s.call(context.Background(), func() {
		s.handle(protocol.Frame{Kind: protocol.StreamAck, Flow: 1, Offset: 8})
		s.handle(protocol.Frame{Kind: protocol.MaxFlowData, Flow: 1, Value: 10})
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("write did not resume on credit update")
	}
	if err := s.call(context.Background(), func() {
		if st.sendNext != 10 || st.sendAck != 8 || s.stats.TXBuffered != 2 {
			t.Errorf("incorrect write credit state: next=%d ack=%d buffer=%d", st.sendNext, st.sendAck, s.stats.TXBuffered)
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFlowWriteDeadlineBoundsBackpressure(t *testing.T) {
	_, f, _ := actorFlow(t, 4)
	if _, err := f.Write([]byte("full")); err != nil {
		t.Fatal(err)
	}
	f.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
	n, err := f.Write([]byte("x"))
	if n != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("backpressure deadline: n=%d err=%v", n, err)
	}
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal("deadline error does not satisfy net.Error timeout")
	}
}

func TestConcurrentWriteWaitHonorsDeadlineWhileAnotherWriterOwnsToken(t *testing.T) {
	s, f, _ := actorFlow(t, 16)
	// Hold the token as if another goroutine is inside Write. The second
	// writer must be able to abandon the lock wait at its own deadline; a
	// sync.Mutex here would make the deadline ineffective.
	<-f.writeGate
	defer func() { f.writeGate <- struct{}{} }()
	f.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
	started := time.Now()
	n, err := f.Write([]byte("blocked behind writer"))
	if n != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("write-token deadline: n=%d err=%v", n, err)
	}
	if elapsed := time.Since(started); elapsed < 20*time.Millisecond || elapsed > 250*time.Millisecond {
		t.Fatalf("write-token deadline elapsed=%s", elapsed)
	}
	_ = s
}

func TestConcurrentWriteDeadlineExtensionWakesTokenWait(t *testing.T) {
	s, f, _ := actorFlow(t, 16)
	<-f.writeGate
	done := make(chan error, 1)
	f.SetWriteDeadline(time.Now().Add(25 * time.Millisecond))
	go func() {
		n, err := f.Write([]byte("token wait"))
		if n != len("token wait") && err == nil {
			err = io.ErrShortWrite
		}
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	f.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	time.Sleep(20 * time.Millisecond)
	f.writeGate <- struct{}{}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("extended write deadline: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("write did not wake after its deadline was extended and token released")
	}
	_ = s
}

func TestFlowBidirectionalFINIsIndependent(t *testing.T) {
	s, f, st := actorFlow(t, 16)
	if err := s.call(context.Background(), func() { s.handle(protocol.Frame{Kind: protocol.Fin, Flow: 1, Offset: 0}) }); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("remote FIN did not end receive direction: %v", err)
	}
	if n, err := f.Write([]byte("reply")); n != 5 || err != nil {
		t.Fatalf("remote FIN blocked opposite direction: %d %v", n, err)
	}
	if err := f.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if n, err := f.Write([]byte("x")); n != 0 || err != io.ErrClosedPipe {
		t.Fatalf("write after local FIN: %d %v", n, err)
	}
	if err := s.call(context.Background(), func() {
		s.handle(protocol.Frame{Kind: protocol.FinAck, Flow: 1, Offset: 5})
		if st.localFinal == nil || *st.localFinal != 5 || st.remoteFinal == nil || *st.remoteFinal != 0 || !st.finAck || st.reset {
			t.Error("FIN state crossed directions")
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFlowCloseUnblocksReadAndIsIdempotent(t *testing.T) {
	s, f, st := actorFlow(t, 16)
	done := make(chan error, 1)
	go func() { _, err := f.Read(make([]byte, 1)); done <- err }()
	f.Close()
	f.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock reader")
	}
	if err := s.call(context.Background(), func() {
		if !st.reset {
			t.Error("close did not reset flow")
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFlowCloseUnblocksBothConcurrentDirections(t *testing.T) {
	_, f, _ := actorFlow(t, 4)
	if _, err := f.Write([]byte("full")); err != nil {
		t.Fatal(err)
	}
	f.SetDeadline(time.Now().Add(time.Second))
	started := make(chan struct{}, 2)
	done := make(chan error, 2)
	go func() { started <- struct{}{}; _, err := f.Read(make([]byte, 1)); done <- err }()
	go func() { started <- struct{}{}; _, err := f.Write([]byte("x")); done <- err }()
	<-started
	<-started
	select {
	case err := <-done:
		t.Fatalf("direction completed before close: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	f.Close()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("closed direction succeeded")
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatal("close woke only one of concurrent reader/writer")
		}
	}
}

func TestBothFINsReleaseActiveFlowSlot(t *testing.T) {
	s, f, _ := actorFlow(t, 16)
	if err := s.call(context.Background(), func() { s.opts.MaxFlows = 1 }); err != nil {
		t.Fatal(err)
	}
	if err := f.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := s.call(context.Background(), func() {
		s.handle(protocol.Frame{Kind: protocol.Fin, Flow: 1, Offset: 0})
		s.handle(protocol.Frame{Kind: protocol.FinAck, Flow: 1, Offset: 0})
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := s.DialClass(ctx, protocol.Target{Network: "tcp", Address: "another.example:80", Class: protocol.Normal})
	if errors.Is(err, ErrLimit) {
		t.Fatal("fully finished stream still consumes the active-flow quota")
	}
}
