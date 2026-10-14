package session

import (
	"bfp/classification"
	"bfp/protocol"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func publicNext22Call(t *testing.T, s *Session, fn func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.call(ctx, fn); err != nil {
		t.Fatal(err)
	}
}

func publicNext22BlockActor(t *testing.T, s *Session) func() {
	t.Helper()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	s.post(func() { close(entered); <-release })
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("public API fixture did not enter actor barrier")
	}
	return unblock
}

type publicNext22ObservedContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *publicNext22ObservedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestPublicLifecycleNext22BusinessDonePrecedesFinalActorDone(t *testing.T) {
	f := newCloseTestFixture(t, "udp", 450*time.Millisecond, func(r *closeTestRelay) { r.dropAck[1].Store(true) })
	flow := f.flow(t)
	owner := f.sessions[0]
	if owner.Done() != owner.done || owner.BusinessDone() != owner.businessContext().Done() {
		t.Fatal("public lifecycle channels do not expose the stable owner lifetimes")
	}
	unblock := publicNext22BlockActor(t, owner)
	result := make(chan error, 1)
	go func() { result <- owner.Close() }()
	select {
	case <-owner.BusinessDone():
	case <-time.After(time.Second):
		t.Fatal("local close did not immediately end business admission")
	}
	select {
	case <-owner.Done():
		t.Fatal("final actor Done closed while the real control actor remained held")
	default:
	}
	if err := flow.CloseContext(context.Background()); err != nil {
		t.Fatalf("terminating owner must already own flow cleanup: %v", err)
	}
	unblock()
	runtimeWait(t, "real authenticated close drain after business termination", func() bool {
		return len(f.relay.selected(0, protocol.SessionClose)) > 0
	})
	select {
	case err := <-result:
		if !errors.Is(err, ErrCloseUnconfirmed) {
			t.Fatalf("all ACK loss close result: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("real close control actor did not finish its bounded drain")
	}
	select {
	case <-owner.Done():
	default:
		t.Fatal("Close returned before final actor Done")
	}
	runtimeWait(t, "real peer target cleanup", func() bool { return f.backend.closed.Load() == 1 && f.backend.cleanups.Load() == 1 })
}

func TestPublicLifecycleNext22CloseContextCancellationIsRetryable(t *testing.T) {
	for _, mode := range []string{"actor-queued", "commands-full"} {
		t.Run(mode, func(t *testing.T) {
			s, flow, st := transportUDPActor(t, 4096)
			left, right := net.Pipe()
			t.Cleanup(func() { left.Close(); right.Close() })
			var closed atomic.Int32
			publicNext22Call(t, s, func() { st.targetConn = &closeCountConn{Conn: left, count: &closed} })
			unblock := publicNext22BlockActor(t, s)
			if mode == "commands-full" {
				for i := 0; i < cap(s.commands); i++ {
					s.commands <- func() {}
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			observed := &publicNext22ObservedContext{Context: ctx, entered: make(chan struct{})}
			done := make(chan error, 1)
			go func() { done <- flow.CloseContext(observed) }()
			select {
			case <-observed.entered:
			case <-time.After(time.Second):
				t.Fatal("CloseContext did not enter its cancellable business call")
			}
			if mode == "actor-queued" {
				runtimeWait(t, "contextual reset queued behind actor barrier", func() bool { return len(s.commands) == 1 })
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("held actor CloseContext cancellation: %v", err)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("CloseContext required the held actor to process cancellation")
			}
			if closed.Load() != 0 {
				t.Fatal("cancelled unadmitted close released the target")
			}
			select {
			case <-flow.closed:
				t.Fatal("cancelled unadmitted close terminated the flow")
			default:
			}
			unblock()
			publicNext22Call(t, s, func() {
				if st.reset || s.queue.Len() != 0 {
					t.Error("cancelled queued reset changed owner state after it drained")
				}
			})
			for i := 0; i < 2; i++ {
				retry, stop := context.WithTimeout(context.Background(), time.Second)
				err := flow.CloseContext(retry)
				stop()
				if err != nil {
					t.Fatalf("contextual close retry %d: %v", i, err)
				}
			}
			if err := flow.Close(); err != nil {
				t.Fatal(err)
			}
			publicNext22Call(t, s, func() {
				if !st.reset || closed.Load() != 1 || s.queue.Len() != 1 || !st.resetPending {
					t.Errorf("successful contextual/legacy close did not share one reset: reset=%v closed=%d queue=%d", st.reset, closed.Load(), s.queue.Len())
				}
			})
		})
	}
}

type publicNext22Admission struct {
	id                             uint64
	items, bytes, messages         int
	reserved, flowReserved, queued int
	txBuffered                     int
	dropped                        uint64
	class                          classification.Snapshot
}

func publicNext22UDPActor(t *testing.T, ready bool) (*Session, *Flow, *streamState) {
	t.Helper()
	s, flow, st := transportUDPActor(t, 32<<10)
	policy, err := compileClassification(nil)
	if err != nil {
		t.Fatal(err)
	}
	var classErr error
	publicNext22Call(t, s, func() {
		s.opts.RetainTimeout = 3 * time.Second
		s.active, s.peerDone = ready, true
		s.current = &carrier{kind: "udp", generation: 1}
		s.classifier, s.classOrigin, s.classNow = policy, time.Now(), time.Now
		st.txClassifier, classErr = policy.NewFlow(classification.Metadata{Target: st.target}, 0)
	})
	if classErr != nil {
		t.Fatal(classErr)
	}
	return s, flow, st
}

func publicNext22Snapshot(t *testing.T, s *Session, st *streamState) publicNext22Admission {
	t.Helper()
	var out publicNext22Admission
	publicNext22Call(t, s, func() {
		out = publicNext22Admission{
			id: st.messageNext, items: s.queue.Len(), bytes: s.queue.Bytes(), messages: len(st.txDatagrams),
			reserved: s.txDatagramReserved, flowReserved: st.txDatagramReserved, queued: s.txDatagramQueued,
			txBuffered: s.stats.TXBuffered, dropped: s.stats.Dropped, class: st.txClassifier.Snapshot(),
		}
	})
	return out
}

func publicNext22AwaitOperation(t *testing.T, flow *Flow) *datagramWriteOperation {
	t.Helper()
	var found *datagramWriteOperation
	runtimeWait(t, "contextual UDP operation registered at entry", func() bool {
		flow.mu.Lock()
		defer flow.mu.Unlock()
		if flow.datagramWrites == nil {
			return false
		}
		found = flow.datagramWrites
		return true
	})
	return found
}

type publicNext22WriteResult struct {
	n   int
	err error
}

func publicNext22StartWrite(flow *Flow, ctx context.Context, b []byte) <-chan publicNext22WriteResult {
	done := make(chan publicNext22WriteResult, 1)
	go func() { n, err := flow.WriteDatagramContext(ctx, b); done <- publicNext22WriteResult{n, err} }()
	return done
}

func publicNext22AwaitCancelled(t *testing.T, flow *Flow, done <-chan publicNext22WriteResult, want error) {
	t.Helper()
	select {
	case out := <-done:
		if out.n != 0 || !errors.Is(out.err, want) {
			t.Fatalf("unadmitted contextual UDP write: n=%d err=%v want=%v", out.n, out.err, want)
		}
	case <-time.After(350 * time.Millisecond):
		t.Fatal("contextual UDP cancellation waited for a held gate or actor")
	}
	flow.mu.Lock()
	retained := flow.datagramWrites != nil
	flow.mu.Unlock()
	if retained {
		t.Fatal("completed contextual UDP write retained an operation")
	}
}

func TestPublicLifecycleNext22DatagramQueuedCancellationHasNoAdmission(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			s, flow, st := publicNext22UDPActor(t, true)
			before := publicNext22Snapshot(t, s, st)
			unblock := publicNext22BlockActor(t, s)
			var ctx context.Context
			var cancel context.CancelFunc
			want := error(context.Canceled)
			if mode == "deadline" {
				ctx, cancel = context.WithTimeout(context.Background(), 150*time.Millisecond)
				want = context.DeadlineExceeded
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			done := publicNext22StartWrite(flow, ctx, []byte("unadmitted queued payload"))
			op := publicNext22AwaitOperation(t, flow)
			runtimeWait(t, "contextual UDP admission command actually queued", func() bool { return len(s.commands) == 1 })
			if mode == "deadline" {
				deadline, _ := ctx.Deadline()
				flow.mu.Lock()
				actual := op.deadline
				flow.mu.Unlock()
				if !actual.Equal(deadline) {
					t.Fatalf("external deadline did not tighten the actual operation: got=%s want=%s", actual, deadline)
				}
			} else {
				cancel()
			}
			publicNext22AwaitCancelled(t, flow, done, want)
			unblock()
			if after := publicNext22Snapshot(t, s, st); after != before {
				t.Fatalf("cancelled queued payload mutated admission/classification after drain: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestPublicLifecycleNext22DatagramGateAndRecoveryCancellation(t *testing.T) {
	for _, mode := range []string{"gate", "recovery"} {
		t.Run(mode, func(t *testing.T) {
			s, flow, st := publicNext22UDPActor(t, mode == "gate")
			before := publicNext22Snapshot(t, s, st)
			var release func()
			if mode == "gate" {
				<-flow.writeGate
				var once sync.Once
				release = func() { once.Do(flow.releaseWrite) }
				t.Cleanup(release)
			} else {
				release = publicNext22BlockActor(t, s)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := publicNext22StartWrite(flow, ctx, []byte("cancellable wait phase"))
			op := publicNext22AwaitOperation(t, flow)
			if mode == "recovery" {
				runtimeWait(t, "contextual UDP not-ready command queued", func() bool { return len(s.commands) == 1 })
				release()
				publicNext22Call(t, s, func() {})
				flow.mu.Lock()
				expired := op.ctx.Err() != nil || !time.Now().Before(op.deadline)
				flow.mu.Unlock()
				if expired {
					t.Fatal("recovery barrier was reached only after the operation expired")
				}
			}
			cancel()
			publicNext22AwaitCancelled(t, flow, done, context.Canceled)
			release()
			if after := publicNext22Snapshot(t, s, st); after != before {
				t.Fatalf("contextual wait cancellation changed admission state: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestPublicLifecycleNext22DatagramCommittedResultWinsCancellation(t *testing.T) {
	for _, payload := range [][]byte{nil, []byte("admission already won")} {
		name := "nonempty"
		if len(payload) == 0 {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			s, flow, st := publicNext22UDPActor(t, true)
			before := publicNext22Snapshot(t, s, st)
			committed, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			publicNext22Call(t, s, func() {
				// observeTX runs after the complete batch/id/reservation commit.
				// Hold it to place cancellation after admission but before return.
				s.classNow = func() time.Time { close(committed); <-release; return time.Now() }
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := publicNext22StartWrite(flow, ctx, payload)
			select {
			case <-committed:
			case <-time.After(time.Second):
				t.Fatal("contextual UDP write did not reach its real admission commit")
			}
			cancel()
			unblock()
			select {
			case out := <-done:
				if out.err != nil || out.n != len(payload) {
					t.Fatalf("post-admission cancellation replaced authoritative result: n=%d err=%v", out.n, out.err)
				}
			case <-time.After(time.Second):
				t.Fatal("committed contextual UDP write did not return")
			}
			after := publicNext22Snapshot(t, s, st)
			if after.id != before.id+1 || after.messages != 1 || after.items != 1 || after.class.TotalBytes != uint64(len(payload)) {
				t.Fatalf("contextual UDP commit/empty-message boundary incorrect: %+v", after)
			}
		})
	}
}

func TestPublicLifecycleNext22DatagramEntryValidation(t *testing.T) {
	s, flow, st := publicNext22UDPActor(t, true)
	before := publicNext22Snapshot(t, s, st)
	<-flow.writeGate
	defer flow.releaseWrite()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		data []byte
		want error
	}{
		{"already-cancelled", ctx, []byte("never queued"), context.Canceled},
		{"oversize", context.Background(), make([]byte, (16<<10)+1), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			done := publicNext22StartWrite(flow, tc.ctx, tc.data)
			select {
			case out := <-done:
				if out.n != 0 || out.err == nil || tc.want != nil && !errors.Is(out.err, tc.want) {
					t.Fatalf("contextual UDP entry validation: n=%d err=%v", out.n, out.err)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("contextual UDP entry rejection waited for the held write gate")
			}
		})
	}
	if after := publicNext22Snapshot(t, s, st); after != before {
		t.Fatal("contextual UDP entry rejection allocated admission state")
	}
	flow.mu.Lock()
	retained := flow.datagramWrites != nil
	flow.mu.Unlock()
	if retained {
		t.Fatal("contextual UDP entry rejection registered an operation")
	}
	_, tcp, _ := actorFlow(t, 16)
	if n, err := tcp.WriteDatagramContext(context.Background(), []byte("wrong network")); n != 0 || err == nil || errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("contextual datagram API accepted non-UDP flow: n=%d err=%v", n, err)
	}
}
