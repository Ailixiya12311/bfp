package session

import (
	"bfp/classification"
	"bfp/protocol"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// These tests use the real command publication/cancellation wrapper. The
// transportUDPActor fixture does not flush or perform carrier I/O: a successful
// Write below proves whole-message admission, not delivery to a remote target.
type next21DeadlineResult struct {
	n   int
	err error
	at  time.Time
}

type next21DeadlineAdmission struct {
	messageNext                       uint64
	queueLength, queueBytes, messages int
	flowReserved, reserved, queued    int
	txBuffered                        int
	dropped                           uint64
	class                             classification.Snapshot
	effectiveClass                    protocol.Class
}

func next21DeadlineActor(t *testing.T, retain time.Duration, ready bool) (*Session, *Flow, *streamState) {
	t.Helper()
	s, flow, st := transportUDPActor(t, 16<<10)
	policy, err := compileClassification(nil)
	if err != nil {
		t.Fatal(err)
	}
	var classErr error
	next21DeadlineCall(t, s, func() {
		s.opts.RetainTimeout = retain
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

func next21DeadlineCall(t *testing.T, s *Session, fn func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.call(ctx, fn); err != nil {
		t.Fatal(err)
	}
}

func next21DeadlineSnapshot(t *testing.T, s *Session, st *streamState) next21DeadlineAdmission {
	t.Helper()
	var out next21DeadlineAdmission
	next21DeadlineCall(t, s, func() {
		out = next21DeadlineAdmission{
			messageNext: st.messageNext, queueLength: s.queue.Len(), queueBytes: s.queue.Bytes(), messages: len(st.txDatagrams),
			flowReserved: st.txDatagramReserved, reserved: s.txDatagramReserved, queued: s.txDatagramQueued,
			txBuffered: s.stats.TXBuffered, dropped: s.stats.Dropped,
			class: st.txClassifier.Snapshot(), effectiveClass: st.effectiveClass,
		}
	})
	return out
}

func next21DeadlineUnchanged(t *testing.T, s *Session, st *streamState, before next21DeadlineAdmission) {
	t.Helper()
	if after := next21DeadlineSnapshot(t, s, st); after != before {
		t.Fatalf("uncommitted UDP Write changed admission or classification state: before=%+v after=%+v", before, after)
	}
}

func next21DeadlineStart(flow *Flow, payload []byte) <-chan next21DeadlineResult {
	done := make(chan next21DeadlineResult, 1)
	go func() {
		n, err := flow.Write(payload)
		done <- next21DeadlineResult{n: n, err: err, at: time.Now()}
	}()
	return done
}

func next21DeadlineHoldGate(t *testing.T, flow *Flow) func() {
	t.Helper()
	<-flow.writeGate
	var once sync.Once
	release := func() { once.Do(flow.releaseWrite) }
	t.Cleanup(release)
	return release
}

func next21DeadlineBlockActor(t *testing.T, s *Session) func() {
	t.Helper()
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	// Registered after transportUDPActor cleanup, so Fatal cannot leave its
	// cancel-and-join cleanup waiting forever on this controlled command.
	t.Cleanup(unblock)
	s.post(func() { close(started); <-release })
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("controlled UDP actor did not enter command barrier")
	}
	return unblock
}

func next21DeadlineOps(flow *Flow) []*datagramWriteOperation {
	flow.mu.Lock()
	defer flow.mu.Unlock()
	var ops []*datagramWriteOperation
	for op := flow.datagramWrites; op != nil; op = op.next {
		ops = append(ops, op)
	}
	return ops
}

func next21DeadlineAwaitOps(t *testing.T, flow *Flow, count int) []*datagramWriteOperation {
	t.Helper()
	var ops []*datagramWriteOperation
	runtimeWait(t, "UDP Write entry budget registration", func() bool {
		ops = next21DeadlineOps(flow)
		return len(ops) == count
	})
	return ops
}

func next21DeadlineAssertCutoff(t *testing.T, flow *Flow, ops []*datagramWriteOperation, want time.Time) {
	t.Helper()
	flow.mu.Lock()
	defer flow.mu.Unlock()
	for _, op := range ops {
		if !op.deadline.Equal(want) {
			t.Errorf("pending UDP Write cutoff changed: got=%s want=%s", op.deadline, want)
		}
	}
}

func next21DeadlineTimeout(t *testing.T, done <-chan next21DeadlineResult, cutoff time.Time) next21DeadlineResult {
	t.Helper()
	left := time.Until(cutoff.Add(250 * time.Millisecond))
	if left <= 0 {
		left = time.Millisecond
	}
	timer := time.NewTimer(left)
	defer timer.Stop()
	select {
	case out := <-done:
		if out.at.Before(cutoff) {
			t.Fatalf("UDP Write reported timeout before its cutoff: returned=%s cutoff=%s", out.at, cutoff)
		}
		if out.n != 0 || !errors.Is(out.err, context.DeadlineExceeded) {
			t.Fatalf("uncommitted UDP deadline result: n=%d err=%v", out.n, out.err)
		}
		if timeout, ok := out.err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatalf("UDP deadline result must satisfy net.Error.Timeout: %v", out.err)
		}
		if out.at.After(cutoff.Add(250 * time.Millisecond)) {
			t.Fatalf("UDP Write returned after independent cutoff observation: returned=%s cutoff=%s", out.at, cutoff)
		}
		return out
	case <-timer.C:
		t.Fatal("UDP Write did not cancel while its gate or actor remained held")
		return next21DeadlineResult{}
	}
}

func next21DeadlineAssertNoOps(t *testing.T, flow *Flow) {
	t.Helper()
	if count := len(next21DeadlineOps(flow)); count != 0 {
		t.Fatalf("completed UDP Writes retained operation list entries: %d", count)
	}
}

func TestDatagramDeadlineNext21GateKeepsOriginalCutoff(t *testing.T) {
	for _, mode := range []string{"extend", "clear"} {
		t.Run(mode, func(t *testing.T) {
			s, flow, st := next21DeadlineActor(t, 3*time.Second, true)
			before := next21DeadlineSnapshot(t, s, st)
			next21DeadlineHoldGate(t, flow)
			original := time.Now().Add(150 * time.Millisecond)
			flow.SetWriteDeadline(original)
			done := next21DeadlineStart(flow, []byte("original gate budget"))
			ops := next21DeadlineAwaitOps(t, flow, 1)
			later := time.Now().Add(2 * time.Second)
			if mode == "clear" {
				later = time.Time{}
			}
			flow.SetWriteDeadline(later)
			next21DeadlineAssertCutoff(t, flow, ops, original)
			next21DeadlineTimeout(t, done, original)
			next21DeadlineAssertNoOps(t, flow)
			next21DeadlineUnchanged(t, s, st, before)
		})
	}
}

func TestDatagramDeadlineNext21UnsetDeadlineUsesEntryRetentionBudget(t *testing.T) {
	const retain = 120 * time.Millisecond
	s, flow, st := next21DeadlineActor(t, retain, true)
	before := next21DeadlineSnapshot(t, s, st)
	next21DeadlineHoldGate(t, flow)
	started := time.Now()
	done := next21DeadlineStart(flow, []byte("no explicit deadline"))
	ops := next21DeadlineAwaitOps(t, flow, 1)
	flow.mu.Lock()
	cutoff := ops[0].deadline
	flow.mu.Unlock()
	if cutoff.Before(started.Add(retain)) || cutoff.After(time.Now().Add(retain)) {
		t.Fatalf("unset write deadline did not capture finite entry retention budget: cutoff=%s start=%s", cutoff, started)
	}
	next21DeadlineTimeout(t, done, cutoff)
	next21DeadlineAssertNoOps(t, flow)
	next21DeadlineUnchanged(t, s, st, before)
}

func TestDatagramDeadlineNext21TransientShorteningCannotBeMissed(t *testing.T) {
	for _, setter := range []string{"write-deadline", "deadline"} {
		for _, mode := range []string{"extend", "clear"} {
			t.Run(setter+"/"+mode, func(t *testing.T) {
				s, flow, st := next21DeadlineActor(t, 3*time.Second, true)
				before := next21DeadlineSnapshot(t, s, st)
				next21DeadlineHoldGate(t, flow)
				flow.SetWriteDeadline(time.Now().Add(2 * time.Second))
				done := next21DeadlineStart(flow, []byte("transient shorter deadline"))
				ops := next21DeadlineAwaitOps(t, flow, 1)
				short := time.Now().Add(70 * time.Millisecond)
				later := time.Now().Add(2 * time.Second)
				if mode == "clear" {
					later = time.Time{}
				}
				// No wait, Sleep or wake observation between these setters: the
				// shorter deadline must survive even if the writer never runs.
				if setter == "deadline" {
					flow.SetDeadline(short)
					flow.SetDeadline(later)
				} else {
					flow.SetWriteDeadline(short)
					flow.SetWriteDeadline(later)
				}
				next21DeadlineAssertCutoff(t, flow, ops, short)
				next21DeadlineTimeout(t, done, short)
				next21DeadlineAssertNoOps(t, flow)
				next21DeadlineUnchanged(t, s, st, before)
			})
		}
	}
}

func TestDatagramDeadlineNext21AllQueuedWritersCancel(t *testing.T) {
	s, flow, st := next21DeadlineActor(t, 3*time.Second, true)
	before := next21DeadlineSnapshot(t, s, st)
	next21DeadlineHoldGate(t, flow)
	flow.SetWriteDeadline(time.Now().Add(2 * time.Second))
	const callers = 8
	done := make([]<-chan next21DeadlineResult, callers)
	for i := range done {
		done[i] = next21DeadlineStart(flow, []byte("queued waiter"))
	}
	ops := next21DeadlineAwaitOps(t, flow, callers)
	short := time.Now().Add(80 * time.Millisecond)
	flow.SetWriteDeadline(short)
	flow.SetWriteDeadline(time.Time{})
	next21DeadlineAssertCutoff(t, flow, ops, short)
	for _, result := range done {
		next21DeadlineTimeout(t, result, short)
	}
	next21DeadlineAssertNoOps(t, flow)
	next21DeadlineUnchanged(t, s, st, before)
}

func TestDatagramDeadlineNext21GateThenRecoveryDoesNotRenewBudget(t *testing.T) {
	s, flow, st := next21DeadlineActor(t, 3*time.Second, false)
	before := next21DeadlineSnapshot(t, s, st)
	releaseGate := next21DeadlineHoldGate(t, flow)
	unblockActor := next21DeadlineBlockActor(t, s)
	original := time.Now().Add(600 * time.Millisecond)
	flow.SetWriteDeadline(original)
	done := next21DeadlineStart(flow, []byte("one gate and recovery budget"))
	ops := next21DeadlineAwaitOps(t, flow, 1)
	// Consume part of the budget under a proven held token, then clear the
	// flow deadline before acquisition. This cannot create a new UDP budget.
	phase := time.NewTimer(200 * time.Millisecond)
	<-phase.C
	flow.SetWriteDeadline(time.Time{})
	releaseGate()
	runtimeWait(t, "UDP Write moved from gate to queued actor command", func() bool { return len(s.commands) > 0 })
	next21DeadlineAssertCutoff(t, flow, ops, original)
	unblockActor()
	// FIFO barrier follows the known queued writer. active=false makes its
	// real command return without admission, entering recovery waiting.
	next21DeadlineCall(t, s, func() {})
	if ops[0].ctx.Err() != nil || !time.Now().Before(original) {
		t.Fatal("gate-to-recovery barrier did not precede the original operation cutoff")
	}
	next21DeadlineAssertCutoff(t, flow, ops, original)
	next21DeadlineTimeout(t, done, original)
	next21DeadlineAssertNoOps(t, flow)
	next21DeadlineUnchanged(t, s, st, before)
}

func TestDatagramDeadlineNext21QueuedActorShorteningHasNoAdmission(t *testing.T) {
	for _, mode := range []string{"extend", "clear"} {
		t.Run(mode, func(t *testing.T) {
			s, flow, st := next21DeadlineActor(t, 3*time.Second, true)
			before := next21DeadlineSnapshot(t, s, st)
			unblock := next21DeadlineBlockActor(t, s)
			flow.SetWriteDeadline(time.Now().Add(2 * time.Second))
			done := next21DeadlineStart(flow, []byte("must never be admitted"))
			ops := next21DeadlineAwaitOps(t, flow, 1)
			runtimeWait(t, "target UDP writer queued behind controlled actor", func() bool { return len(s.commands) > 0 })
			short := time.Now().Add(-time.Millisecond)
			later := time.Now().Add(2 * time.Second)
			if mode == "clear" {
				later = time.Time{}
			}
			flow.SetWriteDeadline(short)
			flow.SetWriteDeadline(later)
			next21DeadlineAssertCutoff(t, flow, ops, short)
			// Obtain timeout while the actor remains held. Releasing first could
			// hide a caller whose queued command ignores cancellation.
			next21DeadlineTimeout(t, done, short)
			next21DeadlineAssertNoOps(t, flow)
			unblock()
			next21DeadlineUnchanged(t, s, st, before)
		})
	}
}

func TestDatagramDeadlineNext21FutureWriteUsesNewDeadline(t *testing.T) {
	for _, mode := range []string{"extend", "clear"} {
		t.Run(mode, func(t *testing.T) {
			const retain = 3 * time.Second
			s, flow, st := next21DeadlineActor(t, retain, true)
			before := next21DeadlineSnapshot(t, s, st)
			releaseGate := next21DeadlineHoldGate(t, flow)
			original := time.Now().Add(90 * time.Millisecond)
			flow.SetWriteDeadline(original)
			done := next21DeadlineStart(flow, []byte("old pending write"))
			next21DeadlineAwaitOps(t, flow, 1)
			later := time.Now().Add(2 * time.Second)
			if mode == "clear" {
				later = time.Time{}
			}
			flow.SetWriteDeadline(later)
			next21DeadlineTimeout(t, done, original)
			next21DeadlineUnchanged(t, s, st, before)
			releaseGate()
			payload := []byte("new deadline, new admitted message")
			started := time.Now()
			if n, err := flow.Write(payload); err != nil || n != len(payload) {
				t.Fatalf("new UDP Write could not use current deadline: n=%d err=%v", n, err)
			}
			finished := time.Now()
			next21DeadlineAssertNoOps(t, flow)
			next21DeadlineCall(t, s, func() {
				tx := st.txDatagrams[before.messageNext]
				if tx == nil || st.messageNext != before.messageNext+1 || len(st.txDatagrams) != 1 || st.txClassifier.Snapshot().TotalBytes != uint64(len(payload)) {
					t.Error("fresh UDP Write did not admit exactly one whole message with its classification bytes")
					return
				}
				if mode == "extend" && !tx.deadline.Equal(later) {
					t.Errorf("new Write did not use extended deadline: got=%s want=%s", tx.deadline, later)
				}
				if mode == "clear" && (tx.deadline.Before(started.Add(retain)) || tx.deadline.After(finished.Add(retain))) {
					t.Errorf("new Write with cleared deadline did not get its own entry retention budget: %s", tx.deadline)
				}
			})
		})
	}
}

func TestDatagramDeadlineNext21OversizeRejectedBeforeGate(t *testing.T) {
	s, flow, st := next21DeadlineActor(t, 3*time.Second, true)
	before := next21DeadlineSnapshot(t, s, st)
	next21DeadlineHoldGate(t, flow)
	done := next21DeadlineStart(flow, make([]byte, (16<<10)+1))
	select {
	case out := <-done:
		if out.n != 0 || out.err == nil || errors.Is(out.err, context.DeadlineExceeded) {
			t.Fatalf("oversize UDP admission while gate held: n=%d err=%v", out.n, out.err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("oversize UDP Write waited for a held token instead of rejecting at entry")
	}
	next21DeadlineAssertNoOps(t, flow)
	next21DeadlineUnchanged(t, s, st, before)
}
