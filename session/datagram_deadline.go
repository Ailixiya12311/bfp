package session

import (
	"context"
	"time"
)

// A UDP Write has one cutoff from entry through gate, recovery and admission.
// The list contains only caller-owned operations, with no copied payload. It
// lets setters tighten every waiting operation without relying on one shared
// wake token. A cleared or extended flow deadline applies to subsequent Writes.
// All deadline/list/timer changes are protected by Flow.mu; the timer callback
// only cancels the context and never takes that lock.
type datagramWriteOperation struct {
	ctx      context.Context
	cancel   context.CancelCauseFunc
	timer    *time.Timer
	deadline time.Time
	prev     *datagramWriteOperation
	next     *datagramWriteOperation
}

func (f *Flow) beginDatagramWrite(start time.Time) *datagramWriteOperation {
	op := &datagramWriteOperation{deadline: start.Add(f.s.opts.defaults().RetainTimeout)}
	op.ctx, op.cancel = context.WithCancelCause(context.Background())
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.writeDeadline.IsZero() {
		op.deadline = earlier(op.deadline, f.writeDeadline)
	}
	op.next = f.datagramWrites
	if op.next != nil {
		op.next.prev = op
	}
	f.datagramWrites = op
	op.timer = time.AfterFunc(time.Until(op.deadline), func() {
		op.cancel(context.DeadlineExceeded)
	})
	return op
}

func (f *Flow) endDatagramWrite(op *datagramWriteOperation) {
	f.mu.Lock()
	if op.prev != nil {
		op.prev.next = op.next
	} else {
		f.datagramWrites = op.next
	}
	if op.next != nil {
		op.next.prev = op.prev
	}
	op.prev, op.next = nil, nil
	op.timer.Stop()
	op.cancel(context.Canceled)
	f.mu.Unlock()
}

// Called only while Flow.mu is held. Reset never extends an existing operation;
// if the old timer callback has already started, the old cutoff is already due
// and cancellation remains valid under the earlier replacement cutoff.
func (f *Flow) tightenDatagramWrites(deadline time.Time) {
	if deadline.IsZero() {
		return
	}
	for op := f.datagramWrites; op != nil; op = op.next {
		if deadline.Before(op.deadline) {
			op.deadline = deadline
			op.timer.Reset(time.Until(deadline))
		}
	}
}

// Called with Flow.mu held, including immediately before the owner commits
// the complete batch. Time is checked directly as a timer may run slightly late.
func (op *datagramWriteOperation) check() error {
	if !time.Now().Before(op.deadline) || op.ctx.Err() != nil {
		return deadlineError("write")
	}
	return nil
}

func (f *Flow) acquireDatagramWrite(op *datagramWriteOperation) error {
	f.initWriteGate()
	if f.s.terminating() {
		return ErrClosed
	}
	f.mu.Lock()
	err := op.check()
	f.mu.Unlock()
	if err != nil {
		return err
	}
	select {
	case <-f.writeGate:
		if f.s.terminating() {
			f.releaseWrite()
			return ErrClosed
		}
		f.mu.Lock()
		err := op.check()
		f.mu.Unlock()
		if err != nil {
			f.releaseWrite()
		}
		return err
	case <-op.ctx.Done():
		return deadlineError("write")
	case <-f.closed:
		return ErrClosed
	case <-f.s.done:
		return ErrClosed
	case <-f.s.businessContext().Done():
		return ErrClosed
	}
}

func (f *Flow) waitDatagramWrite(op *datagramWriteOperation) error {
	if f.s.terminating() {
		return ErrClosed
	}
	f.mu.Lock()
	err := op.check()
	f.mu.Unlock()
	if err != nil {
		return err
	}
	select {
	case <-f.wake:
		return nil
	case <-op.ctx.Done():
		return deadlineError("write")
	case <-f.closed:
		return ErrClosed
	case <-f.s.done:
		return ErrClosed
	case <-f.s.businessContext().Done():
		return ErrClosed
	}
}
