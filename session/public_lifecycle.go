package session

import (
	"context"
	"errors"
	"io"
	"time"
)

// Done closes after the Session actor has stopped and released its owned
// resources. Graceful business termination can precede this final control drain.
func (s *Session) Done() <-chan struct{} { return s.done }

// BusinessDone closes when the Session stops admitting business operations.
// Authenticated close-control processing may continue until Done closes.
func (s *Session) BusinessDone() <-chan struct{} { return s.businessContext().Done() }

// CloseContext closes this flow through the Session actor. Cancellation before
// actor admission leaves the flow open and permits a later retry. Once admitted,
// the reset completes and its actual result wins over concurrent cancellation.
// An already terminating Session owns flow cleanup, so no new reset is needed.
func (f *Flow) CloseContext(ctx context.Context) error {
	if f.s.terminating() {
		return nil
	}
	err := f.s.businessCall(ctx, func() {
		if st := f.s.streams[f.id]; st != nil && !st.reset {
			f.s.reset(st, io.ErrClosedPipe, true)
		}
	})
	if errors.Is(err, ErrClosed) && f.s.terminating() {
		return nil
	}
	return err
}

// WriteDatagramContext admits one whole UDP datagram, including an empty one.
// Its cutoff is the earliest of the caller's deadline, the flow's deadline and
// the retention budget captured at entry. Later flow setters can tighten it.
// Cancellation reaches gate, recovery and queued admission waits directly;
// no detached Write can admit data after this method reports cancellation.
// If admission already won, its byte count and result remain authoritative.
// Successful admission does not establish delivery to the remote UDP target.
func (f *Flow) WriteDatagramContext(ctx context.Context, b []byte) (int, error) {
	if f.network != "udp" {
		return 0, errors.New("session: contextual datagram write requires UDP")
	}
	if len(b) > 16<<10 {
		return 0, errors.New("session: datagram too large")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	op := f.beginDatagramWrite(time.Now())
	defer f.endDatagramWrite(op)

	// Deriving the admission context directly from ctx makes caller cancellation
	// visible to the final op.check synchronously, even before AfterFunc runs.
	// Keep the original cancel function immutable: the deadline timer reads it.
	f.mu.Lock()
	internal := op.ctx
	joined, cancelJoined := context.WithCancelCause(ctx)
	op.ctx = joined
	if cutoff, ok := ctx.Deadline(); ok && cutoff.Before(op.deadline) {
		op.deadline = cutoff
		op.timer.Reset(time.Until(cutoff))
	}
	f.mu.Unlock()
	stopInternal := context.AfterFunc(internal, func() { cancelJoined(context.Cause(internal)) })
	stopCaller := context.AfterFunc(ctx, func() { op.cancel(ctx.Err()) })
	defer cancelJoined(context.Canceled)
	defer stopInternal()
	defer stopCaller()

	if err := f.acquireDatagramWrite(op); err != nil {
		if callerErr := ctx.Err(); callerErr != nil {
			return 0, callerErr
		}
		return 0, err
	}
	defer f.releaseWrite()
	n, err := f.writeDatagram(b, op)
	if err != nil && n == 0 {
		if callerErr := ctx.Err(); callerErr != nil {
			return 0, callerErr
		}
	}
	return n, err
}
