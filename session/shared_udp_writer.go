package session

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	sharedUDPWriteBudget = 2 * time.Second
	sharedUDPQueueLimit  = 256
)

var errSharedUDPWriterClosed = errors.New("session: shared UDP writer closed")

// udpWriteSocket is deliberately smaller than *net.UDPConn. Tests can model
// a blocked physical write, while production still uses the concrete shared
// Server socket. The writer is the only owner allowed to set its deadline.
type udpWriteSocket interface {
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
	SetWriteDeadline(time.Time) error
}

type sharedUDPWriteRequest struct {
	record   []byte
	remote   *net.UDPAddr
	carrier  *carrier
	ctx      context.Context
	deadline time.Time
	done     chan error
}

type sharedUDPWriteResult struct {
	n   int
	err error
}

type sharedUDPWriter struct {
	socket  udpWriteSocket
	queue   chan *sharedUDPWriteRequest
	stop    chan struct{}
	stopOne sync.Once
	retired atomic.Bool
	wg      sync.WaitGroup
}

func newSharedUDPWriter(socket udpWriteSocket) *sharedUDPWriter {
	w := &sharedUDPWriter{socket: socket, queue: make(chan *sharedUDPWriteRequest, sharedUDPQueueLimit), stop: make(chan struct{})}
	w.wg.Add(1)
	go w.run()
	return w
}

func (w *sharedUDPWriter) write(record []byte, remote *net.UDPAddr, carrier *carrier, until time.Time) error {
	if w == nil || w.socket == nil || remote == nil {
		return errSharedUDPWriterClosed
	}
	if len(record) > 0xffff {
		return errSharedUDPWriterClosed
	}
	now := time.Now()
	deadline := now.Add(sharedUDPWriteBudget)
	if !until.IsZero() && until.Before(deadline) {
		deadline = until
	}
	ctx := context.Background()
	if carrier != nil {
		// A Session-owned carrier has no independent context here. Its closed
		// channel is the cancellation authority for this physical write.
	}
	req := &sharedUDPWriteRequest{record: append([]byte(nil), record...), remote: cloneUDPAddr(remote), carrier: carrier, ctx: ctx, deadline: deadline, done: make(chan error, 1)}
	if err := w.enqueue(req); err != nil {
		return err
	}
	select {
	case err := <-req.done:
		return err
	case <-w.stop:
		return errSharedUDPWriterClosed
	case <-carrierClosed(carrier):
		return net.ErrClosed
	case <-time.After(time.Until(deadline)):
		return context.DeadlineExceeded
	}
}

func (w *sharedUDPWriter) enqueue(req *sharedUDPWriteRequest) error {
	if w.retired.Load() {
		return errSharedUDPWriterClosed
	}
	var timer *time.Timer
	if wait := time.Until(req.deadline); wait > 0 {
		timer = time.NewTimer(wait)
		defer timer.Stop()
	} else {
		return context.DeadlineExceeded
	}
	for {
		if req.carrier != nil {
			if limit, _ := req.carrier.writeState(); !limit.IsZero() && limit.Before(req.deadline) {
				req.deadline = limit
				if timer != nil {
					timer.Stop()
				}
				if wait := time.Until(req.deadline); wait > 0 {
					timer = time.NewTimer(wait)
				} else {
					return context.DeadlineExceeded
				}
			}
		}
		var timerC <-chan time.Time
		if timer != nil {
			timerC = timer.C
		}
		var wake <-chan struct{}
		if req.carrier != nil {
			_, wake = req.carrier.writeState()
		}
		select {
		case w.queue <- req:
			return nil
		case <-w.stop:
			return errSharedUDPWriterClosed
		case <-carrierClosed(req.carrier):
			return net.ErrClosed
		case <-wake:
			if req.carrier != nil {
				if limit, _ := req.carrier.writeState(); !limit.IsZero() && limit.Before(req.deadline) {
					req.deadline = limit
					if timer != nil {
						timer.Stop()
					}
					if wait := time.Until(req.deadline); wait > 0 {
						timer = time.NewTimer(wait)
					} else {
						return context.DeadlineExceeded
					}
				}
			}
		case <-timerC:
			return context.DeadlineExceeded
		}
	}
}

func carrierClosed(c *carrier) <-chan struct{} {
	if c == nil || c.closed == nil {
		return nil
	}
	return c.closed
}

func cloneUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	b := *a
	b.IP = append(net.IP(nil), a.IP...)
	return &b
}

func (w *sharedUDPWriter) run() {
	defer w.wg.Done()
	for {
		select {
		case req := <-w.queue:
			if req != nil {
				w.process(req)
			}
		case <-w.stop:
			w.drain(errSharedUDPWriterClosed)
			return
		}
	}
}

func (w *sharedUDPWriter) process(req *sharedUDPWriteRequest) {
	if req == nil {
		return
	}
	if w.retired.Load() {
		req.done <- errSharedUDPWriterClosed
		return
	}
	deadline := req.deadline
	var wake <-chan struct{}
	if req.carrier != nil {
		limit, signal := req.carrier.writeState()
		if !limit.IsZero() && limit.Before(deadline) {
			deadline = limit
		}
		wake = signal
	}
	if !time.Now().Before(deadline) {
		req.done <- context.DeadlineExceeded
		return
	}
	if err := w.socket.SetWriteDeadline(deadline); err != nil {
		req.done <- err
		return
	}
	result := make(chan sharedUDPWriteResult, 1)
	go func() {
		n, err := w.socket.WriteToUDP(req.record, req.remote)
		result <- sharedUDPWriteResult{n: n, err: err}
	}()
	forced := error(nil)
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	for {
		select {
		case out := <-result:
			_ = w.socket.SetWriteDeadline(time.Time{})
			if forced != nil {
				req.done <- forced
				return
			}
			if out.err == nil && out.n != len(req.record) {
				out.err = io.ErrShortWrite
			}
			req.done <- out.err
			return
		case <-w.stop:
			if forced == nil {
				forced = errSharedUDPWriterClosed
			}
			_ = w.socket.SetWriteDeadline(time.Now())
		case <-carrierClosed(req.carrier):
			if forced == nil {
				forced = net.ErrClosed
			}
			_ = w.socket.SetWriteDeadline(time.Now())
		case <-wake:
			if req.carrier != nil {
				limit, signal := req.carrier.writeState()
				wake = signal
				if !limit.IsZero() && limit.Before(deadline) {
					deadline = limit
					_ = w.socket.SetWriteDeadline(deadline)
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					if wait := time.Until(deadline); wait > 0 {
						timer.Reset(wait)
					} else {
						forced = context.DeadlineExceeded
						_ = w.socket.SetWriteDeadline(time.Now())
					}
				}
			}
		case <-timer.C:
			if forced == nil {
				forced = context.DeadlineExceeded
			}
			_ = w.socket.SetWriteDeadline(time.Now())
		}
	}
}

func (w *sharedUDPWriter) drain(err error) {
	for {
		select {
		case req := <-w.queue:
			if req != nil {
				req.done <- err
			}
		default:
			return
		}
	}
}

func (w *sharedUDPWriter) retire() {
	if w == nil {
		return
	}
	w.stopOne.Do(func() {
		w.retired.Store(true)
		close(w.stop)
	})
	w.wg.Wait()
}
