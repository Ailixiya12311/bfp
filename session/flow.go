package session

import (
	"bfp/protocol"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type Flow struct {
	s                           *Session
	id                          uint64
	network                     string
	mu                          sync.Mutex
	buffer                      bytes.Buffer
	messages                    [][]byte
	readErr                     error
	eof                         bool
	openErr                     error
	openDone                    chan struct{}
	wake                        chan struct{}
	readWake                    chan struct{}
	closed                      chan struct{}
	failOnce                    sync.Once
	readDeadline, writeDeadline time.Time
	closeOnce                   sync.Once
	// writeGate serializes writes without making a caller wait on an
	// unbounded sync.Mutex. The token can be acquired with the caller's
	// current write deadline and is released even when the Session actor
	// blocks on flow credit.
	writeGate chan struct{}
	writeWake chan struct{}
	writeInit sync.Once
	// In-flight UDP operations retain their own deadline from Write entry,
	// including callers still waiting for writeGate. Protected by mu.
	datagramWrites *datagramWriteOperation
}

func newFlow(s *Session, id uint64, network string) *Flow {
	f := &Flow{s: s, id: id, network: network, openDone: make(chan struct{}), wake: make(chan struct{}, 1), readWake: make(chan struct{}, 1), closed: make(chan struct{})}
	f.initWriteGate()
	return f
}

func (f *Flow) initWriteGate() {
	f.writeInit.Do(func() {
		f.writeGate = make(chan struct{}, 1)
		f.writeGate <- struct{}{}
		f.writeWake = make(chan struct{}, 1)
	})
}
func (f *Flow) signal() {
	select {
	case f.readWake <- struct{}{}:
	default:
	}
	select {
	case f.wake <- struct{}{}:
	default:
	}
	select {
	case f.writeWake <- struct{}{}:
	default:
	}
}
func (f *Flow) push(b []byte) {
	f.mu.Lock()
	if f.readErr == nil {
		f.buffer.Write(b)
	}
	f.mu.Unlock()
	f.signal()
}
func (f *Flow) pushDatagram(b []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil || len(f.messages) >= 32 {
		return false
	}
	f.messages = append(f.messages, append([]byte(nil), b...))
	f.signal()
	return true
}
func (f *Flow) endRead() { f.mu.Lock(); f.eof = true; f.mu.Unlock(); f.signal() }
func (f *Flow) fail(e error) {
	f.failOnce.Do(func() { close(f.closed) })
	f.mu.Lock()
	if f.readErr == nil {
		f.readErr = e
	}
	if f.openErr == nil {
		f.openErr = e
	}
	select {
	case <-f.openDone:
	default:
		close(f.openDone)
	}
	f.mu.Unlock()
	f.signal()
}
func (f *Flow) wait(deadline time.Time, writing bool) error {
	if f.s.terminating() {
		return ErrClosed
	}
	wake := f.readWake
	if writing {
		wake = f.wake
	}
	var timer <-chan time.Time
	var t *time.Timer
	if !deadline.IsZero() {
		left := time.Until(deadline)
		if left <= 0 {
			return &net.OpError{Op: "read/write", Net: "bfp", Err: context.DeadlineExceeded}
		}
		t = time.NewTimer(left)
		defer t.Stop()
		timer = t.C
	}
	select {
	case <-wake:
		return nil
	case <-f.closed:
		return ErrClosed
	case <-f.s.done:
		return ErrClosed
	case <-f.s.businessContext().Done():
		return ErrClosed
	case <-timer:
		return &net.OpError{Op: "read/write", Net: "bfp", Err: context.DeadlineExceeded}
	}
}

func deadlineError(op string) error {
	return &net.OpError{Op: op, Net: "bfp", Err: context.DeadlineExceeded}
}

// acquireWrite waits for the per-flow write token while observing the
// deadline that is current at each wake. SetWriteDeadline signals writeWake,
// so extending a deadline also extends a caller already waiting for another
// goroutine's write to finish. A plain sync.Mutex cannot provide that
// cancellation boundary.
func (f *Flow) acquireWrite() error {
	f.initWriteGate()
	for {
		if f.s.terminating() {
			return ErrClosed
		}
		f.mu.Lock()
		dl := f.writeDeadline
		f.mu.Unlock()
		if !dl.IsZero() && !time.Now().Before(dl) {
			return deadlineError("write")
		}
		var timer <-chan time.Time
		var t *time.Timer
		if !dl.IsZero() {
			t = time.NewTimer(time.Until(dl))
			timer = t.C
		}
		select {
		case <-f.writeGate:
			if t != nil {
				t.Stop()
			}
			f.mu.Lock()
			current := f.writeDeadline
			f.mu.Unlock()
			if !current.IsZero() && !time.Now().Before(current) {
				f.releaseWrite()
				return deadlineError("write")
			}
			return nil
		case <-f.closed:
			if t != nil {
				t.Stop()
			}
			return ErrClosed
		case <-f.s.done:
			if t != nil {
				t.Stop()
			}
			return ErrClosed
		case <-f.s.businessContext().Done():
			if t != nil {
				t.Stop()
			}
			return ErrClosed
		case <-f.writeWake:
			if t != nil {
				t.Stop()
			}
			continue
		case <-timer:
			return deadlineError("write")
		}
	}
}

func (f *Flow) releaseWrite() {
	select {
	case f.writeGate <- struct{}{}:
	default:
		// A release is paired with exactly one successful acquire. A full
		// channel here means a test fixture or caller released twice; keep the
		// actor alive rather than blocking it forever.
	}
}
func (f *Flow) Read(b []byte) (int, error) {
	if f.s.terminating() {
		return 0, ErrClosed
	}
	if len(b) == 0 && f.network == "tcp" {
		return 0, nil
	}
	for {
		if f.s.terminating() {
			return 0, ErrClosed
		}
		f.mu.Lock()
		var n int
		if f.network == "udp" && len(f.messages) > 0 {
			msg := f.messages[0]
			f.messages = f.messages[1:]
			if len(b) < len(msg) {
				f.mu.Unlock()
				f.s.post(func() {
					if !f.s.terminating() {
						f.s.stats.RXBuffered -= len(msg)
					}
				})
				return 0, errors.New("session: datagram read buffer too small")
			}
			n = copy(b, msg)
			f.mu.Unlock()
			f.s.post(func() {
				if !f.s.terminating() {
					f.s.stats.RXBuffered -= len(msg)
				}
			})
			return n, nil
		}
		if f.network == "tcp" && f.buffer.Len() > 0 {
			n, _ = f.buffer.Read(b)
			f.mu.Unlock()
			f.s.post(func() {
				if f.s.terminating() {
					return
				}
				st := f.s.streams[f.id]
				if st == nil {
					return
				}
				st.consumed += uint64(n)
				f.s.totalConsumed += uint64(n)
				f.s.stats.RXBuffered -= n
				f.s.finishReceive(st)
				f.s.enqueue(f.s.maxFlowFrame(st), protocol.Interactive)
				f.s.enqueue(f.s.maxSessionFrame(), protocol.Interactive)
			})
			return n, nil
		}
		e, eof, dl := f.readErr, f.eof, f.readDeadline
		f.mu.Unlock()
		if e != nil {
			return 0, e
		}
		if eof {
			return 0, io.EOF
		}
		if e = f.wait(dl, false); e != nil {
			return 0, e
		}
	}
}
func (f *Flow) Write(b []byte) (int, error) {
	if f.network == "udp" {
		if len(b) > 16<<10 {
			return 0, errors.New("session: datagram too large")
		}
		op := f.beginDatagramWrite(time.Now())
		defer f.endDatagramWrite(op)
		if err := f.acquireDatagramWrite(op); err != nil {
			return 0, err
		}
		defer f.releaseWrite()
		return f.writeDatagram(b, op)
	}
	if err := f.acquireWrite(); err != nil {
		return 0, err
	}
	defer f.releaseWrite()
	total := 0
	for total < len(b) {
		f.mu.Lock()
		dl, e := f.writeDeadline, f.readErr
		f.mu.Unlock()
		if e != nil {
			return total, e
		}
		var accepted int
		var we error
		part := append([]byte(nil), b[total:min(len(b), total+900)]...)
		ctx := context.Background()
		var cancel context.CancelFunc
		if !dl.IsZero() {
			ctx, cancel = context.WithDeadline(ctx, dl)
		}
		err := f.s.businessCall(ctx, func() {
			st := f.s.streams[f.id]
			if st == nil || st.reset || st.localFinal != nil {
				we = io.ErrClosedPipe
				return
			}
			if st.sendNext+uint64(len(part)) > st.maxRemote || f.s.totalSent+uint64(len(part)) > f.s.peerSessionMax || st.sendNext-st.sendAck+uint64(len(part)) > uint64(f.s.opts.MaxFlowBuffer) || f.s.stats.TXBuffered+f.s.txDatagramReserved+len(part) > f.s.opts.MaxSessionBuffer {
				return
			}
			if ctx.Err() != nil || !dl.IsZero() && !time.Now().Before(dl) {
				we = &net.OpError{Op: "write", Net: "bfp", Err: context.DeadlineExceeded}
				return
			}
			st.chunks = append(st.chunks, chunk{offset: st.sendNext, data: part})
			st.sendNext += uint64(len(part))
			f.s.totalSent += uint64(len(part))
			f.s.stats.TXBuffered += len(part)
			accepted = len(part)
			f.s.observeTX(st, uint64(accepted))
		})
		if cancel != nil {
			cancel()
		}
		if err != nil {
			return total, err
		}
		if we != nil {
			return total, we
		}
		total += accepted
		if accepted == 0 {
			if e = f.wait(dl, true); e != nil {
				return total, e
			}
		}
	}
	return total, nil
}
func (f *Flow) CloseWrite() error {
	if f.network == "udp" {
		return f.Close()
	}
	var e error
	err := f.s.businessCall(context.Background(), func() {
		st := f.s.streams[f.id]
		if st == nil || st.reset {
			e = ErrClosed
			return
		}
		if st.localFinal == nil {
			final := st.sendNext
			st.localFinal = &final
			f.s.enqueue(protocol.Frame{Kind: protocol.Fin, Flow: f.id, Offset: final}, protocol.Interactive)
		}
	})
	if err != nil {
		return err
	}
	return e
}
func (f *Flow) Close() error {
	if f.s.terminating() {
		return nil
	}
	f.closeOnce.Do(func() {
		f.s.post(func() {
			if f.s.terminating() {
				return
			}
			if st := f.s.streams[f.id]; st != nil {
				f.s.reset(st, io.ErrClosedPipe, true)
			}
		})
	})
	return nil
}
func (f *Flow) LocalAddr() net.Addr  { return flowAddr(f.s.info.ClientAddress) }
func (f *Flow) RemoteAddr() net.Addr { return flowAddr(f.s.info.ServerAddress) }
func (f *Flow) SetDeadline(t time.Time) error {
	f.mu.Lock()
	f.readDeadline = t
	f.writeDeadline = t
	f.tightenDatagramWrites(t)
	f.mu.Unlock()
	f.signal()
	return nil
}
func (f *Flow) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	f.readDeadline = t
	f.mu.Unlock()
	f.signal()
	return nil
}
func (f *Flow) SetWriteDeadline(t time.Time) error {
	f.mu.Lock()
	f.writeDeadline = t
	f.tightenDatagramWrites(t)
	f.mu.Unlock()
	f.signal()
	return nil
}

type flowAddr string

func (a flowAddr) Network() string { return "bfp" }
func (a flowAddr) String() string  { return string(a) }

type bridgeTargetConn struct {
	net.Conn
	closeOnce sync.Once
	closeErr  error
}

func (c *bridgeTargetConn) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.Conn.Close() })
	return c.closeErr
}
func (c *bridgeTargetConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("session: target does not support half-close")
}

func (s *Session) bridge(st *streamState) {
	conn := st.targetConn
	// Share one full close with RESET and Session destruction, while retaining
	// the original connection's optional CloseWrite for TCP half-close.
	target := &bridgeTargetConn{Conn: conn}
	st.targetConn = target
	flow := st.flow
	network := st.target.Network
	var completedMu sync.Mutex
	completed := 0
	complete := func() {
		completedMu.Lock()
		completed++
		last := completed == 2
		completedMu.Unlock()
		if last {
			// Flow data and FIN remain in Session state until acknowledged.
			// Closing the target must not turn graceful EOF into RESET.
			target.Close()
		}
	}
	go func() {
		defer complete()
		buf := make([]byte, (16<<10)+1)
		for {
			n, e := conn.Read(buf)
			if network == "udp" && n > 16<<10 {
				continue
			}
			if n > 0 || e == nil && network == "udp" {
				if _, we := flow.Write(buf[:n]); we != nil {
					flow.Close()
					return
				}
			}
			if e != nil {
				if e == io.EOF && network == "tcp" {
					flow.CloseWrite()
				} else {
					flow.Close()
				}
				return
			}
		}
	}()
	go func() {
		defer complete()
		buf := make([]byte, 16<<10)
		for {
			n, e := flow.Read(buf)
			if n > 0 || e == nil && network == "udp" {
				if network == "udp" {
					if _, we := conn.Write(buf[:n]); we != nil {
						flow.Close()
						return
					}
				} else {
					at := 0
					for at < n {
						k, we := conn.Write(buf[at:n])
						at += k
						if we != nil || k == 0 {
							flow.Close()
							return
						}
					}
				}
				written := n
				s.post(func() {
					if s.terminating() {
						return
					}
					if current := s.streams[flow.id]; current != nil && !current.reset {
						current.bridgeWritten += uint64(written)
						s.finishReceive(current)
					}
				})
			}
			if e != nil {
				if e == io.EOF {
					// The peer's FIN is acknowledged by finishReceive only after
					// all preceding bytes have been written to the target and its
					// write side has been half-closed.
				} else {
					target.Close()
				}
				return
			}
		}
	}()
}
func (s *Session) datagram(frame protocol.Frame) {
	st := s.streams[frame.Flow]
	if st == nil || st.reset || st.opening || st.target.Network != "udp" {
		return
	}
	id := frame.Offset
	total, at := int(frame.Value>>32), int(uint32(frame.Value))
	if total > 16<<10 || at > total || len(frame.Data) > total-at || frame.Flags != 0 {
		s.stats.Dropped++
		return
	}
	if st.fecProfile.Enabled() {
		size := int(st.fecProfile.ShardSize)
		if !s.fecPermitted(st.fecProfile) || total > int(st.fecProfile.MaxBlockSize) ||
			max(1, (total+size-1)/size) > int(st.fecProfile.MaxDataShards) ||
			at%size != 0 || at == total && total != 0 || len(frame.Data) != min(size, total-at) {
			s.stats.Dropped++
			return
		}
	}
	a := s.datagramAssembly(st, id, total)
	if a == nil {
		return
	}
	for i, b := range frame.Data {
		pos := at + i
		if a.seen[pos] && a.data[pos] != b {
			s.discardDatagram(st, id)
			return
		}
		if !a.seen[pos] {
			a.seen[pos] = true
			a.count++
		}
		a.data[pos] = b
	}
	s.recoverDatagram(st, id, a)
	s.finishDatagram(st, id, a)
}
