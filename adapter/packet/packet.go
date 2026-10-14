package packet

import (
	"bfp/session"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type message struct {
	data   []byte
	addr   Addr
	target *target
}
type target struct {
	addr     Addr
	token    TargetToken
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	retire   bool
	ready    chan struct{}
	gate     chan struct{}
	flow     *session.Flow
	err      error
	last     time.Time
	active   int
	reserved bool
}
type writeOperation struct {
	ctx         context.Context
	cancel      context.CancelCauseFunc
	timer       *time.Timer
	deadline    time.Time
	cost        int
	flow        *session.Flow
	targetToken *TargetToken
	caller      context.Context
}

type Conn struct {
	owner                       *session.Session
	cfg                         Config
	ctx                         context.Context
	cancel                      context.CancelFunc
	mu                          sync.Mutex
	closed                      bool
	wake                        chan struct{}
	targets                     map[Addr]*target
	replies                     []message
	writes                      map[*writeOperation]struct{}
	bytes                       int
	dropped                     uint64
	pendingDials                int
	readers                     int
	readDeadline, writeDeadline time.Time
	wg                          sync.WaitGroup
	monitorDone                 chan struct{}
	stopOnce                    sync.Once
	closeOnce                   sync.Once
	cleanupErrors               []error
	cleanupFailures             uint64
	closeErr                    error
	nextGeneration              uint64
}

var _ net.PacketConn = (*Conn)(nil)

// Connect selects a Session exactly once. The adapter does not retain client,
// so no later WriteTo can call Client.Connect or silently replace the owner.
func Connect(ctx context.Context, client *session.Client, cfg Config) (*Conn, error) {
	if client == nil {
		return nil, errors.New("packet: nil Client")
	}
	if _, err := cfg.defaults(); err != nil {
		return nil, err
	}
	owner, err := client.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return New(ctx, owner, cfg)
}

// New borrows a fixed Session. Close releases adapter-owned Flows and workers;
// it neither closes that shared Session nor owns the physical carrier dialer.
func New(ctx context.Context, owner *session.Session, cfg Config) (*Conn, error) {
	if ctx == nil || owner == nil {
		return nil, errors.New("packet: context and Session required")
	}
	var err error
	cfg, err = cfg.defaults()
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-owner.BusinessDone():
		return nil, session.ErrClosed
	default:
	}
	work, cancel := context.WithCancel(ctx)
	p := &Conn{owner: owner, cfg: cfg, ctx: work, cancel: cancel, wake: make(chan struct{}), targets: make(map[Addr]*target), writes: make(map[*writeOperation]struct{}), monitorDone: make(chan struct{})}
	go func() {
		defer close(p.monitorDone)
		select {
		case <-owner.BusinessDone():
		case <-work.Done():
		}
		p.stop()
	}()
	return p, nil
}

func (p *Conn) Owner() *session.Session { return p.owner }
func (p *Conn) Done() <-chan struct{}   { return p.ctx.Done() }
func (p *Conn) LocalAddr() net.Addr     { return localAddr("bfp-packet") }

type localAddr string

func (a localAddr) Network() string { return "bfp" }
func (a localAddr) String() string  { return string(a) }

func (p *Conn) ownerEnded() bool {
	select {
	case <-p.owner.BusinessDone():
		return true
	default:
		return false
	}
}
func (p *Conn) notifyLocked()            { close(p.wake); p.wake = make(chan struct{}) }
func opError(op string, err error) error { return &net.OpError{Op: op, Net: "bfp-packet", Err: err} }

func (p *Conn) stop() {
	p.stopOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.cancel()
		for _, t := range p.targets {
			if t.flow != nil {
				// Same lock as read/write deadline updates: stop must win over
				// any stale idle deadline and interrupt the actual Flow.Read.
				t.flow.SetReadDeadline(time.Now())
			}
		}
		for _, m := range p.replies {
			p.bytes -= len(m.data) + itemOverhead
		}
		p.replies = nil
		p.notifyLocked()
		p.mu.Unlock()
	})
}

func (p *Conn) Close() error {
	p.closeOnce.Do(func() {
		p.stop()
		<-p.monitorDone
		p.wg.Wait()
		p.mu.Lock()
		p.targets, p.replies = nil, nil
		p.bytes = 0
		p.closeErr = errors.Join(p.cleanupErrors...)
		p.mu.Unlock()
	})
	return p.closeErr
}

func (p *Conn) beginWrite(size int) (*writeOperation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil || p.ownerEnded() {
		return nil, net.ErrClosed
	}
	cost := size + itemOverhead
	if len(p.writes) >= p.cfg.MaxPendingWrites || cost > p.cfg.MaxBufferedBytes-p.bytes {
		return nil, ErrLimit
	}
	op := &writeOperation{deadline: time.Now().Add(p.cfg.WriteTimeout), cost: cost}
	if !p.writeDeadline.IsZero() && p.writeDeadline.Before(op.deadline) {
		op.deadline = p.writeDeadline
	}
	if !time.Now().Before(op.deadline) {
		return nil, context.DeadlineExceeded
	}
	op.ctx, op.cancel = context.WithCancelCause(p.ctx)
	op.timer = time.AfterFunc(time.Until(op.deadline), func() { op.cancel(context.DeadlineExceeded) })
	p.writes[op] = struct{}{}
	p.bytes += cost
	p.wg.Add(1)
	return op, nil
}
func (p *Conn) endWrite(op *writeOperation) {
	p.mu.Lock()
	delete(p.writes, op)
	p.bytes -= op.cost
	op.timer.Stop()
	op.cancel(context.Canceled)
	p.mu.Unlock()
	p.wg.Done()
}

func (p *Conn) writeError(op *writeOperation, err error) error {
	if p.ctx.Err() != nil || p.ownerEnded() || errors.Is(err, session.ErrClosed) {
		return opError("write", net.ErrClosed)
	}
	if op.caller != nil && op.caller.Err() != nil {
		return opError("write", op.caller.Err())
	}
	if errors.Is(context.Cause(op.ctx), context.DeadlineExceeded) {
		return opError("write", context.DeadlineExceeded)
	}
	return opError("write", err)
}

func (p *Conn) WriteTo(b []byte, destination net.Addr) (int, error) {
	return p.WriteToContext(context.Background(), b, destination)
}

// WriteToContext gives trusted logical adapters a per-packet cancellation
// boundary while retaining the same bounded PacketConn admission and owner.
func (p *Conn) WriteToContext(ctx context.Context, b []byte, destination net.Addr) (int, error) {
	if ctx == nil {
		return 0, opError("write", errors.New("packet: context required"))
	}
	if err := ctx.Err(); err != nil {
		return 0, opError("write", err)
	}
	if len(b) > MaxDatagramSize {
		return 0, opError("write", ErrOversize)
	}
	var selectedToken *TargetToken
	switch token := destination.(type) {
	case TargetToken:
		selectedToken = &token
	case *TargetToken:
		if token != nil {
			copyToken := *token
			selectedToken = &copyToken
		}
	}
	if selectedToken != nil && !p.TargetAlive(*selectedToken) {
		return 0, opError("write", ErrTargetClosed)
	}
	addr, domain, err := normalize(destination)
	if err != nil {
		return 0, opError("write", err)
	}
	op, err := p.beginWrite(len(b))
	if err != nil {
		return 0, opError("write", err)
	}
	defer p.endWrite(op)
	op.caller = ctx
	stop := context.AfterFunc(ctx, func() { op.cancel(context.Cause(ctx)) })
	defer stop()
	if err := ctx.Err(); err != nil {
		op.cancel(err)
	}
	op.targetToken = selectedToken
	data := append([]byte(nil), b...)
	t, err := p.getTarget(op, addr, domain)
	if err != nil {
		return 0, p.writeError(op, err)
	}
	select {
	case <-t.ready:
	case <-op.ctx.Done():
		return 0, p.writeError(op, context.Cause(op.ctx))
	}
	p.mu.Lock()
	if p.closed || t.err != nil || t.flow == nil || op.ctx.Err() != nil {
		err = t.err
		if err == nil {
			err = net.ErrClosed
		}
		p.mu.Unlock()
		return 0, p.writeError(op, err)
	}
	t.active++
	op.flow = t.flow
	p.mu.Unlock()
	defer func() { p.mu.Lock(); t.active--; p.mu.Unlock() }()
	select {
	case <-t.gate:
	case <-op.ctx.Done():
		return 0, p.writeError(op, context.Cause(op.ctx))
	}
	defer func() { t.gate <- struct{}{} }()
	p.mu.Lock()
	closed, targetErr := p.closed, t.err
	if !closed && targetErr == nil && op.ctx.Err() == nil {
		// Serialize this setter with adapter setters: an old snapshot must not
		// overwrite a shorter cutoff before Flow registers actual admission.
		t.flow.SetWriteDeadline(op.deadline)
	}
	p.mu.Unlock()
	if closed || targetErr != nil || op.ctx.Err() != nil {
		if targetErr == nil {
			targetErr = net.ErrClosed
		}
		return 0, p.writeError(op, targetErr)
	}
	n, err := t.flow.WriteDatagramContext(op.ctx, data)
	if err != nil {
		return n, p.writeError(op, err)
	}
	if n != len(data) {
		return n, opError("write", io.ErrShortWrite)
	}
	p.mu.Lock()
	if !p.closed && p.ctx.Err() == nil && !p.ownerEnded() {
		t.last = time.Now()
		t.flow.SetReadDeadline(t.last.Add(p.cfg.IdleTimeout))
	}
	p.mu.Unlock()
	return n, nil
}

func (p *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	p.mu.Lock()
	p.readers++
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.readers--; p.mu.Unlock() }()
	for {
		p.mu.Lock()
		if p.closed || p.ctx.Err() != nil || p.ownerEnded() {
			p.mu.Unlock()
			return 0, nil, opError("read", net.ErrClosed)
		}
		dl := p.readDeadline
		if !dl.IsZero() && !time.Now().Before(dl) {
			p.mu.Unlock()
			return 0, nil, opError("read", context.DeadlineExceeded)
		}
		if len(p.replies) != 0 {
			m := p.replies[0]
			copy(p.replies, p.replies[1:])
			p.replies[len(p.replies)-1] = message{}
			p.replies = p.replies[:len(p.replies)-1]
			p.bytes -= len(m.data) + itemOverhead
			p.mu.Unlock()
			if p.cfg.ExposeTargetToken {
				return copy(b, m.data), m.target.token, nil
			}
			return copy(b, m.data), m.addr, nil
		}
		wake := p.wake
		p.mu.Unlock()
		var timer *time.Timer
		var expiry <-chan time.Time
		if !dl.IsZero() {
			timer = time.NewTimer(time.Until(dl))
			expiry = timer.C
		}
		select {
		case <-wake:
		case <-p.ctx.Done():
		case <-p.owner.BusinessDone():
		case <-expiry:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

// TargetAlive verifies a token against its exact current target. Aggregate
// Stats intentionally cannot substitute for this per-generation check.
func (p *Conn) TargetAlive(token TargetToken) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	t := p.targets[token.Address]
	return token.owner == p && token.Generation != 0 && t != nil && t.token == token && t.err == nil && !t.retire && t.ctx.Err() == nil && !p.closed && p.ctx.Err() == nil && !p.ownerEnded()
}

// TargetTokenForAddress snapshots the current exact target, including a
// pending dial. RetireTarget revalidates this token before changing anything.
func (p *Conn) TargetTokenForAddress(address Addr) (TargetToken, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t := p.targets[address]
	if t == nil {
		return TargetToken{}, false
	}
	return t.token, true
}

// RetireTarget cancels the exact generation and waits for its owned target
// worker and Flow cleanup. A stale/foreign token cannot retire a replacement.
// Unlike ordinary WriteTo failure, this is an explicit adapter transaction
// abort and therefore permits a later explicit preparation of a new target.
func (p *Conn) RetireTarget(token TargetToken) bool {
	p.mu.Lock()
	t := p.targets[token.Address]
	if token.owner != p || token.Generation == 0 || t == nil || t.token != token {
		p.mu.Unlock()
		return false
	}
	select {
	case <-t.done:
		delete(p.targets, token.Address)
		p.discardTargetRepliesLocked(t)
		p.releaseTargetBufferLocked(t)
		p.mu.Unlock()
		if p.cfg.TargetRetired != nil {
			p.notifyRetired(token)
		}
		return true
	default:
	}
	t.retire, t.err = true, ErrTargetClosed
	t.cancel()
	p.discardTargetRepliesLocked(t)
	if t.flow != nil {
		t.flow.SetReadDeadline(time.Now())
		t.flow.SetWriteDeadline(time.Now())
		for op := range p.writes {
			if op.flow == t.flow {
				op.cancel(ErrTargetClosed)
			}
		}
	}
	done := t.done
	p.mu.Unlock()
	<-done
	return true
}

// Read deadline updates wake every blocked reader. Write operations capture a
// finite cutoff at entry; setters can tighten it but cannot renew or clear an
// already-running operation. Extended/cleared deadlines apply to new Writes.
func (p *Conn) SetDeadline(dl time.Time) error      { return p.setDeadline(dl, true, true) }
func (p *Conn) SetReadDeadline(dl time.Time) error  { return p.setDeadline(dl, true, false) }
func (p *Conn) SetWriteDeadline(dl time.Time) error { return p.setDeadline(dl, false, true) }
func (p *Conn) setDeadline(dl time.Time, read, write bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ownerEnded() {
		return net.ErrClosed
	}
	if read {
		p.readDeadline = dl
	}
	if write {
		p.writeDeadline = dl
		if !dl.IsZero() {
			for op := range p.writes {
				if dl.Before(op.deadline) {
					op.deadline = dl
					op.timer.Reset(time.Until(dl))
					if op.flow != nil {
						op.flow.SetWriteDeadline(dl)
					}
				}
			}
		}
	}
	p.notifyLocked()
	return nil
}

type Stats struct {
	Targets, PendingDials, PendingWrites, PendingReads, QueuedDatagrams, BufferedBytes int
	Dropped                                                                            uint64
	CleanupFailures                                                                    uint64
}

func (p *Conn) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Stats{Targets: len(p.targets), PendingDials: p.pendingDials, PendingWrites: len(p.writes), PendingReads: p.readers, QueuedDatagrams: len(p.replies), BufferedBytes: p.bytes, Dropped: p.dropped, CleanupFailures: p.cleanupFailures}
}
