package packet

import (
	"bfp/session"
	"context"
	"errors"
	"net"
	"time"
)

func (p *Conn) getTarget(op *writeOperation, addr Addr, domain string) (*target, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil || p.ownerEnded() {
		return nil, net.ErrClosed
	}
	if op.ctx.Err() != nil {
		return nil, context.Cause(op.ctx)
	}
	if !time.Now().Before(op.deadline) {
		return nil, context.DeadlineExceeded
	}
	if t := p.targets[addr]; t != nil {
		if op.targetToken != nil && t.token != *op.targetToken {
			return nil, ErrTargetClosed
		}
		return t, nil
	}
	if op.targetToken != nil {
		return nil, ErrTargetClosed
	}
	if len(p.targets) >= p.cfg.MaxTargets || targetReservation > p.cfg.MaxBufferedBytes-p.bytes {
		return nil, ErrLimit
	}
	if p.nextGeneration == ^uint64(0) {
		// Refuse exhaustion instead of wrapping a generation onto an old
		// token. This check precedes every target/resource allocation.
		return nil, ErrLimit
	}
	p.nextGeneration++
	ctx, cancel := context.WithCancel(p.ctx)
	t := &target{addr: addr, token: TargetToken{Address: addr, Generation: p.nextGeneration, owner: p}, ctx: ctx, cancel: cancel, done: make(chan struct{}), ready: make(chan struct{}), gate: make(chan struct{}, 1), last: time.Now(), reserved: true}
	t.gate <- struct{}{}
	p.targets[addr] = t
	p.bytes += targetReservation
	p.pendingDials++
	p.wg.Add(1)
	go p.dialTarget(t, domain)
	return t, nil
}

func (p *Conn) dialTarget(t *target, domain string) {
	defer p.wg.Done()
	ctx, cancel := context.WithTimeout(t.ctx, p.cfg.DialTimeout)
	meta, err := p.targetMetadata(ctx, t.token, domain)
	var conn net.Conn
	if err == nil {
		conn, err = p.owner.DialMetadata(ctx, meta)
	}
	cancel()
	var flow *session.Flow
	if err == nil {
		var ok bool
		flow, ok = conn.(*session.Flow)
		if !ok {
			err = errors.New("packet: Session returned a non-Flow UDP connection")
		}
	}
	p.mu.Lock()
	p.pendingDials--
	install := err == nil && !p.closed && p.ctx.Err() == nil && !p.ownerEnded() && !t.retire && t.ctx.Err() == nil
	if install {
		t.flow, t.last = flow, time.Now()
		p.wg.Add(1)
	} else {
		if err == nil {
			err = net.ErrClosed
		}
		t.err = err
		p.releaseTargetBufferLocked(t)
	}
	close(t.ready)
	p.mu.Unlock()
	if !install {
		if flow != nil {
			p.closeFlow(flow)
		}
		p.finishTarget(t)
		return
	}
	go p.readTarget(t)
}

func (p *Conn) finishTarget(t *target) {
	t.cancel()
	p.mu.Lock()
	if t.err == nil {
		t.err = ErrTargetClosed
	}
	// Default adapters retain terminal errors so ordinary WriteTo cannot
	// silently retry. Lifecycle-aware adapters retire the exact generation
	// and let their own Prepare decide when a new association is allowed.
	removed := false
	if p.targets[t.addr] == t && (t.retire || p.cfg.TargetRetired != nil || p.closed) {
		delete(p.targets, t.addr)
		p.discardTargetRepliesLocked(t)
		removed = true
	}
	p.releaseTargetBufferLocked(t)
	p.mu.Unlock()
	if removed && p.cfg.TargetRetired != nil {
		p.notifyRetired(t.token)
	}
	close(t.done)
}

func (p *Conn) notifyRetired(token TargetToken) {
	defer func() {
		if recover() != nil {
			// Trusted local callbacks must be cooperative. A panic is still
			// contained so target completion and Close cannot wait forever.
			p.mu.Lock()
			p.cleanupFailures++
			if len(p.cleanupErrors) < p.cfg.MaxTargets {
				p.cleanupErrors = append(p.cleanupErrors, errors.New("packet: target retirement callback panicked"))
			}
			p.mu.Unlock()
		}
	}()
	p.cfg.TargetRetired(token)
}

func (p *Conn) releaseTargetBufferLocked(t *target) {
	if t.reserved {
		p.bytes -= targetReservation
		t.reserved = false
	}
}

func (p *Conn) closeFlow(flow *session.Flow) {
	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.CleanupTimeout)
	err := flow.CloseContext(ctx)
	cancel()
	if err != nil {
		p.mu.Lock()
		p.cleanupFailures++
		if len(p.cleanupErrors) < p.cfg.MaxTargets {
			p.cleanupErrors = append(p.cleanupErrors, err)
		}
		p.mu.Unlock()
	}
}

func (p *Conn) readTarget(t *target) {
	defer p.wg.Done()
	defer func() {
		p.closeFlow(t.flow)
		p.finishTarget(t)
	}()
	buffer := make([]byte, MaxDatagramSize+1)
	for {
		p.mu.Lock()
		if p.closed || p.ctx.Err() != nil || p.ownerEnded() || t.err != nil || t.ctx.Err() != nil {
			p.mu.Unlock()
			return
		}
		until := t.last.Add(p.cfg.IdleTimeout)
		if t.active > 0 && !time.Now().Before(until) {
			until = time.Now().Add(p.cfg.IdleTimeout)
		}
		t.flow.SetReadDeadline(until)
		p.mu.Unlock()
		n, err := t.flow.Read(buffer)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				p.mu.Lock()
				idle := !p.closed && t.active == 0 && !time.Now().Before(t.last.Add(p.cfg.IdleTimeout))
				if idle && p.targets[t.addr] == t {
					t.err = ErrTargetClosed
					t.retire = true
				}
				p.mu.Unlock()
				if !idle && p.ctx.Err() == nil {
					continue
				}
			}
			return
		}
		p.mu.Lock()
		if p.closed || p.ctx.Err() != nil || p.ownerEnded() || t.err != nil || t.ctx.Err() != nil || p.targets[t.addr] != t {
			p.mu.Unlock()
			return
		}
		t.last = time.Now()
		cost := n + itemOverhead
		if n > MaxDatagramSize || len(p.replies) >= p.cfg.MaxReceiveQueue || cost > p.cfg.MaxBufferedBytes-p.bytes {
			p.dropped++
			p.mu.Unlock()
			continue
		}
		// n==0 and err==nil is one real empty datagram, charged as one item.
		p.replies = append(p.replies, message{data: append([]byte(nil), buffer[:n]...), addr: t.addr, target: t})
		p.bytes += cost
		p.notifyLocked()
		p.mu.Unlock()
	}
}

func (p *Conn) discardTargetRepliesLocked(t *target) {
	out := p.replies[:0]
	for _, m := range p.replies {
		if m.target == t {
			p.bytes -= len(m.data) + itemOverhead
		} else {
			out = append(out, m)
		}
	}
	for i := len(out); i < len(p.replies); i++ {
		p.replies[i] = message{}
	}
	p.replies = out
}
