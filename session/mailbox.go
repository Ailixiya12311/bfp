package session

import (
	"context"
	"sync"
)

// Registration covers only queue publication, never waiting for actor work.
// Retirement seals registration, wakes blocked publishers, and joins every
// already-registered select before the actor discards retained queue entries.
// Data channels remain open; stopped senders cannot panic on a closed queue.
type publishGate struct {
	mu         sync.Mutex
	retired    bool
	stopped    chan struct{}
	publishers sync.WaitGroup
}

func (g *publishGate) begin() (<-chan struct{}, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopped == nil {
		g.stopped = make(chan struct{})
	}
	if g.retired {
		return g.stopped, false
	}
	g.publishers.Add(1)
	return g.stopped, true
}

func (g *publishGate) retire() {
	g.mu.Lock()
	if g.stopped == nil {
		g.stopped = make(chan struct{})
	}
	if !g.retired {
		g.retired = true
		close(g.stopped)
	}
	g.mu.Unlock()
	g.publishers.Wait()
}

func (s *Session) publishCommand(ctx context.Context, fn func()) error {
	stopped, ok := s.mailbox.begin()
	if !ok {
		return ErrClosed
	}
	defer s.mailbox.publishers.Done()
	select {
	case s.commands <- fn:
		return nil
	case <-stopped:
	case <-s.controlContext().Done():
	case <-s.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return ErrClosed
}

func (s *Session) publishPacket(p packet, wait bool) bool {
	if p.c == nil {
		return false
	}
	stopped, ok := s.mailbox.begin()
	if !ok {
		return false
	}
	defer s.mailbox.publishers.Done()
	if wait {
		select {
		case s.incoming <- p:
			return true
		case <-stopped:
		case <-s.controlContext().Done():
		case <-s.done:
		case <-p.c.closed:
		}
		return false
	}
	select {
	case s.incoming <- p:
		return true
	case <-stopped:
	case <-s.controlContext().Done():
	case <-s.done:
	default:
	}
	return false
}

func (s *Session) retireMailbox() {
	s.mailbox.retire()
	// Registered publishers have all finished. New ones observe retired under
	// the same lock, so neither queue can be refilled after these drains.
	for {
		select {
		case <-s.commands:
		default:
			goto packets
		}
	}
packets:
	for {
		select {
		case <-s.incoming:
		default:
			return
		}
	}
}
