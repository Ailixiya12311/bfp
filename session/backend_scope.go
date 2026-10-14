package session

import (
	"bfp/internal/backend"
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// A retained resolver guard owns only immutable eligibility and cancellation
// state. It must not keep a terminated Session or its actor tables reachable.
type backendLifetime struct {
	ctx       context.Context
	until     time.Time
	authority *deviceAuthority
	terminal  atomic.Bool
}

func (g *backendLifetime) check() error {
	if g == nil || g.terminal.Load() || g.ctx == nil || g.ctx.Err() != nil ||
		g.authority != nil && g.authority.revoked.Load() ||
		!g.until.IsZero() && !time.Now().Before(g.until) {
		return ErrClosed
	}
	return nil
}

// The first terminal decision publishes this under the Session admission
// gate. Resolver goroutines can reject it before actor cleanup or cancellation.
func (s *Session) markBackendTerminal() {
	if s != nil && s.backendGuard != nil {
		s.backendGuard.terminal.Store(true)
	}
	if s != nil && s.localAddressGuard != nil {
		s.localAddressGuard.terminal.Store(true)
	}
}

// Cleanup may race an already-started AfterFunc. Once joins cleanup execution;
// watchDone separately joins the callback itself. Its stop result is only a
// proof of callback completion when stopping returned true.
type backendRetirement struct {
	mu        sync.Mutex
	once      sync.Once
	cleanup   func()
	stopWatch func() bool
	watchDone chan struct{}
	watchOnce sync.Once
}

func newBackendRetirement(ctx context.Context, cleanup func()) *backendRetirement {
	b := &backendRetirement{cleanup: cleanup, watchDone: make(chan struct{})}
	stop := context.AfterFunc(ctx, func() {
		defer b.finishWatch()
		b.clean()
	})
	b.mu.Lock()
	select {
	case <-b.watchDone:
		// Cancellation completed before registration returned. Do not
		// reinstall a stop closure after the callback retired itself.
	default:
		b.stopWatch = stop
	}
	b.mu.Unlock()
	return b
}

func (b *backendRetirement) clean() {
	b.once.Do(func() {
		b.mu.Lock()
		cleanup := b.cleanup
		b.mu.Unlock()
		if cleanup != nil {
			cleanup()
		}
		b.mu.Lock()
		b.cleanup = nil
		b.mu.Unlock()
	})
}

func (b *backendRetirement) finishWatch() {
	b.watchOnce.Do(func() {
		b.mu.Lock()
		b.stopWatch = nil
		close(b.watchDone)
		b.mu.Unlock()
	})
}

func (b *backendRetirement) retire() {
	b.clean()
	b.mu.Lock()
	stop := b.stopWatch
	b.stopWatch = nil
	b.mu.Unlock()
	if stop != nil && stop() {
		b.finishWatch()
	}
	<-b.watchDone
}

// Called once before the actor starts, after fresh proof authorization. The
// stable cancellation closure captures this binding and the raw context
// cancel function, independently of Session's mutable backend references.
func (s *Session) bindSessionBackend(base Backend, cancel context.CancelFunc) {
	if s.client || backend.IsNil(base) {
		return
	}
	factory, ok := base.(SessionBackendFactory)
	if !ok {
		return
	}
	guard := &backendLifetime{ctx: s.ctx, until: s.info.lifetimeUntil, authority: s.authority}
	s.backendGuard = guard
	scoped, cleanup := factory.ForSession(s.ctx, guard.check)
	binding := newBackendRetirement(s.ctx, cleanup)
	s.closeBackend = binding.retire
	s.stopBusiness = func() {
		cancel()
		binding.retire()
	}
	if backend.IsNil(scoped) {
		s.cancel()
		return
	}
	s.backend = scoped
}
