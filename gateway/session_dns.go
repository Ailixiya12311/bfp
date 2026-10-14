package gateway

import (
	"bfp/internal/backend"
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"
)

const (
	sessionDNSEntries   = 64
	sessionDNSAnswers   = 16
	sessionDNSHostBytes = 253
	sessionDNSMaxAge    = 30 * time.Second
	globalDNSConcurrent = 32
)

var (
	ErrDNSLimit             = errors.New("gateway: session DNS budget exceeded")
	ErrSessionBackendClosed = errors.New("gateway: session backend closed")
)

type dnsEntry struct {
	addresses []netip.Addr
	expires   time.Time
}

// Only this scope owns its cache. The factory Dialer owns the shared execution
// slots and immutable policy. No query names or answers enter diagnostic logs.
type sessionDNS struct {
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	valid      func() error
	closed     bool
	generation uint64
	entries    map[string]dnsEntry
	now        func() time.Time
}

var _ backend.SessionFactory = (*Dialer)(nil)
var _ backend.SessionAddressAllocator = (*Dialer)(nil)

// The returned cleanup may outlive the scope. Retire both its target closure
// and its AfterFunc registration once local cleanup and callback completion
// are joined; resolver or socket operations are deliberately not awaited.
type dnsRetirement struct {
	mu        sync.Mutex
	once      sync.Once
	cleanup   func()
	stopWatch func() bool
	watchDone chan struct{}
	watchOnce sync.Once
}

func newDNSRetirement(ctx context.Context, cleanup func()) *dnsRetirement {
	r := &dnsRetirement{cleanup: cleanup, watchDone: make(chan struct{})}
	stop := context.AfterFunc(ctx, func() {
		defer r.finishWatch()
		r.clean()
	})
	r.mu.Lock()
	select {
	case <-r.watchDone:
	default:
		r.stopWatch = stop
	}
	r.mu.Unlock()
	return r
}

func (r *dnsRetirement) clean() {
	r.once.Do(func() {
		r.mu.Lock()
		cleanup := r.cleanup
		r.mu.Unlock()
		if cleanup != nil {
			cleanup()
		}
		r.mu.Lock()
		r.cleanup = nil
		r.mu.Unlock()
	})
}

func (r *dnsRetirement) finishWatch() {
	r.watchOnce.Do(func() {
		r.mu.Lock()
		r.stopWatch = nil
		close(r.watchDone)
		r.mu.Unlock()
	})
}

func (r *dnsRetirement) retire() {
	r.clean()
	r.mu.Lock()
	stop := r.stopWatch
	r.stopWatch = nil
	r.mu.Unlock()
	if stop != nil && stop() {
		r.finishWatch()
	}
	<-r.watchDone
}

// ForSession allocates no sockets and performs no DNS work. Its fixed local
// 30-second max-age is not an authoritative DNS TTL: LookupIPAddr exposes none.
func (d *Dialer) ForSession(parent context.Context, valid func() error) (backend.Dialer, func()) {
	ctx, cancel := context.WithCancel(parent)
	scope := &sessionDNS{ctx: ctx, cancel: cancel, valid: valid, generation: 1,
		entries: make(map[string]dnsEntry), now: time.Now}
	clone := *d
	clone.dns = scope
	// A fake-IP scope is created only after Session confirmation. Its parent is
	// the same scoped context as DNS, so explicit stop, Session cancellation,
	// authority revocation, and lifetime expiry all retire both maps together.
	fake, err := newFakeIPScopeWithGuard(ctx, d.fakeIPLifetime, d.fakeIPCapacity, valid)
	if err != nil {
		// SessionFactory has no error return. A malformed internal profile
		// therefore returns an unusable backend instead of silently bypassing
		// the configured scope; Session's existing nil-result gate aborts it.
		scope.close()
		return nil, scope.close
	}
	clone.fakeIP = fake
	retirement := newDNSRetirement(ctx, func() {
		scope.close()
		if clone.fakeIP != nil {
			_ = clone.fakeIP.Close()
		}
	})
	return &clone, retirement.retire
}

func (s *sessionDNS) invalidateLocked() {
	if !s.closed {
		s.closed = true
		s.generation++
		s.entries = nil
		s.valid = nil
		s.cancel()
	}
}

func (s *sessionDNS) checkLocked() error {
	if s.closed {
		return ErrSessionBackendClosed
	}
	if err := s.ctx.Err(); err != nil {
		s.invalidateLocked()
		return err
	}
	if s.valid != nil {
		if err := s.valid(); err != nil {
			s.invalidateLocked()
			return err
		}
	}
	return nil
}

func (s *sessionDNS) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalidateLocked()
}

func (s *sessionDNS) guard() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkLocked()
}

func (s *sessionDNS) get(host string) ([]netip.Addr, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkLocked(); err != nil {
		return nil, 0, err
	}
	now := s.now()
	for name, entry := range s.entries {
		if !now.Before(entry.expires) {
			delete(s.entries, name)
		}
	}
	entry, ok := s.entries[host]
	if !ok {
		return nil, s.generation, nil
	}
	return append([]netip.Addr(nil), entry.addresses...), s.generation, nil
}

func (s *sessionDNS) put(host string, addresses []netip.Addr, generation uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkLocked(); err != nil {
		return err
	}
	if generation != s.generation {
		return ErrSessionBackendClosed
	}
	now := s.now()
	for name, entry := range s.entries {
		if !now.Before(entry.expires) {
			delete(s.entries, name)
		}
	}
	if _, exists := s.entries[host]; !exists && len(s.entries) >= sessionDNSEntries {
		// A bounded scan chooses the oldest expiry; lexical ties are deterministic.
		victim := ""
		var oldest time.Time
		for name, entry := range s.entries {
			if victim == "" || entry.expires.Before(oldest) || entry.expires.Equal(oldest) && name < victim {
				victim, oldest = name, entry.expires
			}
		}
		delete(s.entries, victim)
	}
	s.entries[host] = dnsEntry{addresses: append([]netip.Addr(nil), addresses...), expires: now.Add(sessionDNSMaxAge)}
	return nil
}

func (d *Dialer) guard(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d.dns != nil {
		return d.dns.guard()
	}
	return nil
}

func (d *Dialer) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if len(host) > sessionDNSHostBytes {
		return nil, ErrDNSLimit
	}
	if err := d.guard(ctx); err != nil {
		return nil, err
	}
	var generation uint64
	if d.dns != nil {
		cached, token, err := d.dns.get(host)
		if err != nil {
			return nil, err
		}
		generation = token
		if len(cached) != 0 {
			if err = d.validateCandidates(cached); err != nil {
				return nil, err
			}
			if err = d.guard(ctx); err != nil {
				return nil, err
			}
			return cached, nil
		}
	}
	select {
	case d.resolverSlots <- struct{}{}:
		// Keep the permit until actual execution returns, even if an injected
		// resolver ignores cancellation. Early release would exceed this budget.
		defer func() { <-d.resolverSlots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := d.guard(ctx); err != nil {
		return nil, err
	}
	resolved, err := d.lookup(ctx, host)
	if err != nil {
		return nil, err // No negative or error caching.
	}
	if err = d.guard(ctx); err != nil {
		return nil, err
	}
	if len(resolved) == 0 {
		return nil, errors.New("gateway: destination has no address")
	}
	if len(resolved) > sessionDNSAnswers {
		return nil, ErrDNSLimit
	}
	candidates := make([]netip.Addr, 0, len(resolved))
	for _, result := range resolved {
		a, ok := netip.AddrFromSlice(result.IP)
		if !ok || result.Zone != "" {
			return nil, ErrPolicyDenied
		}
		candidates = append(candidates, a.Unmap())
	}
	if err = d.validateCandidates(candidates); err != nil {
		return nil, err
	}
	if d.dns != nil {
		if err = d.dns.put(host, candidates, generation); err != nil {
			return nil, err
		}
	}
	if err = d.guard(ctx); err != nil {
		return nil, err
	}
	return candidates, nil
}

func (d *Dialer) validateCandidates(candidates []netip.Addr) error {
	if len(candidates) == 0 {
		return errors.New("gateway: destination has no address")
	}
	for _, address := range candidates {
		if d.routeExcluded(address) {
			return ErrRouteExcluded
		}
		if !d.permitted(address) {
			return ErrPolicyDenied
		}
	}
	return nil
}
