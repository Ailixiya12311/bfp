package gateway

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"bfp/internal/addressscope"
)

// FakeIPScopeFactory creates empty client maps after a fresh confirmed Session.
// Reuse one factory for successive Sessions of a client. Its monotonic address
// cursor prevents immediate cross-Session reuse and fails closed at exhaustion.
// The cursor stores no names, answers, leases or Session identities. It does
// not persist across process restart, so external caches still require owner
// and TTL isolation. No DNS server, TUN or OS address is configured here.
type FakeIPScopeFactory struct {
	mu       sync.Mutex
	next     netip.Addr
	lifetime time.Duration
	capacity int
}

var _ addressscope.Factory = (*FakeIPScopeFactory)(nil)
var _ addressscope.Scope = (*FakeIPScope)(nil)
var _ addressscope.FamilyLeaseAllocator = (*FakeIPScope)(nil)

func NewFakeIPScopeFactory(lifetime time.Duration, capacity int) (*FakeIPScopeFactory, error) {
	return NewFakeIPScopeFactoryFrom(lifetime, capacity, fakeIPScopePrefix.Addr())
}

// NewFakeIPScopeFactoryFrom leaves addresses below first unused. A host TUN
// adapter can reserve its own gateway subnet without consuming DNS mappings.
// Successive scopes still share one monotonic cursor and fail at exhaustion.
func NewFakeIPScopeFactoryFrom(lifetime time.Duration, capacity int, first netip.Addr) (*FakeIPScopeFactory, error) {
	if capacity == 0 {
		capacity = defaultFakeIPCapacity
	}
	if lifetime <= 0 || lifetime > maxFakeIPLifetime || capacity != defaultFakeIPCapacity && capacity != maxFakeIPCapacity || !first.Is4() || !fakeIPScopePrefix.Contains(first) {
		return nil, ErrFakeIPConfig
	}
	return &FakeIPScopeFactory{next: first, lifetime: lifetime, capacity: capacity}, nil
}

func (f *FakeIPScopeFactory) ForClientSession(ctx context.Context, valid func() error) (addressscope.Scope, error) {
	if f == nil {
		return nil, ErrFakeIPConfig
	}
	scope, err := newFakeIPScopeWithGuard(ctx, f.lifetime, f.capacity, valid)
	if err != nil {
		return nil, err
	}
	// No mappings exist yet; Session has not published this scope to callers.
	scope.mu.Lock()
	if !scope.closed {
		scope.clientFactory = f
	}
	scope.mu.Unlock()
	return scope, nil
}

func (f *FakeIPScopeFactory) allocate(owner *FakeIPScope) (netip.Addr, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for f.next.IsValid() && fakeIPScopePrefix.Contains(f.next) {
		ip := f.next
		f.next = ip.Next()
		last := ip.As4()[3]
		if last == 0 || last == 255 {
			continue
		}
		fakeIPLeases.Lock()
		if _, exists := fakeIPLeases.owners[ip]; exists {
			fakeIPLeases.Unlock()
			continue
		}
		fakeIPLeases.owners[ip] = owner
		fakeIPLeases.Unlock()
		return ip, true
	}
	return netip.Addr{}, false
}

func (s *FakeIPScope) AllocateSessionAddress(host string) (netip.Addr, error) {
	return s.Allocate(host)
}

func (s *FakeIPScope) ResolveSessionAddress(ip netip.Addr) (string, error) {
	return s.Resolve(ip)
}
