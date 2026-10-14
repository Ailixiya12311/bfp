package gateway

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode"

	"bfp/internal/addressscope"
	"bfp/protocol"
)

// FakeIPScope is a bounded, session-owned reverse map for an upstream fake-IP
// allocator. It is deliberately separate from the gateway's destination
// policy: an address in 198.18.0.0/15 is never dialed until a live scope maps it
// back to a hostname. The scope does not allocate an OS address or configure a
// TUN, route, DNS server, ARP entry, or NAT table.
//
// A scope's lifetime is the upper bound for every mapping. Close is synchronous
// and idempotent; after it returns, Resolve and RestoreTarget cannot observe a
// mapping and Allocate cannot create one.
type FakeIPScope struct {
	mu            sync.Mutex
	ctx           context.Context
	valid         func() error
	stop          func() bool
	capacity      int
	ttl           time.Duration
	byHost        map[string]fakeIPEntry
	byIP          map[netip.Addr]string
	next          netip.Addr
	closed        bool
	clientFactory *FakeIPScopeFactory
}

type fakeIPEntry struct {
	ip      netip.Addr
	expires time.Time
}

var (
	ErrFakeIPScopeClosed = errors.New("gateway: fake-IP scope closed")
	ErrFakeIPUnmapped    = errors.New("gateway: fake-IP is not mapped in this session")
	ErrFakeIPCapacity    = errors.New("gateway: fake-IP scope capacity exhausted")
	ErrFakeIPConfig      = errors.New("gateway: invalid fake-IP scope configuration")
	ErrFakeIPHost        = errors.New("gateway: invalid fake-IP hostname")
	ErrFakeIPTarget      = errors.New("gateway: invalid fake-IP target")
)

const (
	defaultFakeIPCapacity = 64
	maxFakeIPCapacity     = 128
	maxFakeIPLifetime     = 30 * 24 * time.Hour
)

var fakeIPScopePrefix = addressscope.FakeIPv4Prefix()

var fakeIPLeases struct {
	sync.Mutex
	owners map[netip.Addr]*FakeIPScope
}

// NewFakeIPScope creates a scope whose mappings expire no later than lifetime.
// Capacity 0 selects the bounded default of 64; the only larger supported
// profile is 128 so a caller cannot silently create an unbounded map.
func NewFakeIPScope(parent context.Context, lifetime time.Duration, capacity int) (*FakeIPScope, error) {
	return newFakeIPScopeWithGuard(parent, lifetime, capacity, nil)
}

// The retained guard is an immutable eligibility object supplied by Session,
// not a closure over its actor tables. A mapping API call must check it before
// waiting for the asynchronous context cancellation watcher.
func newFakeIPScopeWithGuard(parent context.Context, lifetime time.Duration, capacity int, valid func() error) (*FakeIPScope, error) {
	if parent == nil {
		parent = context.Background()
	}
	if lifetime <= 0 || lifetime > maxFakeIPLifetime || capacity < 0 || capacity > maxFakeIPCapacity {
		return nil, ErrFakeIPConfig
	}
	if capacity == 0 {
		capacity = defaultFakeIPCapacity
	}
	if capacity != defaultFakeIPCapacity && capacity != maxFakeIPCapacity {
		return nil, ErrFakeIPConfig
	}
	fakeIPLeases.Lock()
	if fakeIPLeases.owners == nil {
		fakeIPLeases.owners = make(map[netip.Addr]*FakeIPScope)
	}
	fakeIPLeases.Unlock()
	s := &FakeIPScope{
		ctx:      parent,
		valid:    valid,
		capacity: capacity,
		ttl:      lifetime,
		byHost:   make(map[string]fakeIPEntry, capacity),
		byIP:     make(map[netip.Addr]string, capacity),
		next:     fakeIPScopePrefix.Addr(),
	}
	// A parent cancellation is the Session owner boundary. AfterFunc does not
	// require a watcher goroutine and Close remains the single cleanup path.
	stop := context.AfterFunc(parent, func() { _ = s.Close() })
	s.mu.Lock()
	if !s.closed {
		s.stop = stop
	}
	closed := s.closed
	s.mu.Unlock()
	if closed {
		stop()
	}
	return s, nil
}

// Allocate returns a stable fake address for a hostname within this scope.
// Host names are canonicalized for reuse, but no DNS lookup is performed.
func (s *FakeIPScope) Allocate(host string) (netip.Addr, error) {
	ip, _, err := s.AllocateSessionAddressLease(host)
	return ip, err
}

// AllocateSessionAddressLease returns the mapping's actual immutable expiry.
// Repeated allocation reuses both its address and its original deadline.
func (s *FakeIPScope) AllocateSessionAddressLease(host string) (netip.Addr, time.Time, error) {
	canonical, err := normalizeFakeHost(host)
	if err != nil {
		return netip.Addr{}, time.Time{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkLocked(); err != nil {
		return netip.Addr{}, time.Time{}, err
	}
	now := time.Now()
	s.expireLocked(now)
	if entry, ok := s.byHost[canonical]; ok {
		return entry.ip, entry.expires, nil
	}
	if len(s.byHost) >= s.capacity {
		return netip.Addr{}, time.Time{}, ErrFakeIPCapacity
	}
	ip, ok := s.nextIPLocked()
	if !ok {
		return netip.Addr{}, time.Time{}, ErrFakeIPCapacity
	}
	entry := fakeIPEntry{ip: ip, expires: now.Add(s.ttl)}
	s.byHost[canonical] = entry
	s.byIP[ip] = canonical
	return ip, entry.expires, nil
}

// IPv6 aliases encode the existing IPv4 mapping key. They consume no second
// map entry, never renew its TTL, and retire with the same Session owner.
func (s *FakeIPScope) AllocateSessionAddressLeaseForFamily(host string, family addressscope.AddressFamily) (netip.Addr, time.Time, error) {
	if family != addressscope.IPv4 && family != addressscope.IPv6 {
		return netip.Addr{}, time.Time{}, ErrFakeIPConfig
	}
	ip, expiry, err := s.AllocateSessionAddressLease(host)
	if err != nil || family == addressscope.IPv4 {
		return ip, expiry, err
	}
	alias, ok := addressscope.IPv6Address(ip)
	if !ok {
		return netip.Addr{}, time.Time{}, ErrFakeIPConfig
	}
	return alias, expiry, nil
}

func (s *FakeIPScope) SessionAddressLeaseExpiry(ip netip.Addr) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkLocked(); err != nil {
		return time.Time{}, err
	}
	s.expireLocked(time.Now())
	mapping, ok := addressscope.MappingAddress(ip)
	if !ok {
		return time.Time{}, ErrFakeIPUnmapped
	}
	host, ok := s.byIP[mapping]
	if !ok {
		return time.Time{}, ErrFakeIPUnmapped
	}
	return s.byHost[host].expires, nil
}

// Resolve returns the original canonical hostname for a live fake address.
func (s *FakeIPScope) Resolve(ip netip.Addr) (string, error) {
	mapping, ok := addressscope.MappingAddress(ip)
	if !ok {
		return "", ErrFakeIPUnmapped
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkLocked(); err != nil {
		return "", err
	}
	s.expireLocked(time.Now())
	host, ok := s.byIP[mapping]
	if !ok {
		return "", ErrFakeIPUnmapped
	}
	return host, nil
}

// RestoreTarget reverse-maps a numeric fake-IP in a TCP or UDP target. A
// non-fake target is returned unchanged. The mapping only restores Address;
// callers still decide independently whether the restored name is trusted
// classification metadata.
func (s *FakeIPScope) RestoreTarget(target protocol.Target) (protocol.Target, error) {
	s.mu.Lock()
	err := s.checkLocked()
	s.mu.Unlock()
	if err != nil {
		return protocol.Target{}, err
	}
	if target.Network != "tcp" && target.Network != "udp" {
		return protocol.Target{}, ErrFakeIPTarget
	}
	host, port, err := net.SplitHostPort(target.Address)
	if err != nil || host == "" || port == "" {
		return protocol.Target{}, ErrFakeIPTarget
	}
	ip, parseErr := netip.ParseAddr(host)
	if parseErr != nil || !isFakeIPScopeAddr(ip) {
		return target, nil
	}
	original, err := s.Resolve(ip)
	if err != nil {
		return protocol.Target{}, err
	}
	target.Address = net.JoinHostPort(original, port)
	return target, nil
}

// Close synchronously destroys all mappings. It is safe to call repeatedly.
func (s *FakeIPScope) Close() error {
	s.mu.Lock()
	if !s.closed {
		s.invalidateLocked()
	}
	stop := s.stop
	s.stop = nil
	s.mu.Unlock()
	if stop != nil {
		stop()
	}
	return nil
}

func (s *FakeIPScope) invalidateLocked() {
	s.closed = true
	for ip := range s.byIP {
		fakeIPLeases.Lock()
		if fakeIPLeases.owners[ip] == s {
			delete(fakeIPLeases.owners, ip)
		}
		fakeIPLeases.Unlock()
	}
	s.byHost = nil
	s.byIP = nil
	s.ctx = nil
	s.valid = nil
	s.clientFactory = nil
}

func (s *FakeIPScope) checkLocked() error {
	if s.closed {
		return ErrFakeIPScopeClosed
	}
	if s.ctx != nil && s.ctx.Err() != nil {
		s.invalidateLocked()
		return ErrFakeIPScopeClosed
	}
	if s.valid != nil {
		if err := s.valid(); err != nil {
			s.invalidateLocked()
			return ErrFakeIPScopeClosed
		}
	}
	return nil
}

func (s *FakeIPScope) expireLocked(now time.Time) {
	for host, entry := range s.byHost {
		if !now.Before(entry.expires) {
			delete(s.byHost, host)
			delete(s.byIP, entry.ip)
			fakeIPLeases.Lock()
			if fakeIPLeases.owners[entry.ip] == s {
				delete(fakeIPLeases.owners, entry.ip)
			}
			fakeIPLeases.Unlock()
		}
	}
}

func (s *FakeIPScope) nextIPLocked() (netip.Addr, bool) {
	if s.clientFactory != nil {
		return s.clientFactory.allocate(s)
	}
	for i := 0; i < 1<<20; i++ {
		candidate := s.next
		if !candidate.IsValid() || !fakeIPScopePrefix.Contains(candidate) {
			candidate = fakeIPScopePrefix.Addr()
		}
		s.next = candidate.Next()
		// Keep the conventional first/last address of each /24 free for
		// adapters that treat those values as network/broadcast markers.
		last := candidate.As4()[3]
		if last == 0 || last == 255 {
			continue
		}
		if _, exists := s.byIP[candidate]; exists {
			continue
		}
		fakeIPLeases.Lock()
		if _, exists := fakeIPLeases.owners[candidate]; exists {
			fakeIPLeases.Unlock()
			continue
		}
		fakeIPLeases.owners[candidate] = s
		fakeIPLeases.Unlock()
		return candidate, true
	}
	return netip.Addr{}, false
}

func isFakeIPScopeAddr(ip netip.Addr) bool {
	return addressscope.IsFakeAddress(ip)
}

func normalizeFakeHost(host string) (string, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if len(host) == 0 || len(host) > 253 || net.ParseIP(host) != nil {
		return "", ErrFakeIPHost
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrFakeIPHost
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') || unicode.IsControl(ch) {
				return "", ErrFakeIPHost
			}
		}
	}
	return host, nil
}
