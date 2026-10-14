// Package gateway applies destination policy before creating an exit socket.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"bfp/internal/addressscope"
	"bfp/protocol"
)

var ErrPolicyDenied = errors.New("gateway: destination denied by policy")

// ErrRouteExcluded reports a destination explicitly excluded from the gateway
// exit policy. Exclusions are checked before AllowedCIDRs and before any socket
// dial. Hostnames are checked after the one bounded DNS resolution. This
// package does not install or remove operating-system routes or perform bypass.
var ErrRouteExcluded = errors.New("gateway: destination excluded by route policy")

type Policy struct {
	AllowPrivate bool
	AllowedCIDRs []string
	// ExcludedCIDRs deny gateway exit destinations regardless of AllowPrivate
	// and AllowedCIDRs. This policy does not route those destinations directly
	// or change the host routing table or interfaces.
	ExcludedCIDRs []string
	AllowedPorts  []int
	MaxConcurrent int
	Timeout       time.Duration
	// FakeIPLifetime and FakeIPCapacity configure the optional per-Session
	// logical address scope. Zero selects bounded defaults. The scope is
	// created only by ForSession; the factory itself never allocates one.
	FakeIPLifetime time.Duration
	FakeIPCapacity int
}

type Dialer struct {
	allowPrivate   bool
	prefixes       []netip.Prefix
	excluded       []netip.Prefix
	ports          map[int]struct{}
	slots          chan struct{}
	resolverSlots  chan struct{}
	dns            *sessionDNS
	fakeIP         *FakeIPScope
	fakeIPLifetime time.Duration
	fakeIPCapacity int
	timeout        time.Duration
	lookup         func(context.Context, string) ([]net.IPAddr, error)
	dial           func(context.Context, string, string) (net.Conn, error)
}

// New validates configuration without opening a connection. CIDR and port lists
// restrict otherwise permitted destinations; they do not override AllowPrivate.
func New(policy Policy) (*Dialer, error) {
	if policy.MaxConcurrent < 0 || policy.Timeout < 0 {
		return nil, errors.New("gateway: negative concurrency or timeout")
	}
	if policy.MaxConcurrent == 0 {
		policy.MaxConcurrent = 32
	}
	if policy.Timeout == 0 {
		policy.Timeout = 10 * time.Second
	}
	d := &Dialer{allowPrivate: policy.AllowPrivate, slots: make(chan struct{}, policy.MaxConcurrent), resolverSlots: make(chan struct{}, globalDNSConcurrent), timeout: policy.Timeout}
	if policy.FakeIPLifetime == 0 {
		policy.FakeIPLifetime = 10 * time.Minute
	}
	if policy.FakeIPLifetime <= 0 || policy.FakeIPLifetime > maxFakeIPLifetime {
		return nil, errors.New("gateway: invalid fake-IP lifetime")
	}
	if policy.FakeIPCapacity == 0 {
		policy.FakeIPCapacity = defaultFakeIPCapacity
	}
	if policy.FakeIPCapacity != defaultFakeIPCapacity && policy.FakeIPCapacity != maxFakeIPCapacity {
		return nil, errors.New("gateway: invalid fake-IP capacity")
	}
	d.fakeIPLifetime = policy.FakeIPLifetime
	d.fakeIPCapacity = policy.FakeIPCapacity
	for _, value := range policy.AllowedCIDRs {
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("gateway: invalid allowed CIDR %q: %w", value, err)
		}
		d.prefixes = append(d.prefixes, p.Masked())
	}
	for _, value := range policy.ExcludedCIDRs {
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("gateway: invalid excluded CIDR %q: %w", value, err)
		}
		// Candidate addresses are unwrapped before destination policy checks.
		// Preserve an explicit IPv4-mapped IPv6 subnet as the equivalent IPv4
		// prefix so spelling a CIDR in mapped form cannot disable exclusion.
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		d.excluded = append(d.excluded, p.Masked())
	}
	if len(policy.AllowedPorts) > 0 {
		d.ports = make(map[int]struct{}, len(policy.AllowedPorts))
		for _, p := range policy.AllowedPorts {
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("gateway: invalid allowed port %d", p)
			}
			d.ports[p] = struct{}{}
		}
	}
	d.lookup = net.DefaultResolver.LookupIPAddr
	d.dial = (&net.Dialer{}).DialContext
	return d, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := d.guard(ctx); err != nil {
		return nil, err
	}
	if d.dns != nil {
		merged, stop := context.WithCancel(ctx)
		stopOwner := context.AfterFunc(d.dns.ctx, stop)
		defer stopOwner()
		defer stop()
		ctx = merged
	}
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
	default:
		return nil, fmt.Errorf("gateway: unsupported network %q", network)
	}
	// A scoped fake address is restored before parsing, policy validation, or
	// the OS dial. An expired or foreign mapping fails closed and never falls
	// through to a numeric fake-IP socket.
	address, err := d.restoreAddress(network, address)
	if err != nil {
		return nil, err
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return nil, fmt.Errorf("gateway: invalid destination %q", address)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("gateway: invalid destination port %q", portText)
	}
	if len(d.ports) != 0 {
		if _, ok := d.ports[port]; !ok {
			return nil, ErrPolicyDenied
		}
	}
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	select {
	case d.slots <- struct{}{}:
		defer func() { <-d.slots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := d.guard(ctx); err != nil {
		return nil, err
	}
	var candidates []netip.Addr
	if literal, err := netip.ParseAddr(host); err == nil {
		if literal.Zone() != "" {
			return nil, ErrPolicyDenied
		}
		candidates = []netip.Addr{literal.Unmap()}
	} else {
		if strings.Contains(host, "%") {
			return nil, ErrPolicyDenied
		}
		resolved, err := d.resolve(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("gateway: resolve: %w", err)
		}
		candidates = resolved
	}
	if len(candidates) == 0 {
		return nil, errors.New("gateway: destination has no address")
	}
	// Validate every answer from this one resolution before attempting any dial.
	// A hostname cannot mix a permitted address with a forbidden fallback.
	if err := d.validateCandidates(candidates); err != nil {
		return nil, err
	}
	var lastDialErr error
	for _, a := range candidates {
		if strings.HasSuffix(network, "4") && !a.Is4() || strings.HasSuffix(network, "6") && !a.Is6() {
			continue
		}
		// Pin every attempt to a validated numeric peer; the OS must not resolve
		// again. TCP may try the next candidate after a failed connection using
		// this same deadline and slot. UDP retains one selected peer: retrying a
		// connected datagram socket is not a delivery or retransmission policy.
		if err := d.guard(ctx); err != nil {
			return nil, err
		}
		conn, dialErr := d.dial(ctx, network, net.JoinHostPort(a.String(), portText))
		if err := d.guard(ctx); err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, err
		}
		if dialErr == nil {
			return conn, nil
		}
		if conn != nil {
			_ = conn.Close()
		}
		if strings.HasPrefix(network, "udp") {
			return nil, dialErr
		}
		lastDialErr = dialErr
	}
	if lastDialErr != nil {
		return nil, lastDialErr
	}
	return nil, errors.New("gateway: no address for requested network family")
}

func (d *Dialer) permitted(a netip.Addr) bool {
	if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || !a.IsGlobalUnicast() && !a.IsLoopback() && !a.IsLinkLocalUnicast() {
		return false
	}
	// 198.18.0.0/15 is the conventional fake-IP pool used by the upstream
	// adapters.  Its reverse mapping must be restored before BFP receives an
	// OPEN; even an explicitly private test policy must not turn an unresolved
	// fake address into a real gateway dial.  The BFP Session address space is
	// independent from this upstream-owned pool.
	if isFakeIP(a) {
		return false
	}
	if d.routeExcluded(a) {
		return false
	}
	if a.Is4() {
		b := a.As4()
		// Unspecified network, limited broadcast and reserved class-E addresses
		// are never useful unicast proxy targets, even with AllowPrivate.
		if b[0] == 0 || b[0] >= 240 {
			return false
		}
	}
	if !d.allowPrivate && (a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || isNonPublic(a)) {
		return false
	}
	if len(d.prefixes) == 0 {
		return true
	}
	for _, p := range d.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func isNonPublic(a netip.Addr) bool {
	for _, p := range nonPublicPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// routeExcluded matches both ordinary IPv4 and IPv4-mapped IPv6 forms. A
// caller may provide a native IPv6 exclusion independently; it remains
// distinct from an IPv4 prefix.
func (d *Dialer) routeExcluded(a netip.Addr) bool {
	if d == nil || !a.IsValid() {
		return false
	}
	for _, prefix := range d.excluded {
		if prefix.Contains(a) || prefix.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func isFakeIP(a netip.Addr) bool {
	return addressscope.IsFakeAddress(a)
}

// FakeIPScope returns the live temporary-address scope created by
// ForSession. It returns nil for the factory dialer. The pointer remains safe
// to call after retirement because the
// scope itself fails closed.
func (d *Dialer) FakeIPScope() *FakeIPScope {
	if d == nil {
		return nil
	}
	return d.fakeIP
}

// AllocateSessionAddress exposes the optional logical address allocator via
// the generic backend.SessionAddressAllocator contract. It never touches the
// host routing table or performs a DNS query.
func (d *Dialer) AllocateSessionAddress(host string) (netip.Addr, error) {
	if d == nil || d.fakeIP == nil {
		return netip.Addr{}, ErrFakeIPScopeClosed
	}
	return d.fakeIP.Allocate(host)
}

// ResolveSessionAddress exposes the reverse mapping for adapter code that
// needs to inspect a temporary address before constructing a Target.
func (d *Dialer) ResolveSessionAddress(ip netip.Addr) (string, error) {
	if d == nil || d.fakeIP == nil {
		return "", ErrFakeIPScopeClosed
	}
	return d.fakeIP.Resolve(ip)
}

// RestoreTarget allows an adapter to share the same Session-owned mapping
// boundary. The network family suffix is preserved for the returned target;
// only the address is rewritten.
func (d *Dialer) RestoreTarget(target protocol.Target) (protocol.Target, error) {
	if d == nil || d.fakeIP == nil {
		return target, nil
	}
	base := target.Network
	if strings.HasSuffix(base, "4") || strings.HasSuffix(base, "6") {
		base = base[:len(base)-1]
	}
	if base != "tcp" && base != "udp" {
		return protocol.Target{}, ErrFakeIPTarget
	}
	toRestore := target
	toRestore.Network = base
	restored, err := d.fakeIP.RestoreTarget(toRestore)
	if err != nil {
		return protocol.Target{}, err
	}
	restored.Network = target.Network
	return restored, nil
}

func (d *Dialer) restoreAddress(network, address string) (string, error) {
	if d == nil || d.fakeIP == nil {
		return address, nil
	}
	target, err := d.RestoreTarget(protocol.Target{Network: network, Address: address})
	if err != nil {
		return "", err
	}
	return target.Address, nil
}
