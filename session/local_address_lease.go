package session

import (
	"context"
	"net/netip"
	"time"

	"bfp/internal/addressscope"
)

// LocalAddressLease is a snapshot bounded by both the real map entry deadline
// and its actual client Session lifetime. It cannot be transferred to another
// Session, and ValidateLocalAddressLease rechecks the exact entry before use.
type LocalAddressLease struct {
	Address       netip.Addr
	ExpiresAt     time.Time
	mappingExpiry time.Time
	owner         *clientScopeLifetime
}

func (s *Session) AllocateLocalAddressLease(ctx context.Context, host string) (LocalAddressLease, error) {
	return s.allocateLocalAddressLease(ctx, host, 0)
}

// AllocateLocalAddressLeaseForFamily requires explicit scope support for IPv6.
// An IPv4-only custom scope retains its existing lease allocation behavior.
func (s *Session) AllocateLocalAddressLeaseForFamily(ctx context.Context, host string, family LocalAddressFamily) (LocalAddressLease, error) {
	if family != LocalAddressIPv4 && family != LocalAddressIPv6 {
		return LocalAddressLease{}, ErrClientAddressScope
	}
	return s.allocateLocalAddressLease(ctx, host, family)
}

func (s *Session) allocateLocalAddressLease(ctx context.Context, host string, family LocalAddressFamily) (LocalAddressLease, error) {
	var lease LocalAddressLease
	var leaseErr error
	err := s.businessCall(ctx, func() {
		if s.localAddressGuard == nil || s.localAddressGuard.check() != nil {
			leaseErr = ErrClosed
			return
		}
		allocator, ok := s.localAddressScope.(addressscope.LeaseAllocator)
		if !ok {
			leaseErr = ErrClientAddressScope
			return
		}
		var ip netip.Addr
		var expiry time.Time
		var allocErr error
		if familyAllocator, ok := allocator.(addressscope.FamilyLeaseAllocator); ok && family != 0 {
			ip, expiry, allocErr = familyAllocator.AllocateSessionAddressLeaseForFamily(host, family)
		} else if family == LocalAddressIPv6 {
			leaseErr = ErrClientAddressScope
			return
		} else {
			ip, expiry, allocErr = allocator.AllocateSessionAddressLease(host)
		}
		if allocErr != nil {
			leaseErr = allocErr
			return
		}
		if family != 0 && (ip.Zone() != "" || family == LocalAddressIPv4 && !ip.Is4() || family == LocalAddressIPv6 && (!ip.Is6() || ip.Is4In6())) {
			leaseErr = ErrClientAddressScope
			return
		}
		until := expiry
		if deadline := s.localAddressGuard.until.Load(); deadline != nil {
			until = earlier(until, *deadline)
		}
		if s.localAddressGuard.check() != nil || !ip.IsValid() || expiry.IsZero() || !until.After(time.Now()) {
			leaseErr = ErrClosed
			return
		}
		lease = LocalAddressLease{Address: ip, ExpiresAt: until, mappingExpiry: expiry, owner: s.localAddressGuard}
	})
	if err != nil {
		return LocalAddressLease{}, err
	}
	return lease, leaseErr
}

// ValidateLocalAddressLease returns the remaining real lifetime. It rejects a
// terminal owner, a foreign Session's lease, or a removed/rebound map entry.
// No cached frontend value can extend the current map or Session deadline.
func (s *Session) ValidateLocalAddressLease(ctx context.Context, lease LocalAddressLease) (time.Duration, error) {
	var remaining time.Duration
	var leaseErr error
	err := s.businessCall(ctx, func() {
		guard := s.localAddressGuard
		if guard == nil || guard != lease.owner || guard.check() != nil {
			leaseErr = ErrClosed
			return
		}
		allocator, ok := s.localAddressScope.(addressscope.LeaseAllocator)
		if !ok {
			leaseErr = ErrClientAddressScope
			return
		}
		expiry, expiryErr := allocator.SessionAddressLeaseExpiry(lease.Address)
		if expiryErr != nil {
			leaseErr = expiryErr
			return
		}
		if !expiry.Equal(lease.mappingExpiry) {
			leaseErr = ErrState
			return
		}
		until := earlier(expiry, lease.ExpiresAt)
		if deadline := guard.until.Load(); deadline != nil {
			until = earlier(until, *deadline)
		}
		remaining = time.Until(until)
		if guard.check() != nil || remaining <= 0 {
			leaseErr = ErrClosed
		}
	})
	if err != nil {
		return 0, err
	}
	if leaseErr != nil {
		return 0, leaseErr
	}
	return remaining, nil
}
