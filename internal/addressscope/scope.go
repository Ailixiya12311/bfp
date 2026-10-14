// Package addressscope separates local address mapping from Session and gateway.
package addressscope

import (
	"context"
	"net/netip"
	"reflect"
	"time"

	"bfp/protocol"
)

// Allocator is a bounded logical map. It performs no DNS or operating-system
// work and becomes unusable when its owner Session terminates.
type Allocator interface {
	AllocateSessionAddress(string) (netip.Addr, error)
	ResolveSessionAddress(netip.Addr) (string, error)
}

// LeaseAllocator optionally exposes exact map deadlines for a DNS front end.
// A DNS TTL must also obey the selected Session's deadline. Returning an old
// expiry after the address was removed or rebound would violate this contract.
type LeaseAllocator interface {
	Allocator
	AllocateSessionAddressLease(string) (netip.Addr, time.Time, error)
	SessionAddressLeaseExpiry(netip.Addr) (time.Time, error)
}

// FamilyLeaseAllocator explicitly supports family-specific aliases. A frontend
// must not invent an IPv6 lease for a scope that implements only LeaseAllocator.
// Both families share the same hostname entry, expiry, capacity and owner.
type FamilyLeaseAllocator interface {
	LeaseAllocator
	AllocateSessionAddressLeaseForFamily(string, AddressFamily) (netip.Addr, time.Time, error)
}

// Scope changes only Target.Address; it preserves all delivery, FEC and local
// policy fields. Methods must be thread-safe, short, and free of network I/O.
// Close synchronously clears the map and is idempotent.
type Scope interface {
	Allocator
	RestoreTarget(protocol.Target) (protocol.Target, error)
	Close() error
}

// Factory creates one empty local scope after the client's fresh handshake.
// Carrier recovery never calls it again. The supplied guard is safe to retain:
// it references only eligibility and cancellation, not the Session actor.
// Returning a non-nil scope with an error still transfers cleanup ownership.
// The supplied context remains live after successful creation until Session
// retirement. Before ownership transfer it also observes Connect cancellation.
// A late result after cancellation is destroyed and never published.
type Factory interface {
	ForClientSession(context.Context, func() error) (Scope, error)
}

func IsNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}
