// Package backend defines exit-backend contracts without coupling gateway to
// the Session implementation.
package backend

import (
	"context"
	"net"
	"net/netip"
	"reflect"
)

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// IsNil also rejects a nil pointer wrapped in a non-nil interface before a
// constructor or Session attempts to invoke its methods.
func IsNil(d Dialer) bool {
	if d == nil {
		return true
	}
	value := reflect.ValueOf(d)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	}
	return false
}

// SessionFactory creates an empty scope after fresh Session confirmation.
// valid must be short, thread-safe and free of I/O; it checks retained lifetime
// and authorization. The returned stop function synchronously invalidates all
// scope-owned state, is idempotent, and must not wait for network operations.
// Carrier replacement must reuse the existing scope rather than call this again.
type SessionFactory interface {
	ForSession(context.Context, func() error) (Dialer, func())
}

// SessionAddressAllocator is an optional, session-owned address boundary.
// Implementations allocate temporary logical addresses and reverse them before
// a backend dial. The interface deliberately exposes no OS routing, TUN, DNS
// server, or NAT operations; callers only receive the logical mapping API.
//
// A returned allocator is valid only until the ForSession cleanup function (or
// its parent context) retires the scope. Implementations must fail closed after
// that point.
type SessionAddressAllocator interface {
	Dialer
	AllocateSessionAddress(string) (netip.Addr, error)
	ResolveSessionAddress(netip.Addr) (string, error)
}
