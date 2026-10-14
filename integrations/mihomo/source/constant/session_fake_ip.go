package constant

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

var ErrSessionFakeIP = errors.New("session fake-IP owner or lease is no longer valid")

// SessionFakeIPLease is an immutable destination capability. Frontends retain
// it after restoring Host so retries and sniffing cannot transfer an address
// to a different proxy or a replacement session with the same proxy name.
type SessionFakeIPLease interface {
	Address() netip.Addr
	Host() string
	ProxyName() string
	Remaining(context.Context) (time.Duration, error)
}

// SessionFakeIPOwner allocates DNS addresses inside its actual outbound
// session. Lookup must never establish a replacement session for an old IP.
type SessionFakeIPOwner interface {
	AllocateSessionFakeIP(context.Context, string, bool) (SessionFakeIPLease, error)
	LookupSessionFakeIP(context.Context, netip.Addr) (SessionFakeIPLease, error)
	SessionFakeIPPrefixes() (netip.Prefix, netip.Prefix)
	OwnsSessionFakeIP(SessionFakeIPLease) bool
	FlushSessionFakeIP() error
}

// SessionFakeIPMapper lets tunnel preprocessing retain the lease behind a
// restored name. The bool distinguishes reserved addresses from real IPs;
// an error on a reserved address is terminal, including during sniffing.
type SessionFakeIPMapper interface {
	SessionFakeIPDestination(context.Context, netip.Addr) (SessionFakeIPLease, bool, error)
}
