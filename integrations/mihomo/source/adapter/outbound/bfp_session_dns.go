package outbound

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"bfp/gateway"
	"bfp/session"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

var bfpSessionPrefixes = [2]netip.Prefix{
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("fd42:6266:7000::/96"),
}

// One process cursor covers all BFP outbounds and configuration reloads. It
// retains no DNS names or session identities. Reserve the TUN gateway /30.
var bfpSessionAddressFactory = sync.OnceValues(func() (*gateway.FakeIPScopeFactory, error) {
	return gateway.NewFakeIPScopeFactoryFrom(30*time.Second, 128, netip.MustParseAddr("198.18.0.4"))
})

var _ C.SessionFakeIPOwner = (*BFP)(nil)

type bfpSessionLease struct {
	outbound *BFP
	owner    *session.Session
	lease    session.LocalAddressLease
	host     string
}

func (l *bfpSessionLease) Address() netip.Addr { return l.lease.Address }
func (l *bfpSessionLease) Host() string        { return l.host }
func (l *bfpSessionLease) ProxyName() string   { return l.outbound.Name() }
func (l *bfpSessionLease) Remaining(ctx context.Context) (time.Duration, error) {
	if l.outbound.ctx.Err() != nil {
		return 0, C.ErrSessionFakeIP
	}
	remaining, err := l.owner.ValidateLocalAddressLease(ctx, l.lease)
	if err != nil {
		return 0, errors.Join(C.ErrSessionFakeIP, err)
	}
	return remaining, nil
}

func (h *BFP) SessionFakeIPPrefixes() (netip.Prefix, netip.Prefix) {
	return bfpSessionPrefixes[0], bfpSessionPrefixes[1]
}

func (h *BFP) OwnsSessionFakeIP(value C.SessionFakeIPLease) bool {
	l, ok := value.(*bfpSessionLease)
	return ok && l != nil && l.outbound == h
}

func (h *BFP) sessionLease(ctx context.Context, owner *session.Session, host string, ipv6 bool) (*bfpSessionLease, error) {
	family := session.LocalAddressIPv4
	if ipv6 {
		family = session.LocalAddressIPv6
	}
	lease, err := owner.AllocateLocalAddressLeaseForFamily(ctx, host, family)
	if err != nil {
		return nil, errors.Join(C.ErrSessionFakeIP, err)
	}
	allocator, ok := owner.LocalAddressAllocator()
	if !ok {
		return nil, C.ErrSessionFakeIP
	}
	canonical, err := allocator.ResolveSessionAddress(lease.Address)
	if err != nil {
		return nil, errors.Join(C.ErrSessionFakeIP, err)
	}
	l := &bfpSessionLease{outbound: h, owner: owner, lease: lease, host: canonical}
	if _, err := l.Remaining(ctx); err != nil {
		return nil, err
	}
	return l, nil
}

func (h *BFP) AllocateSessionFakeIP(ctx context.Context, host string, ipv6 bool) (C.SessionFakeIPLease, error) {
	if err := h.beginSetup(false); err != nil {
		return nil, err
	}
	defer h.endSetup(false)
	work, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(h.ctx, cancel)
	defer cancel()
	defer stop()
	owner, err := h.client.Connect(work)
	if err != nil {
		return nil, err
	}
	h.watchSessionTermination(owner)
	return h.sessionLease(work, owner, host, ipv6)
}

func (h *BFP) LookupSessionFakeIP(ctx context.Context, ip netip.Addr) (C.SessionFakeIPLease, error) {
	if h.ctx.Err() != nil || ip.Zone() != "" {
		return nil, C.ErrSessionFakeIP
	}
	// Deliberately do not Connect: a stale address cannot create a network.
	owner := h.client.Session()
	if owner == nil {
		return nil, C.ErrSessionFakeIP
	}
	allocator, ok := owner.LocalAddressAllocator()
	if !ok {
		return nil, C.ErrSessionFakeIP
	}
	host, err := allocator.ResolveSessionAddress(ip)
	if err != nil {
		return nil, errors.Join(C.ErrSessionFakeIP, err)
	}
	l, err := h.sessionLease(ctx, owner, host, ip.Is6() && !ip.Is4In6())
	if err != nil {
		return nil, err
	}
	if l.Address() != ip.Unmap() {
		return nil, C.ErrSessionFakeIP
	}
	h.watchSessionTermination(owner)
	return l, nil
}

// An explicit fake-IP flush retires this owner's entire temporary network;
// the next DNS request may establish a fresh session with new addresses.
func (h *BFP) FlushSessionFakeIP() error {
	if owner := h.client.Session(); owner != nil {
		h.mu.Lock()
		sequence := h.sessions[owner]
		h.mu.Unlock()
		log.Warnln("[BFP] event=bfp_session_close_requested outbound=%d owner=%d source=fakeip_flush", h.outboundSequence, sequence)
		return owner.Close()
	}
	return nil
}

func (h *BFP) destinationSession(ctx context.Context, metadata *C.Metadata) (*session.Session, error) {
	if metadata.SessionFakeIP == nil {
		return h.client.Connect(ctx)
	}
	l, ok := metadata.SessionFakeIP.(*bfpSessionLease)
	if !ok || l == nil || l.outbound != h {
		return nil, C.ErrSessionFakeIP
	}
	if _, err := l.Remaining(ctx); err != nil {
		return nil, err
	}
	return l.owner, nil
}

func bfpLogicalMetadata(ctx context.Context, metadata *C.Metadata) *C.Metadata {
	if original, ok := C.LogicalDestinationMetadataFromContext(ctx); ok && original.SessionFakeIP != nil && metadata != nil {
		metadata = metadata.Clone()
		metadata.SessionFakeIP = original.SessionFakeIP
	}
	return metadata
}
