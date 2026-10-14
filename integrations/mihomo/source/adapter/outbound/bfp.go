package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"bfp/adapter/packet"
	"bfp/classification"
	"bfp/clientconfig"
	"bfp/protocol"
	"bfp/session"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// BFPOption loads private BFP keys from the same bounded, permission-checked
// base client.json as keygen. Construction validates keys without connecting.
type BFPOption struct {
	BasicOption
	Name             string         `proxy:"name"`
	ClientConfigFile string         `proxy:"client-config-file"`
	UDP              bool           `proxy:"udp,omitempty"`
	MaxPacketConns   int            `proxy:"max-packet-conns,omitempty"`
	Classification   map[string]any `proxy:"classification,omitempty"`
}

var _ ProxyAdapter = (*BFP)(nil)

// Process-local diagnostic ordinals are unrelated to protocol identities and
// retain no target, credential, or Session ID information.
var bfpOutboundSequence atomic.Uint64

type BFP struct {
	*Base
	dialerProxy string

	client           *session.Client
	ctx              context.Context
	cancel           context.CancelFunc
	mu               sync.Mutex
	closed           bool
	packets          map[*bfpPacketConn]struct{}
	pending          int
	maxPacket        int
	closeOnce        sync.Once
	closeErr         error
	setups           sync.WaitGroup
	watchers         sync.WaitGroup
	sessions         map[*session.Session]uint64
	retireErr        error
	outboundSequence uint64
	ownerSequence    uint64 // Guarded by mu; most recently registered owner.
}

func NewBFP(option BFPOption) (*BFP, error) {
	if option.Name == "" || option.ClientConfigFile == "" || option.MaxPacketConns < 0 || option.MaxPacketConns > 256 {
		return nil, errors.New("bfp: invalid outbound configuration")
	}
	if option.MaxPacketConns == 0 {
		option.MaxPacketConns = 64
	}
	loaded, err := clientconfig.Load(option.ClientConfigFile)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &BFP{
		Base: NewBase(BaseOption{Name: option.Name, Addr: loaded.Session.Server, Type: C.BFP,
			ProviderName: option.ProviderName, UDP: option.UDP, TFO: option.TFO, MPTCP: option.MPTCP,
			Interface: option.Interface, RoutingMark: option.RoutingMark, Prefer: option.IPVersion}),
		dialerProxy: option.DialerProxy,
		ctx:         ctx, cancel: cancel, packets: make(map[*bfpPacketConn]struct{}), maxPacket: option.MaxPacketConns,
	}
	h.dialer = option.NewDialer(h.DialOptions())
	loaded.Session.DialTCP = h.dialCarrierTCP
	loaded.Session.DialUDP = h.dialCarrierUDP
	if option.Classification != nil {
		loaded.Session.Classification, err = parseBFPClassification(option.Classification)
		if err != nil {
			cancel()
			return nil, err
		}
	}
	loaded.Session.AddressScopeFactory, err = bfpSessionAddressFactory()
	if err != nil {
		cancel()
		return nil, err
	}
	h.client, err = session.NewClient(loaded.Session)
	if err != nil {
		cancel()
		return nil, err
	}
	h.outboundSequence = bfpOutboundSequence.Add(1)
	log.Infoln("[BFP] event=bfp_outbound_started outbound=%d owner=0", h.outboundSequence)
	return h, nil
}

// ProxyInfo reports the same configured detour used by the host dialer so
// Mihomo can validate its dependency before activating the proxy graph.
func (h *BFP) ProxyInfo() C.ProxyInfo {
	info := h.Base.ProxyInfo()
	info.DialerProxy = h.dialerProxy
	return info
}

func (h *BFP) carrierEndpoint(ctx context.Context, address string) (netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, errors.New("bfp: invalid carrier port")
	}
	// Endpoint DNS uses Mihomo's configured resolver, and packet creation uses
	// the host dialer so interface, routing mark and dialer-proxy apply.
	ip, err := resolveIPWithResolver(ctx, host, h.prefer, resolver.ProxyServerHostResolver)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.AddrPort{}, session.ErrCarrierDialContract
	}
	return netip.AddrPortFrom(ip, uint16(port)), nil
}

func (h *BFP) dialCarrierTCP(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, session.ErrCarrierDialContract
	}
	peer, err := h.carrierEndpoint(ctx, address)
	if err != nil {
		return nil, err
	}
	conn, err := h.dialer.DialContext(ctx, network, peer.String())
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, err
	}
	if conn == nil {
		return nil, session.ErrCarrierDialContract
	}
	if _, packetSocket := conn.(net.PacketConn); packetSocket {
		conn.Close()
		return nil, session.ErrCarrierDialContract
	}
	// A host detour can expose a logical address whose Network is not tcp.
	// Preserve the successfully requested numeric server endpoint; BFP still
	// authenticates the server's pinned key on this real host-owned stream.
	return &bfpCarrierStream{Conn: conn, peer: peer}, nil
}

type bfpCarrierStream struct {
	net.Conn
	peer netip.AddrPort
}

func (c *bfpCarrierStream) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.peer) }

func (h *BFP) dialCarrierUDP(ctx context.Context, network, address string) (net.PacketConn, *net.UDPAddr, error) {
	if network != "udp" {
		return nil, nil, session.ErrCarrierDialContract
	}
	endpoint, err := h.carrierEndpoint(ctx, address)
	if err != nil {
		return nil, nil, err
	}
	peer := net.UDPAddrFromAddrPort(endpoint)
	carrierNetwork := "udp4"
	if endpoint.Addr().Is6() {
		carrierNetwork = "udp6"
	}
	conn, err := h.dialer.ListenPacket(ctx, carrierNetwork, "", peer.AddrPort())
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, nil, err
	}
	if conn == nil {
		return nil, nil, session.ErrCarrierDialContract
	}
	wrapped := &bfpCarrierPacketConn{PacketConn: conn, peer: endpoint}
	if connected, ok := conn.(net.Conn); ok && connected.RemoteAddr() != nil {
		remote, parseErr := netip.ParseAddrPort(connected.RemoteAddr().String())
		if parseErr != nil || netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port()) != endpoint {
			conn.Close()
			return nil, nil, session.ErrCarrierDialContract
		}
		wrapped.connected = connected
	}
	return wrapped, peer, nil
}

type bfpCarrierPacketConn struct {
	net.PacketConn
	peer      netip.AddrPort
	connected net.Conn
}

func (c *bfpCarrierPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, address, err := c.PacketConn.ReadFrom(b)
	if err == nil && address != nil {
		if peer, parseErr := netip.ParseAddrPort(address.String()); parseErr == nil {
			return n, net.UDPAddrFromAddrPort(peer), nil
		}
	}
	if err != nil {
		return n, nil, err
	}
	return 0, nil, session.ErrCarrierDialContract
}

func (c *bfpCarrierPacketConn) WriteTo(b []byte, address net.Addr) (int, error) {
	if c.connected != nil {
		if address == nil {
			return 0, session.ErrCarrierDialContract
		}
		peer, err := netip.ParseAddrPort(address.String())
		if err != nil || netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port()) != c.peer {
			return 0, session.ErrCarrierDialContract
		}
		return c.connected.Write(b)
	}
	return c.PacketConn.WriteTo(b, address)
}

func bfpMetadata(metadata *C.Metadata, network string) (classification.Metadata, error) {
	if metadata == nil || !metadata.Valid() || metadata.DstPort == 0 {
		return classification.Metadata{}, errors.New("bfp: invalid destination")
	}
	// Host is the host stack's restored destination. SniffHost is deliberately
	// not substituted for the real endpoint. Rule/process hints are copied only
	// from Mihomo's local metadata below, never fabricated from the selected
	// outbound and never treated as authorization evidence.
	address, host := metadata.Pure().RemoteAddress(), metadata.Host
	if lease := metadata.SessionFakeIP; lease != nil {
		address = net.JoinHostPort(lease.Address().String(), strconv.Itoa(int(metadata.DstPort)))
		host = lease.Host()
	}
	result := classification.Metadata{Target: protocol.Target{Network: network,
		Address: address, Domain: host}, DomainTrusted: host != ""}
	// SpecialRules and Process are produced by Mihomo's local rule/process
	// resolution. They are local policy hints, never authorization evidence and
	// are only copied into the adapter-neutral metadata bridge after strict
	// bounded validation. The BFP protocol may carry RuleTag as an OPEN hint;
	// Application remains local-only in classification.Metadata.
	if tag := bfpLocalRuleTag(metadata.SpecialRules); tag != "" {
		result.Target.RuleTag = tag
		result.RuleTagTrusted = true
	}
	if application := bfpLocalApplication(metadata.Process); application != "" {
		result.Application = application
		result.ApplicationTrusted = true
	}
	return result, nil
}

func bfpBridgeMetadata(meta classification.Metadata) (classification.Metadata, error) {
	if !meta.DomainTrusted && !meta.RuleTagTrusted && !meta.ApplicationTrusted {
		return meta, nil
	}
	bridge := classification.NewLocalMetadataBridge(meta.Target)
	var err error
	if meta.DomainTrusted {
		bridge, err = bridge.WithTrustedDomain(meta.Target.Domain)
		if err != nil {
			return classification.Metadata{}, err
		}
	}
	if meta.RuleTagTrusted {
		bridge, err = bridge.WithTrustedRuleTag(meta.Target.RuleTag)
		if err != nil {
			return classification.Metadata{}, err
		}
	}
	if meta.ApplicationTrusted {
		bridge, err = bridge.WithTrustedApplication(meta.Application)
		if err != nil {
			return classification.Metadata{}, err
		}
	}
	return bridge.Metadata(), nil
}

func bfpLocalRuleTag(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 {
		return ""
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return value
}

func bfpLocalApplication(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return ""
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return ""
		}
	}
	return value
}

func (h *BFP) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	metadata = bfpLogicalMetadata(ctx, metadata)
	meta, err := bfpMetadata(metadata, "tcp")
	if err != nil {
		return nil, err
	}
	if original, ok := C.LogicalDestinationMetadataFromContext(ctx); ok && original.Host != "" && metadata.SessionFakeIP == nil {
		meta.Target.Domain, meta.DomainTrusted = original.Host, true
	}
	if err := h.beginSetup(false); err != nil {
		return nil, err
	}
	defer h.endSetup(false)
	work, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(h.ctx, cancel)
	defer cancel()
	defer stop()
	owner, err := h.destinationSession(work, metadata)
	if err != nil {
		return nil, err
	}
	h.watchSessionTermination(owner)
	conn, err := owner.DialMetadata(work, meta)
	if err != nil {
		return nil, err
	}
	if work.Err() != nil || h.ctx.Err() != nil {
		conn.Close()
		return nil, net.ErrClosed
	}
	flow, ok := conn.(*session.Flow)
	if !ok {
		conn.Close()
		return nil, errors.New("bfp: unexpected stream type")
	}
	return &bfpConn{Conn: NewConn(conn, h), flow: flow}, nil
}

// Keep half-close visible to Mihomo's Relay and keep the host's ordinary
// connection/deadline interfaces. AddRef retains the auto-close adapter owner.
type bfpConn struct {
	C.Conn
	flow *session.Flow
}

func (c *bfpConn) CloseWrite() error { return c.flow.CloseWrite() }
func (c *bfpConn) AddRef(ref any) {
	if owner, ok := c.Conn.(AddRef); ok {
		owner.AddRef(ref)
	}
}

func (h *BFP) beginSetup(packetSetup bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return net.ErrClosed
	}
	if packetSetup {
		if len(h.packets)+h.pending >= h.maxPacket {
			return packet.ErrLimit
		}
		h.pending++
	}
	h.setups.Add(1)
	return nil
}

func (h *BFP) endSetup(packetSetup bool) {
	if packetSetup {
		h.mu.Lock()
		h.pending--
		h.mu.Unlock()
	}
	h.setups.Done()
}

// Watch each selected Session once while it is alive, including TCP-only and
// DNS-only owners. Registration shares Close's admission lock; no watcher can
// be added after Close starts waiting. Retired actors are removed so this
// diagnostic does not retain every previous temporary network.
func (h *BFP) watchSessionTermination(owner *session.Session) uint64 {
	if owner == nil {
		return 0
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return 0
	}
	if h.sessions == nil {
		h.sessions = make(map[*session.Session]uint64)
	}
	if sequence, exists := h.sessions[owner]; exists {
		h.mu.Unlock()
		return sequence
	}
	h.ownerSequence++
	sequence := h.ownerSequence
	h.sessions[owner] = sequence
	h.watchers.Add(1)
	h.mu.Unlock()
	log.Infoln("[BFP] event=bfp_session_started outbound=%d owner=%d", h.outboundSequence, sequence)
	go func() {
		defer h.watchers.Done()
		defer func() {
			h.mu.Lock()
			delete(h.sessions, owner)
			h.mu.Unlock()
		}()
		select {
		case <-owner.BusinessDone():
			source, recorded := owner.TerminationSource()
			if !recorded {
				source = "context_end_without_cancel"
			} else if source == "" {
				source = "unknown"
			}
			state := owner.TerminationState()
			log.Warnln("[BFP] event=bfp_session_business_ended outbound=%d owner=%d source=%s business_ended=%t control_ended=%t close_intent=%t local_close=%t",
				h.outboundSequence, sequence, source, state.BusinessEnded, state.ControlEnded, state.CloseIntent, state.LocalClose)
		case <-h.ctx.Done():
			return
		}
		select {
		case <-owner.Done():
		case <-h.ctx.Done():
		}
	}()
	return sequence
}

func (h *BFP) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if !h.SupportUDP() {
		return nil, C.ErrNotSupport
	}
	metadata = bfpLogicalMetadata(ctx, metadata)
	meta, err := bfpMetadata(metadata, "udp")
	if err != nil {
		return nil, err
	}
	if original, ok := C.LogicalUDPMetadataFromContext(ctx); ok && original.Host != "" {
		meta.Target.Domain, meta.DomainTrusted = original.Host, true
	}
	if err := h.beginSetup(true); err != nil {
		return nil, err
	}
	defer h.endSetup(true)
	work, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(h.ctx, cancel)
	defer cancel()
	defer stop()
	owner, err := h.destinationSession(work, metadata)
	if err != nil {
		return nil, err
	}
	h.watchSessionTermination(owner)
	// The setup context controls selection only. The returned connection has
	// the outbound lifetime; a setup cancel cannot invalidate it afterwards.
	// Each WriteTo supplies its own actual domain; the initial target's Host
	// must not describe another target on this multi-target connection.
	meta.Target.Domain = ""
	meta.DomainTrusted = true
	wrapped := &bfpPacketConn{owner: h, sessionOwner: owner, done: make(chan struct{}), destinations: make(map[packet.Addr]bfpUDPDestination), preparations: make(map[*bfpUDPPreparation]struct{})}
	conn, err := packet.New(h.ctx, owner, packet.Config{Metadata: meta, MetadataForTargetToken: wrapped.metadataForTarget, TargetRetired: wrapped.targetRetired, ExposeTargetToken: true})
	if err != nil {
		return nil, err
	}
	wrapped.Conn = conn
	h.mu.Lock()
	if h.closed || work.Err() != nil {
		h.mu.Unlock()
		conn.Close()
		return nil, net.ErrClosed
	}
	h.packets[wrapped] = struct{}{}
	h.watchers.Add(1)
	h.mu.Unlock()
	go func() {
		defer h.watchers.Done()
		select {
		case <-owner.BusinessDone():
		case <-h.ctx.Done():
		case <-wrapped.done:
			return
		}
		wrapped.Close()
	}()
	return &bfpMihomoPacketConn{PacketConn: NewPacketConn(wrapped, h), logical: wrapped}, nil
}

// Preserve the restored logical address until BFP's server policy resolves it.
// A fake-IP mapping must already be restored by Mihomo before this call.
func (h *BFP) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	_, err := bfpMetadata(metadata, "udp")
	return err
}

type bfpPacketConn struct {
	*packet.Conn
	owner        *BFP
	sessionOwner *session.Session
	once         sync.Once
	err          error
	done         chan struct{}
	destMu       sync.Mutex
	destinations map[packet.Addr]bfpUDPDestination
	preparations map[*bfpUDPPreparation]struct{}
	prepared     bool
	plainUsed    bool
	ended        bool
}

type bfpUDPDestination struct {
	meta         classification.Metadata
	lease        C.SessionFakeIPLease
	origin       netip.AddrPort
	target       packet.TargetToken
	reservations int
	committed    bool
	retiring     bool
	publication  chan struct{}
}

// A preparation is an opaque one-write transaction. It cannot be fabricated
// from a matching host:port string, reused by a different PacketConn, or commit
// a replacement generation after the original target retires.
type bfpUDPPreparation struct {
	ctx          context.Context
	address      packet.Addr
	owner        *bfpPacketConn
	lease        C.SessionFakeIPLease
	completed    bool
	committed    bool
	writeStarted bool
	written      bool
	stop         func() bool
	done         chan struct{}
	finishOnce   sync.Once
}

func (p *bfpUDPPreparation) Network() string { return "udp" }
func (p *bfpUDPPreparation) String() string  { return p.address.String() }

type bfpMihomoPacketConn struct {
	C.PacketConn
	logical *bfpPacketConn
}

var _ C.LogicalUDPPacketConn = (*bfpMihomoPacketConn)(nil)
var _ C.LogicalUDPPacketConnTransaction = (*bfpMihomoPacketConn)(nil)

func (c *bfpMihomoPacketConn) PrepareUDPMetadata(ctx context.Context, metadata *C.Metadata, origin netip.AddrPort) (net.Addr, error) {
	return c.logical.prepareMetadata(ctx, metadata, origin)
}

func (c *bfpMihomoPacketConn) RestoreUDPSource(source net.Addr) (net.Addr, error) {
	return c.logical.restoreSource(source)
}

func (c *bfpMihomoPacketConn) CommitUDPMetadata(address net.Addr) error {
	return c.logical.commitMetadata(address)
}

func (c *bfpMihomoPacketConn) AbortUDPMetadata(address net.Addr) {
	c.logical.abortMetadata(address)
}

func (c *bfpMihomoPacketConn) AddRef(ref any) {
	if owner, ok := c.PacketConn.(AddRef); ok {
		owner.AddRef(ref)
	}
}

// Return a canonical exact target key without any business DNS lookup.
func bfpUDPKey(text string) (packet.Addr, error) {
	return bfpUDPKeyWithScope(text, false)
}

func bfpUDPKeyWithScope(text string, scoped bool) (packet.Addr, error) {
	if len(text) > 320 {
		return "", packet.ErrAddress
	}
	host, portText, err := net.SplitHostPort(text)
	if err != nil || host == "" {
		return "", packet.ErrAddress
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", packet.ErrAddress
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		// Host fake-IP values must be restored by its DNS subsystem first.
		if !scoped && (bfpSessionPrefixes[0].Contains(ip) || bfpSessionPrefixes[1].Contains(ip)) {
			return "", packet.ErrAddress
		}
		host = ip.String()
	} else {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if len(host) == 0 || len(host) > 253 || strings.ContainsAny(host, " \t\r\n/\\\x00%") {
			return "", packet.ErrAddress
		}
	}
	return packet.Addr(net.JoinHostPort(host, strconv.FormatUint(port, 10))), nil
}

func (c *bfpPacketConn) metadataForTarget(ctx context.Context, target packet.TargetToken, base classification.Metadata) (classification.Metadata, error) {
	if err := ctx.Err(); err != nil {
		return base, err
	}
	c.destMu.Lock()
	if c.ended {
		c.destMu.Unlock()
		return base, net.ErrClosed
	}
	entry, exists := c.destinations[target.Address]
	if exists {
		if entry.retiring || entry.target.Generation != 0 && entry.target != target {
			c.destMu.Unlock()
			return base, packet.ErrTargetClosed
		}
		entry.target = target
		c.destinations[target.Address] = entry
		// Preserve the structural destination and locally established policy
		// hints chosen by the fixed packet owner.
		base.Target.Domain, base.DomainTrusted = entry.meta.Target.Domain, entry.meta.DomainTrusted
		base.Target.RuleTag, base.RuleTagTrusted = entry.meta.Target.RuleTag, entry.meta.RuleTagTrusted
		base.Application, base.ApplicationTrusted = entry.meta.Application, entry.meta.ApplicationTrusted
	} else if c.prepared {
		// Once logical preparation has started, every target must have a live
		// destination record. This rejects a stale PacketConn dial racing an
		// aborted or retired reservation.
		c.destMu.Unlock()
		return base, packet.ErrTargetClosed
	}
	c.destMu.Unlock()
	if entry.lease != nil {
		if _, err := entry.lease.Remaining(ctx); err != nil {
			return base, err
		}
	}
	return base, nil
}

func (c *bfpPacketConn) targetRetired(target packet.TargetToken) {
	c.destMu.Lock()
	defer c.destMu.Unlock()
	entry, exists := c.destinations[target.Address]
	if !exists || entry.target != target {
		return
	}
	if !entry.committed {
		close(entry.publication)
	}
	delete(c.destinations, target.Address)
	for preparation := range c.preparations {
		if preparation.address == target.Address {
			preparation.completed = true
			if preparation.stop != nil {
				preparation.stop()
			}
			preparation.finishOnce.Do(func() { close(preparation.done) })
			delete(c.preparations, preparation)
		}
	}
}

func (c *bfpPacketConn) prepareMetadata(ctx context.Context, metadata *C.Metadata, origin netip.AddrPort) (net.Addr, error) {
	if ctx == nil {
		return nil, packet.ErrAddress
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if metadata == nil || metadata.NetWork != C.UDP || origin.IsValid() && origin.Port() == 0 {
		return nil, packet.ErrAddress
	}
	if lease := metadata.SessionFakeIP; lease != nil {
		l, ok := lease.(*bfpSessionLease)
		if !ok || l == nil || l.outbound != c.owner || l.owner != c.sessionOwner || origin.IsValid() && origin.Addr() != l.Address() {
			return nil, C.ErrSessionFakeIP
		}
		if _, err := l.Remaining(ctx); err != nil {
			return nil, err
		}
	}
	meta, err := bfpMetadata(metadata, "udp")
	if err != nil {
		return nil, err
	}
	address, err := bfpUDPKeyWithScope(meta.Target.Address, c.sessionOwner != nil)
	if err != nil {
		return nil, err
	}
	meta.Target.Address = address.String()
	if meta, err = bfpBridgeMetadata(meta); err != nil {
		return nil, err
	}
	c.destMu.Lock()
	defer c.destMu.Unlock()
	if c.ended {
		return nil, net.ErrClosed
	}
	if c.plainUsed {
		return nil, packet.ErrAddress
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The map follows real packet target retirement, including replies that
	// extend its idle lifetime. There is no independent wall-clock expiry.
	entry, exists := c.destinations[address]
	if old, exists := c.destinations[address]; exists {
		if old.retiring {
			return nil, packet.ErrTargetClosed
		}
		// An association is bound to the exact host-provided origin for its
		// lifetime.  Treat an invalid origin as a value too: allowing an
		// invalid-to-valid transition (or the reverse) would let a later
		// packet replace the reply destination while the old target is still
		// live.
		if old.origin != origin {
			return nil, packet.ErrAddress
		}
		if old.meta.Target.Domain != meta.Target.Domain || old.meta.DomainTrusted != meta.DomainTrusted {
			return nil, classification.ErrMetadata
		}
	} else if len(c.destinations) >= 16 {
		return nil, packet.ErrLimit
	}
	if len(c.preparations) >= 32 {
		return nil, packet.ErrLimit
	}
	if !exists {
		entry = bfpUDPDestination{meta: meta, lease: metadata.SessionFakeIP, origin: origin, publication: make(chan struct{})}
	}
	entry.reservations++
	c.destinations[address] = entry
	if c.preparations == nil {
		c.preparations = make(map[*bfpUDPPreparation]struct{})
	}
	preparation := &bfpUDPPreparation{ctx: ctx, address: address, owner: c, lease: metadata.SessionFakeIP, done: make(chan struct{})}
	c.preparations[preparation] = struct{}{}
	preparation.stop = context.AfterFunc(ctx, func() { c.abortMetadata(preparation) })
	c.prepared = true
	return preparation, nil
}

func (c *bfpPacketConn) transactionAddress(address net.Addr) (*bfpUDPPreparation, error) {
	preparation, ok := address.(*bfpUDPPreparation)
	if !ok || preparation == nil || preparation.owner != c {
		return nil, packet.ErrAddress
	}
	return preparation, nil
}

func (c *bfpPacketConn) commitMetadata(address net.Addr) error {
	preparation, err := c.transactionAddress(address)
	if err != nil {
		return err
	}
	c.destMu.Lock()
	defer c.destMu.Unlock()
	if c.ended {
		return net.ErrClosed
	}
	if preparation.completed {
		if preparation.committed {
			return nil
		}
		return packet.ErrTargetClosed
	}
	if err := preparation.ctx.Err(); err != nil {
		return err
	}
	entry, ok := c.destinations[preparation.address]
	if !ok || entry.retiring || entry.target.Generation == 0 || !preparation.written {
		return packet.ErrTargetClosed
	}
	entry.reservations--
	if !entry.committed {
		close(entry.publication)
	}
	entry.committed = true
	c.destinations[preparation.address] = entry
	preparation.completed, preparation.committed = true, true
	if preparation.stop != nil {
		preparation.stop()
	}
	preparation.finishOnce.Do(func() { close(preparation.done) })
	delete(c.preparations, preparation)
	return nil
}

func (c *bfpPacketConn) abortMetadata(address net.Addr) {
	preparation, err := c.transactionAddress(address)
	if err != nil {
		return
	}
	c.destMu.Lock()
	if c.ended || preparation.completed {
		c.destMu.Unlock()
		if preparation.done != nil {
			<-preparation.done
		}
		return
	}
	preparation.completed = true
	defer preparation.finishOnce.Do(func() { close(preparation.done) })
	if preparation.stop != nil {
		preparation.stop()
	}
	delete(c.preparations, preparation)
	entry, ok := c.destinations[preparation.address]
	if !ok {
		c.destMu.Unlock()
		return
	}
	entry.reservations--
	if entry.committed || entry.reservations != 0 {
		c.destinations[preparation.address] = entry
		c.destMu.Unlock()
		return
	}
	if entry.target.Generation == 0 {
		if c.Conn != nil {
			if token, exists := c.Conn.TargetTokenForAddress(preparation.address); exists {
				entry.target = token
			}
		}
		if entry.target.Generation == 0 {
			close(entry.publication)
			delete(c.destinations, preparation.address)
			c.destMu.Unlock()
			return
		}
	}
	entry.retiring = true
	c.destinations[preparation.address] = entry
	target := entry.target
	c.destMu.Unlock()
	// Keep the entry as retiring until the exact target has joined. This
	// closes the race between Abort and an already-running metadata/dial hook.
	if c.Conn != nil {
		c.Conn.RetireTarget(target)
	}
	c.targetRetired(target)
}

func (c *bfpPacketConn) restoreSource(source net.Addr) (net.Addr, error) {
	if !validUDPAddress(source) {
		return nil, packet.ErrAddress
	}
	address, err := bfpUDPKeyWithScope(source.String(), c.sessionOwner != nil)
	if err != nil {
		return nil, err
	}
	for {
		c.destMu.Lock()
		if c.ended {
			c.destMu.Unlock()
			return nil, net.ErrClosed
		}
		entry, exists := c.destinations[address]
		if !exists {
			prepared := c.prepared
			c.destMu.Unlock()
			if prepared {
				return nil, packet.ErrAddress
			}
			return source, nil
		}
		token, ok := source.(packet.TargetToken)
		if !ok || entry.retiring || token != entry.target || c.Conn == nil || !c.Conn.TargetAlive(token) {
			c.destMu.Unlock()
			return nil, packet.ErrTargetClosed
		}
		if entry.committed {
			c.destMu.Unlock()
			if entry.origin.IsValid() {
				return net.UDPAddrFromAddrPort(entry.origin), nil
			}
			return address, nil
		}
		// A fast target can reply before the sender returns from WriteTo and
		// calls Commit. Hold that exact generation here; publishing a
		// provisional origin or dropping a valid fast reply is unnecessary.
		publication, done := entry.publication, c.Conn.Done()
		c.destMu.Unlock()
		select {
		case <-publication:
		case <-done:
			return nil, net.ErrClosed
		}
	}
}

func (c *bfpPacketConn) WriteTo(b []byte, address net.Addr) (int, error) {
	if !validUDPAddress(address) {
		return 0, packet.ErrAddress
	}
	key, err := bfpUDPKeyWithScope(address.String(), c.sessionOwner != nil)
	if err != nil {
		return 0, err
	}
	var preparation *bfpUDPPreparation
	var destination net.Addr = key
	c.destMu.Lock()
	if c.ended {
		c.destMu.Unlock()
		return 0, net.ErrClosed
	}
	if c.prepared {
		preparation, err = c.transactionAddress(address)
		if err != nil || preparation.completed || preparation.writeStarted {
			c.destMu.Unlock()
			return 0, packet.ErrAddress
		}
		entry, exists := c.destinations[key]
		if !exists || entry.retiring {
			c.destMu.Unlock()
			return 0, packet.ErrTargetClosed
		}
		preparation.writeStarted = true
		if entry.target.Generation != 0 {
			destination = entry.target
		}
	} else {
		c.plainUsed = true
	}
	c.destMu.Unlock()
	var n int
	if preparation != nil {
		if preparation.lease != nil {
			if _, err := preparation.lease.Remaining(preparation.ctx); err != nil {
				return 0, err
			}
		}
		n, err = c.Conn.WriteToContext(preparation.ctx, b, destination)
	} else {
		n, err = c.Conn.WriteTo(b, destination)
	}
	if err == nil && n == len(b) {
		if preparation, ok := address.(*bfpUDPPreparation); ok {
			c.destMu.Lock()
			preparation.written = true
			c.destMu.Unlock()
		}
	}
	return n, err
}

func validUDPAddress(address net.Addr) bool {
	if address == nil {
		return false
	}
	value := reflect.ValueOf(address)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return false
		}
	}
	return address.Network() == "udp"
}

func (c *bfpPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, address, err := c.Conn.ReadFrom(b)
	c.destMu.Lock()
	prepared := c.prepared
	c.destMu.Unlock()
	if prepared {
		return n, address, err
	}
	if err == nil && address != nil {
		if peer, parseErr := netip.ParseAddrPort(address.String()); parseErr == nil {
			return n, net.UDPAddrFromAddrPort(peer), nil
		}
	}
	return n, address, err
}

func (c *bfpPacketConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.destMu.Lock()
		c.ended = true
		for _, entry := range c.destinations {
			if !entry.committed {
				close(entry.publication)
			}
		}
		c.destinations = nil
		for preparation := range c.preparations {
			preparation.completed = true
			if preparation.stop != nil {
				preparation.stop()
			}
			preparation.finishOnce.Do(func() { close(preparation.done) })
		}
		c.preparations = nil
		c.destMu.Unlock()
		c.owner.mu.Lock()
		delete(c.owner.packets, c)
		if c.err != nil && c.owner.retireErr == nil {
			c.owner.retireErr = c.err
		}
		c.owner.mu.Unlock()
		close(c.done)
	})
	return c.err
}

func (h *BFP) Close() error {
	h.closeOnce.Do(func() {
		h.mu.Lock()
		h.closed = true
		// This is the last registered diagnostic owner, not a Client lookup;
		// obtaining Client's handshake lock here would delay cancellation.
		sequence := h.ownerSequence
		owned := make([]*bfpPacketConn, 0, len(h.packets))
		for conn := range h.packets {
			owned = append(owned, conn)
		}
		h.mu.Unlock()
		log.Infoln("[BFP] event=bfp_outbound_close_requested outbound=%d owner=%d", h.outboundSequence, sequence)
		h.cancel()
		h.closeErr = h.client.Close()
		// closed and Add share mu, so Wait cannot race a new setup admission.
		// A setup arriving after closed cleans its own resources before Done.
		h.setups.Wait()
		for _, conn := range owned {
			h.closeErr = errors.Join(h.closeErr, conn.Close())
		}
		h.watchers.Wait()
		h.mu.Lock()
		h.closeErr = errors.Join(h.closeErr, h.retireErr)
		h.mu.Unlock()
	})
	return h.closeErr
}
