//go:build with_gvisor

package outbound

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bfp/gateway"
	"bfp/session"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	SN "github.com/metacubex/sing/common/network"
)

// This fixture enters the same sing-tun gVisor TCP forwarder and Mihomo
// BufferedConn -> Relay -> tracker -> native BFP Flow paths used by the TUN
// client. Its two IP stacks exchange packets only through in-memory channels;
// the encrypted BFP carrier and TLS target use synthetic keys and loopback.
// It creates no OS adapter, DNS setting, route, firewall rule or public request.
func TestBFPGVisorRelayTLSKeepsDNSOwnerLocal(t *testing.T) {
	path, credentials := bfpPrivateFixture(t)
	f := bfpStartNativeFixture(t, credentials)
	bfpFixtureEndpoint(t, path, f.server.Addr().String())
	wantBody := bytes.Repeat([]byte("local-gvisor-bfp-tls\n"), 64)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(wantBody)
	}))
	target.StartTLS()
	t.Cleanup(target.Close)
	tlsPort := target.Listener.Addr().(*net.TCPAddr).Port
	_, echoPortText, err := net.SplitHostPort(f.tcp)
	if err != nil {
		t.Fatal(err)
	}
	echoPort, _ := strconv.Atoi(echoPortText)
	f.backend.dialer, err = gateway.New(gateway.Policy{
		AllowPrivate: true, AllowedCIDRs: []string{"127.0.0.0/8"},
		AllowedPorts: []int{tlsPort, echoPort}, MaxConcurrent: 8, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewBFP(BFPOption{Name: "gvisor-local-isolation", ClientConfigFile: path, UDP: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Establish the native Session exclusively through DNS ownership first,
	// then end the DNS request context before the first TCP/TLS connection.
	dnsContext, endDNS := context.WithTimeout(ctx, time.Second)
	lease, err := h.AllocateSessionFakeIP(dnsContext, "service.bfp.invalid", false)
	endDNS()
	if err != nil {
		t.Fatal("DNS-only Session establishment", err)
	}
	owner := h.client.Session()
	if owner == nil {
		t.Fatal("DNS-only allocation did not establish Session")
	}
	checkOwner := func(stage string) {
		t.Helper()
		select {
		case <-owner.BusinessDone():
			source, recorded := owner.TerminationSource()
			t.Fatalf("stage=%s early_business_end source=%q recorded=%v state=%+v", stage, source, recorded, owner.TerminationState())
		default:
		}
		if h.client.Session() != owner {
			t.Fatalf("stage=%s replaced DNS-owned shared Session", stage)
		}
		if _, err := lease.Remaining(ctx); err != nil {
			t.Fatalf("stage=%s retired DNS lease: %v", stage, err)
		}
	}
	checkOwner("DNS caller canceled")
	forwarder := &bfpGVisorRelayFixture{h: h, owner: owner, lease: lease,
		errors: make(chan error, 16), done: make(chan struct{}, 16)}
	clientStack := bfpLocalGVisorPair(t, ctx, forwarder)
	dial := func(port int) (*gonet.TCPConn, error) {
		conn, err := gonet.DialContextTCP(ctx, clientStack,
			tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tun.AddressFromAddr(lease.Address()), Port: uint16(port)}, ipv4.ProtocolNumber)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		}
		return conn, err
	}
	https := func() error {
		conn, err := dial(tlsPort)
		if err != nil {
			return fmt.Errorf("memory TCP dial: %w", err)
		}
		defer conn.Close()
		// The target uses httptest's synthetic certificate. There is no
		// credential, remote host or production trust setting in this fixture.
		secured := tls.Client(conn, &tls.Config{ServerName: "service.bfp.invalid", InsecureSkipVerify: true})
		defer secured.Close()
		if err := secured.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("TLS handshake: %w", err)
		}
		request, _ := http.NewRequest("GET", "https://service.bfp.invalid/local-only", nil)
		request.Close = true
		if err := request.Write(secured); err != nil {
			return err
		}
		response, err := http.ReadResponse(bufio.NewReader(secured), request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, int64(len(wantBody)+1)))
		if err != nil {
			return err
		}
		if response.StatusCode != 200 || !bytes.Equal(body, wantBody) {
			return fmt.Errorf("HTTPS response mismatch status=%d bytes=%d", response.StatusCode, len(body))
		}
		return nil
	}
	if err := https(); err != nil {
		t.Fatal("first gVisor HTTPS after DNS-only establishment", err)
	}
	checkOwner("first HTTPS")

	// The existing local target answers only after it receives TCP FIN.
	// This exercises Relay's real CloseWrite traversal through tracker/BFP
	// while keeping the reverse direction open for the after-FIN response.
	finConn, err := dial(echoPort)
	if err != nil {
		t.Fatal(err)
	}
	defer finConn.Close()
	finPayload := []byte("memory-gvisor-client-fin")
	if _, err := finConn.Write(finPayload); err != nil {
		t.Fatal(err)
	}
	if err := finConn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	afterFIN, err := io.ReadAll(io.LimitReader(finConn, 1024))
	if err != nil || !bytes.Equal(afterFIN, append([]byte("after-fin:"), finPayload...)) {
		t.Fatalf("reverse response after client FIN bytes=%q err=%v", afterFIN, err)
	}
	_ = finConn.Close()
	checkOwner("after client FIN")

	var concurrent sync.WaitGroup
	errors := make(chan error, 3)
	for i := 0; i < 3; i++ {
		concurrent.Add(1)
		go func() { defer concurrent.Done(); errors <- https() }()
	}
	concurrent.Wait()
	for i := 0; i < 3; i++ {
		if err := <-errors; err != nil {
			t.Fatal("three-flow HTTPS wave", err)
		}
	}
	checkOwner("three concurrent HTTPS")
	if err := https(); err != nil {
		t.Fatal("HTTPS after other flow closures", err)
	}
	for i := 0; i < 6; i++ {
		select {
		case <-forwarder.done:
		case err := <-forwarder.errors:
			t.Fatal("gVisor native forwarder", err)
		case <-time.After(2 * time.Second):
			t.Fatalf("Relay did not complete after stream closure: completed=%d want=6", i)
		}
	}
	select {
	case err := <-forwarder.errors:
		t.Fatal(err)
	default:
	}
	if forwarder.readWithBuffer.Load() == 0 || forwarder.closeWrite.Load() == 0 || forwarder.accepted.Load() != 6 {
		t.Fatalf("gVisor-specific path missing accepted=%d lazy_reads=%d reverse_half_closes=%d", forwarder.accepted.Load(), forwarder.readWithBuffer.Load(), forwarder.closeWrite.Load())
	}
	checkOwner("all Relay workers ended")
	if f.backend.tcp.Load() != 6 {
		t.Fatalf("real local BFP backend target dial count=%d want=6", f.backend.tcp.Load())
	}
	t.Logf("local_only=true dns_only_owner=true https=5 concurrent_https=3 after_fin=true relays=6 lazy_gvisor_reads=%d reverse_half_closes=%d same_session=true state=%+v", forwarder.readWithBuffer.Load(), forwarder.closeWrite.Load(), owner.TerminationState())
}

type bfpGVisorRelayFixture struct {
	h              *BFP
	owner          *session.Session
	lease          C.SessionFakeIPLease
	errors         chan error
	done           chan struct{}
	accepted       atomic.Int32
	readWithBuffer atomic.Int32
	closeWrite     atomic.Int32
}

func (f *bfpGVisorRelayFixture) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	defer func() { f.done <- struct{}{} }()
	defer conn.Close()
	meta := &C.Metadata{NetWork: C.TCP, Type: C.TUN, DstIP: metadata.Destination.Addr,
		DstPort: metadata.Destination.Port, Host: f.lease.Host(), SessionFakeIP: f.lease}
	setup, endSetup := context.WithTimeout(context.Background(), time.Second)
	remote, err := f.h.DialContext(setup, meta)
	endSetup()
	if err != nil {
		f.errors <- err
		return err
	}
	defer remote.Close()
	if f.h.client.Session() != f.owner {
		err := fmt.Errorf("gVisor inbound replaced DNS owner")
		f.errors <- err
		return err
	}
	gConn, ok := conn.(*gonet.TCPConn)
	if !ok {
		err := fmt.Errorf("sing-tun returned unexpected inbound %T", conn)
		f.errors <- err
		return err
	}
	f.accepted.Add(1)
	counted := &bfpGVisorCountedConn{TCPConn: gConn, f: f}
	inbound := N.NewBufferedConn(counted)
	tracked := statistic.NewTCPTracker(remote, new(statistic.Manager), meta, nil, 0, 0, false)
	N.Relay(inbound, tracked)
	return nil
}

func (f *bfpGVisorRelayFixture) PrepareConnection(string, M.Socksaddr, M.Socksaddr, tun.DirectRouteContext, time.Duration) (tun.DirectRouteDestination, error) {
	return nil, nil
}
func (f *bfpGVisorRelayFixture) NewPacket(_ context.Context, _ netip.AddrPort, buffer *buf.Buffer, _ M.Metadata, _ func(SN.PacketConn) SN.PacketWriter) {
	buffer.Release()
	f.errors <- fmt.Errorf("unexpected UDP packet in TCP-only memory fixture")
}
func (f *bfpGVisorRelayFixture) NewError(_ context.Context, err error) { f.errors <- err }

type bfpGVisorCountedConn struct {
	*gonet.TCPConn
	f *bfpGVisorRelayFixture
}

func (c *bfpGVisorCountedConn) ReadWithBuffer(getBuffer func(int) []byte) (int, error) {
	c.f.readWithBuffer.Add(1)
	return c.TCPConn.ReadWithBuffer(getBuffer)
}
func (c *bfpGVisorCountedConn) CloseWrite() error {
	c.f.closeWrite.Add(1)
	return c.TCPConn.CloseWrite()
}

func bfpLocalGVisorPair(t *testing.T, ctx context.Context, handler tun.Handler) *stack.Stack {
	t.Helper()
	clientLink, serverLink := channel.New(128, 1500, ""), channel.New(128, 1500, "")
	client, err := tun.NewGVisorStack(clientLink)
	if err != nil {
		t.Fatal(err)
	}
	server, err := tun.NewGVisorStack(serverLink)
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	if err := client.AddProtocolAddress(tun.DefaultNIC, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 91, 0, 2}), PrefixLen: 24}}, stack.AddressProperties{}); err != nil {
		t.Fatal(err.String())
	}
	server.SetTransportProtocolHandler(tcp.ProtocolNumber, tun.NewTCPForwarder(ctx, server, handler).HandlePacket)
	pumpContext, stopPumps := context.WithCancel(ctx)
	var pumps sync.WaitGroup
	pump := func(from, to *channel.Endpoint) {
		defer pumps.Done()
		for {
			packet := from.ReadContext(pumpContext)
			if packet == nil {
				return
			}
			// Recreate the inbound packet so its parsed-header cursor starts at
			// the IP header, as it does when read from a real TUN device.
			inbound := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: packet.ToBuffer()})
			to.InjectInbound(packet.NetworkProtocolNumber, inbound)
			inbound.DecRef()
			packet.DecRef()
		}
	}
	pumps.Add(2)
	go pump(clientLink, serverLink)
	go pump(serverLink, clientLink)
	t.Cleanup(func() {
		stopPumps()
		pumps.Wait()
		for _, ipStack := range []*stack.Stack{client, server} {
			ipStack.Close()
			for _, endpoint := range ipStack.CleanupEndpoints() {
				endpoint.Abort()
			}
		}
		clientLink.Close()
		serverLink.Close()
	})
	return client
}
