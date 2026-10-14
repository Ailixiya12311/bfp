package outbound

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bfp/adapter/packet"
	"bfp/classification"
	"bfp/clientconfig"
	"bfp/gateway"
	"bfp/protocol"
	"bfp/session"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/miekg/dns"
)

func bfpPrivateFixture(t *testing.T) (string, session.Credentials) {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate fixture source")
	}
	checkout := filepath.Dir(filepath.Dir(filepath.Dir(source)))
	base := t.TempDir()
	binary := filepath.Join(base, "bfp-fixture")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	locate := exec.CommandContext(ctx, "go", "list", "-m", "-f", "{{.Dir}}", "bfp")
	locate.Dir = checkout
	location, err := locate.Output()
	if err != nil {
		t.Fatal("locate actual BFP module dependency")
	}
	module := strings.TrimSpace(string(location))
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/bfp")
	build.Dir = module
	build.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOTOOLCHAIN=local")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("compile real keygen: %v\n%s", err, output)
	}
	dir := filepath.Join(base, "private")
	if err := exec.CommandContext(ctx, binary, "keygen", "-out", dir).Run(); err != nil {
		t.Fatal("generate permission-protected synthetic keys")
	}
	body, err := os.ReadFile(filepath.Join(dir, "server.json"))
	if err != nil {
		t.Fatal("read synthetic server fixture")
	}
	defer clear(body)
	var config struct {
		Credentials session.Credentials `json:"credentials"`
	}
	if json.Unmarshal(body, &config) != nil {
		t.Fatal("decode synthetic server fixture")
	}
	return filepath.Join(dir, "client.json"), config.Credentials
}

func bfpFixtureEndpoint(t *testing.T, path, address string) {
	t.Helper()
	loaded, err := clientconfig.Load(path)
	if err != nil {
		t.Fatal("read protected synthetic client fixture")
	}
	body, err := json.Marshal(struct {
		Server      string              `json:"server"`
		TCPServer   string              `json:"tcp_server"`
		Credentials session.Credentials `json:"credentials"`
	}{address, address, loaded.Session.Credentials})
	if err != nil {
		t.Fatal("encode synthetic endpoint")
	}
	defer clear(body)
	// Truncate the existing protected file rather than replacing its ACL.
	if os.WriteFile(path, body, 0600) != nil {
		t.Fatal("write protected synthetic endpoint")
	}
}

type bfpNativeBackend struct {
	dialer   *gateway.Dialer
	tcp, udp atomic.Int32
}

func (b *bfpNativeBackend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// The explicit fixture alias tests logical domain transport without any
	// system DNS request. It does not claim production DNS resolver coverage.
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host == "service.bfp.invalid" {
		address = net.JoinHostPort("127.0.0.1", port)
	}
	conn, err := b.dialer.DialContext(ctx, network, address)
	if err == nil {
		if network == "tcp" {
			b.tcp.Add(1)
		} else {
			b.udp.Add(1)
		}
	}
	return conn, err
}

type bfpNativeFixture struct {
	server      *session.Server
	backend     *bfpNativeBackend
	tcp         string
	udp         [2]string
	udpReceived atomic.Int32
}

func bfpStartNativeFixture(t *testing.T, credentials session.Credentials) *bfpNativeFixture {
	t.Helper()
	f := new(bfpNativeFixture)
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f.tcp = tcp.Addr().String()
	var workers sync.WaitGroup
	acceptDone := make(chan struct{})
	var socketsMu sync.Mutex
	sockets := make(map[net.Conn]struct{})
	workers.Add(1)
	go func() {
		defer workers.Done()
		defer close(acceptDone)
		for {
			conn, err := tcp.AcceptTCP()
			if err != nil {
				return
			}
			socketsMu.Lock()
			sockets[conn] = struct{}{}
			socketsMu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				defer func() { socketsMu.Lock(); delete(sockets, conn); socketsMu.Unlock() }()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				payload, err := io.ReadAll(io.LimitReader(conn, 32769))
				if err == nil && len(payload) <= 32768 {
					conn.Write(append([]byte("after-fin:"), payload...))
					conn.CloseWrite()
				}
			}()
		}
	}()
	var udp [2]*net.UDPConn
	ports := []int{tcp.Addr().(*net.TCPAddr).Port}
	for i := range udp {
		udp[i], err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			tcp.Close()
			t.Fatal(err)
		}
		f.udp[i] = udp[i].LocalAddr().String()
		ports = append(ports, udp[i].LocalAddr().(*net.UDPAddr).Port)
		workers.Add(1)
		go func(conn *net.UDPConn) {
			defer workers.Done()
			buffer := make([]byte, 16385)
			for {
				n, peer, err := conn.ReadFromUDP(buffer)
				if err != nil {
					return
				}
				f.udpReceived.Add(1)
				conn.WriteToUDP(buffer[:n], peer)
			}
		}(udp[i])
	}
	t.Cleanup(func() {
		tcp.Close()
		<-acceptDone
		for _, conn := range udp {
			if conn != nil {
				conn.Close()
			}
		}
		// Wait for Accept to stop before closing its final accepted sockets.
		socketsMu.Lock()
		for conn := range sockets {
			conn.Close()
		}
		socketsMu.Unlock()
		joined := make(chan struct{})
		go func() { workers.Wait(); close(joined) }()
		select {
		case <-joined:
		case <-time.After(2 * time.Second):
			t.Error("target fixture workers did not join")
		}
	})
	dialer, err := gateway.New(gateway.Policy{AllowPrivate: true, AllowedCIDRs: []string{"127.0.0.0/8"}, AllowedPorts: ports, MaxConcurrent: 16, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	f.backend = &bfpNativeBackend{dialer: dialer}
	f.server, err = session.NewServer(session.ServerConfig{Listen: "127.0.0.1:0", Credentials: credentials, Backend: f.backend,
		Options: session.Options{CloseTimeout: 100 * time.Millisecond}, MaxSessions: 4})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		f.server.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("BFP fixture server did not join")
		}
	})
	return f
}

type bfpNativePhysical struct {
	tcp, udp       atomic.Int32
	blockUDP       bool
	connectedUDP   bool
	logicalSources bool
}

func (p *bfpNativePhysical) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	p.tcp.Add(1)
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err == nil && p.logicalSources {
		return &bfpLogicalStream{Conn: conn}, nil
	}
	return conn, err
}

func (p *bfpNativePhysical) ListenPacket(ctx context.Context, network, address string, peer netip.AddrPort) (net.PacketConn, error) {
	p.udp.Add(1)
	if p.blockUDP {
		return nil, errors.New("fixture UDP unavailable")
	}
	if p.connectedUDP {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, peer.String())
		if err != nil {
			return nil, err
		}
		return conn.(*net.UDPConn), nil
	}
	conn, err := (&net.ListenConfig{}).ListenPacket(ctx, network, address)
	if err == nil && p.logicalSources {
		return &bfpLogicalPacket{PacketConn: conn}, nil
	}
	return conn, err
}

type bfpLogicalAddress string

func (a bfpLogicalAddress) Network() string { return "socks" }
func (a bfpLogicalAddress) String() string  { return string(a) }

type bfpLogicalStream struct{ net.Conn }

func (c *bfpLogicalStream) RemoteAddr() net.Addr {
	return bfpLogicalAddress(c.Conn.RemoteAddr().String())
}

type bfpLogicalPacket struct{ net.PacketConn }

func (c *bfpLogicalPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, source, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, nil, err
	}
	return n, bfpLogicalAddress(source.String()), nil
}

func bfpNativeMetadata(t *testing.T, address string, network C.NetWork) *C.Metadata {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	metadata := &C.Metadata{NetWork: network, DstPort: uint16(port)}
	if ip, err := netip.ParseAddr(host); err == nil {
		metadata.DstIP = ip
	} else {
		metadata.Host = host
	}
	return metadata
}

func bfpNativeAfterFIN(t *testing.T, ctx context.Context, h *BFP, address string) {
	t.Helper()
	conn, err := h.DialContext(ctx, bfpNativeMetadata(t, address, C.TCP))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("upload-ended-response-still-required")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	writer, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("native wrapper lost half-close")
	}
	if err := writer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(response, append([]byte("after-fin:"), payload...)) {
		t.Fatalf("after-FIN response mismatch: length=%d err=%v", len(response), err)
	}
	if len(conn.Chains()) != 1 || conn.Chains()[0] != h.Name() {
		t.Fatal("lost native connection chain")
	}
}

func bfpNativeRoundTrip(t *testing.T, conn C.PacketConn, address net.Addr, payload []byte) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if n, err := conn.WriteTo(payload, address); err != nil || n != len(payload) {
		t.Fatalf("datagram admission n=%d err=%v", n, err)
	}
	buffer := make([]byte, 16385)
	n, source, err := conn.ReadFrom(buffer)
	if err != nil || !bytes.Equal(buffer[:n], payload) || source == nil || source.String() != address.String() {
		t.Fatalf("datagram result n=%d source=%v err=%v", n, source, err)
	}
}

func TestBFPNativeNext23(t *testing.T) {
	path, credentials := bfpPrivateFixture(t)
	t.Run("constructor_validates_without_dial", func(t *testing.T) {
		physical := new(bfpNativePhysical)
		h, err := NewBFP(BFPOption{Name: "native-test", ClientConfigFile: path, UDP: true, BasicOption: BasicOption{DialerForAPI: physical}})
		if err != nil {
			t.Fatal(err)
		}
		if physical.tcp.Load() != 0 || physical.udp.Load() != 0 || h.client.Session() != nil {
			t.Fatal("constructor performed carrier I/O")
		}
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := h.DialContext(context.Background(), bfpNativeMetadata(t, "127.0.0.1:53", C.TCP)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed outbound dial err=%v", err)
		}
	})
	for _, mode := range []struct {
		name     string
		physical *bfpNativePhysical
	}{
		{name: "normal_udp_logical_source", physical: &bfpNativePhysical{logicalSources: true}},
		{name: "connected_udp", physical: &bfpNativePhysical{connectedUDP: true}},
		{name: "initial_udp_failure_tcp_logical_remote", physical: &bfpNativePhysical{blockUDP: true, logicalSources: true}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			fixture := bfpStartNativeFixture(t, credentials)
			bfpFixtureEndpoint(t, path, fixture.server.Addr().String())
			physical := mode.physical
			h, err := NewBFP(BFPOption{Name: "native-test", ClientConfigFile: path, UDP: true, MaxPacketConns: 1, BasicOption: BasicOption{DialerForAPI: physical}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := h.Close(); err != nil {
					t.Error(err)
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			bfpNativeAfterFIN(t, ctx, h, fixture.tcp)
			owner := h.client.Session()
			if owner == nil {
				t.Fatal("missing shared Session")
			}
			setup, endSetup := context.WithCancel(ctx)
			conn, err := h.ListenPacketContext(setup, bfpNativeMetadata(t, fixture.udp[0], C.UDP))
			endSetup()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if n, err := conn.WriteTo([]byte("foreign-network"), &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9}); n != 0 || !errors.Is(err, packet.ErrAddress) {
				t.Fatalf("foreign UDP address was accepted n=%d err=%v", n, err)
			}
			for i, target := range fixture.udp {
				peer, _ := net.ResolveUDPAddr("udp", target)
				bfpNativeRoundTrip(t, conn, peer, bytes.Repeat([]byte{byte(10 + i)}, 48+i))
			}
			peer, _ := net.ResolveUDPAddr("udp", fixture.udp[0])
			bfpNativeRoundTrip(t, conn, peer, nil)
			bfpNativeRoundTrip(t, conn, peer, bytes.Repeat([]byte{37}, 16384))
			_, port, _ := net.SplitHostPort(fixture.udp[1])
			domain := packet.Addr(net.JoinHostPort("service.bfp.invalid", port))
			bfpNativeRoundTrip(t, conn, domain, []byte("logical-domain"))
			if h.client.Session() != owner || fixture.backend.udp.Load() != 3 {
				t.Fatal("Session replaced or target associations not shared")
			}
			before := fixture.udpReceived.Load()
			if n, err := conn.WriteTo(make([]byte, 16385), peer); n != 0 || !errors.Is(err, packet.ErrOversize) {
				t.Fatalf("oversize admission n=%d err=%v", n, err)
			}
			if fixture.udpReceived.Load() != before {
				t.Fatal("oversize reached target")
			}
			if _, err := h.ListenPacketContext(ctx, bfpNativeMetadata(t, fixture.udp[0], C.UDP)); !errors.Is(err, packet.ErrLimit) {
				t.Fatalf("packet instance cap err=%v", err)
			}
			conn.Close()
			if owner != h.client.Session() {
				t.Fatal("closing PacketConn closed shared Session")
			}
			if _, err := h.client.Connect(ctx); err != nil {
				t.Fatal("shared owner unavailable after packet close")
			}
			if physical.udp.Load() == 0 || physical.blockUDP && physical.tcp.Load() == 0 {
				t.Fatal("host physical dialer bypassed")
			}
		})
	}
	t.Run("metadata_restore_and_sniff_boundary", func(t *testing.T) {
		metadata := bfpNativeMetadata(t, "service.bfp.invalid:443", C.TCP)
		metadata.SniffHost = "untrusted.other.invalid"
		meta, err := bfpMetadata(metadata, "tcp")
		if err != nil || meta.Target.Address != "service.bfp.invalid:443" || meta.Target.Domain != "service.bfp.invalid" || !meta.DomainTrusted || meta.RuleTagTrusted {
			t.Fatal("metadata destination/trust boundary")
		}
		metadata = bfpNativeMetadata(t, "127.0.0.1:443", C.TCP)
		metadata.SniffHost = "untrusted.other.invalid"
		meta, err = bfpMetadata(metadata, "tcp")
		if err != nil || meta.Target.Domain != "" || meta.DomainTrusted || meta.Target.Address != "127.0.0.1:443" {
			t.Fatal("numeric destination rewritten by sniff")
		}
	})
	t.Run("local_rule_and_process_hints_are_bounded", func(t *testing.T) {
		metadata := bfpNativeMetadata(t, "service.bfp.invalid:443", C.TCP)
		metadata.SpecialRules = "bulk-download"
		metadata.Process = "curl"
		meta, err := bfpMetadata(metadata, "tcp")
		if err != nil || !meta.RuleTagTrusted || meta.Target.RuleTag != "bulk-download" || !meta.ApplicationTrusted || meta.Application != "curl" {
			t.Fatalf("local hints were not bridged: %+v err=%v", meta, err)
		}
		metadata.Process = `C:\\Program Files\\curl.exe`
		meta, err = bfpMetadata(metadata, "tcp")
		if err != nil || meta.ApplicationTrusted || meta.Application != "" {
			t.Fatalf("invalid process identity was trusted: %+v err=%v", meta, err)
		}
	})
}

func TestBFPNativeClassificationUsesMihomoApplicationHint(t *testing.T) {
	path, credentials := bfpPrivateFixture(t)
	fixture := bfpStartNativeFixture(t, credentials)
	bfpFixtureEndpoint(t, path, fixture.server.Addr().String())
	h, err := NewBFP(BFPOption{
		Name:             "classification-application-test",
		ClientConfigFile: path,
		UDP:              true,
		Classification: map[string]any{
			"default-class": "normal",
			"rules": []any{map[string]any{
				"name":        "curl-bulk",
				"application": "curl",
				"class":       "bulk",
				"locked":      true,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	metadata := bfpNativeMetadata(t, fixture.tcp, C.TCP)
	metadata.Process = "curl"
	conn, err := h.DialContext(context.Background(), metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("classification-hint")); err != nil {
		t.Fatal(err)
	}
	owner := h.client.Session()
	if owner == nil {
		t.Fatal("missing BFP session")
	}
	views, err := owner.FlowClassifications(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 {
		t.Fatalf("flow count=%d, want 1", len(views))
	}
	view := views[0]
	if view.LocalTX.Class != protocol.Bulk || view.LocalTX.Baseline.Class != protocol.Bulk || view.LocalTX.Baseline.Source != classification.SourceMetadata || view.LocalTX.Baseline.Rule != "curl-bulk" {
		t.Fatalf("application hint did not select bulk: %+v", view.LocalTX)
	}
}

// This resolver fixture exercises the actual host resolver interface while
// forbidding fallback to the ordinary business resolver or external DNS.
type bfpBootstrapResolver struct {
	calls   atomic.Int32
	allowed string
}

func (r *bfpBootstrapResolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	r.calls.Add(1)
	if host != r.allowed {
		return nil, errors.New("unexpected bootstrap lookup")
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, ctx.Err()
}
func (r *bfpBootstrapResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, host)
}
func (r *bfpBootstrapResolver) LookupIPv6(context.Context, string) ([]netip.Addr, error) {
	return nil, errors.New("fixture IPv6 unavailable")
}
func (r *bfpBootstrapResolver) ResolveECH(context.Context, string) ([]byte, error) {
	return nil, errors.New("fixture ECH unavailable")
}
func (r *bfpBootstrapResolver) ExchangeContext(context.Context, *dns.Msg) (*dns.Msg, error) {
	return nil, errors.New("fixture DNS exchange forbidden")
}

// Mihomo's Resolver.Invalid name means the resolver is available for use;
// returning true selects this fixture in Lookup*WithResolver.  Keep the
// business resolver explicitly forbidden below so a fallback would fail.
func (r *bfpBootstrapResolver) Invalid() bool    { return true }
func (r *bfpBootstrapResolver) ClearCache()      {}
func (r *bfpBootstrapResolver) ResetConnection() {}

func TestBFPBootstrapUsesProxyResolverAndPreservesOwnerSlots(t *testing.T) {
	path, credentials := bfpPrivateFixture(t)
	fixture := bfpStartNativeFixture(t, credentials)
	_, port, _ := net.SplitHostPort(fixture.server.Addr().String())
	bfpFixtureEndpoint(t, path, net.JoinHostPort("bootstrap.bfp.invalid", port))
	bootstrap := &bfpBootstrapResolver{allowed: "bootstrap.bfp.invalid"}
	business := &bfpBootstrapResolver{allowed: "forbidden.invalid"}
	oldBootstrap, oldBusiness := resolver.ProxyServerHostResolver, resolver.DefaultResolver
	resolver.ProxyServerHostResolver, resolver.DefaultResolver = bootstrap, business
	defer func() { resolver.ProxyServerHostResolver, resolver.DefaultResolver = oldBootstrap, oldBusiness }()
	h, err := NewBFP(BFPOption{Name: "bootstrap-test", ClientConfigFile: path, UDP: true, MaxPacketConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, err := h.ListenPacketContext(ctx, bfpNativeMetadata(t, fixture.udp[0], C.UDP))
	if err != nil {
		t.Fatal(err)
	}
	owner := h.client.Session()
	peer, _ := net.ResolveUDPAddr("udp", fixture.udp[0])
	bfpNativeRoundTrip(t, pc, peer, []byte("bootstrap"))
	if bootstrap.calls.Load() == 0 || business.calls.Load() != 0 {
		t.Fatalf("wrong resolver selected bootstrap=%d business=%d", bootstrap.calls.Load(), business.calls.Load())
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		h.mu.Lock()
		count := len(h.packets)
		h.mu.Unlock()
		if count == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ended owner retained packet slot without caller Close")
		}
		time.Sleep(time.Millisecond)
	}
	next, err := h.ListenPacketContext(ctx, bfpNativeMetadata(t, fixture.udp[1], C.UDP))
	if err != nil {
		t.Fatal("new owner could not reuse retired packet slot", err)
	}
	defer next.Close()
	if h.client.Session() == owner {
		t.Fatal("ended Session reused")
	}
	if _, err := pc.WriteTo([]byte("old-owner"), peer); err == nil {
		t.Fatal("old handle entered new Session")
	}
	peer, _ = net.ResolveUDPAddr("udp", fixture.udp[1])
	bfpNativeRoundTrip(t, next, peer, []byte("new-owner"))
	if business.calls.Load() != 0 {
		t.Fatal("business DNS used during carrier bootstrap")
	}
}
