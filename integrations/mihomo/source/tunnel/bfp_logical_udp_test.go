package tunnel_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

	"bfp/clientconfig"
	"bfp/session"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/socks"
	"github.com/metacubex/mihomo/transport/socks5"
	T "github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// The fixture uses actual SOCKS5 UDP decoding/write-back, actual packetSender,
// UDPTracker and authenticated BFP, with real loopback UDP targets. Only server
// DNS for the reserved .invalid names is replaced by explicit fixture aliases.
// No system DNS or TUN device is configured by these tests.
type logicalUDPBackend struct {
	mu       sync.Mutex
	aliases  map[string]string
	opened   []string
	received atomic.Int32
}

func (b *logicalUDPBackend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	b.mu.Lock()
	real, ok := b.aliases[address]
	if ok {
		b.opened = append(b.opened, address)
	}
	b.mu.Unlock()
	if !ok || network != "udp" {
		return nil, errors.New("logical UDP fixture: unexpected target")
	}
	return (&net.Dialer{}).DialContext(ctx, "udp", real)
}

type logicalUDPMapper struct {
	pool  *fakeip.Pool
	redir map[netip.Addr]string
}

func (m *logicalUDPMapper) FakeIPEnabled() bool                  { return true }
func (m *logicalUDPMapper) MappingEnabled() bool                 { return true }
func (m *logicalUDPMapper) IsFakeIP(ip netip.Addr) bool          { return m.pool.IPNet().Contains(ip) }
func (m *logicalUDPMapper) IsFakeBroadcastIP(ip netip.Addr) bool { return false }
func (m *logicalUDPMapper) IsExistFakeIP(ip netip.Addr) bool     { return m.pool.Exist(ip) }
func (m *logicalUDPMapper) FindHostByIP(ip netip.Addr) (string, bool) {
	if host, ok := m.redir[ip]; ok {
		return host, true
	}
	return m.pool.LookBack(ip)
}
func (m *logicalUDPMapper) FlushFakeIP() error                        { return m.pool.FlushFakeIP() }
func (m *logicalUDPMapper) InsertHostByIP(ip netip.Addr, host string) {}
func (m *logicalUDPMapper) StoreFakePoolState()                       {}

type logicalUDPRealTunnel struct {
	name string
}

func (t logicalUDPRealTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) { conn.Close() }
func (t logicalUDPRealTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	metadata.SpecialProxy = t.name
	T.Tunnel.HandleUDPPacket(packet, metadata)
}
func (t logicalUDPRealTunnel) NatTable() C.NatTable { return T.NatTable() }

func logicalUDPWait(t *testing.T, description string, check func() bool) {
	t.Helper()
	limit := time.NewTimer(3 * time.Second)
	defer limit.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for !check() {
		select {
		case <-tick.C:
		case <-limit.C:
			t.Fatalf("timeout: %s", description)
		}
	}
}

func logicalUDPKeys(t *testing.T) (string, session.Credentials) {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	checkout := filepath.Dir(filepath.Dir(source))
	tmp := t.TempDir()
	binary := filepath.Join(tmp, "bfp-keys")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	locate := exec.CommandContext(ctx, "go", "list", "-mod=readonly", "-m", "-f", "{{.Dir}}", "bfp")
	locate.Dir = checkout
	locate.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOTOOLCHAIN=local")
	moduleDir, err := locate.Output()
	if err != nil {
		t.Fatal("locate actual BFP module dependency")
	}
	module := strings.TrimSpace(string(moduleDir))
	if !filepath.IsAbs(module) {
		t.Fatal("BFP module dependency path is not absolute")
	}
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/bfp")
	build.Dir = module
	build.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOTOOLCHAIN=local")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("compile fixture keygen: %v\n%s", err, output)
	}
	private := filepath.Join(tmp, "private")
	if err := exec.CommandContext(ctx, binary, "keygen", "-out", private).Run(); err != nil {
		t.Fatal("create protected synthetic key fixture")
	}
	body, err := os.ReadFile(filepath.Join(private, "server.json"))
	if err != nil {
		t.Fatal("read synthetic server credentials")
	}
	defer clear(body)
	var cfg struct {
		Credentials session.Credentials `json:"credentials"`
	}
	if json.Unmarshal(body, &cfg) != nil {
		t.Fatal("decode synthetic fixture")
	}
	return filepath.Join(private, "client.json"), cfg.Credentials
}

func logicalUDPEndpoint(t *testing.T, path, address string) {
	t.Helper()
	loaded, err := clientconfig.Load(path)
	if err != nil {
		t.Fatal("load protected synthetic client fixture")
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
	// Preserve keygen's protected ACL by updating its existing file.
	if os.WriteFile(path, body, 0600) != nil {
		t.Fatal("update protected synthetic endpoint")
	}
}

func logicalUDPReply(t *testing.T, socket *net.UDPConn, target string, payload []byte) (string, byte) {
	t.Helper()
	encoded, err := socks5.EncodeUDPPacket(socks5.ParseAddr(target), payload)
	if err != nil {
		t.Fatal("encode real SOCKS5 UDP packet", err)
	}
	if err = socket.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = socket.Write(encoded); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32768)
	n, err := socket.Read(buffer)
	if err != nil {
		t.Fatal("real SOCKS5 UDP reply", err)
	}
	from, body, err := socks5.DecodeUDPPacket(buffer[:n])
	if err != nil || !bytes.Equal(body, payload) {
		t.Fatalf("SOCKS5 reply decode/payload: %v", err)
	}
	return from.String(), from[0]
}

func TestBFPLogicalUDPRealTunnelMultiTargetAndFakeIP(t *testing.T) {
	configPath, credentials := logicalUDPKeys(t)
	backend := &logicalUDPBackend{aliases: make(map[string]string)}
	var targets [2]*net.UDPConn
	var targetWorkers sync.WaitGroup
	for i := range targets {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		targets[i] = conn
		targetWorkers.Add(1)
		go func() {
			defer targetWorkers.Done()
			buffer := make([]byte, 32768)
			for {
				n, from, err := conn.ReadFromUDP(buffer)
				if err != nil {
					return
				}
				backend.received.Add(1)
				if _, err = conn.WriteToUDP(buffer[:n], from); err != nil {
					return
				}
			}
		}()
	}
	t.Cleanup(func() {
		for _, c := range targets {
			if c != nil {
				c.Close()
			}
		}
		targetWorkers.Wait()
	})
	logicalTargets := [2]string{}
	for i, conn := range targets {
		logicalTargets[i] = net.JoinHostPort([]string{"one.bfp.invalid", "two.bfp.invalid"}[i], strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port))
		backend.aliases[logicalTargets[i]] = conn.LocalAddr().String()
		backend.aliases[conn.LocalAddr().String()] = conn.LocalAddr().String()
		backend.aliases[net.JoinHostPort([]string{"203.0.113.31", "203.0.113.32"}[i], strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port))] = conn.LocalAddr().String()
	}
	server, err := session.NewServer(session.ServerConfig{Listen: "127.0.0.1:0", Credentials: credentials, Backend: backend,
		Options: session.Options{CloseTimeout: 300 * time.Millisecond, KeyUpdateBytes: 1 << 30, KeyUpdateInterval: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(context.Background()) }()
	t.Cleanup(func() {
		server.Close()
		select {
		case err := <-serverDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("server cleanup did not join")
		}
	})
	logicalUDPEndpoint(t, configPath, server.Addr().String())
	h, err := outbound.NewBFP(outbound.BFPOption{Name: "bfp-tunnel-runtime", ClientConfigFile: configPath, UDP: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Error("native outbound cleanup", err)
		}
	})

	pool, err := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("198.18.0.0/24"), Size: 32})
	if err != nil {
		t.Fatal(err)
	}
	mapper := &logicalUDPMapper{pool: pool, redir: map[netip.Addr]string{
		netip.MustParseAddr("203.0.113.31"): "one.bfp.invalid", netip.MustParseAddr("203.0.113.32"): "two.bfp.invalid",
	}}
	savedMapper, savedStatus := resolver.DefaultHostMapper, T.Status()
	savedProxies, savedProviders := T.Proxies(), T.Providers()
	T.UpdateProxies(map[string]C.Proxy{h.Name(): adapter.NewProxy(h)}, savedProviders)
	resolver.DefaultHostMapper = mapper
	T.OnRunning()
	t.Cleanup(func() {
		h.Close()
		logicalUDPWait(t, "native trackers released", func() bool {
			found := false
			statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
				for _, name := range c.Info().Chain {
					if name == h.Name() {
						found = true
					}
				}
				return true
			})
			return !found
		})
		resolver.DefaultHostMapper = savedMapper
		switch savedStatus {
		case T.Running:
			T.OnRunning()
		case T.Inner:
			T.OnInnerLoading()
		default:
			T.OnSuspend()
		}
		T.UpdateProxies(savedProxies, savedProviders)
	})

	listener, err := socks.NewUDP("127.0.0.1:0", logicalUDPRealTunnel{h.Name()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	listenAddr, err := net.ResolveUDPAddr("udp4", listener.Address())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		targets [2]string
		atyp    byte
	}{
		{"domain_sources", logicalTargets, socks5.AtypDomainName},
		{"fake_ip_sources", [2]string{
			net.JoinHostPort(pool.Lookup("one.bfp.invalid").String(), strconv.Itoa(targets[0].LocalAddr().(*net.UDPAddr).Port)),
			net.JoinHostPort(pool.Lookup("two.bfp.invalid").String(), strconv.Itoa(targets[1].LocalAddr().(*net.UDPAddr).Port)),
		}, socks5.AtypIPv4},
		{"redir_host_snapshot", [2]string{
			net.JoinHostPort("203.0.113.31", strconv.Itoa(targets[0].LocalAddr().(*net.UDPAddr).Port)),
			net.JoinHostPort("203.0.113.32", strconv.Itoa(targets[1].LocalAddr().(*net.UDPAddr).Port)),
		}, socks5.AtypIPv4},
		{"numeric_sources", [2]string{targets[0].LocalAddr().String(), targets[1].LocalAddr().String()}, socks5.AtypIPv4},
	}
	var total int64
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			socket, err := net.DialUDP("udp4", nil, listenAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			var expected int64
			for i := 0; i < 4; i++ {
				target := tc.targets[i%2]
				payload := []byte(tc.name + "-" + strconv.Itoa(i))
				from, atyp := logicalUDPReply(t, socket, target, payload)
				if from != target || atyp != tc.atyp {
					t.Fatalf("multi-target source: got %s/%d want %s/%d", from, atyp, target, tc.atyp)
				}
				expected += int64(len(payload))
			}
			info := (*statistic.TrackerInfo)(nil)
			statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
				if c.Info().Metadata.SrcPort == uint16(socket.LocalAddr().(*net.UDPAddr).Port) {
					info = c.Info()
				}
				return true
			})
			if info == nil || info.UploadTotal.Load() != expected || info.DownloadTotal.Load() != expected {
				t.Fatal("ordinary UDPTracker did not account for every actual payload")
			}
			total += expected
		})
	}
	if backend.received.Load() != 16 {
		t.Fatalf("target datagrams: got %d want 16", backend.received.Load())
	}
	t.Run("unknown_fake_ip_rejected_before_target", func(t *testing.T) {
		socket, err := net.DialUDP("udp4", nil, listenAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer socket.Close()
		badTarget := net.JoinHostPort("198.18.0.200", strconv.Itoa(targets[0].LocalAddr().(*net.UDPAddr).Port))
		wire, err := socks5.EncodeUDPPacket(socks5.ParseAddr(badTarget), []byte("missing-fake-record"))
		if err != nil {
			t.Fatal(err)
		}
		socket.SetDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err = socket.Write(wire); err != nil {
			t.Fatal(err)
		}
		_, err = socket.Read(make([]byte, 1024))
		if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatalf("missing fake record produced a response: %v", err)
		}
		if backend.received.Load() != 16 {
			t.Fatal("unknown fake address reached business target")
		}
	})
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.opened) != 8 {
		t.Fatalf("actual per-association target sockets: got %d want 8", len(backend.opened))
	}
	for i, target := range backend.opened {
		if i < 4 && target != logicalTargets[0] && target != logicalTargets[1] {
			t.Fatalf("restored domain lost before BFP server: %s", target)
		}
		if i >= 4 && i < 6 {
			expected := net.JoinHostPort([]string{"203.0.113.31", "203.0.113.32"}[i-4], strconv.Itoa(targets[i-4].LocalAddr().(*net.UDPAddr).Port))
			if target != expected {
				t.Fatalf("redir-host numeric target changed: got %s want %s", target, expected)
			}
		}
	}
	if total <= 0 {
		t.Fatal("no tracked payloads")
	}
}

func TestBFPLogicalUDPContextSnapshotIsolation(t *testing.T) {
	metadata := &C.Metadata{NetWork: C.UDP, Host: "context.bfp.invalid", DstIP: netip.MustParseAddr("203.0.113.8"), DstPort: 53, DNSMode: C.DNSMapping}
	ctx := C.WithLogicalUDPMetadata(context.Background(), metadata)
	pure := metadata.Pure()
	if pure.Host != "" {
		t.Fatal("ordinary DNSMapping Pure behavior changed")
	}
	metadata.Host = "mutated.invalid"
	first, ok := C.LogicalUDPMetadataFromContext(ctx)
	if !ok || first.Host != "context.bfp.invalid" {
		t.Fatal("setup snapshot did not retain original restored Host")
	}
	first.Host = "second-mutated.invalid"
	second, ok := C.LogicalUDPMetadataFromContext(ctx)
	if !ok || second.Host != "context.bfp.invalid" {
		t.Fatal("retrieval exposed mutable shared snapshot")
	}
	if _, ok := C.LogicalUDPMetadataFromContext(context.Background()); ok {
		t.Fatal("ordinary context has logical metadata")
	}
	metadata.NetWork = C.TCP
	metadata.Host = "tcp-context.bfp.invalid"
	genericCtx := C.WithLogicalDestinationMetadata(context.Background(), metadata)
	metadata.Host = "tcp-mutated.invalid"
	tcpSnapshot, ok := C.LogicalDestinationMetadataFromContext(genericCtx)
	if !ok || tcpSnapshot.Host != "tcp-context.bfp.invalid" || tcpSnapshot.NetWork != C.TCP || tcpSnapshot.Pure().RemoteAddress() != "203.0.113.8:53" {
		t.Fatal("generic TCP snapshot changed the numeric Pure target")
	}
}

func TestBFPLogicalUDPOrdinaryDirectPathStillWorks(t *testing.T) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		buffer := make([]byte, 2048)
		for {
			n, from, err := target.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if _, err = target.WriteToUDP(buffer[:n], from); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		target.Close()
		select {
		case <-workerDone:
		case <-time.After(time.Second):
			t.Error("ordinary target did not join")
		}
	})
	direct := outbound.NewDirectWithOption(outbound.DirectOption{Name: "bfp-logical-ordinary-direct"})
	savedStatus, savedProxies, savedProviders := T.Status(), T.Proxies(), T.Providers()
	T.UpdateProxies(map[string]C.Proxy{direct.Name(): adapter.NewProxy(direct)}, savedProviders)
	T.OnRunning()
	t.Cleanup(func() {
		statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
			for _, name := range c.Info().Chain {
				if name == direct.Name() {
					c.Close()
					break
				}
			}
			return true
		})
		logicalUDPWait(t, "ordinary trackers released", func() bool {
			found := false
			statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
				for _, name := range c.Info().Chain {
					if name == direct.Name() {
						found = true
					}
				}
				return true
			})
			return !found
		})
		T.UpdateProxies(savedProxies, savedProviders)
		switch savedStatus {
		case T.Running:
			T.OnRunning()
		case T.Inner:
			T.OnInnerLoading()
		default:
			T.OnSuspend()
		}
		direct.Close()
	})
	listener, err := socks.NewUDP("127.0.0.1:0", logicalUDPRealTunnel{direct.Name()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	listenAddr, err := net.ResolveUDPAddr("udp4", listener.Address())
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.DialUDP("udp4", nil, listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	payload := []byte("ordinary-direct-remains-numeric")
	from, atyp := logicalUDPReply(t, socket, target.LocalAddr().String(), payload)
	if from != target.LocalAddr().String() || atyp != socks5.AtypIPv4 {
		t.Fatal("ordinary nonlogical UDP source changed")
	}
	info := (*statistic.TrackerInfo)(nil)
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		if c.Info().Metadata.SrcPort == uint16(socket.LocalAddr().(*net.UDPAddr).Port) {
			info = c.Info()
		}
		return true
	})
	if info == nil || info.UploadTotal.Load() != int64(len(payload)) || info.DownloadTotal.Load() != int64(len(payload)) {
		t.Fatal("ordinary tracker accounting changed")
	}
}
