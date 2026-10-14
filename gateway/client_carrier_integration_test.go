package gateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"bfp/session"
)

// Exercise the merged client scope and physical carrier hooks together. The
// configured addresses cannot be directly dialed; only the hooks reach the
// real encrypted local Session. Payloads go through the ordinary gateway's
// numeric TCP/UDP sockets, rather than a fake backend echo.
func TestClientCarrierHooksAndAddressScopeCombinedRuntime(t *testing.T) {
	for _, scene := range []string{"initial_udp", "initial_udp_blocked", "running_udp_blackhole"} {
		t.Run(scene, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			tcpPort, targets, _ := sessionDNSTerminationEcho(t, deadline)
			udpEcho, udpMessages := sessionFakeIPRuntimeUDPEcho(t)
			udpPort := udpEcho.LocalAddr().(*net.UDPAddr).Port
			base, err := New(Policy{AllowPrivate: true, AllowedCIDRs: []string{"127.0.0.0/8"}, AllowedPorts: []int{tcpPort, udpPort}, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			const host = "combined-carrier-scope.test"
			var lookups, tcpDials, udpDials atomic.Int32
			base.lookup = func(ctx context.Context, name string) ([]net.IPAddr, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if name != host {
					return nil, errors.New("combined fixture received an unrestored target")
				}
				lookups.Add(1)
				return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
			}
			actualDial := base.dial
			base.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
				switch network {
				case "tcp":
					if address != net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpPort)) {
						return nil, errors.New("combined TCP target differs from restored echo")
					}
					tcpDials.Add(1)
				case "udp":
					if address != udpEcho.LocalAddr().String() {
						return nil, errors.New("combined UDP target differs from restored echo")
					}
					udpDials.Add(1)
				default:
					return nil, errors.New("unexpected combined target network")
				}
				return actualDial(ctx, network, address)
			}
			opts := session.Options{HandshakeTimeout: 500 * time.Millisecond, ProbeInterval: 100 * time.Millisecond, FailureTimeout: 600 * time.Millisecond, RetainTimeout: 5 * time.Second}
			backendFactory := &sessionDNSRuntimeFactory{base: base}
			server, credentials := sessionDNSTerminationServer(t, ctx, backendFactory, opts)
			proxy := newSessionDNSCloseUDPProxy(t, server.Addr())
			if scene == "initial_udp_blocked" {
				proxy.dropClient.Store(true)
				proxy.dropResponder.Store(true)
			}
			recorder := newClientAddressScopeRecorder(t)
			const configuredUDP = "scope-combination-udp.invalid:9"
			const configuredTCP = "scope-combination-tcp.invalid:9"
			var udpHooks, tcpHooks atomic.Int32
			client, err := session.NewClient(session.ClientConfig{
				Server: configuredUDP, TCPServer: configuredTCP, Credentials: credentials,
				Options: opts, AddressScopeFactory: recorder,
				DialUDP: func(ctx context.Context, network, address string) (net.PacketConn, *net.UDPAddr, error) {
					udpHooks.Add(1)
					if network != "udp" || address != configuredUDP {
						return nil, nil, errors.New("UDP hook received a target rather than configured carrier address")
					}
					if err := ctx.Err(); err != nil {
						return nil, nil, err
					}
					peer, err := net.ResolveUDPAddr("udp4", proxy.front.LocalAddr().String())
					if err != nil {
						return nil, nil, err
					}
					socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
					return socket, peer, err
				},
				DialTCP: func(ctx context.Context, network, address string) (net.Conn, error) {
					tcpHooks.Add(1)
					if network != "tcp" || address != configuredTCP {
						return nil, errors.New("TCP hook received a target rather than configured carrier address")
					}
					return (&net.Dialer{}).DialContext(ctx, "tcp", server.Addr().String())
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { client.Abort() })
			if len(recorder.snapshot()) != 0 || udpHooks.Load() != 0 || tcpHooks.Load() != 0 {
				t.Fatal("Client construction allocated scope or dialed physical carrier")
			}
			owner, err := client.Connect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			allocator, ok := owner.LocalAddressAllocator()
			if !ok || len(recorder.snapshot()) != 1 || allocator != recorder.snapshot()[0] {
				t.Fatal("hook-established Session did not own its exact client map")
			}
			ip, err := allocator.AllocateSessionAddress(host)
			if err != nil {
				t.Fatal(err)
			}
			address := net.JoinHostPort(ip.String(), strconv.Itoa(tcpPort))
			flow := sessionDNSRuntimeExchange(t, ctx, client, address, []byte("combined scope and hooks before recovery"))
			initial := owner.Stats()
			expectedCarrier := "udp"
			if scene == "initial_udp_blocked" {
				expectedCarrier = "tcp"
			}
			if initial.Carrier != expectedCarrier || udpHooks.Load() != 1 || (tcpHooks.Load() == 0) != (expectedCarrier == "udp") || targets.Load() != 1 || tcpDials.Load() != 1 {
				t.Fatalf("unexpected initial carrier/target: stats=%+v udp_hooks=%d tcp_hooks=%d targets=%d tcp_dials=%d", initial, udpHooks.Load(), tcpHooks.Load(), targets.Load(), tcpDials.Load())
			}
			if scene == "running_udp_blackhole" {
				proxy.dropClient.Store(true)
				proxy.dropResponder.Store(true)
				flow.SetDeadline(time.Now().Add(8 * time.Second))
				payload := bytes.Repeat([]byte("merged scope and physical carrier recovery;"), 2048)
				written := make(chan error, 1)
				go func() { _, err := io.Copy(flow, bytes.NewReader(payload)); written <- err }()
				response := make([]byte, len(payload))
				if _, err := io.ReadFull(flow, response); err != nil {
					t.Fatalf("combined recovery exceeded original 8s business deadline: %v stats=%+v", err, owner.Stats())
				}
				if err := <-written; err != nil || !bytes.Equal(response, payload) {
					t.Fatalf("combined recovery bytes differ: %v", err)
				}
				final := owner.Stats()
				after, ok := owner.LocalAddressAllocator()
				if !ok || after != allocator || final.ID != initial.ID || final.Generation <= initial.Generation || final.Carrier != "tcp" || final.Switches < 1 || tcpHooks.Load() < 1 || udpHooks.Load() != 1 || tcpDials.Load() != 1 || targets.Load() != 1 || len(recorder.snapshot()) != 1 || len(backendFactory.snapshot()) != 1 {
					t.Fatalf("combined recovery changed map/Session/TCP target: initial=%+v final=%+v hooks=%d/%d dials=%d scopes=%d", initial, final, udpHooks.Load(), tcpHooks.Load(), tcpDials.Load(), len(recorder.snapshot()))
				}
			}
			// Open a distinct Datagram flow after the carrier choice/recovery. The
			// application datagram must use the same selected Session's map, even
			// when its physical Carrier is now TCP.
			udp, err := client.DialContext(ctx, "udp", net.JoinHostPort(ip.String(), strconv.Itoa(udpPort)))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { udp.Close() })
			udp.SetDeadline(deadline)
			payload := []byte("later UDP business on the same restored scope")
			if n, err := udp.Write(payload); err != nil || n != len(payload) {
				t.Fatalf("later datagram write n=%d err=%v", n, err)
			}
			response := make([]byte, 4096)
			n, err := udp.Read(response)
			if err != nil || !bytes.Equal(response[:n], payload) {
				t.Fatalf("later UDP echo n=%d err=%v", n, err)
			}
			if udpMessages.Load() != 1 || udpDials.Load() != 1 || tcpDials.Load() != 1 || targets.Load() != 1 || lookups.Load() != 1 || len(recorder.snapshot()) != 1 {
				t.Fatal("later UDP recreated scope, TCP target or cached DNS answer")
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			requireFakeIPCleared(t, recorder.snapshot()[0], ip)
			if retained, ok := owner.LocalAddressAllocator(); ok || retained != nil {
				t.Fatal("closed combined owner republished allocator")
			}
			// Automatic fresh Connect must also use the hooks, but its scope is
			// empty. The old numeric address cannot be restored or create OPEN.
			if conn, err := client.DialContext(ctx, "tcp", address); conn != nil || !errors.Is(err, ErrFakeIPUnmapped) {
				if conn != nil {
					conn.Close()
				}
				t.Fatalf("new hook-created Session inherited an old mapping: %v", err)
			}
			fresh := client.Session()
			if fresh == nil || fresh == owner || fresh.Stats().ID == initial.ID || fresh.Stats().Opened != 0 || len(recorder.snapshot()) != 2 || udpHooks.Load() != 2 || tcpDials.Load() != 1 || udpDials.Load() != 1 || targets.Load() != 1 || udpMessages.Load() != 1 {
				t.Fatal("fresh Session/stale-address rejection created flow or target work")
			}
			freshAllocator, ok := fresh.LocalAddressAllocator()
			if !ok {
				t.Fatal("fresh hook-created Session has no local allocator")
			}
			freshIP, err := freshAllocator.AllocateSessionAddress("next-combined-owner.test")
			if err != nil || freshIP == ip {
				t.Fatalf("fresh map reused old address: %s old=%s err=%v", freshIP, ip, err)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			requireFakeIPCleared(t, recorder.snapshot()[1], freshIP)
		})
	}
}
