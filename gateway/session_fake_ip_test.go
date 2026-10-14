package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bfp/protocol"
	"bfp/session"
)

func fakeIPScopeState(scope *FakeIPScope) (hosts, ips int, closed bool) {
	scope.mu.Lock()
	defer scope.mu.Unlock()
	return len(scope.byHost), len(scope.byIP), scope.closed
}

func requireFakeIPCleared(t *testing.T, scope *FakeIPScope, ip netip.Addr) {
	t.Helper()
	if hosts, ips, closed := fakeIPScopeState(scope); hosts != 0 || ips != 0 || !closed {
		t.Fatalf("fake-IP scope retained state: hosts=%d ips=%d closed=%t", hosts, ips, closed)
	}
	if _, err := scope.Resolve(ip); !errors.Is(err, ErrFakeIPScopeClosed) {
		t.Fatalf("terminated reverse lookup error=%v", err)
	}
	if _, err := scope.Allocate("after-termination.test"); !errors.Is(err, ErrFakeIPScopeClosed) {
		t.Fatalf("terminated allocation error=%v", err)
	}
	fakeIPLeases.Lock()
	owner := fakeIPLeases.owners[ip]
	fakeIPLeases.Unlock()
	if owner == scope {
		t.Fatal("terminated mapping still owns a global address lease")
	}
}

func TestSessionFakeIPScopeOwnedPrivateAndStopSynchronous(t *testing.T) {
	factory, err := New(Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if factory.FakeIPScope() != nil {
		t.Fatal("unconfirmed factory allocated a fake-IP scope")
	}
	first, stopFirst := scopedDNS(t, factory, context.Background(), nil)
	defer stopFirst()
	second, stopSecond := scopedDNS(t, factory, context.Background(), nil)
	defer stopSecond()
	if first.FakeIPScope() == nil || second.FakeIPScope() == nil || first.FakeIPScope() == second.FakeIPScope() {
		t.Fatal("confirmed scopes did not own independent fake-IP maps")
	}
	ip, err := first.AllocateSessionAddress("private-scope.test")
	if err != nil {
		t.Fatal(err)
	}
	other, err := second.AllocateSessionAddress("private-scope.test")
	if err != nil || other == ip {
		t.Fatalf("parallel scope allocation reused address: %v ip=%s other=%s", err, ip, other)
	}
	if _, err := second.ResolveSessionAddress(ip); !errors.Is(err, ErrFakeIPUnmapped) {
		t.Fatalf("foreign mapping resolved: %v", err)
	}
	stopFirst()
	requireFakeIPCleared(t, first.FakeIPScope(), ip)
	if host, err := second.ResolveSessionAddress(other); err != nil || host != "private-scope.test" {
		t.Fatalf("first stop damaged the other live scope: host=%q err=%v", host, err)
	}
	if _, err := first.DialContext(context.Background(), "tcp", net.JoinHostPort(ip.String(), "443")); !errors.Is(err, ErrSessionBackendClosed) {
		t.Fatalf("retired backend dial error=%v", err)
	}
}

func TestSessionFakeIPRestoresBeforeDNSAndNumericDial(t *testing.T) {
	factory, err := New(Policy{})
	if err != nil {
		t.Fatal(err)
	}
	var lookups, dials atomic.Int32
	factory.lookup = func(_ context.Context, host string) ([]net.IPAddr, error) {
		lookups.Add(1)
		if host != "mapped.test" {
			return nil, errors.New("unexpected restored DNS hostname")
		}
		return publicAnswers(), nil
	}
	factory.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if network != "tcp4" || address != "8.8.8.8:443" {
			t.Fatalf("OS hook got unrecovered target: network=%s address=%s", network, address)
		}
		return nil, nil
	}
	dialer, stop := scopedDNS(t, factory, context.Background(), nil)
	defer stop()
	ip, err := dialer.AllocateSessionAddress("Mapped.TEST.")
	if err != nil {
		t.Fatal(err)
	}
	delivery := protocol.DefaultDelivery("tcp")
	fec := protocol.DisabledFECProfile()
	meta := protocol.Target{Network: "tcp4", Address: net.JoinHostPort(ip.String(), "443"), Class: protocol.Bulk, Domain: "metadata.test", RuleTag: "existing-tag", Delivery: &delivery, FEC: &fec}
	restored, err := dialer.RestoreTarget(meta)
	if err != nil || restored.Address != "mapped.test:443" || restored.Network != meta.Network || restored.Class != meta.Class || restored.Domain != meta.Domain || restored.RuleTag != meta.RuleTag || restored.Delivery == nil || *restored.Delivery != delivery || restored.FEC == nil || *restored.FEC != fec {
		t.Fatalf("restored target lost non-address fields: %+v err=%v", restored, err)
	}
	// Exercise a non-default enabled datagram profile as well: a helper that
	// accidentally drops optional fields must not make explicit OPEN semantics
	// fall back to the disabled/default contracts after reverse mapping.
	datagramDelivery := protocol.DefaultDelivery("udp")
	parity := protocol.FECProfile{Version: protocol.FECWireVersion, Algorithm: protocol.FECXOR1, MaxDataShards: 4, ParityShards: 1, ShardSize: 256, MaxBlockSize: 1024}
	if err := parity.Validate(); err != nil {
		t.Fatal(err)
	}
	udpTarget := meta
	udpTarget.Network = "udp"
	udpTarget.Delivery, udpTarget.FEC = &datagramDelivery, &parity
	udpRestored, err := dialer.RestoreTarget(udpTarget)
	if err != nil || udpRestored.Address != "mapped.test:443" || udpRestored.Network != "udp" || udpRestored.Class != meta.Class || udpRestored.Domain != meta.Domain || udpRestored.RuleTag != meta.RuleTag || udpRestored.Delivery == nil || *udpRestored.Delivery != datagramDelivery || udpRestored.FEC == nil || *udpRestored.FEC != parity {
		t.Fatalf("restored datagram target lost immutable delivery/FEC: %+v err=%v", udpRestored, err)
	}
	if _, err := dialer.DialContext(context.Background(), "tcp4", net.JoinHostPort(ip.String(), "443")); err != nil {
		t.Fatal(err)
	}
	if lookups.Load() != 1 || dials.Load() != 1 {
		t.Fatalf("unexpected restored execution: lookups=%d dials=%d", lookups.Load(), dials.Load())
	}
	if _, err := dialer.DialContext(context.Background(), "udp", "198.19.255.254:443"); !errors.Is(err, ErrFakeIPUnmapped) {
		t.Fatalf("unmapped numeric fake-IP reached backend: %v", err)
	}
	if lookups.Load() != 1 || dials.Load() != 1 {
		t.Fatal("unmapped address caused DNS or socket work")
	}
}

func TestSessionFakeIPGuardClosesBeforeAsyncCallback(t *testing.T) {
	for _, reason := range []string{"parent-cancel", "guard-revoked", "guard-expired"} {
		t.Run(reason, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			var invalid atomic.Bool
			scope, err := newFakeIPScopeWithGuard(parent, time.Minute, 64, func() error {
				if invalid.Load() {
					return session.ErrClosed
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer scope.Close()
			ip, err := scope.Allocate("guarded.test")
			if err != nil {
				t.Fatal(err)
			}
			if reason == "parent-cancel" {
				cancel()
			} else {
				invalid.Store(true)
			}
			// No sleep/poll: the mapping API itself must observe the published
			// eligibility decision and clear the map before returning.
			if _, err := scope.Resolve(ip); !errors.Is(err, ErrFakeIPScopeClosed) {
				t.Fatalf("ineligible scope reverse lookup=%v", err)
			}
			requireFakeIPCleared(t, scope, ip)
		})
	}
}

func TestSessionFakeIPPolicyRejectsInvalidProfilesBeforeAllocation(t *testing.T) {
	for _, policy := range []Policy{
		{FakeIPLifetime: -time.Second},
		{FakeIPLifetime: maxFakeIPLifetime + time.Second},
		{FakeIPCapacity: 32},
		{FakeIPCapacity: 129},
	} {
		if _, err := New(policy); err == nil {
			t.Fatalf("invalid profile accepted: %+v", policy)
		}
	}
}

// This is actual encrypted UDP -> scoped gateway -> ordinary numeric TCP
// business. The fixture's local control API allocates the mapping; it does not
// claim DNS interception, TUN, or wire allocation negotiation exists.
func TestSessionFakeIPRuntimeRestorationAndTerminalCleanup(t *testing.T) {
	for _, reason := range []string{"close", "revocation", "expiry", "serve-cancel"} {
		t.Run(reason, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			serveCtx, cancelServe := context.WithCancel(ctx)
			defer cancelServe()
			deadline, _ := ctx.Deadline()
			port, targets, targetClosed := sessionDNSTerminationEcho(t, deadline)
			base, err := New(Policy{AllowPrivate: true, AllowedCIDRs: []string{"127.0.0.0/8"}, AllowedPorts: []int{port}, MaxConcurrent: 1, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			const host = "scoped-runtime.test"
			var lookups atomic.Int32
			base.lookup = func(ctx context.Context, name string) ([]net.IPAddr, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if name != host {
					return nil, errors.New("unexpected mapped runtime hostname")
				}
				lookups.Add(1)
				return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
			}
			factory := &sessionDNSRuntimeFactory{base: base}
			options := session.Options{}
			if reason == "expiry" {
				options.MaxSessionLifetime = 250 * time.Millisecond
			}
			server, credentials := sessionDNSTerminationServer(t, serveCtx, factory, options)
			client, connected := sessionDNSTerminationClient(t, ctx, server, credentials)
			scopes := factory.snapshot()
			if len(scopes) != 1 || scopes[0].dialer.FakeIPScope() == nil || base.FakeIPScope() != nil {
				t.Fatal("real fresh confirmation failed to install one private address scope")
			}
			scope := scopes[0]
			ip, err := scope.dialer.AllocateSessionAddress(host)
			if err != nil {
				t.Fatal(err)
			}
			flow := sessionDNSRuntimeExchange(t, ctx, client, net.JoinHostPort(ip.String(), strconv.Itoa(port)), []byte("encrypted fake-IP target restored by its confirmed Session backend"))
			if connected.Stats().Carrier != "udp" || targets.Load() != 1 || lookups.Load() != 1 || factory.unscopedDials.Load() != 0 {
				t.Fatal("runtime mapping did not reach a single ordinary numeric socket")
			}
			switch reason {
			case "close":
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
			case "revocation":
				if err := server.RevokeDevice(credentials.Public); err != nil {
					t.Fatal(err)
				}
			case "serve-cancel":
				cancelServe()
			case "expiry":
				// Observe immutable expiration without forcing the guard API.
			}
			sessionDNSTerminationWait(t, ctx, scope, targetClosed)
			requireFakeIPCleared(t, scope.dialer.FakeIPScope(), ip)
			if targets.Load() != 1 || lookups.Load() != 1 || len(factory.snapshot()) != 1 {
				t.Fatal("terminal cleanup recreated a scope, DNS answer, or socket")
			}
			flow.Close()
		})
	}
}

type sessionFakeIPObservedConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *sessionFakeIPObservedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func sessionFakeIPRuntimeUDPEcho(t *testing.T, hosts ...string) (*net.UDPConn, *atomic.Int32) {
	t.Helper()
	ip, network := net.IPv4(127, 0, 0, 1), "udp4"
	if len(hosts) != 0 {
		ip = net.ParseIP(hosts[0])
		if ip.To4() == nil {
			network = "udp6"
		}
	}
	listener, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	messages := &atomic.Int32{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			n, peer, err := listener.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			messages.Add(1)
			if _, err := listener.WriteToUDP(buffer[:n], peer); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("owned fake-IP UDP echo did not stop within 1s")
		}
	})
	return listener, messages
}

func TestSessionFakeIPRuntimeUDPDatagramAndTerminalCleanup(t *testing.T) {
	for _, reason := range []string{"close", "revocation"} {
		t.Run(reason, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			echo, messages := sessionFakeIPRuntimeUDPEcho(t)
			port := echo.LocalAddr().(*net.UDPAddr).Port
			base, err := New(Policy{AllowPrivate: true, AllowedCIDRs: []string{"127.0.0.0/8"}, AllowedPorts: []int{port}, MaxConcurrent: 1, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			const host = "datagram-scoped-runtime.test"
			var lookups, dials atomic.Int32
			base.lookup = func(ctx context.Context, name string) ([]net.IPAddr, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if name != host {
					return nil, errors.New("unexpected datagram mapping name")
				}
				lookups.Add(1)
				return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
			}
			actualDial := base.dial
			targetClosed := make(chan struct{})
			base.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
				dials.Add(1)
				if network != "udp" || address != echo.LocalAddr().String() {
					return nil, errors.New("UDP gateway did not choose its restored numeric peer")
				}
				conn, err := actualDial(ctx, network, address)
				if err != nil {
					return conn, err
				}
				return &sessionFakeIPObservedConn{Conn: conn, closed: targetClosed}, nil
			}
			factory := &sessionDNSRuntimeFactory{base: base}
			server, credentials := sessionDNSTerminationServer(t, ctx, factory, session.Options{})
			client, connected := sessionDNSTerminationClient(t, ctx, server, credentials)
			scopes := factory.snapshot()
			if len(scopes) != 1 || scopes[0].dialer.FakeIPScope() == nil {
				t.Fatal("fresh UDP Session did not allocate its backend map")
			}
			scope := scopes[0]
			ip, err := scope.dialer.AllocateSessionAddress(host)
			if err != nil {
				t.Fatal(err)
			}
			flow, err := client.DialContext(ctx, "udp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { flow.Close() })
			deadline, _ := ctx.Deadline()
			flow.SetDeadline(deadline)
			payload := []byte("one application datagram over actual encrypted Session")
			if n, err := flow.Write(payload); err != nil || n != len(payload) {
				t.Fatalf("DATAGRAM write n=%d err=%v", n, err)
			}
			response := make([]byte, 4096)
			n, err := flow.Read(response)
			if err != nil || !bytes.Equal(response[:n], payload) {
				t.Fatalf("DATAGRAM echo n=%d err=%v", n, err)
			}
			if connected.Stats().Carrier != "udp" || messages.Load() != 1 || dials.Load() != 1 || lookups.Load() != 1 {
				t.Fatal("datagram did not use exactly one scoped lookup and actual UDP socket")
			}
			if reason == "close" {
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err := server.RevokeDevice(credentials.Public); err != nil {
				t.Fatal(err)
			}
			sessionDNSTerminationWait(t, ctx, scope, targetClosed)
			requireFakeIPCleared(t, scope.dialer.FakeIPScope(), ip)
			if conn, err := scope.dialer.DialContext(ctx, "udp", net.JoinHostPort(ip.String(), strconv.Itoa(port))); conn != nil || !errors.Is(err, ErrSessionBackendClosed) {
				if conn != nil {
					conn.Close()
				}
				t.Fatalf("terminal scope accepted a new UDP target: %v", err)
			}
			if messages.Load() != 1 || lookups.Load() != 1 || dials.Load() != 1 || len(factory.snapshot()) != 1 {
				t.Fatal("terminal UDP scope performed new network work")
			}
		})
	}
}

func TestSessionFakeIPRuntimeUDPToTCPRecoveryRetainsRealScopeAndSocket(t *testing.T) {
	// This is a separately named active recovery scene with the same options
	// as the established integration fixture. Its transfer has an explicit 8s
	// deadline; it does not alter the existing WAN or default-watchdog gates.
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	port, targets, targetClosed := sessionDNSTerminationEcho(t, deadline)
	base, err := New(Policy{AllowPrivate: true, AllowedCIDRs: []string{"127.0.0.0/8"}, AllowedPorts: []int{port}, MaxConcurrent: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	const host = "recovery-scoped-runtime.test"
	var lookups atomic.Int32
	base.lookup = func(ctx context.Context, name string) ([]net.IPAddr, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if name != host {
			return nil, errors.New("unexpected recovery mapping name")
		}
		lookups.Add(1)
		return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
	}
	factory := &sessionDNSRuntimeFactory{base: base}
	options := session.Options{HandshakeTimeout: 500 * time.Millisecond, ProbeInterval: 100 * time.Millisecond, FailureTimeout: 600 * time.Millisecond, RetainTimeout: 5 * time.Second}
	server, credentials := sessionDNSTerminationServer(t, ctx, factory, options)
	proxy := newSessionDNSCloseUDPProxy(t, server.Addr())
	client, err := session.NewClient(session.ClientConfig{Server: proxy.front.LocalAddr().String(), TCPServer: server.Addr().String(), Credentials: credentials, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Abort() })
	connected, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	scopes := factory.snapshot()
	if len(scopes) != 1 || scopes[0].dialer.FakeIPScope() == nil {
		t.Fatal("fresh recovery Session did not create its owned map")
	}
	scope := scopes[0]
	mapOwner := scope.dialer.FakeIPScope()
	ip, err := scope.dialer.AllocateSessionAddress(host)
	if err != nil {
		t.Fatal(err)
	}
	flow := sessionDNSRuntimeExchange(t, ctx, client, net.JoinHostPort(ip.String(), strconv.Itoa(port)), []byte("same mapped TCP socket before carrier failure"))
	initial := connected.Stats()
	if initial.Carrier != "udp" || targets.Load() != 1 || lookups.Load() != 1 {
		t.Fatal("recovery did not start from actual UDP business")
	}
	proxy.dropClient.Store(true)
	proxy.dropResponder.Store(true)
	if err := flow.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("temporary mapping belongs to Session, carrier replacement keeps target;"), 2048)
	written := make(chan error, 1)
	go func() {
		_, err := io.Copy(flow, bytes.NewReader(payload))
		written <- err
	}()
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(flow, response); err != nil {
		t.Fatalf("mapped flow did not recover within original 8s: %v stats=%+v", err, connected.Stats())
	}
	if err := <-written; err != nil || !bytes.Equal(response, payload) {
		t.Fatalf("recovered TCP bytes differed or write failed: %v", err)
	}
	final := connected.Stats()
	if final.Carrier != "tcp" || final.ID != initial.ID || final.Generation <= initial.Generation || final.Switches < 1 || final.ClientAddress != initial.ClientAddress || final.ServerAddress != initial.ServerAddress {
		t.Fatalf("carrier replacement changed Session identity: initial=%+v final=%+v", initial, final)
	}
	if len(factory.snapshot()) != 1 || scope.stops.Load() != 0 || scope.dialer.FakeIPScope() != mapOwner || targets.Load() != 1 || lookups.Load() != 1 {
		t.Fatal("actual recovery recreated backend scope, mapping, DNS answer, or target socket")
	}
	if hosts, ips, closed := fakeIPScopeState(mapOwner); hosts != 1 || ips != 1 || closed {
		t.Fatalf("actual recovery damaged live mapping: hosts=%d ips=%d closed=%t", hosts, ips, closed)
	}
	if host, err := scope.dialer.ResolveSessionAddress(ip); err != nil || host != "recovery-scoped-runtime.test" {
		t.Fatalf("actual recovery lost original mapping: host=%q err=%v", host, err)
	}
	if entries, closed, _ := dnsState(scope.dialer); entries != 1 || closed {
		t.Fatal("actual recovery lost original positive DNS cache")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	sessionDNSTerminationWait(t, ctx, scope, targetClosed)
	requireFakeIPCleared(t, mapOwner, ip)
	if lookups.Load() != 1 || targets.Load() != 1 || len(factory.snapshot()) != 1 {
		t.Fatal("post-recovery cleanup created more network state")
	}
}

func TestSessionFakeIPRuntimeConcurrentAPIsDuringShutdown(t *testing.T) {
	for _, reason := range []string{"close", "revocation"} {
		t.Run(reason, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			base, err := New(Policy{})
			if err != nil {
				t.Fatal(err)
			}
			// This scene performs no lookup or target dial. It exercises local
			// mapping APIs on the actual confirmed Session's owned backend while
			// authenticated close or administrative revocation cleans it.
			factory := &sessionDNSRuntimeFactory{base: base}
			server, credentials := sessionDNSTerminationServer(t, ctx, factory, session.Options{})
			client, _ := sessionDNSTerminationClient(t, ctx, server, credentials)
			scopes := factory.snapshot()
			if len(scopes) != 1 || scopes[0].dialer.FakeIPScope() == nil {
				t.Fatal("confirmed Session did not expose one owned fake-IP map")
			}
			dialer := scopes[0].dialer
			scope := dialer.FakeIPScope()
			anchor, err := dialer.AllocateSessionAddress("shutdown-anchor.test")
			if err != nil {
				t.Fatal(err)
			}
			const workers = 16
			const afterShutdownTurns = 32
			ready := make(chan struct{}, workers)
			failures := make(chan error, workers)
			stopWorkers := make(chan struct{})
			var stopOnce sync.Once
			var shutdownReturned atomic.Bool
			var postShutdownCalls atomic.Int32
			var wg sync.WaitGroup
			stop := func() { stopOnce.Do(func() { close(stopWorkers) }) }
			t.Cleanup(func() { stop(); wg.Wait() })
			for i := 0; i < workers; i++ {
				wg.Add(1)
				go func(worker int) {
					defer wg.Done()
					host := "shutdown-worker-" + strconv.Itoa(worker) + ".test"
					announced := false
					postTurns := 0
					check := func(startedAfter bool, method string, err error) bool {
						if startedAfter {
							postShutdownCalls.Add(1)
							if !errors.Is(err, ErrFakeIPScopeClosed) {
								failures <- fmt.Errorf("worker %d: %s started after shutdown returned err=%v", worker, method, err)
								return false
							}
						} else if err != nil && !errors.Is(err, ErrFakeIPScopeClosed) {
							failures <- fmt.Errorf("worker %d: concurrent %s returned unexpected err=%v", worker, method, err)
							return false
						}
						return true
					}
					for {
						select {
						case <-stopWorkers:
							return
						default:
						}
						startedAfter := shutdownReturned.Load()
						_, allocateErr := dialer.AllocateSessionAddress(host)
						if !check(startedAfter, "Allocate", allocateErr) {
							return
						}
						startedAfter = shutdownReturned.Load()
						_, resolveErr := dialer.ResolveSessionAddress(anchor)
						if !check(startedAfter, "Resolve", resolveErr) {
							return
						}
						startedAfter = shutdownReturned.Load()
						_, restoreErr := dialer.RestoreTarget(protocol.Target{Network: "udp", Address: net.JoinHostPort(anchor.String(), "443")})
						if !check(startedAfter, "RestoreTarget", restoreErr) {
							return
						}
						if !announced {
							if allocateErr != nil || resolveErr != nil || restoreErr != nil {
								failures <- fmt.Errorf("worker %d: did not complete live mapping operations before shutdown", worker)
								return
							}
							announced = true
							ready <- struct{}{}
						}
						if shutdownReturned.Load() {
							postTurns++
							if postTurns == afterShutdownTurns {
								return
							}
						}
					}
				}(i)
			}
			for i := 0; i < workers; i++ {
				select {
				case <-ready:
				case err := <-failures:
					t.Fatal(err)
				case <-ctx.Done():
					t.Fatal("concurrent workers failed to establish live API activity")
				}
			}
			if reason == "close" {
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err := server.RevokeDevice(credentials.Public); err != nil {
				t.Fatal(err)
			}
			shutdownReturned.Store(true)
			// Workers are deliberately still running. Observe the state as soon
			// as shutdown returns; no post-return wait may provide the cleanup.
			requireFakeIPCleared(t, scope, anchor)
			fakeIPLeases.Lock()
			ownedLeases := 0
			for _, owner := range fakeIPLeases.owners {
				if owner == scope {
					ownedLeases++
				}
			}
			fakeIPLeases.Unlock()
			if ownedLeases != 0 {
				t.Fatalf("shutdown returned with %d retained scope-owned leases", ownedLeases)
			}
			joined := make(chan struct{})
			go func() { wg.Wait(); close(joined) }()
			select {
			case <-joined:
			case <-ctx.Done():
				t.Fatal("post-shutdown mapping API workers did not finish")
			}
			select {
			case err := <-failures:
				t.Fatal(err)
			default:
			}
			if postShutdownCalls.Load() < workers*(afterShutdownTurns-1)*3 {
				t.Fatalf("insufficient after-return API checks: %d", postShutdownCalls.Load())
			}
			requireFakeIPCleared(t, scope, anchor)
			if len(factory.snapshot()) != 1 || scopes[0].stops.Load() != 1 {
				t.Fatal("shutdown recreated the scope or repeated backend cleanup")
			}
		})
	}
}
