package gateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bfp/session"
)

type clientAddressScopeRecorder struct {
	base   *FakeIPScopeFactory
	mu     sync.Mutex
	scopes []*FakeIPScope
}

// Public aliases are used here to exercise the externally usable contract.
func (f *clientAddressScopeRecorder) ForClientSession(ctx context.Context, valid func() error) (session.ClientAddressScope, error) {
	scope, err := f.base.ForClientSession(ctx, valid)
	if err != nil {
		return scope, err
	}
	f.mu.Lock()
	f.scopes = append(f.scopes, scope.(*FakeIPScope))
	f.mu.Unlock()
	return scope, nil
}

func (f *clientAddressScopeRecorder) snapshot() []*FakeIPScope {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*FakeIPScope(nil), f.scopes...)
}

func newClientAddressScopeRecorder(t *testing.T) *clientAddressScopeRecorder {
	t.Helper()
	factory, err := NewFakeIPScopeFactory(time.Minute, 64)
	if err != nil {
		t.Fatal(err)
	}
	return &clientAddressScopeRecorder{base: factory}
}

func newClientAddressScoped(t *testing.T, ctx context.Context, server *session.Server, credentials session.Credentials, opts session.Options, recorder *clientAddressScopeRecorder, udpAddress string) (*session.Client, *session.Session, session.ClientAddressAllocator) {
	t.Helper()
	if udpAddress == "" {
		udpAddress = server.Addr().String()
	}
	client, err := session.NewClient(session.ClientConfig{Server: udpAddress, TCPServer: server.Addr().String(), Credentials: credentials, Options: opts, AddressScopeFactory: recorder})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Abort() })
	if len(recorder.snapshot()) != 0 {
		t.Fatal("unconfirmed client allocated a local map")
	}
	connected, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	allocator, ok := connected.LocalAddressAllocator()
	if !ok || len(recorder.snapshot()) != 1 || allocator != recorder.snapshot()[0] {
		t.Fatal("confirmed client did not publish its exact local allocator")
	}
	return client, connected, allocator
}

func TestClientAddressScopeRealTCPUDPAndTerminalCleanup(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, reason := range []string{"close", "abort", "revocation", "expiry"} {
			t.Run(network+"/"+reason, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				deadline, _ := ctx.Deadline()
				var port int
				var requests *atomic.Int32
				if network == "tcp" {
					port, requests = sessionDNSRuntimeEcho(t, deadline)
				} else {
					echo, messages := sessionFakeIPRuntimeUDPEcho(t)
					port, requests = echo.LocalAddr().(*net.UDPAddr).Port, messages
				}
				base, err := New(Policy{AllowPrivate: true, AllowedCIDRs: []string{"127.0.0.0/8"}, AllowedPorts: []int{port}, Timeout: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				const host = "client-owner.test"
				var lookups, dials atomic.Int32
				base.lookup = func(ctx context.Context, name string) ([]net.IPAddr, error) {
					if ctx.Err() != nil || name != host {
						return nil, errors.New("unexpected client-restored domain")
					}
					lookups.Add(1)
					return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
				}
				actualDial := base.dial
				base.dial = func(ctx context.Context, netw, address string) (net.Conn, error) {
					dials.Add(1)
					return actualDial(ctx, netw, address)
				}
				opts := session.Options{}
				if reason == "revocation" {
					opts.HandshakeTimeout = 150 * time.Millisecond
					opts.RetainTimeout = 300 * time.Millisecond
				}
				if reason == "expiry" {
					opts.MaxSessionLifetime = 900 * time.Millisecond
				}
				server, credentials := sessionDNSTerminationServer(t, ctx, &sessionDNSRuntimeFactory{base: base}, opts)
				recorder := newClientAddressScopeRecorder(t)
				udpAddress := ""
				if reason == "revocation" {
					// Revocation currently aborts the peer without sending a close
					// control. Establish a real TCP carrier so its closed socket is
					// observable; the client map ends at the existing retention bound.
					proxy := newSessionDNSCloseUDPProxy(t, server.Addr())
					proxy.dropClient.Store(true)
					proxy.dropResponder.Store(true)
					udpAddress = proxy.front.LocalAddr().String()
				}
				client, connected, allocator := newClientAddressScoped(t, ctx, server, credentials, opts, recorder, udpAddress)
				ip, err := allocator.AllocateSessionAddress(host)
				if err != nil {
					t.Fatal(err)
				}
				flow, err := client.DialContext(ctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { flow.Close() })
				flow.SetDeadline(deadline)
				payload := []byte("client scope restores hostname before encrypted OPEN")
				if n, err := flow.Write(payload); err != nil || n != len(payload) {
					t.Fatalf("write n=%d err=%v", n, err)
				}
				response := make([]byte, len(payload))
				if _, err := io.ReadFull(flow, response); err != nil || !bytes.Equal(response, payload) {
					t.Fatalf("actual %s echo failed: %v", network, err)
				}
				if requests.Load() != 1 || dials.Load() != 1 || lookups.Load() != 1 {
					t.Fatal("scope did not restore before the single real target dial")
				}
				switch reason {
				case "close":
					if err := client.Close(); err != nil {
						t.Fatal(err)
					}
				case "abort":
					client.Abort()
				case "revocation":
					if err := server.RevokeDevice(credentials.Public); err != nil {
						t.Fatal(err)
					}
				}
				// Remote revocation is observed through the TCP carrier's socket
				// closure and bounded retention. It is not instantaneous knowledge.
				until := time.Now().Add(2 * time.Second)
				for {
					if _, err := allocator.ResolveSessionAddress(ip); errors.Is(err, ErrFakeIPScopeClosed) {
						break
					}
					if time.Now().After(until) {
						t.Fatal("client allocator stayed live after terminal event")
					}
					time.Sleep(time.Millisecond)
				}
				requireFakeIPCleared(t, recorder.snapshot()[0], ip)
				if retained, ok := connected.LocalAddressAllocator(); ok || retained != nil {
					t.Fatal("terminating Session republished its allocator")
				}
				if flow, err := connected.DialContext(ctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(port))); flow != nil || !errors.Is(err, session.ErrClosed) {
					if flow != nil {
						flow.Close()
					}
					t.Fatalf("retired Session created OPEN: %v", err)
				}
				if lookups.Load() != 1 || dials.Load() != 1 || len(recorder.snapshot()) != 1 {
					t.Fatal("retired client scope caused new network work")
				}
			})
		}
	}
}

func TestClientAddressScopeNewSessionRejectsOldAddressWithoutOPEN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	base, err := New(Policy{})
	if err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int32
	base.dial = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("test: no target work authorized")
	}
	server, credentials := sessionDNSTerminationServer(t, ctx, &sessionDNSRuntimeFactory{base: base}, session.Options{})
	recorder := newClientAddressScopeRecorder(t)
	client, first, allocator := newClientAddressScoped(t, ctx, server, credentials, session.Options{}, recorder, "")
	ip, err := allocator.AllocateSessionAddress("old-owner.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	// Client automatically selects its new Session for this exact Dial. The
	// old map cannot be consulted before Connect and forwarded into the new one.
	if conn, err := client.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), "443")); conn != nil || !errors.Is(err, ErrFakeIPUnmapped) {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("old mapping inherited by automatic new Session: %v", err)
	}
	second := client.Session()
	if second == nil || second == first || second.Stats().ID == first.Stats().ID || second.Stats().Opened != 0 || len(recorder.snapshot()) != 2 {
		t.Fatal("new Session identity/scope or zero-OPEN failure boundary is wrong")
	}
	nextAllocator, ok := second.LocalAddressAllocator()
	if !ok {
		t.Fatal("new Session has no allocator")
	}
	nextIP, err := nextAllocator.AllocateSessionAddress("new-owner.test")
	if err != nil || nextIP == ip {
		t.Fatalf("new allocation reused retired address: ip=%s old=%s err=%v", nextIP, ip, err)
	}
	if conn, err := client.DialContext(ctx, "udp", net.JoinHostPort(ip.String(), "443")); conn != nil || !errors.Is(err, ErrFakeIPUnmapped) {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("retired address aliased a new hostname: %v", err)
	}
	if second.Stats().Opened != 0 || dials.Load() != 0 {
		t.Fatal("unmapped client target created flow or socket work")
	}
	requireFakeIPCleared(t, recorder.snapshot()[0], ip)
}

func TestClientAddressScopeUDPToTCPRetainsMapAndRealSocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	port, targets, _ := sessionDNSTerminationEcho(t, deadline)
	base, err := New(Policy{AllowPrivate: true, AllowedCIDRs: []string{"127.0.0.0/8"}, AllowedPorts: []int{port}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	const host = "client-recovery.test"
	base.lookup = func(_ context.Context, name string) ([]net.IPAddr, error) {
		if name != host {
			return nil, errors.New("unexpected client recovery hostname")
		}
		return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
	}
	opts := session.Options{HandshakeTimeout: 500 * time.Millisecond, ProbeInterval: 100 * time.Millisecond, FailureTimeout: 600 * time.Millisecond, RetainTimeout: 5 * time.Second}
	server, credentials := sessionDNSTerminationServer(t, ctx, &sessionDNSRuntimeFactory{base: base}, opts)
	proxy := newSessionDNSCloseUDPProxy(t, server.Addr())
	recorder := newClientAddressScopeRecorder(t)
	client, connected, allocator := newClientAddressScoped(t, ctx, server, credentials, opts, recorder, proxy.front.LocalAddr().String())
	ip, err := allocator.AllocateSessionAddress(host)
	if err != nil {
		t.Fatal(err)
	}
	flow := sessionDNSRuntimeExchange(t, ctx, client, net.JoinHostPort(ip.String(), strconv.Itoa(port)), []byte("before UDP path blackhole"))
	initial := connected.Stats()
	proxy.dropClient.Store(true)
	proxy.dropResponder.Store(true)
	flow.SetDeadline(time.Now().Add(8 * time.Second))
	payload := bytes.Repeat([]byte("session-owned client map across recovery;"), 2048)
	written := make(chan error, 1)
	go func() { _, err := io.Copy(flow, bytes.NewReader(payload)); written <- err }()
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(flow, response); err != nil {
		t.Fatalf("8s recovery business deadline: %v stats=%+v", err, connected.Stats())
	}
	if err := <-written; err != nil || !bytes.Equal(response, payload) {
		t.Fatalf("recovery bytes differed: %v", err)
	}
	final := connected.Stats()
	after, ok := connected.LocalAddressAllocator()
	if !ok || after != allocator || len(recorder.snapshot()) != 1 || final.ID != initial.ID || final.Generation <= initial.Generation || final.Carrier != "tcp" || targets.Load() != 1 {
		t.Fatalf("recovery changed map/Session/socket: initial=%+v final=%+v scopes=%d targets=%d", initial, final, len(recorder.snapshot()), targets.Load())
	}
	if restored, err := allocator.ResolveSessionAddress(ip); err != nil || restored != host {
		t.Fatalf("recovery lost original mapping: %q %v", restored, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	requireFakeIPCleared(t, recorder.snapshot()[0], ip)
}

func TestClientAddressScopeConcurrentAllocatorDuringClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	base, err := New(Policy{})
	if err != nil {
		t.Fatal(err)
	}
	server, credentials := sessionDNSTerminationServer(t, ctx, &sessionDNSRuntimeFactory{base: base}, session.Options{})
	recorder := newClientAddressScopeRecorder(t)
	client, _, allocator := newClientAddressScoped(t, ctx, server, credentials, session.Options{}, recorder, "")
	ip, err := allocator.AllocateSessionAddress("concurrent-client.test")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	started := make(chan struct{}, 8)
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			started <- struct{}{}
			for {
				select {
				case <-stop:
					return
				default:
				}
				allocated, err := allocator.AllocateSessionAddress("concurrent-client.test")
				if err != nil && !errors.Is(err, ErrFakeIPScopeClosed) {
					t.Errorf("concurrent allocation: %v", err)
					return
				}
				if err == nil && allocated != ip {
					t.Error("concurrent mapping changed address")
					return
				}
				name, err := allocator.ResolveSessionAddress(ip)
				if err != nil && !errors.Is(err, ErrFakeIPScopeClosed) {
					t.Errorf("concurrent reverse lookup: %v", err)
					return
				}
				if err == nil && name != "concurrent-client.test" {
					t.Error("concurrent reverse lookup changed hostname")
					return
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-started
	}
	closeErr := client.Close()
	close(stop)
	workers.Wait()
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	requireFakeIPCleared(t, recorder.snapshot()[0], ip)
}
