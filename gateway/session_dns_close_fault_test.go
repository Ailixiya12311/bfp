package gateway

import (
	"bfp/internal/backend"
	"bfp/security"
	"bfp/session"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Preserve the ordinary gateway Session scope and numeric OS dial. This wrapper
// counts every Session-issued target Close; it has no once guard that could hide
// duplicate closes in the implementation under test.
type sessionDNSCloseTarget struct {
	net.Conn
	closes *atomic.Int32
}

func (c *sessionDNSCloseTarget) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

type sessionDNSCloseDialer struct {
	backend.Dialer
	closes *atomic.Int32
}

func (d *sessionDNSCloseDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil || conn == nil {
		return conn, err
	}
	return &sessionDNSCloseTarget{Conn: conn, closes: d.closes}, nil
}

type sessionDNSCloseFactory struct {
	*sessionDNSRuntimeFactory
	closes atomic.Int32
}

func (f *sessionDNSCloseFactory) ForSession(ctx context.Context, valid func() error) (backend.Dialer, func()) {
	dialer, cleanup := f.sessionDNSRuntimeFactory.ForSession(ctx, valid)
	return &sessionDNSCloseDialer{Dialer: dialer, closes: &f.closes}, cleanup
}

// This proxy only forwards opaque authenticated records. A responder-direction
// blackout drops all CloseAck records without decrypting their frames, and is
// deliberately named as such rather than claiming an identified first-ACK drop.
type sessionDNSCloseUDPProxy struct {
	front          *net.UDPConn
	back           *net.UDPConn
	mu             sync.Mutex
	client         *net.UDPAddr
	dropClient     atomic.Bool
	dropResponder  atomic.Bool
	clientRecords  atomic.Int32
	droppedRecords atomic.Int32
	wg             sync.WaitGroup
}

func newSessionDNSCloseUDPProxy(t *testing.T, server net.Addr) *sessionDNSCloseUDPProxy {
	t.Helper()
	address, err := net.ResolveUDPAddr("udp4", server.String())
	if err != nil {
		t.Fatal(err)
	}
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	back, err := net.DialUDP("udp4", nil, address)
	if err != nil {
		front.Close()
		t.Fatal(err)
	}
	p := &sessionDNSCloseUDPProxy{front: front, back: back}
	p.wg.Add(2)
	go func() {
		defer p.wg.Done()
		buffer := make([]byte, security.MaxUDPRecordSize+1)
		for {
			n, peer, err := front.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			p.clientRecords.Add(1)
			p.mu.Lock()
			if p.client == nil {
				p.client = peer
			}
			allowed := p.client.String() == peer.String()
			p.mu.Unlock()
			if allowed && !p.dropClient.Load() {
				if _, err = back.Write(buffer[:n]); err != nil {
					return
				}
			}
		}
	}()
	go func() {
		defer p.wg.Done()
		buffer := make([]byte, security.MaxUDPRecordSize+1)
		for {
			n, err := back.Read(buffer)
			if err != nil {
				return
			}
			if p.dropResponder.Load() {
				p.droppedRecords.Add(1)
				continue
			}
			p.mu.Lock()
			peer := p.client
			p.mu.Unlock()
			if peer != nil {
				if _, err = front.WriteToUDP(buffer[:n], peer); err != nil {
					return
				}
			}
		}
	}()
	t.Cleanup(func() {
		front.Close()
		back.Close()
		done := make(chan struct{})
		go func() { p.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("owned opaque UDP proxy did not stop within fixed 1s")
		}
	})
	return p
}

func sessionDNSCloseServer(t *testing.T, ctx context.Context, factory *sessionDNSCloseFactory, options session.Options) (*session.Server, session.Credentials) {
	t.Helper()
	clientKey, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	admission := make([]byte, 32)
	if _, err = rand.Read(admission); err != nil {
		t.Fatal(err)
	}
	server, err := session.NewServer(session.ServerConfig{Listen: "127.0.0.1:0", Backend: factory,
		Options: options, Credentials: session.Credentials{Admission: admission, Private: serverKey.Private,
			Public: serverKey.Public, AllowedClients: [][]byte{clientKey.Public}}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		sessionDNSTerminationClose(t, "close-fault BFP server", server.Close)
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("owned close-fault Serve did not stop within fixed 1s")
		}
	})
	return server, session.Credentials{Admission: admission, Private: clientKey.Private,
		Public: clientKey.Public, ServerPublic: serverKey.Public}
}

func testSessionDNSRuntimeBoundedClose(t *testing.T, carrier string, responderBlackout bool) {
	t.Helper()
	// This new scene has its own explicit 750ms close-control timeout. It does
	// not change the existing 5s runtime business or 1s resource observation.
	const closeTimeout = 750 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	port, targets, targetClosed := sessionDNSTerminationEcho(t, deadline)
	base, err := New(Policy{AllowPrivate: true, AllowedCIDRs: []string{"127.0.0.0/8"},
		AllowedPorts: []int{port}, MaxConcurrent: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	const hostname = "session-close-runtime.test"
	var lookups atomic.Int32
	base.lookup = func(ctx context.Context, name string) ([]net.IPAddr, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lookups.Add(1)
		if name != hostname {
			return nil, errors.New("test: terminated close scope performed a new lookup")
		}
		return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
	}
	factory := &sessionDNSCloseFactory{sessionDNSRuntimeFactory: &sessionDNSRuntimeFactory{base: base}}
	options := session.Options{CloseTimeout: closeTimeout}
	server, credentials := sessionDNSCloseServer(t, ctx, factory, options)
	proxy := newSessionDNSCloseUDPProxy(t, server.Addr())
	if carrier == "tcp" {
		// Prove initial UDP was attempted, then establish actual encrypted TCP
		// over the independent reachable listener. Only this named fixture's
		// handshake timeout is shortened; watchdog/retention stay at defaults.
		proxy.dropClient.Store(true)
		options.HandshakeTimeout = 500 * time.Millisecond
	}
	client, err := session.NewClient(session.ClientConfig{Server: proxy.front.LocalAddr().String(),
		TCPServer: server.Addr().String(), Credentials: credentials, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		err := client.Close()
		if err != nil && !errors.Is(err, session.ErrCloseUnconfirmed) {
			t.Errorf("owned close-fault client cleanup failed: %v", err)
		}
	})
	connected, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if connected.Stats().Carrier != carrier || proxy.clientRecords.Load() == 0 {
		t.Fatal("close fixture did not establish its requested actual carrier after an initial UDP attempt")
	}
	destination := net.JoinHostPort(hostname, strconv.Itoa(port))
	flow := sessionDNSRuntimeExchange(t, ctx, client, destination, []byte("actual encrypted business before bounded Session close"))
	scopes := factory.snapshot()
	if len(scopes) != 1 || lookups.Load() != 1 || targets.Load() != 1 || factory.unscopedDials.Load() != 0 {
		t.Fatal("actual close fixture did not populate one Session DNS cache through one numeric target dial")
	}
	scope := scopes[0]
	entries, closed, generation := dnsState(scope.dialer)
	if entries != 1 || closed || scope.stops.Load() != 0 || factory.closes.Load() != 0 {
		t.Fatal("bounded close did not start from a live positive cache and target socket")
	}
	if responderBlackout {
		proxy.dropResponder.Store(true)
	}
	started := time.Now()
	// The direct Session and Client calls share the same terminal decision,
	// deadline and result; Client must preserve an unconfirmed close error.
	sessionResult := make(chan error, 1)
	clientResult := make(chan error, 1)
	go func() { sessionResult <- connected.Close() }()
	go func() { clientResult <- client.Close() }()
	sessionDNSTerminationWait(t, ctx, scope, targetClosed)
	if responderBlackout {
		select {
		case result := <-sessionResult:
			t.Fatalf("all responder records were lost but local close finished before peer resource observation: %v", result)
		default:
		}
	}
	if factory.closes.Load() != 1 {
		t.Fatalf("Session did not close its actual registered numeric target exactly once: %d", factory.closes.Load())
	}
	if entries, closed, current := dnsState(scope.dialer); entries != 0 || !closed || current != generation+1 || scope.stops.Load() != 1 {
		t.Fatal("bounded close did not invalidate the original positive cache exactly once")
	}
	for _, name := range []string{hostname, "uncached-after-close.test"} {
		conn, err := scope.dialer.DialContext(ctx, "tcp", net.JoinHostPort(name, strconv.Itoa(port)))
		if conn != nil {
			conn.Close()
			t.Fatal("closed old scope returned another numeric target")
		}
		if !errors.Is(err, ErrSessionBackendClosed) {
			t.Fatalf("closed old scope accepted cached or uncached hostname: %v", err)
		}
	}
	for _, result := range []<-chan error{sessionResult, clientResult} {
		select {
		case err := <-result:
			if responderBlackout {
				if !errors.Is(err, session.ErrCloseUnconfirmed) {
					t.Fatalf("all responder records lost: Close result did not preserve unconfirmed status: %v", err)
				}
			} else if err != nil {
				t.Fatalf("normal authenticated close did not confirm: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("bounded Close exceeded original 5s runtime context")
		case <-time.After(closeTimeout + 250*time.Millisecond):
			t.Fatal("bounded Close exceeded its own fixed close-control deadline plus 250ms observation")
		}
	}
	if elapsed := time.Since(started); elapsed > closeTimeout+250*time.Millisecond {
		t.Fatalf("combined concurrent Close exceeded the fixed close deadline plus observation: %v", elapsed)
	}
	if responderBlackout && proxy.droppedRecords.Load() == 0 {
		t.Fatal("responder blackout did not discard any actual encrypted record")
	}
	sessionDNSTerminationFlowFailure(t, ctx, flow, true)
	if lookups.Load() != 1 || targets.Load() != 1 || factory.closes.Load() != 1 ||
		len(factory.snapshot()) != 1 || scope.stops.Load() != 1 {
		t.Fatal("close drain resolved, dialed, closed target again, or replaced the terminated scope")
	}
	if err := client.Close(); responderBlackout && !errors.Is(err, session.ErrCloseUnconfirmed) || !responderBlackout && err != nil {
		t.Fatalf("repeated Client.Close changed the immutable close result: %v", err)
	}
	t.Logf("actual encrypted %s close: responder blackout=%t discarded records=%d; original DNS cache and numeric TCP target cleared once, old scope refused both hostname forms", carrier, responderBlackout, proxy.droppedRecords.Load())
}

func TestSessionDNSRuntimeBoundedCloseUDP(t *testing.T) {
	testSessionDNSRuntimeBoundedClose(t, "udp", false)
}

func TestSessionDNSRuntimeBoundedCloseTCP(t *testing.T) {
	testSessionDNSRuntimeBoundedClose(t, "tcp", false)
}

func TestSessionDNSRuntimeBoundedCloseUDPAllResponderRecordsLost(t *testing.T) {
	testSessionDNSRuntimeBoundedClose(t, "udp", true)
}
