package gateway

import (
	"bfp/internal/backend"
	"bfp/security"
	"bfp/session"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type sessionDNSRuntimeScope struct {
	dialer *Dialer
	stops  atomic.Int32
}

// Wrap the real gateway factory without substituting the numeric socket dial.
// This records which scope the actual server installs after Noise confirmation.
type sessionDNSRuntimeFactory struct {
	base          *Dialer
	mu            sync.Mutex
	scopes        []*sessionDNSRuntimeScope
	unscopedDials atomic.Int32
}

var _ backend.SessionFactory = (*sessionDNSRuntimeFactory)(nil)

func (f *sessionDNSRuntimeFactory) DialContext(context.Context, string, string) (net.Conn, error) {
	f.unscopedDials.Add(1)
	return nil, errors.New("test: Session bypassed the gateway DNS scope")
}

func (f *sessionDNSRuntimeFactory) ForSession(ctx context.Context, valid func() error) (backend.Dialer, func()) {
	dialer, stop := f.base.ForSession(ctx, valid)
	scope := &sessionDNSRuntimeScope{dialer: dialer.(*Dialer)}
	f.mu.Lock()
	f.scopes = append(f.scopes, scope)
	f.mu.Unlock()
	return dialer, func() {
		scope.stops.Add(1)
		stop()
	}
}

func (f *sessionDNSRuntimeFactory) snapshot() []*sessionDNSRuntimeScope {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*sessionDNSRuntimeScope(nil), f.scopes...)
}

func sessionDNSRuntimeEcho(t *testing.T, deadline time.Time, hosts ...string) (int, *atomic.Int32) {
	t.Helper()
	host, network := "127.0.0.1", "tcp4"
	if len(hosts) != 0 {
		host = hosts[0]
		if net.ParseIP(host).To4() == nil {
			network = "tcp6"
		}
	}
	listener, err := net.Listen(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	count := &atomic.Int32{}
	acceptedDone := make(chan struct{})
	var workers sync.WaitGroup
	var mu sync.Mutex
	connections := make(map[net.Conn]bool)
	go func() {
		defer close(acceptedDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			mu.Lock()
			connections[conn] = true
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() {
					conn.Close()
					mu.Lock()
					delete(connections, conn)
					mu.Unlock()
				}()
				_ = conn.SetDeadline(deadline)
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		select {
		case <-acceptedDone:
		case <-time.After(time.Second):
			t.Error("owned echo listener did not stop")
		}
		mu.Lock()
		for conn := range connections {
			conn.Close()
		}
		mu.Unlock()
		workersDone := make(chan struct{})
		go func() { workers.Wait(); close(workersDone) }()
		select {
		case <-workersDone:
		case <-time.After(time.Second):
			t.Error("owned echo workers did not stop")
		}
	})
	return listener.Addr().(*net.TCPAddr).Port, count
}

func sessionDNSRuntimeServer(t *testing.T, ctx context.Context, factory *sessionDNSRuntimeFactory) (*session.Server, session.Credentials) {
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
	// One constructor owns both sockets continuously, without a released
	// preflight reservation. Ordinary Session options/deadlines remain intact.
	server, err := session.NewServer(session.ServerConfig{Listen: "127.0.0.1:0", Backend: factory,
		Credentials: session.Credentials{Admission: admission, Private: serverKey.Private, Public: serverKey.Public,
			AllowedClients: [][]byte{clientKey.Public}}})
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()
	t.Cleanup(func() {
		closed := make(chan struct{})
		go func() { server.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Error("owned BFP server cleanup did not finish")
		}
		select {
		case err := <-serveDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("owned BFP Serve did not stop")
		}
	})
	return server, session.Credentials{Admission: admission, Private: clientKey.Private,
		Public: clientKey.Public, ServerPublic: serverKey.Public}
}

func sessionDNSRuntimeClient(t *testing.T, ctx context.Context, server *session.Server, credentials session.Credentials) (*session.Client, *session.Session) {
	t.Helper()
	client, err := session.NewClient(session.ClientConfig{Server: server.Addr().String(), TCPServer: server.Addr().String(), Credentials: credentials})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	connected, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if connected.Stats().Carrier != "udp" {
		t.Fatal("runtime DNS fixture did not establish the encrypted UDP carrier")
	}
	return client, connected
}

func sessionDNSRuntimeExchange(t *testing.T, ctx context.Context, client *session.Client, destination string, payload []byte) net.Conn {
	t.Helper()
	conn, err := client.DialContext(ctx, "tcp", destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("encrypted flow write failed: written=%d want=%d error=%v", n, len(payload), err)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("real loopback echo changed the encrypted flow bytes")
	}
	return conn
}

func sessionDNSRuntimeWaitCleared(t *testing.T, ctx context.Context, scope *sessionDNSRuntimeScope) {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		entries, closed, _ := dnsState(scope.dialer)
		if scope.dialer.dns.ctx.Err() != nil && closed && entries == 0 && scope.stops.Load() == 1 {
			return
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatalf("original runtime deadline reached while waiting for remote scope cleanup: %v", ctx.Err())
		case <-timer.C:
			t.Fatalf("Client.Close did not terminate server DNS scope within fixed 1s: entries=%d closed=%t stop calls=%d context canceled=%t", entries, closed, scope.stops.Load(), scope.dialer.dns.ctx.Err() != nil)
		}
	}
}

func TestSessionDNSRuntimeFreshSessionIsolationAndClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	port, targets := sessionDNSRuntimeEcho(t, deadline)
	base, err := New(Policy{AllowPrivate: true, AllowedCIDRs: []string{"127.0.0.0/8"}, AllowedPorts: []int{port},
		MaxConcurrent: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	const host = "session-runtime.test"
	var lookups atomic.Int32
	base.lookup = func(ctx context.Context, name string) ([]net.IPAddr, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if name != host {
			return nil, errors.New("test: unexpected DNS lookup")
		}
		lookups.Add(1)
		return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
	}
	factory := &sessionDNSRuntimeFactory{base: base}
	server, credentials := sessionDNSRuntimeServer(t, ctx, factory)
	if len(factory.snapshot()) != 0 || lookups.Load() != 0 || base.dns != nil {
		t.Fatal("listening server allocated a Session cache or resolved before fresh authentication")
	}
	destination := net.JoinHostPort(host, strconv.Itoa(port))
	firstClient, firstSession := sessionDNSRuntimeClient(t, ctx, server, credentials)
	one := sessionDNSRuntimeExchange(t, ctx, firstClient, destination, []byte("first Session: real echo flow one"))
	two := sessionDNSRuntimeExchange(t, ctx, firstClient, destination, []byte("first Session: independent real echo flow two"))
	first := firstSession.Stats()
	scopes := factory.snapshot()
	if one == two || first.Opened != 2 || first.Carrier != "udp" || first.WireSent == 0 || first.WireReceived == 0 ||
		len(scopes) != 1 || lookups.Load() != 1 || targets.Load() != 2 || factory.unscopedDials.Load() != 0 {
		t.Fatalf("first real Session did not reuse one scoped DNS cache across two flows: opened=%d carrier=%s scopes=%d lookups=%d targets=%d unscoped dials=%d",
			first.Opened, first.Carrier, len(scopes), lookups.Load(), targets.Load(), factory.unscopedDials.Load())
	}
	firstScope := scopes[0]
	if count, closed, _ := dnsState(firstScope.dialer); count != 1 || closed || firstScope.stops.Load() != 0 {
		t.Fatal("active server scope did not retain its single positive DNS answer")
	}
	if firstScope.dialer.slots != base.slots || firstScope.dialer.resolverSlots != base.resolverSlots {
		t.Fatal("actual Session scope multiplied factory-owned dial or resolver execution slots")
	}
	if err = firstClient.Close(); err != nil {
		t.Fatal(err)
	}
	sessionDNSRuntimeWaitCleared(t, ctx, firstScope)

	secondClient, secondSession := sessionDNSRuntimeClient(t, ctx, server, credentials)
	second := secondSession.Stats()
	scopes = factory.snapshot()
	if len(scopes) != 2 || lookups.Load() != 1 || first.ID == second.ID ||
		first.ClientAddress == second.ClientAddress || first.ServerAddress == second.ServerAddress {
		t.Fatal("new Client reused the old Session network identity or resolved during scope creation")
	}
	secondScope := scopes[1]
	if secondScope.dialer.dns == firstScope.dialer.dns || secondScope.dialer.slots != firstScope.dialer.slots ||
		secondScope.dialer.resolverSlots != firstScope.dialer.resolverSlots {
		t.Fatal("actual fresh Sessions failed independent-cache/shared-execution-slot ownership")
	}
	if count, closed, _ := dnsState(secondScope.dialer); count != 0 || closed {
		t.Fatal("fresh Session cache contained state before its first hostname flow")
	}
	three := sessionDNSRuntimeExchange(t, ctx, secondClient, destination, []byte("second Session: fresh network echo flow"))
	if three.LocalAddr().String() != second.ClientAddress || three.RemoteAddr().String() != second.ServerAddress ||
		lookups.Load() != 2 || targets.Load() != 3 || len(factory.snapshot()) != 2 || factory.unscopedDials.Load() != 0 {
		t.Fatal("fresh network inherited the old DNS answer, Flow identity, or unscoped backend")
	}
	if count, closed, _ := dnsState(firstScope.dialer); count != 0 || !closed || firstScope.stops.Load() != 1 {
		t.Fatal("new Session repopulated its terminated predecessor's cache")
	}
	if count, closed, _ := dnsState(secondScope.dialer); count != 1 || closed {
		t.Fatal("new Session did not create its own positive DNS cache entry")
	}
	if err = secondClient.Close(); err != nil {
		t.Fatal(err)
	}
	sessionDNSRuntimeWaitCleared(t, ctx, secondScope)
	t.Log("real encrypted UDP flows and numeric TCP echo passed: 2 fresh scopes, 2 DNS lookups, 3 independent target sockets; both terminated caches cleared")
}
