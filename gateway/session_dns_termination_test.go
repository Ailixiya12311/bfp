package gateway

import (
	"bfp/security"
	"bfp/session"
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

// These are local runtime tests: the client uses actual encrypted UDP records,
// the gateway resolves through a controlled lookup, and its ordinary numeric
// OS dial reaches a real loopback TCP echo socket. No WAN or external DNS runs.
func sessionDNSTerminationEcho(t *testing.T, deadline time.Time) (int, *atomic.Int32, <-chan struct{}) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	count := &atomic.Int32{}
	activeClosed := make(chan struct{})
	workerDone := make(chan struct{})
	var mu sync.Mutex
	var active *net.TCPConn
	go func() {
		defer close(workerDone)
		conn, err := listener.AcceptTCP()
		if err != nil {
			return
		}
		count.Add(1)
		mu.Lock()
		active = conn
		mu.Unlock()
		defer conn.Close()
		_ = conn.SetDeadline(deadline)
		_, _ = io.Copy(conn, conn)
		// The original five-second socket deadline cannot satisfy the one-second
		// termination observation. A server-side close must unblock this echo.
		close(activeClosed)
	}()
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		if active != nil {
			active.Close()
		}
		mu.Unlock()
		select {
		case <-workerDone:
		case <-time.After(time.Second):
			t.Error("owned termination echo worker did not stop within fixed 1s")
		}
	})
	return listener.Addr().(*net.TCPAddr).Port, count, activeClosed
}

func sessionDNSTerminationServer(t *testing.T, serveCtx context.Context, factory *sessionDNSRuntimeFactory, options session.Options) (*session.Server, session.Credentials) {
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
	// Production owns both ephemeral listeners continuously. There is one
	// constructor call and no port reservation, release, preflight, or retry.
	server, err := session.NewServer(session.ServerConfig{Listen: "127.0.0.1:0", Backend: factory,
		Options: options, Credentials: session.Credentials{Admission: admission, Private: serverKey.Private,
			Public: serverKey.Public, AllowedClients: [][]byte{clientKey.Public}}})
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(serveCtx) }()
	t.Cleanup(func() {
		sessionDNSTerminationClose(t, "BFP server", server.Close)
		select {
		case err := <-serveDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("owned termination Serve did not stop within fixed 1s")
		}
	})
	return server, session.Credentials{Admission: admission, Private: clientKey.Private,
		Public: clientKey.Public, ServerPublic: serverKey.Public}
}

func sessionDNSTerminationClose(t *testing.T, owned string, closeFn func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- closeFn() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("owned %s cleanup failed: %v", owned, err)
		}
	case <-time.After(time.Second):
		t.Errorf("owned %s cleanup did not finish within fixed 1s", owned)
	}
}

func sessionDNSTerminationClient(t *testing.T, ctx context.Context, server *session.Server, credentials session.Credentials) (*session.Client, *session.Session) {
	t.Helper()
	client, err := session.NewClient(session.ClientConfig{Server: server.Addr().String(),
		TCPServer: server.Addr().String(), Credentials: credentials})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sessionDNSTerminationClose(t, "BFP client local abort", client.Abort) })
	connected, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if connected.Stats().Carrier != "udp" {
		t.Fatal("termination fixture did not establish the actual encrypted UDP carrier")
	}
	return client, connected
}

func sessionDNSTerminationWait(t *testing.T, ctx context.Context, scope *sessionDNSRuntimeScope, targetClosed <-chan struct{}) {
	t.Helper()
	observation, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	closedSocket := false
	for {
		select {
		case <-targetClosed:
			closedSocket = true
		default:
		}
		entries, closed, _ := dnsState(scope.dialer)
		if closedSocket && scope.dialer.dns.ctx.Err() != nil && closed && entries == 0 && scope.stops.Load() == 1 {
			return
		}
		select {
		case <-tick.C:
		case <-observation.Done():
			t.Fatalf("termination exceeded fixed 1s observation: target closed=%t entries=%d cache closed=%t stop calls=%d scope canceled=%t",
				closedSocket, entries, closed, scope.stops.Load(), scope.dialer.dns.ctx.Err() != nil)
		}
	}
}

func sessionDNSTerminationFlowFailure(t *testing.T, ctx context.Context, flow net.Conn, requireTerminal bool) {
	t.Helper()
	deadline, _ := ctx.Deadline()
	if err := flow.SetDeadline(minTime(deadline, time.Now().Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	payload := []byte("post-termination echo must not reach the closed target")
	n, err := flow.Write(payload)
	if err == nil {
		if n != len(payload) {
			t.Fatalf("post-termination write returned an unexplained short count: %d", n)
		}
		response := make([]byte, len(payload))
		read, readErr := io.ReadFull(flow, response)
		if read != 0 {
			t.Fatalf("terminated target echoed %d new application bytes", read)
		}
		err = readErr
	}
	if err == nil {
		t.Fatal("terminated Session's existing application flow remained usable")
	}
	var timeout net.Error
	isTimeout := errors.As(err, &timeout) && timeout.Timeout()
	if requireTerminal && (isTimeout || !errors.Is(err, session.ErrClosed)) {
		t.Fatalf("immutable lifetime did not terminate the client's existing flow: %v", err)
	}
	if isTimeout {
		// Revocation and parent cancellation currently publish no UDP terminal
		// notification. This bounded absence of echo is auxiliary evidence only;
		// it cannot prove that the client itself reached a closed Session state.
		t.Log("post-termination flow had no echo within fixed 1s read deadline; this is not proof of immediate client termination")
	} else {
		t.Logf("post-termination existing flow failed with terminal error: %v", err)
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func testSessionDNSRuntimeTermination(t *testing.T, reason string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serveCtx, cancelServe := context.WithCancel(ctx)
	defer cancelServe()
	deadline, _ := ctx.Deadline()
	port, targets, targetClosed := sessionDNSTerminationEcho(t, deadline)
	base, err := New(Policy{AllowPrivate: true, AllowedCIDRs: []string{"127.0.0.0/8"},
		AllowedPorts: []int{port}, MaxConcurrent: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	const host = "session-termination.test"
	var lookups atomic.Int32
	base.lookup = func(ctx context.Context, name string) ([]net.IPAddr, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lookups.Add(1)
		if name != host {
			return nil, errors.New("test: terminated scope performed a new lookup")
		}
		return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
	}
	factory := &sessionDNSRuntimeFactory{base: base}
	options := session.Options{}
	if reason == "expiry" {
		// Only authorization lifetime is shortened for this test. Production
		// UDP failure budget (15s) and Session retention (30s) remain defaults.
		options.MaxSessionLifetime = 250 * time.Millisecond
	}
	server, credentials := sessionDNSTerminationServer(t, serveCtx, factory, options)
	client, connected := sessionDNSTerminationClient(t, ctx, server, credentials)
	destination := net.JoinHostPort(host, strconv.Itoa(port))
	flow := sessionDNSRuntimeExchange(t, ctx, client, destination, []byte("live Session DNS and numeric TCP echo before termination"))
	scopes := factory.snapshot()
	if len(scopes) != 1 || lookups.Load() != 1 || targets.Load() != 1 || factory.unscopedDials.Load() != 0 {
		t.Fatal("real encrypted flow did not pass through exactly one scoped lookup and numeric target socket")
	}
	scope := scopes[0]
	entries, closed, generation := dnsState(scope.dialer)
	if entries != 1 || closed || scope.stops.Load() != 0 || connected.Stats().Carrier != "udp" {
		t.Fatal("termination did not start from a live UDP Session with its own populated DNS cache")
	}
	select {
	case <-targetClosed:
		t.Fatal("numeric target closed before the tested terminal transition")
	default:
	}
	transition := time.Now()
	switch reason {
	case "revocation":
		done := make(chan error, 1)
		go func() { done <- server.RevokeDevice(credentials.Public) }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("original 5s context elapsed during administrative revocation")
		case <-time.After(time.Second):
			t.Fatal("RevokeDevice did not return within fixed 1s")
		}
	case "expiry":
		// Observe the original constructor-time lifetime expiring naturally.
		// Do not close either peer or make a backend guard call to force cleanup.
	case "serve-cancel":
		cancelServe()
	default:
		t.Fatal("unknown terminal transition")
	}
	sessionDNSTerminationWait(t, ctx, scope, targetClosed)
	if time.Since(transition) >= time.Second {
		t.Fatal("combined terminal transition and resource observation exceeded original 1s bound")
	}
	if entries, closed, current := dnsState(scope.dialer); entries != 0 || !closed || current != generation+1 || scope.stops.Load() != 1 {
		t.Fatal("terminal transition did not invalidate and clear the original cache exactly once")
	}
	for _, hostname := range []string{host, "new-after-termination.test"} {
		conn, err := scope.dialer.DialContext(ctx, "tcp", net.JoinHostPort(hostname, strconv.Itoa(port)))
		if conn != nil {
			conn.Close()
			t.Fatal("terminated scope returned another numeric target socket")
		}
		if !errors.Is(err, ErrSessionBackendClosed) {
			t.Fatalf("terminated backend guard did not reject cached or uncached destination: %v", err)
		}
	}
	if lookups.Load() != 1 || targets.Load() != 1 || len(factory.snapshot()) != 1 {
		t.Fatal("terminated old scope resolved again, created another target, or was replaced")
	}
	sessionDNSTerminationFlowFailure(t, ctx, flow, reason == "expiry")
	// These administrative transitions already removed the peer. Local abort
	// joins the owned Client without requesting an impossible peer confirmation.
	// The original 1s resource assertions above succeed before this teardown can
	// close the target itself; the teardown's own 1s limit is unchanged.
	sessionDNSTerminationClose(t, "BFP client local abort", client.Abort)
	sessionDNSTerminationClose(t, "BFP server", server.Close)
	if entries, closed, current := dnsState(scope.dialer); entries != 0 || !closed || current != generation+1 || scope.stops.Load() != 1 || lookups.Load() != 1 {
		t.Fatal("later cleanup repopulated the cache or repeated its terminal invalidation")
	}
	t.Logf("local runtime %s: encrypted UDP business passed before termination; original positive cache cleared once and target TCP socket closed within 1s; old cached and uncached dials rejected", reason)
}

func TestSessionDNSRuntimeRevocationClearsCacheAndTarget(t *testing.T) {
	testSessionDNSRuntimeTermination(t, "revocation")
}

func TestSessionDNSRuntimeImmutableExpiryClearsCacheAndTarget(t *testing.T) {
	testSessionDNSRuntimeTermination(t, "expiry")
}

func TestSessionDNSRuntimeParentCancellationClearsCacheAndTarget(t *testing.T) {
	testSessionDNSRuntimeTermination(t, "serve-cancel")
}
