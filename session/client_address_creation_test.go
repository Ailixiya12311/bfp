package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"bfp/protocol"
)

type clientCreationFactoryFunc func(context.Context, func() error) (ClientAddressScope, error)

func (f clientCreationFactoryFunc) ForClientSession(ctx context.Context, valid func() error) (ClientAddressScope, error) {
	return f(ctx, valid)
}

func clientCreationServer(t *testing.T) (*Server, Credentials) {
	t.Helper()
	server, credentials := newSecurityTestServer(t)
	served := make(chan error, 1)
	go func() { served <- server.Serve(context.Background()) }()
	t.Cleanup(func() {
		server.Close()
		select {
		case err := <-served:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("factory creation server did not stop")
		}
	})
	return server, credentials
}

func clientCreationClient(t *testing.T, server *Server, credentials Credentials, factory ClientAddressScopeFactory, options ...Options) (*Client, *atomic.Int32) {
	t.Helper()
	physicalDials := &atomic.Int32{}
	opts := Options{HandshakeTimeout: time.Second}
	if len(options) > 0 {
		opts = options[0]
	}
	client, err := NewClient(ClientConfig{Server: "factory-carrier.invalid:443", TCPServer: server.Addr().String(), Credentials: credentials,
		Options: opts, AddressScopeFactory: factory,
		DialUDP: func(ctx context.Context, network, address string) (net.PacketConn, *net.UDPAddr, error) {
			physicalDials.Add(1)
			socket, err := (&net.ListenConfig{}).ListenPacket(ctx, network, "127.0.0.1:0")
			return socket, server.udp.LocalAddr().(*net.UDPAddr), err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Abort() })
	return client, physicalDials
}

func creationMustEnter(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("confirmed handshake did not invoke factory")
	}
}

func TestClientAddressCreationConnectDeadlineCancelsCooperativeFactory(t *testing.T) {
	server, credentials := clientCreationServer(t)
	entered := make(chan struct{})
	factoryCanceled := make(chan struct{})
	factory := clientCreationFactoryFunc(func(ctx context.Context, valid func() error) (ClientAddressScope, error) {
		close(entered)
		<-ctx.Done()
		close(factoryCanceled)
		return nil, ctx.Err()
	})
	client, _ := clientCreationClient(t, server, credentials, factory)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := client.Connect(ctx); result <- err }()
	creationMustEnter(t, entered)
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Connect did not preserve deadline cause: %v", err)
		}
	case <-time.After(400 * time.Millisecond):
		t.Fatal("Connect deadline still waits for the factory's Session context")
	}
	creationMustEnter(t, factoryCanceled)
	if client.Session() != nil {
		t.Fatal("canceled factory published Session")
	}
	runtimeWait(t, "cooperative factory releases callback slot", func() bool { return len(client.cfg.addressCreations.gate) == 0 })
}

func TestClientAddressCreationCloseCancelsFactoryAndDestroysLateScope(t *testing.T) {
	for _, cooperative := range []bool{true, false} {
		name := "ignores-context"
		if cooperative {
			name = "observes-context"
		}
		t.Run(name, func(t *testing.T) {
			server, credentials := clientCreationServer(t)
			entered := make(chan struct{})
			release := make(chan struct{})
			returned := make(chan struct{})
			scope := &testClientAddressScope{}
			factory := clientCreationFactoryFunc(func(ctx context.Context, valid func() error) (ClientAddressScope, error) {
				scope.valid = valid
				close(entered)
				if cooperative {
					<-ctx.Done()
				} else {
					<-release
				}
				defer close(returned)
				return scope, nil
			})
			client, _ := clientCreationClient(t, server, credentials, factory)
			connectResult := make(chan error, 1)
			go func() { _, err := client.Connect(context.Background()); connectResult <- err }()
			creationMustEnter(t, entered)
			closeResult := make(chan error, 1)
			go func() { closeResult <- client.Close() }()
			select {
			case err := <-closeResult:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("Client.Close blocked on a pending scope factory")
			}
			select {
			case err := <-connectResult:
				if !errors.Is(err, context.Canceled) && !errors.Is(err, ErrClosed) {
					t.Fatalf("Connect ignored Client.Close: %v", err)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("Connect retained Client mutex after Close")
			}
			if !cooperative {
				if scope.closed.Load() {
					t.Fatal("scope was used before its late return")
				}
				close(release)
			}
			creationMustEnter(t, returned)
			runtimeWait(t, "late scope destruction and callback release", func() bool { return scope.closes.Load() == 1 && len(client.cfg.addressCreations.gate) == 0 })
			if client.Session() != nil {
				t.Fatal("late factory result resurrected closed Client")
			}
			if _, err := scope.AllocateSessionAddress("after-close.test"); !errors.Is(err, ErrClosed) {
				t.Fatal("late scope remained eligible", err)
			}
		})
	}
}

func TestClientAddressCreationCanceledNoncooperativeFactoryHasOneBoundedCallback(t *testing.T) {
	server, credentials := clientCreationServer(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	lateScope := &testClientAddressScope{}
	freshScope := &testClientAddressScope{}
	factory := clientCreationFactoryFunc(func(ctx context.Context, valid func() error) (ClientAddressScope, error) {
		if calls.Add(1) == 1 {
			lateScope.valid = valid
			close(entered)
			<-release // Explicitly ignore ctx for this bounded fault.
			return lateScope, nil
		}
		freshScope.valid = valid
		return freshScope, nil
	})
	client, physicalDials := clientCreationClient(t, server, credentials, factory)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := client.Connect(ctx); result <- err }()
	creationMustEnter(t, entered)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("noncooperative factory prevented Connect cancellation")
	}
	for n := 0; n < 100; n++ {
		if _, err := client.Connect(context.Background()); !errors.Is(err, ErrClientAddressScopeBusy) {
			t.Fatalf("retry %d added callback: %v", n, err)
		}
	}
	if calls.Load() != 1 || physicalDials.Load() != 1 {
		t.Fatalf("busy retries created work: factories=%d physical=%d", calls.Load(), physicalDials.Load())
	}
	close(release)
	runtimeWait(t, "late callback returns and clears reservation", func() bool { return lateScope.closes.Load() == 1 && len(client.cfg.addressCreations.gate) == 0 })
	if client.Session() != nil {
		t.Fatal("late callback published its canceled Session")
	}
	fresh, err := client.Connect(context.Background())
	if err != nil {
		t.Fatal("fresh Connect after late cleanup", err)
	}
	allocator, ok := fresh.LocalAddressAllocator()
	if !ok || allocator != freshScope || calls.Load() != 2 || physicalDials.Load() != 2 {
		t.Fatal("fresh Connect did not create one new scope/carrier")
	}
	if err = client.Abort(); err != nil {
		t.Fatal(err)
	}
	if freshScope.closes.Load() != 1 || lateScope.closes.Load() != 1 {
		t.Fatal("scope ownership did not close each result exactly once")
	}
}

func TestClientAddressCreationSuccessScopeSurvivesConnectContextUntilSessionClose(t *testing.T) {
	server, credentials := clientCreationServer(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	accepted := make(chan net.Conn, 1)
	served := make(chan struct{})
	go func() {
		defer close(served)
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
			_, _ = io.Copy(conn, conn)
			conn.Close()
		}
	}()
	var peer net.Conn
	t.Cleanup(func() {
		listener.Close()
		if peer != nil {
			peer.Close()
		}
		<-served
	})
	scope := &testClientAddressScope{restore: func(target protocol.Target) (protocol.Target, error) {
		target.Address = listener.Addr().String()
		return target, nil
	}}
	var scopeCtx context.Context
	factory := clientCreationFactoryFunc(func(ctx context.Context, valid func() error) (ClientAddressScope, error) {
		scopeCtx, scope.valid = ctx, valid
		return scope, nil
	})
	client, _ := clientCreationClient(t, server, credentials, factory)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	s, err := client.Connect(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	// Observe well beyond asynchronous callback dispatch. The context supplied
	// to the successful scope remains independent of the completed Connect.
	select {
	case <-scopeCtx.Done():
		t.Fatal("successful map inherited Connect/deferred cancellation")
	case <-time.After(200 * time.Millisecond):
	}
	allocator, ok := s.LocalAddressAllocator()
	if !ok {
		t.Fatal("successful scope disappeared with Connect context")
	}
	ip, err := allocator.AllocateSessionAddress("scope-owner.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = allocator.ResolveSessionAddress(ip); err != nil {
		t.Fatal(err)
	}
	flow, err := s.DialContext(context.Background(), "tcp", net.JoinHostPort(ip.String(), "443"))
	if err != nil {
		t.Fatal("scope restoration after Connect cancellation", err)
	}
	defer flow.Close()
	select {
	case peer = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("restored target not dialed")
	}
	flow.SetDeadline(time.Now().Add(time.Second))
	payload := []byte("real bytes after Connect context has ended")
	if _, err = flow.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(flow, response); err != nil || !bytes.Equal(response, payload) {
		t.Fatalf("scope business failed: %v", err)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	if scope.closes.Load() != 1 || scopeCtx.Err() == nil {
		t.Fatal("Session retirement did not destroy scope and its long-lived context")
	}
}

func TestClientAddressCreationInvalidOrErrorResultCleanupAndRetry(t *testing.T) {
	for _, scene := range []string{"nil", "typed-nil", "scope-and-error", "canceled-scope-and-error"} {
		t.Run(scene, func(t *testing.T) {
			server, credentials := clientCreationServer(t)
			entered, release := make(chan struct{}), make(chan struct{})
			scope := &testClientAddressScope{}
			failure := errors.New("controlled factory failure")
			factory := clientCreationFactoryFunc(func(ctx context.Context, valid func() error) (ClientAddressScope, error) {
				scope.valid = valid
				close(entered)
				if scene == "canceled-scope-and-error" {
					<-release
				}
				switch scene {
				case "nil":
					return nil, nil
				case "typed-nil":
					var missing *testClientAddressScope
					return missing, nil
				default:
					return scope, failure
				}
			})
			client, _ := clientCreationClient(t, server, credentials, factory)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := client.Connect(ctx); result <- err }()
			creationMustEnter(t, entered)
			if scene == "canceled-scope-and-error" {
				cancel()
			}
			select {
			case err := <-result:
				switch scene {
				case "nil", "typed-nil":
					if !errors.Is(err, ErrClientAddressScope) {
						t.Fatal(err)
					}
				case "scope-and-error":
					if !errors.Is(err, failure) {
						t.Fatal(err)
					}
				case "canceled-scope-and-error":
					if !errors.Is(err, context.Canceled) {
						t.Fatal(err)
					}
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("invalid/error factory result did not release Connect")
			}
			if scene == "canceled-scope-and-error" {
				close(release)
			}
			runtimeWait(t, "invalid/error callback retires", func() bool { return len(client.cfg.addressCreations.gate) == 0 })
			if scene == "scope-and-error" || scene == "canceled-scope-and-error" {
				if scope.closes.Load() != 1 {
					t.Fatal("scope returned with error was not closed exactly once")
				}
			} else if scope.closes.Load() != 0 {
				t.Fatal("nil result called a nonexistent scope Close")
			}
			if client.Session() != nil {
				t.Fatal("invalid/error factory published Session")
			}
		})
	}
}

func TestClientAddressCreationUnstartedReservationReleasedAfterHandshakeError(t *testing.T) {
	_, credentials := newSecurityTestServer(t)
	var callbacks atomic.Int32
	factory := clientCreationFactoryFunc(func(context.Context, func() error) (ClientAddressScope, error) { callbacks.Add(1); return nil, nil })
	client, err := NewClient(ClientConfig{Server: "127.0.0.1:1", Credentials: credentials, AddressScopeFactory: factory,
		DialUDP: func(context.Context, string, string) (net.PacketConn, *net.UDPAddr, error) {
			return nil, nil, errors.New("controlled UDP dial failure")
		},
		DialTCP: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("controlled TCP dial failure")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Abort()
	for n := 0; n < 2; n++ {
		if _, err = client.Connect(context.Background()); err == nil || errors.Is(err, ErrClientAddressScopeBusy) {
			t.Fatal("unstarted reservation was retained", err)
		}
		if len(client.cfg.addressCreations.gate) != 0 {
			t.Fatal("handshake failure retained factory reservation")
		}
	}
	if callbacks.Load() != 0 {
		t.Fatal("factory called before confirmed handshake")
	}
}

func TestClientAddressCreationUsesDefaultPhaseBudgetAndEarlierConnectDeadline(t *testing.T) {
	for _, earlierConnect := range []bool{false, true} {
		name := "background-connect-phase-budget"
		if earlierConnect {
			name = "earlier-post-handshake-operation-deadline"
		}
		t.Run(name, func(t *testing.T) {
			server, credentials := clientCreationServer(t)
			entered, release := make(chan struct{}), make(chan struct{})
			scope := &testClientAddressScope{}
			var factoryCtx context.Context
			factory := clientCreationFactoryFunc(func(ctx context.Context, valid func() error) (ClientAddressScope, error) {
				factoryCtx, scope.valid = ctx, valid
				close(entered)
				<-release // Keeps the callback alive after the bounded operation.
				return scope, nil
			})
			client, _ := clientCreationClient(t, server, credentials, factory, Options{HandshakeTimeout: 150 * time.Millisecond})
			ctx := context.Background()
			cancel := func() {}
			var confirmed sessionInfo
			if earlierConnect {
				// Confirm the real handshake before starting the 60ms scope phase.
				// This case verifies the constructor used by Connect honors an
				// earlier operation deadline, independently of cryptographic work
				// and scheduling while completing the preceding handshake.
				handshakeCtx, stopHandshake := context.WithTimeout(ctx, time.Second)
				carrier, info, err := establish(handshakeCtx, client.cfg, "udp", randomID(), nil)
				stopHandshake()
				if err != nil {
					t.Fatal(err)
				}
				defer carrier.close()
				confirmed = info
				ctx, cancel = context.WithTimeout(ctx, 60*time.Millisecond)
			}
			defer cancel()
			result := make(chan error, 1)
			started := time.Now()
			go func() {
				if !earlierConnect {
					_, err := client.Connect(ctx)
					result <- err
					return
				}
				creation, err := client.cfg.addressCreations.reserve(ctx)
				if err != nil {
					result <- err
					return
				}
				defer creation.releaseUnused()
				owner, err := newSessionWithAddressScopeOperation(client.sessionCtx, ctx, confirmed, client.cfg.Options, true, nil, client.datagramFEC, client.cfg.AddressScopeFactory, creation, client.classifier)
				if owner != nil {
					_ = owner.Close()
				}
				result <- err
			}()
			creationMustEnter(t, entered)
			limit := 400 * time.Millisecond
			if earlierConnect {
				limit = 120 * time.Millisecond
			}
			select {
			case err := <-result:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("bounded phase lost deadline cause: %v", err)
				}
			case <-time.After(limit):
				t.Fatal("Connect exceeded the selected factory creation budget")
			}
			if factoryCtx.Err() == nil {
				t.Fatal("bounded operation did not cancel pending factory context")
			}
			if client.Session() != nil || len(client.cfg.addressCreations.gate) != 1 {
				t.Fatal("timeout published Session or discarded outstanding callback owner")
			}
			if _, err := client.Connect(context.Background()); !errors.Is(err, ErrClientAddressScopeBusy) {
				t.Fatal("timed out callback admitted duplicate work", err)
			}
			close(release)
			runtimeWait(t, "phase budget late result destruction", func() bool { return scope.closes.Load() == 1 && len(client.cfg.addressCreations.gate) == 0 })
			t.Logf("earlier_connect=%v elapsed=%s handshake_budget=150ms", earlierConnect, time.Since(started))
		})
	}
}

func TestClientAddressCreationTypedNilFactoryRejected(t *testing.T) {
	_, credentials := newSecurityTestServer(t)
	var nilPointer *testClientScopeFactory
	var nilFunc clientCreationFactoryFunc
	for _, factory := range []ClientAddressScopeFactory{nilPointer, nilFunc} {
		client, err := NewClient(ClientConfig{Server: "127.0.0.1:1", Credentials: credentials, AddressScopeFactory: factory})
		if client != nil || !errors.Is(err, ErrClientAddressScope) {
			t.Fatalf("typed-nil factory accepted: client=%v err=%v", client, err)
		}
	}
}
