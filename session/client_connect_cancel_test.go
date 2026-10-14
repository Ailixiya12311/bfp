package session

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientConnectQueuedCancellationDoesNotCancelOwnerOrDialAgain(t *testing.T) {
	server, credentials := clientCreationServer(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var hookCalls, factoryCalls atomic.Int32
	scope := &testClientAddressScope{}
	factory := clientCreationFactoryFunc(func(ctx context.Context, valid func() error) (ClientAddressScope, error) {
		factoryCalls.Add(1)
		scope.valid = valid
		return scope, nil
	})
	client, err := NewClient(ClientConfig{Server: "queue-hook.invalid:443", Credentials: credentials, AddressScopeFactory: factory, Options: Options{HandshakeTimeout: time.Second},
		DialUDP: func(ctx context.Context, network, address string) (net.PacketConn, *net.UDPAddr, error) {
			hookCalls.Add(1)
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
			socket, err := (&net.ListenConfig{}).ListenPacket(ctx, network, "127.0.0.1:0")
			return socket, server.udp.LocalAddr().(*net.UDPAddr), err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Abort()
	type result struct {
		s   *Session
		err error
	}
	first := make(chan result, 1)
	go func() { s, err := client.Connect(context.Background()); first <- result{s, err} }()
	creationMustEnter(t, entered)
	var waiters sync.WaitGroup
	errorsOut := make(chan error, 16)
	for n := 0; n < 16; n++ {
		waiters.Add(1)
		go func() {
			defer waiters.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			_, err := client.Connect(ctx)
			errorsOut <- err
		}()
	}
	joined := make(chan struct{})
	go func() { waiters.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("queued Connect ignored independent deadlines")
	}
	close(errorsOut)
	for err := range errorsOut {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("queued cancellation cause lost", err)
		}
	}
	if hookCalls.Load() != 1 || factoryCalls.Load() != 0 {
		t.Fatalf("queued Connect created work before lock ownership: hooks=%d factories=%d", hookCalls.Load(), factoryCalls.Load())
	}
	select {
	case r := <-first:
		if r.s != nil {
			r.s.Close()
		}
		t.Fatal("queued cancellation canceled unrelated Connect owner", r.err)
	default:
	}
	close(release)
	var owned *Session
	select {
	case r := <-first:
		if r.err != nil {
			t.Fatal(r.err)
		}
		owned = r.s
	case <-time.After(time.Second):
		t.Fatal("original Connect failed after queued cancellation")
	}
	if hookCalls.Load() != 1 || factoryCalls.Load() != 1 {
		t.Fatal("queued callers changed hook/factory counts")
	}
	if _, ok := owned.LocalAddressAllocator(); !ok {
		t.Fatal("queued caller deadline canceled owner's scope")
	}
	if reused, err := client.Connect(context.Background()); err != nil || reused != owned {
		t.Fatal("Connect did not retain original Session", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if scope.closes.Load() != 1 {
		t.Fatal("owner scope not closed exactly once")
	}
}

func TestClientConnectCloseWakesQueuedCallersWithoutEnteringHookOrFactory(t *testing.T) {
	_, credentials := newSecurityTestServer(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var hookCalls, factoryCalls atomic.Int32
	client, err := NewClient(ClientConfig{Server: "held-hook.invalid:443", Credentials: credentials, Options: Options{HandshakeTimeout: time.Second},
		AddressScopeFactory: clientCreationFactoryFunc(func(context.Context, func() error) (ClientAddressScope, error) { factoryCalls.Add(1); return nil, nil }),
		DialUDP: func(context.Context, string, string) (net.PacketConn, *net.UDPAddr, error) {
			hookCalls.Add(1)
			close(entered)
			<-release
			return nil, nil, errors.New("late controlled hook failure")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Abort()
	first := make(chan error, 1)
	go func() { _, err := client.Connect(context.Background()); first <- err }()
	creationMustEnter(t, entered)
	results := make(chan error, 32)
	for n := 0; n < 32; n++ {
		go func() { _, err := client.Connect(context.Background()); results <- err }()
	}
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Close did not wake lock owner/queued callers")
	}
	for n := 0; n < 32; n++ {
		select {
		case err := <-results:
			if !errors.Is(err, ErrClosed) {
				t.Fatal("closed queued Connect returned", err)
			}
		case <-time.After(250 * time.Millisecond):
			t.Fatal("queued Connect remained blocked after Close")
		}
	}
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) && !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("first Connect retained lock on Close")
	}
	if hookCalls.Load() != 1 || factoryCalls.Load() != 0 {
		t.Fatal("Close admitted a queued hook/factory")
	}
	close(release)
	runtimeWait(t, "late hook callback joins", func() bool { return len(client.cfg.carrierDials.udp) == 0 })
	if client.Session() != nil {
		t.Fatal("Close resurrected Session")
	}
}

func TestClientConnectCanceledContextNeverAuthenticatesOrReturnsCurrentSession(t *testing.T) {
	server, credentials := clientCreationServer(t)
	client, dials := clientCreationClient(t, server, credentials, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for n := 0; n < 100; n++ {
		if s, err := client.Connect(ctx); s != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("expired context admitted initial Connect: session=%v err=%v", s, err)
		}
	}
	if dials.Load() != 0 {
		t.Fatal("expired context entered carrier hook")
	}
	s, err := client.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s, err := client.Connect(ctx); s != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expired context bypassed cancellation via current Session: session=%v err=%v", s, err)
	}
	if dials.Load() != 1 {
		t.Fatal("expired current lookup dialed again")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestContextMutexZeroValueCanceledTokenAndOrdinaryCallers(t *testing.T) {
	var mu contextMutex
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for n := 0; n < 100; n++ {
		if err := mu.LockContext(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("available token admitted canceled context", err)
		}
	}
	mu.Lock()
	waiting := make(chan error, 1)
	deadline, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	go func() { waiting <- mu.LockContext(deadline) }()
	select {
	case err := <-waiting:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatal("context mutex ignored deadline")
	}
	mu.Unlock()
	var count int
	var workers sync.WaitGroup
	for n := 0; n < 8; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for k := 0; k < 100; k++ {
				mu.Lock()
				count++
				mu.Unlock()
			}
		}()
	}
	workers.Wait()
	if count != 800 {
		t.Fatal("ordinary Lock/Unlock lost exclusion", count)
	}
	if err := mu.LockContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Unlock()
}
