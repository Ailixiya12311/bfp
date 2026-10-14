package session

import (
	"bfp/protocol"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func next11AbortResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		t.Fatal("Client administrative abort/join exceeded fixed 1s")
		return nil
	}
}

// Connect genuinely replaces the local current Session while its predecessor
// is draining. The original actor barrier isolates ownership: Abort must wait
// for both actors, even though the first recovery worker has already stopped
// admitting recovery after business cancellation.
func TestNext11ClientAbortJoinsReplacedDrainingSession(t *testing.T) {
	f, _ := newClassRecoveryFixture(t, false, false)
	old := f.local
	oldID := old.Stats().ID
	unblock := next10BlockActor(t, old)
	oldClose := next10BeginCloseAtBarrier(t, old)
	t.Cleanup(func() { old.cancel(); unblock() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	fresh, err := f.client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if fresh == old || fresh.Stats().ID == oldID {
		t.Fatal("explicit Connect did not replace the draining temporary network")
	}
	f.client.mu.Lock()
	_, ownsOld := f.client.owners[old]
	_, ownsFresh := f.client.owners[fresh]
	f.client.mu.Unlock()
	if !ownsOld || !ownsFresh {
		t.Fatal("Client lost a still-live owner when replacing current")
	}
	result := make(chan error, 1)
	go func() { result <- f.client.Abort() }()
	select {
	case <-f.client.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Abort did not cancel recovery before joining")
	}
	select {
	case <-fresh.done:
	case <-time.After(time.Second):
		t.Fatal("Abort joined an old blocked actor before canceling the fresh actor")
	}
	select {
	case <-result:
		t.Fatal("Abort returned while a replaced actor still owned local resources")
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	if err := next11AbortResult(t, result); err != nil {
		t.Fatal(err)
	}
	if err := next11AbortResult(t, oldClose); !errors.Is(err, ErrCloseUnconfirmed) {
		t.Fatalf("administrative abort forged the old Session's close confirmation: %v", err)
	}
	for _, owner := range []*Session{old, fresh} {
		if !owner.closed() {
			t.Fatal("Abort completed without joining every owned actor")
		}
	}
	f.client.mu.Lock()
	remaining := len(f.client.owners)
	f.client.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("completed Client retained %d actor ownership entries", remaining)
	}
	if _, err := f.client.Connect(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("aborted Client accepted another Session: %v", err)
	}
}

// The relay drops real authenticated peer ACK records. Administrative cleanup
// can interrupt Close's control drain, but cannot turn that missing receipt
// into success. Concurrent callers must all join the same already-owned actor.
func TestNext11ClientAbortConcurrentWithUnconfirmedClose(t *testing.T) {
	f := newCloseTestFixture(t, "udp", 3*time.Second, func(r *closeTestRelay) {
		r.dropAck[1].Store(true)
	})
	_, credentials := newSecurityTestServer(t)
	client, err := NewClient(ClientConfig{Credentials: credentials})
	if err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	client.current = f.sessions[0]
	client.owners[f.sessions[0]] = struct{}{}
	client.wg.Add(1)
	go client.recover(f.sessions[0])
	client.mu.Unlock()
	t.Cleanup(func() { _ = client.Abort() })
	graceful := make(chan error, 1)
	go func() { graceful <- client.Close() }()
	deadline := time.Now().Add(time.Second)
	for len(f.relay.selected(0, protocol.SessionClose)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("Close never published its actual authenticated request")
		}
		time.Sleep(time.Millisecond)
	}
	const callers = 12
	results := make(chan error, callers)
	var started sync.WaitGroup
	started.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			started.Done()
			results <- client.Abort()
		}()
	}
	started.Wait()
	joinDeadline := time.After(time.Second)
	for i := 0; i < callers; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-joinDeadline:
			t.Fatal("concurrent administrative abort callers did not join within fixed 1s")
		}
	}
	closeErr := next11AbortResult(t, graceful)
	if !errors.Is(closeErr, ErrCloseUnconfirmed) || client.Close() != closeErr {
		t.Fatalf("Abort changed or lost Close's unconfirmed result: %v", closeErr)
	}
	if !f.sessions[0].closed() || f.sessions[0].closing.localAcked {
		t.Fatal("Abort claimed receipt success or returned before the actor stopped")
	}
	if err := client.Abort(); err != nil {
		t.Fatal("repeated local Abort failed", err)
	}
}

// An INIT is physically observed on a real blackhole UDP socket. Cancellation
// must stop the pending Connect and release its mutex well before the original
// ten-second handshake deadline; this also rejects any fallback publication.
func TestNext11ClientAbortCancelsPendingConnect(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	_, credentials := newSecurityTestServer(t)
	client, err := NewClient(ClientConfig{Server: udp.LocalAddr().String(), TCPServer: "127.0.0.1:1",
		Credentials: credentials, Options: Options{HandshakeTimeout: 10 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Abort() })
	connect := make(chan error, 1)
	go func() {
		s, err := client.Connect(context.Background())
		if s != nil {
			connect <- errors.New("pending aborted Connect published a Session")
			return
		}
		connect <- err
	}()
	if err := udp.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	if _, _, err := udp.ReadFromUDP(buf); err != nil {
		t.Fatalf("pending Connect did not emit its actual INIT before abort: %v", err)
	}
	result := make(chan error, 1)
	go func() { result <- client.Abort() }()
	if err := next11AbortResult(t, result); err != nil {
		t.Fatal(err)
	}
	if err := next11AbortResult(t, connect); err == nil {
		t.Fatal("pending Connect succeeded after Client abort")
	}
	if client.Session() != nil {
		t.Fatal("aborted Client retained a newly committed Session")
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Client with no established Session acquired a spurious graceful-close result: %v", err)
	}
}
