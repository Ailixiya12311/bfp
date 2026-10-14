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

// The actor barrier leaves the control actor alive while Close publishes its
// independent intent. These assertions therefore cannot pass merely because
// done has closed or the one-second server maintenance removed credentials.
func next10BlockActor(t *testing.T, owner *Session) func() {
	t.Helper()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	owner.post(func() {
		close(entered)
		<-release
	})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("owner did not enter admission-test barrier")
	}
	return unblock
}

func next10BeginCloseAtBarrier(t *testing.T, owner *Session) <-chan error {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- owner.Close() }()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !owner.terminating() {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("Close did not publish independent terminal intent")
		}
	}
	if owner.closed() {
		t.Fatal("admission barrier did not retain the control actor")
	}
	return result
}

func next10AwaitClose(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		t.Fatal("aborted close did not join its actor")
		return nil
	}
}

func TestNext10AdmissionIntentRejectsAliasesCachedRepliesAndSiblingConfirm(t *testing.T) {
	server, cred := newSecurityTestServer(t)
	p, initial, proof, _ := ticketAdversarialCandidate(t, server, cred, 47301, nil)
	// The second real Noise candidate has the same operation identity, and
	// remains uncommitted with session=nil after the first carrier commits.
	sibling, siblingProof, _ := prepareCandidate(t, server, cred, "udp", initial.Attempt, 47302, nil)
	if _, _, err := server.confirm(proof, "udp", p.peer); err != nil {
		t.Fatal(err)
	}
	owner := p.session
	if sibling.session != nil || sibling.group != p.group {
		t.Fatal("fixture did not preserve a sibling candidate without an owner")
	}
	if err := owner.call(context.Background(), func() { _ = server.rotateTicket(owner, time.Now()) }); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	locators := make([]string, 0, len(server.tickets))
	for locator := range server.tickets {
		locators = append(locators, locator)
	}
	server.mu.Unlock()
	if len(locators) != 2 {
		t.Fatal("fixture did not install live and overlap aliases")
	}
	unblock := next10BlockActor(t, owner)
	result := next10BeginCloseAtBarrier(t, owner)
	t.Cleanup(func() { owner.cancel(); unblock(); next10AwaitClose(t, result) })
	server.mu.Lock()
	for _, locator := range locators {
		if server.ticketValidLocked(locator, owner, time.Now()) {
			t.Error("closing owner retained live or overlap recovery authority")
		}
	}
	server.mu.Unlock()
	if _, err := server.initialize(initial, "udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 47301}); err == nil {
		t.Error("closing owner returned cached initial reply")
	}
	if _, _, err := server.confirm(proof, "udp", p.peer); err == nil {
		t.Error("closing owner returned cached committed READY")
	}
	if _, _, err := server.confirm(siblingProof, "udp", sibling.peer); err == nil {
		t.Error("sibling candidate committed after its shared owner close intent")
	}
	if snapshot, err := sessionSnapshot(owner); !errors.Is(err, ErrClosed) || len(snapshot.Secret) != 0 || len(snapshot.Handle) != 0 || len(snapshot.Challenge) != 0 {
		t.Error("closing owner exported recovery state")
	}
	// This direct actor-owned signing call is safe while its actor is blocked;
	// it must reject without introducing another alias or modifying credentials.
	if err := server.rotateTicket(owner, time.Now()); !errors.Is(err, ErrClosed) {
		t.Error("late ticket rotation did not reject terminal intent")
	}
	server.mu.Lock()
	if len(server.tickets) != len(locators) {
		t.Error("late rotation changed the ticket registry")
	}
	server.mu.Unlock()
}

func TestNext10AdmissionClientCloseSharesCompletionAndResult(t *testing.T) {
	_, cred := newSecurityTestServer(t)
	client, err := NewClient(ClientConfig{Credentials: cred})
	if err != nil {
		t.Fatal(err)
	}
	owner := newSession(client.sessionCtx, sessionInfo{ID: randomID(), lifetimeUntil: time.Now().Add(time.Minute)}, Options{}, true, nil)
	client.current = owner // No carrier: a real bounded unconfirmed close result.
	client.wg.Add(1)
	joined := false
	t.Cleanup(func() {
		if !joined {
			client.wg.Done()
		}
		owner.cancel()
		_ = client.Close()
	})
	cancelled := make(chan struct{})
	originalCancel := client.cancel
	client.cancel = func() { originalCancel(); close(cancelled) }
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { first <- client.Close() }()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("first Client.Close did not publish client termination")
	}
	go func() { second <- client.Close() }()
	// Both calls must wait for the same first completion, including worker join.
	for _, result := range []<-chan error{first, second} {
		select {
		case <-result:
			t.Fatal("concurrent Client.Close returned before shared completion")
		case <-time.After(20 * time.Millisecond):
		}
	}
	client.wg.Done()
	joined = true
	a, b := next10AwaitClose(t, first), next10AwaitClose(t, second)
	if !errors.Is(a, ErrCloseUnconfirmed) || a != b || client.Close() != a {
		t.Fatal("Client.Close did not preserve its Session close result")
	}
}

func TestNext10AdmissionExplicitConnectCreatesFreshSessionDuringOldDrain(t *testing.T) {
	server, cred := newSecurityTestServer(t)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background()) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case <-serveDone:
		case <-time.After(time.Second):
			t.Error("server did not stop")
		}
	})
	client, err := NewClient(ClientConfig{Server: server.Addr().String(), TCPServer: server.Addr().String(), Credentials: cred})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	old, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	oldInfo, err := sessionSnapshot(old)
	if err != nil {
		t.Fatal(err)
	}
	unblock := next10BlockActor(t, old)
	result := next10BeginCloseAtBarrier(t, old)
	t.Cleanup(func() { old.cancel(); unblock(); next10AwaitClose(t, result) })
	fresh, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	freshInfo, err := sessionSnapshot(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if fresh == old || freshInfo.ID == oldInfo.ID || freshInfo.ClientAddress == oldInfo.ClientAddress || freshInfo.Ticket == oldInfo.Ticket {
		t.Error("explicit Connect reused closing temporary identity")
	}
	if old.closed() || !old.terminating() || fresh.terminating() {
		t.Error("fresh Session admission changed the old terminal decision")
	}
}

type next10RevokeCleanupLocks struct {
	server, authority bool
}

type next10RevokeCleanupFactory struct {
	server    *Server
	authority *deviceAuthority
	cleanup   chan next10RevokeCleanupLocks
	calls     atomic.Int32
}

func (f *next10RevokeCleanupFactory) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("test: no unscoped target dial is authorized")
}

func (f *next10RevokeCleanupFactory) ForSession(context.Context, func() error) (Backend, func()) {
	return &net.Dialer{}, func() {
		f.calls.Add(1)
		locks := next10RevokeCleanupLocks{}
		locks.server = f.server.mu.TryLock()
		if locks.server {
			f.server.mu.Unlock()
		}
		locks.authority = f.authority.gate.TryLock()
		if locks.authority {
			f.authority.gate.Unlock()
		}
		f.cleanup <- locks
	}
}

func TestNext10AdmissionRevokeScopeCleanupOutsideRegistryLocks(t *testing.T) {
	server, cred := newSecurityTestServer(t)
	server.mu.Lock()
	authority := server.devices[string(cred.Public)]
	server.mu.Unlock()
	factory := &next10RevokeCleanupFactory{server: server, authority: authority, cleanup: make(chan next10RevokeCleanupLocks, 2)}
	server.cfg.Backend = factory
	p, _, _ := ticketAdversarialCommit(t, server, cred, 47303)
	owner := p.session
	// Hold the actor so the external administrative path, rather than an actor
	// maintenance tick observing revoked, must cause this first scope cleanup.
	unblock := next10BlockActor(t, owner)
	result := make(chan error, 1)
	go func() { result <- server.RevokeDevice(cred.Public) }()
	select {
	case locks := <-factory.cleanup:
		if !locks.server || !locks.authority {
			t.Error("administrative revocation ran scope cleanup under registry or device locks")
		}
	case <-time.After(time.Second):
		t.Fatal("administrative revocation did not execute terminal scope cleanup")
	}
	if !authority.revoked.Load() || !owner.terminating() || owner.closed() {
		t.Error("scope cleanup did not occur after revocation publication and before actor stop")
	}
	select {
	case <-result:
		t.Fatal("RevokeDevice returned before the owned actor completed")
	default:
	}
	unblock()
	if err := next10AwaitClose(t, result); err != nil {
		t.Fatal(err)
	}
	if !owner.closed() || factory.calls.Load() != 1 {
		t.Fatal("revocation did not stop the owner with exactly one scope cleanup")
	}
	ticketAdversarialNoTickets(t, server)
	if err := server.RevokeDevice(cred.Public); err != nil || factory.calls.Load() != 1 {
		t.Fatal("repeated administrative revocation duplicated scope cleanup")
	}
}
