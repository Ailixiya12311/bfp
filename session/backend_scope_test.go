package session

import (
	"bfp/internal/backend"
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The factory records the actual lifetime guard and context supplied by the
// Session constructor. Its unscoped DialContext deliberately fails: a Session
// that bypasses the returned scoped backend cannot satisfy these tests.
type backendScopeTestFactory struct {
	mu            sync.Mutex
	scopes        []*backendScopeTestDialer
	unscopedDials atomic.Int32
}

var _ backend.SessionFactory = (*backendScopeTestFactory)(nil)
var _ backend.Dialer = (*backendScopeTestFactory)(nil)

func (f *backendScopeTestFactory) DialContext(context.Context, string, string) (net.Conn, error) {
	f.unscopedDials.Add(1)
	return nil, errors.New("test: unscoped factory used for a target dial")
}

func (f *backendScopeTestFactory) ForSession(ctx context.Context, valid func() error) (backend.Dialer, func()) {
	scope := &backendScopeTestDialer{ctx: ctx, valid: valid, cached: map[string]bool{"retained-test-entry": true}}
	f.mu.Lock()
	f.scopes = append(f.scopes, scope)
	f.mu.Unlock()
	return scope, func() {
		// State clearing itself is idempotent. Count every invocation so a
		// duplicate call is observable rather than hidden by this fake.
		scope.closeCalls.Add(1)
		scope.mu.Lock()
		scope.stopped = true
		scope.cached = nil
		scope.mu.Unlock()
	}
}

type backendScopeTestDialer struct {
	ctx        context.Context
	valid      func() error
	mu         sync.Mutex
	cached     map[string]bool
	stopped    bool
	dials      atomic.Int32
	closeCalls atomic.Int32
}

func (s *backendScopeTestDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.valid(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil, ErrClosed
	}
	if err := s.valid(); err != nil {
		return nil, err
	}
	s.dials.Add(1)
	client, peer := net.Pipe()
	peer.Close()
	return client, nil
}

func backendScopeTestCount(t *testing.T, factory *backendScopeTestFactory, want int) {
	t.Helper()
	factory.mu.Lock()
	count := len(factory.scopes)
	factory.mu.Unlock()
	if count != want || factory.unscopedDials.Load() != 0 {
		t.Fatalf("scope creations=%d want=%d unscoped dials=%d", count, want, factory.unscopedDials.Load())
	}
}

func backendScopeTestOnly(t *testing.T, factory *backendScopeTestFactory, owner *Session) *backendScopeTestDialer {
	t.Helper()
	backendScopeTestCount(t, factory, 1)
	factory.mu.Lock()
	scope := factory.scopes[0]
	factory.mu.Unlock()
	if scope.ctx == nil || scope.valid == nil || scope.ctx != owner.ctx || owner.backend != scope {
		t.Fatal("fresh Session did not install its scoped backend with the Session context and guard")
	}
	return scope
}

func backendScopeTestLiveDial(t *testing.T, dialer Backend) {
	t.Helper()
	conn, err := dialer.DialContext(context.Background(), "tcp", "fixture.invalid:443")
	if err != nil || conn == nil {
		t.Fatalf("live scoped backend dial failed: %v", err)
	}
	conn.Close()
}

func backendScopeTestRejectedDial(t *testing.T, scope *backendScopeTestDialer) {
	t.Helper()
	before := scope.dials.Load()
	if err := scope.valid(); err == nil {
		t.Fatal("constructor-supplied authorization guard remained valid after terminal authority")
	}
	conn, err := scope.DialContext(context.Background(), "tcp", "fixture.invalid:443")
	if conn != nil {
		conn.Close()
	}
	if err == nil || conn != nil || scope.dials.Load() != before {
		t.Fatal("terminal authority reached a scoped backend target dial")
	}
}

func backendScopeTestCleared(t *testing.T, scope *backendScopeTestDialer) {
	t.Helper()
	scope.mu.Lock()
	stopped, entries := scope.stopped, len(scope.cached)
	scope.mu.Unlock()
	if scope.closeCalls.Load() != 1 || !stopped || entries != 0 {
		t.Fatalf("terminal cleanup calls=%d stopped=%t retained entries=%d", scope.closeCalls.Load(), stopped, entries)
	}
}

func backendScopeTestWaitDone(t *testing.T, owner *Session) {
	t.Helper()
	select {
	case <-owner.done:
	case <-time.After(time.Second):
		t.Fatal("terminal Session did not finish its backend cleanup")
	}
}

// Holding the actor lets the test inspect the constructor-supplied guard before
// periodic maintenance or actor cleanup can provide a second rejection path.
func backendScopeTestHoldActor(t *testing.T, owner *Session) func() {
	t.Helper()
	held, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	owner.post(func() {
		close(held)
		<-release
	})
	select {
	case <-held:
	case <-time.After(time.Second):
		t.Fatal("Session actor did not reach the controlled guard observation")
	}
	return unblock
}

func TestBackendScopeFreshNoiseCommitAndResumeReuse(t *testing.T) {
	server, credentials := newSecurityTestServer(t)
	factory := &backendScopeTestFactory{}
	server.cfg.Backend = factory
	attempt := randomID()
	pending, proof, _ := prepareCandidate(t, server, credentials, "udp", attempt, 47381, nil)
	backendScopeTestCount(t, factory, 0)
	if pending.session != nil {
		t.Fatal("authenticated INIT allocated a Session before fresh confirmation")
	}
	ready, committed, err := server.confirm(proof, "udp", pending.peer)
	if err != nil || committed != pending || pending.session == nil {
		t.Fatalf("fresh authenticated confirmation failed: %v", err)
	}
	owner := pending.session
	scope := backendScopeTestOnly(t, factory, owner)
	if scope.dials.Load() != 0 || scope.closeCalls.Load() != 0 || scope.valid() != nil {
		t.Fatal("fresh confirmation unexpectedly dialed or closed its backend scope")
	}
	backendScopeTestLiveDial(t, owner.backend)
	duplicate, _, err := server.confirm(proof, "udp", pending.peer)
	if err != nil || !bytes.Equal(duplicate, ready) {
		t.Fatalf("same-proof confirmation retry failed: %v", err)
	}
	backendScopeTestCount(t, factory, 1)

	// A fresh Noise candidate belonging to the committed initial attempt also
	// attaches to the existing Session rather than creating another scope.
	late, lateProof, _ := prepareCandidate(t, server, credentials, "udp", attempt, 47382, nil)
	if _, _, err = server.confirm(lateProof, "udp", late.peer); err != nil || late.session != owner {
		t.Fatalf("same-attempt fresh Noise retry did not retain Session: %v", err)
	}
	previous, err := sessionSnapshot(owner)
	if err != nil {
		t.Fatal(err)
	}
	resumed, resumeProof, _ := prepareCandidate(t, server, credentials, "tcp", randomID(), 0, &previous)
	if _, _, err = server.confirm(resumeProof, "tcp", resumed.peer); err != nil || resumed.session != owner {
		t.Fatalf("authenticated TCP resume did not retain Session: %v", err)
	}
	if backendScopeTestOnly(t, factory, owner) != scope || scope.closeCalls.Load() != 0 || scope.dials.Load() != 1 {
		t.Fatal("carrier replacement rebuilt, closed, or unexpectedly dialed the retained backend scope")
	}
	backendScopeTestLiveDial(t, owner.backend)
	owner.Close()
	backendScopeTestCleared(t, scope)
}

func TestBackendScopeRejectedFreshConfirmationCreatesNoScope(t *testing.T) {
	server, credentials := newSecurityTestServer(t)
	factory := &backendScopeTestFactory{}
	server.cfg.Backend = factory
	pending, proof, _ := prepareCandidate(t, server, credentials, "udp", randomID(), 47383, nil)
	backendScopeTestCount(t, factory, 0)
	if _, _, err := server.confirm(proof, "udp", "127.0.0.1:47384"); err == nil {
		t.Fatal("confirmation accepted a different source")
	}
	bad := proof
	bad.Message = append([]byte(nil), proof.Message...)
	bad.Message[len(bad.Message)-1] ^= 1
	if _, _, err := server.confirm(bad, "udp", pending.peer); err == nil {
		t.Fatal("tampered encrypted fresh confirmation was accepted")
	}
	if err := server.RevokeDevice(credentials.Public); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.confirm(proof, "udp", pending.peer); err == nil {
		t.Fatal("revoked pending candidate committed")
	}
	backendScopeTestCount(t, factory, 0)
	if pending.session != nil {
		t.Fatal("rejected confirmation created a Session backend scope")
	}
}

func TestBackendScopeTerminalClearExactlyOnce(t *testing.T) {
	for _, reason := range []string{"close", "context-cancel", "revocation"} {
		t.Run(reason, func(t *testing.T) {
			server, credentials := newSecurityTestServer(t)
			factory := &backendScopeTestFactory{}
			server.cfg.Backend = factory
			pending, proof, _ := prepareCandidate(t, server, credentials, "udp", randomID(), 47385, nil)
			if _, _, err := server.confirm(proof, "udp", pending.peer); err != nil {
				t.Fatal(err)
			}
			owner := pending.session
			scope := backendScopeTestOnly(t, factory, owner)
			backendScopeTestLiveDial(t, owner.backend)
			switch reason {
			case "close":
				owner.Close()
			case "context-cancel":
				unblock := backendScopeTestHoldActor(t, owner)
				owner.cancel()
				if scope.ctx.Err() == nil {
					t.Fatal("backend context did not synchronously observe Session cancellation")
				}
				backendScopeTestRejectedDial(t, scope)
				unblock()
				backendScopeTestWaitDone(t, owner)
			case "revocation":
				unblock := backendScopeTestHoldActor(t, owner)
				// Publish the atomic administrative revocation bit before the
				// cancellation continuation. This isolates the guard's atomic
				// check from both context cancellation and actor maintenance.
				owner.authority.revoked.Store(true)
				if scope.ctx.Err() != nil {
					t.Fatal("test failed to isolate atomic revocation from cancellation")
				}
				backendScopeTestRejectedDial(t, scope)
				unblock()
				if err := server.RevokeDevice(credentials.Public); err != nil {
					t.Fatal(err)
				}
			}
			backendScopeTestRejectedDial(t, scope)
			backendScopeTestCleared(t, scope)
			owner.Close()
			server.Close()
			backendScopeTestCleared(t, scope)
			backendScopeTestCount(t, factory, 1)
		})
	}
}

func TestBackendScopeImmutableDeadlineRejectsBeforeActorCleanup(t *testing.T) {
	server, credentials := newSecurityTestServer(t)
	factory := &backendScopeTestFactory{}
	server.cfg.Backend = factory
	pending, proof, _ := prepareCandidate(t, server, credentials, "udp", randomID(), 47386, nil)
	// Fix this candidate's real authorization deadline before its new Session
	// exists. Production options and the original recovery deadlines are intact.
	deadline := time.Now().Add(200 * time.Millisecond)
	pending.info.lifetimeUntil = deadline
	if _, _, err := server.confirm(proof, "udp", pending.peer); err != nil {
		t.Fatal(err)
	}
	owner := pending.session
	scope := backendScopeTestOnly(t, factory, owner)
	backendScopeTestLiveDial(t, owner.backend)
	held, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	owner.post(func() {
		// Simulate an old mutable field being refreshed by the actor. The
		// factory guard must retain its constructor-time deadline instead.
		owner.info.lifetimeUntil = deadline.Add(time.Hour)
		close(held)
		<-release
		owner.info.lifetimeUntil = deadline
	})
	select {
	case <-held:
	case <-time.After(time.Second):
		t.Fatal("actor did not reach the immutable-deadline observation")
	}
	timer := time.NewTimer(max(time.Duration(0), time.Until(deadline)) + time.Millisecond)
	defer timer.Stop()
	<-timer.C
	if scope.ctx.Err() != nil {
		t.Fatal("test did not isolate the copied deadline from context cancellation")
	}
	backendScopeTestRejectedDial(t, scope)
	unblock()
	backendScopeTestWaitDone(t, owner)
	backendScopeTestCleared(t, scope)
	owner.Close()
	backendScopeTestCleared(t, scope)
}

type backendScopeTestLegacyDialer struct{ dials atomic.Int32 }

func (d *backendScopeTestLegacyDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.dials.Add(1)
	client, peer := net.Pipe()
	peer.Close()
	return client, nil
}

func TestBackendScopeLegacyCustomBackendCompatible(t *testing.T) {
	server, credentials := newSecurityTestServer(t)
	legacy := &backendScopeTestLegacyDialer{}
	if _, ok := any(legacy).(backend.SessionFactory); ok {
		t.Fatal("compatibility fixture unexpectedly implements the factory interface")
	}
	server.cfg.Backend = legacy
	pending, proof, _ := prepareCandidate(t, server, credentials, "udp", randomID(), 47387, nil)
	if _, _, err := server.confirm(proof, "udp", pending.peer); err != nil {
		t.Fatal(err)
	}
	if pending.session.backend != legacy || legacy.dials.Load() != 0 {
		t.Fatal("fresh confirmation replaced or prematurely dialed a custom non-factory backend")
	}
	backendScopeTestLiveDial(t, pending.session.backend)
	if legacy.dials.Load() != 1 {
		t.Fatal("custom non-factory backend no longer receives Session target dials")
	}
	pending.session.Close()
}

func TestBackendScopeTypedNilConfigurationRejectedBeforeListen(t *testing.T) {
	seed, _ := newSecurityTestServer(t)
	cfg := seed.cfg
	// The address is already held by our fixture. A constructor that overlooks
	// the wrapped nil pointer will reach listen and report the wrong error.
	cfg.Listen = seed.Addr().String()
	var missing *backendScopeTestFactory
	cfg.Backend = missing
	if cfg.Backend == nil {
		t.Fatal("test did not create a typed nil inside a non-nil backend interface")
	}
	server, err := NewServer(cfg)
	if server != nil {
		server.Close()
	}
	if server != nil || err == nil || !strings.Contains(err.Error(), "requires backend") {
		t.Fatalf("typed nil backend was not rejected before socket listen: %v", err)
	}
}

type backendScopeTestNilFactory struct {
	factoryCalls atomic.Int32
	dials        atomic.Int32
	closeCalls   atomic.Int32
}

var _ backend.SessionFactory = (*backendScopeTestNilFactory)(nil)

func (f *backendScopeTestNilFactory) DialContext(context.Context, string, string) (net.Conn, error) {
	f.dials.Add(1)
	return nil, errors.New("test: failed scope attempted an unscoped target dial")
}

func (f *backendScopeTestNilFactory) ForSession(context.Context, func() error) (backend.Dialer, func()) {
	f.factoryCalls.Add(1)
	var missing *backendScopeTestDialer
	return missing, func() { f.closeCalls.Add(1) }
}

func TestBackendScopeTypedNilFactoryResultFailsClosedExactlyOnce(t *testing.T) {
	server, credentials := newSecurityTestServer(t)
	factory := &backendScopeTestNilFactory{}
	server.cfg.Backend = factory
	pending, initial, proof, _ := ticketAdversarialCandidate(t, server, credentials, 47388, nil)
	if factory.factoryCalls.Load() != 0 || factory.dials.Load() != 0 {
		t.Fatal("typed nil scope factory was invoked before fresh confirmation")
	}
	ready, _, err := server.confirm(proof, "udp", pending.peer)
	if err == nil || len(ready) != 0 || pending.committed {
		t.Fatal("typed nil backend scope produced a usable committed Session")
	}
	// The aborted constructor may remain in the server registry until normal
	// maintenance. It must be canceled and fully cleaned, never usable by a
	// cached INIT/confirmation or a subsequent target operation.
	if pending.session == nil || pending.session.ctx.Err() == nil {
		t.Fatal("typed nil scoped backend did not cancel its allocated Session")
	}
	backendScopeTestWaitDone(t, pending.session)
	if _, _, err = server.confirm(proof, "udp", pending.peer); err == nil {
		t.Fatal("failed typed nil scope returned cached confirmation success")
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 47388}
	if _, err = server.initialize(initial, "udp", nil, addr); err == nil {
		t.Fatal("failed typed nil scope returned a cached usable INIT candidate")
	}
	pending.session.Close()
	server.Close()
	if factory.factoryCalls.Load() != 1 || factory.closeCalls.Load() != 1 || factory.dials.Load() != 0 {
		t.Fatalf("failed scope factory calls=%d cleanup calls=%d target dials=%d", factory.factoryCalls.Load(), factory.closeCalls.Load(), factory.dials.Load())
	}
}
