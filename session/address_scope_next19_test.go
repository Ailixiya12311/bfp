package session

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"bfp/internal/backend"
)

// The wrapper proves AddressAllocator publishes exactly the scoped backend
// that fresh authenticated confirmation installed. Carrier recovery must keep
// this identity. No test-only API is used to mutate Session ownership.
type addressScopeNext19Dialer struct {
	*backendScopeTestDialer
	ip netip.Addr
}

func (d *addressScopeNext19Dialer) AllocateSessionAddress(host string) (netip.Addr, error) {
	if err := d.valid(); err != nil {
		return netip.Addr{}, err
	}
	if host == "" {
		return netip.Addr{}, errors.New("test: empty hostname")
	}
	return d.ip, nil
}

func (d *addressScopeNext19Dialer) ResolveSessionAddress(ip netip.Addr) (string, error) {
	if err := d.valid(); err != nil {
		return "", err
	}
	if ip != d.ip {
		return "", errors.New("test: foreign scope address")
	}
	return "session-owned.test", nil
}

type addressScopeNext19Factory struct {
	backendScopeTestFactory
	allocated *addressScopeNext19Dialer
}

func (f *addressScopeNext19Factory) ForSession(ctx context.Context, valid func() error) (backend.Dialer, func()) {
	dialer, stop := f.backendScopeTestFactory.ForSession(ctx, valid)
	f.allocated = &addressScopeNext19Dialer{backendScopeTestDialer: dialer.(*backendScopeTestDialer), ip: netip.MustParseAddr("198.18.2.1")}
	return f.allocated, stop
}

func TestSessionAddressAllocatorPublishesConfirmedScopeAndResumeKeepsIt(t *testing.T) {
	server, credentials := newSecurityTestServer(t)
	factory := &addressScopeNext19Factory{}
	server.cfg.Backend = factory
	pending, proof, _ := prepareCandidate(t, server, credentials, "udp", randomID(), 47391, nil)
	if factory.allocated != nil {
		t.Fatal("INIT created an address scope before fresh confirmation")
	}
	if _, _, err := server.confirm(proof, "udp", pending.peer); err != nil || pending.session == nil {
		t.Fatalf("fresh confirmation failed: %v", err)
	}
	owner := pending.session
	allocator, ok := owner.AddressAllocator()
	if !ok || allocator != factory.allocated {
		t.Fatal("Session accessor did not publish the confirmed scoped backend")
	}
	ip, err := allocator.AllocateSessionAddress("session-owned.test")
	if err != nil {
		t.Fatal(err)
	}
	previous, err := sessionSnapshot(owner)
	if err != nil {
		t.Fatal(err)
	}
	resumed, resumeProof, _ := prepareCandidate(t, server, credentials, "tcp", randomID(), 0, &previous)
	if _, _, err = server.confirm(resumeProof, "tcp", resumed.peer); err != nil || resumed.session != owner {
		t.Fatalf("TCP resume failed: %v", err)
	}
	retained, ok := owner.AddressAllocator()
	if !ok || retained != allocator {
		t.Fatal("carrier replacement changed the address scope")
	}
	if host, err := retained.ResolveSessionAddress(ip); err != nil || host != "session-owned.test" {
		t.Fatalf("carrier replacement lost retained mapping: host=%q err=%v", host, err)
	}
	owner.Close()
	if allocator, ok := owner.AddressAllocator(); ok || allocator != nil {
		t.Fatal("closed Session published a usable address scope")
	}
	if _, err := retained.ResolveSessionAddress(ip); !errors.Is(err, ErrClosed) {
		t.Fatalf("retained allocator accepted termination: %v", err)
	}
	backendScopeTestCleared(t, factory.allocated.backendScopeTestDialer)
}

func TestSessionAddressAllocatorAbsentForLegacyAndClient(t *testing.T) {
	for _, client := range []bool{false, true} {
		owner := newSession(context.Background(), sessionInfo{}, Options{}, client, &backendScopeTestLegacyDialer{})
		if allocator, ok := owner.AddressAllocator(); ok || allocator != nil {
			t.Fatal("backend without allocator exposed an address scope")
		}
		owner.cancel()
		backendScopeTestWaitDone(t, owner)
	}
	var missing *Session
	if allocator, ok := missing.AddressAllocator(); ok || allocator != nil {
		t.Fatal("nil Session exposed an address scope")
	}
}
