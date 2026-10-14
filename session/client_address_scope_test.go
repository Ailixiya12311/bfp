package session

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"bfp/classification"
	"bfp/protocol"
)

type testClientAddressScope struct {
	valid   func() error
	restore func(protocol.Target) (protocol.Target, error)
	closed  atomic.Bool
	closes  atomic.Int32
}

func (s *testClientAddressScope) AllocateSessionAddress(string) (netip.Addr, error) {
	if s.closed.Load() || s.valid() != nil {
		return netip.Addr{}, ErrClosed
	}
	return netip.MustParseAddr("198.18.7.1"), nil
}
func (s *testClientAddressScope) ResolveSessionAddress(netip.Addr) (string, error) {
	if s.closed.Load() || s.valid() != nil {
		return "", ErrClosed
	}
	return "client-map.test", nil
}
func (s *testClientAddressScope) RestoreTarget(t protocol.Target) (protocol.Target, error) {
	if s.valid() != nil {
		return protocol.Target{}, ErrClosed
	}
	if s.restore != nil {
		return s.restore(t)
	}
	t.Address = "client-map.test:443"
	return t, nil
}
func (s *testClientAddressScope) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		s.closes.Add(1)
	}
	return nil
}

type testClientScopeFactory struct {
	scope *testClientAddressScope
	err   error
}

func (f *testClientScopeFactory) ForClientSession(_ context.Context, valid func() error) (ClientAddressScope, error) {
	if f.scope == nil {
		return nil, f.err
	}
	f.scope.valid = valid
	return f.scope, f.err
}

func TestClientAddressScopeParentCancellationAndRetainedGuard(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	scope := &testClientAddressScope{}
	s, err := newSessionWithAddressScope(parent, sessionInfo{ID: "client-parent", lifetimeUntil: time.Now().Add(time.Minute)}, Options{}, true, nil, datagramFECPolicy{}, &testClientScopeFactory{scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	allocator, ok := s.LocalAddressAllocator()
	if !ok || allocator != scope {
		t.Fatal("local allocator is absent or not the exact scope")
	}
	cancel()
	// The retained guard rejects cancellation without waiting for AfterFunc.
	if _, err := allocator.AllocateSessionAddress("after-cancel.test"); !errors.Is(err, ErrClosed) {
		t.Fatalf("parent cancel accepted allocation: %v", err)
	}
	select {
	case <-s.done:
	case <-time.After(time.Second):
		t.Fatal("parent-cancelled actor did not retire")
	}
	if !scope.closed.Load() || scope.closes.Load() != 1 {
		t.Fatal("parent cancellation did not synchronously join scope cleanup")
	}
	if allocator, ok := s.LocalAddressAllocator(); ok || allocator != nil {
		t.Fatal("terminated actor republished local scope")
	}
}

func TestClientAddressScopeFactoryFailureClosesReturnedScope(t *testing.T) {
	for _, missing := range []bool{false, true} {
		scope := &testClientAddressScope{}
		factory := &testClientScopeFactory{scope: scope, err: errors.New("factory failure")}
		if missing {
			factory.scope, factory.err = nil, nil
		}
		s, err := newSessionWithAddressScope(context.Background(), sessionInfo{}, Options{}, true, nil, datagramFECPolicy{}, factory)
		if s != nil || err == nil {
			t.Fatal("failed factory published a Session")
		}
		if !missing && (!scope.closed.Load() || scope.closes.Load() != 1) {
			t.Fatal("scope returned with error was not synchronously destroyed")
		}
	}
}

func TestClientAddressScopeRestorePreservesContractsAndTrust(t *testing.T) {
	delivery := protocol.DefaultDelivery("udp")
	fec := protocol.DisabledFECProfile()
	original := protocol.Target{Network: "udp", Address: "198.18.7.1:443", Domain: "caller.test", RuleTag: "caller-rule", Class: protocol.Bulk, Delivery: &delivery, FEC: &fec}
	for _, mutate := range []string{"network", "class", "domain", "rule", "delivery", "fec", "shape"} {
		t.Run(mutate, func(t *testing.T) {
			scope := &testClientAddressScope{restore: func(target protocol.Target) (protocol.Target, error) {
				target.Address = "client-map.test:443"
				switch mutate {
				case "network":
					target.Network = "tcp"
				case "class":
					target.Class = protocol.Interactive
				case "domain":
					target.Domain = "injected.test"
				case "rule":
					target.RuleTag = "injected-rule"
				case "delivery":
					target.Delivery.Version++
				case "fec":
					target.FEC.Version++
				case "shape":
					target.Address = "not-a-target"
				}
				return target, nil
			}}
			s, err := newSessionWithAddressScope(context.Background(), sessionInfo{ID: "bad-restorer"}, Options{}, true, nil, datagramFECPolicy{}, &testClientScopeFactory{scope: scope})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { s.cancel(); <-s.done }()
			if conn, err := s.DialMetadata(context.Background(), classification.Metadata{Target: original, DomainTrusted: true, RuleTagTrusted: true}); conn != nil || !errors.Is(err, ErrClientAddressScope) {
				t.Fatalf("invalid restorer created flow: conn=%v err=%v", conn, err)
			}
			if s.Stats().Opened != 0 || *original.Delivery != delivery || *original.FEC != fec {
				t.Fatal("invalid restorer mutated admitted contracts or created OPEN")
			}
		})
	}
	guard := &clientScopeLifetime{ctx: context.Background()}
	scope := &testClientAddressScope{valid: guard.check}
	restored, err := restoreLocalAddress(scope, original)
	if err != nil || restored.Address != "client-map.test:443" || restored.Domain != original.Domain || restored.RuleTag != original.RuleTag || restored.Class != original.Class || *restored.Delivery != delivery || *restored.FEC != fec {
		t.Fatalf("address-only restoration damaged caller metadata: %+v err=%v", restored, err)
	}
}

func TestClientAddressScopeResumeDeadlineOnlyShortens(t *testing.T) {
	guard := &clientScopeLifetime{ctx: context.Background()}
	future := time.Now().Add(time.Minute)
	guard.shorten(future)
	guard.shorten(future.Add(time.Minute))
	if !guard.until.Load().Equal(future) {
		t.Fatal("resume extended local scope lifetime")
	}
	guard.shorten(time.Now().Add(-time.Millisecond))
	if !errors.Is(guard.check(), ErrClosed) {
		t.Fatal("expired resume deadline stayed eligible")
	}
}
