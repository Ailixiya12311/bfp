package session

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

type testLeaseScope struct {
	*testClientAddressScope
	expires     time.Time
	allocations int
}

func (s *testLeaseScope) AllocateSessionAddressLease(string) (netip.Addr, time.Time, error) {
	s.allocations++
	if s.valid() != nil {
		return netip.Addr{}, time.Time{}, ErrClosed
	}
	return netip.MustParseAddr("198.18.8.9"), s.expires, nil
}

type testFamilyLeaseScope struct {
	*testLeaseScope
	v6 netip.Addr
}

func (s *testFamilyLeaseScope) AllocateSessionAddressLeaseForFamily(host string, family LocalAddressFamily) (netip.Addr, time.Time, error) {
	if family == LocalAddressIPv4 {
		return s.AllocateSessionAddressLease(host)
	}
	return s.v6, s.expires, nil
}

type testFamilyLeaseFactory struct{ scope *testFamilyLeaseScope }

func (f *testFamilyLeaseFactory) ForClientSession(_ context.Context, valid func() error) (ClientAddressScope, error) {
	f.scope.valid = valid
	return f.scope, nil
}

func TestLocalAddressFamilyLeaseRequiresCapabilityAndValidFamily(t *testing.T) {
	now := time.Now()
	legacy, scope := newLeaseOwner(t, now.Add(20*time.Second), now.Add(10*time.Second))
	for _, family := range []LocalAddressFamily{LocalAddressIPv6, 0, 5} {
		if _, err := legacy.AllocateLocalAddressLeaseForFamily(context.Background(), "unsupported.test", family); !errors.Is(err, ErrClientAddressScope) {
			t.Fatalf("unsupported family allocated: %d %v", family, err)
		}
	}
	if scope.allocations != 0 {
		t.Fatal("unsupported IPv6 consumed an IPv4 mapping")
	}
	if lease, err := legacy.AllocateLocalAddressLeaseForFamily(context.Background(), "legacy.test", LocalAddressIPv4); err != nil || !lease.Address.Is4() {
		t.Fatal("IPv4 legacy scope compatibility lost")
	}
	for _, ip := range []netip.Addr{netip.MustParseAddr("fd42:6266:7000::c612:809"), netip.MustParseAddr("198.18.8.9"), netip.MustParseAddr("fd42:6266:7000::c612:809%lo"), netip.Addr{}} {
		t.Run(ip.String(), func(t *testing.T) {
			mapEnd, sessionEnd := now.Add(20*time.Second), now.Add(10*time.Second)
			familyScope := &testFamilyLeaseScope{testLeaseScope: &testLeaseScope{testClientAddressScope: &testClientAddressScope{}, expires: mapEnd}, v6: ip}
			owner, err := newSessionWithAddressScope(context.Background(), sessionInfo{ID: "family-owner", lifetimeUntil: sessionEnd}, Options{}, true, nil, datagramFECPolicy{}, &testFamilyLeaseFactory{scope: familyScope})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { owner.cancel(); <-owner.done }()
			lease, err := owner.AllocateLocalAddressLeaseForFamily(context.Background(), "family.test", LocalAddressIPv6)
			if !ip.Is6() || ip.Zone() != "" {
				if !errors.Is(err, ErrClientAddressScope) {
					t.Fatalf("invalid IPv6 scope answer accepted: %v", err)
				}
				return
			}
			if err != nil || lease.Address != ip || !lease.ExpiresAt.Equal(sessionEnd) {
				t.Fatalf("IPv6 lease lost Session deadline: %+v %v", lease, err)
			}
			if remaining, err := owner.ValidateLocalAddressLease(context.Background(), lease); err != nil || remaining <= 0 || remaining > 10*time.Second {
				t.Fatalf("IPv6 validation not bounded: %s %v", remaining, err)
			}
			if _, err := legacy.ValidateLocalAddressLease(context.Background(), lease); !errors.Is(err, ErrClosed) {
				t.Fatal("IPv6 lease transferred to another owner")
			}
			owner.cancel()
			<-owner.done
			if _, err := owner.ValidateLocalAddressLease(context.Background(), lease); !errors.Is(err, ErrClosed) {
				t.Fatal("terminal IPv6 owner validated a lease")
			}
		})
	}
}
func (s *testLeaseScope) SessionAddressLeaseExpiry(netip.Addr) (time.Time, error) {
	if s.valid() != nil {
		return time.Time{}, ErrClosed
	}
	return s.expires, nil
}

type testLeaseFactory struct{ scope *testLeaseScope }

func (f *testLeaseFactory) ForClientSession(_ context.Context, valid func() error) (ClientAddressScope, error) {
	f.scope.valid = valid
	return f.scope, nil
}

func newLeaseOwner(t *testing.T, expires, lifetime time.Time) (*Session, *testLeaseScope) {
	t.Helper()
	scope := &testLeaseScope{testClientAddressScope: &testClientAddressScope{}, expires: expires}
	s, err := newSessionWithAddressScope(context.Background(), sessionInfo{ID: "lease-owner", lifetimeUntil: lifetime}, Options{}, true, nil, datagramFECPolicy{}, &testLeaseFactory{scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.cancel(); <-s.done })
	return s, scope
}

func TestLocalAddressLeaseBoundsActualMapAndSessionAndRejectsForeignOwner(t *testing.T) {
	now := time.Now()
	mapEnd, sessionEnd := now.Add(20*time.Second), now.Add(10*time.Second)
	first, _ := newLeaseOwner(t, mapEnd, sessionEnd)
	lease, err := first.AllocateLocalAddressLease(context.Background(), "lease.test")
	if err != nil || !lease.ExpiresAt.Equal(sessionEnd) || !lease.mappingExpiry.Equal(mapEnd) {
		t.Fatalf("lease not bounded by actual Session: %+v err=%v", lease, err)
	}
	second, _ := newLeaseOwner(t, mapEnd, sessionEnd)
	if _, err := second.ValidateLocalAddressLease(context.Background(), lease); !errors.Is(err, ErrClosed) {
		t.Fatalf("foreign Session accepted DNS lease: %v", err)
	}
	shortMap, _ := newLeaseOwner(t, now.Add(2*time.Second), sessionEnd)
	short, err := shortMap.AllocateLocalAddressLease(context.Background(), "short.test")
	if err != nil || !short.ExpiresAt.Equal(now.Add(2*time.Second)) {
		t.Fatalf("lease ignored original map TTL: %+v err=%v", short, err)
	}
	if err := first.call(context.Background(), func() { first.localAddressGuard.shorten(time.Now().Add(200 * time.Millisecond)) }); err != nil {
		t.Fatal(err)
	}
	remaining, err := first.ValidateLocalAddressLease(context.Background(), lease)
	if err != nil || remaining <= 0 || remaining > 200*time.Millisecond {
		t.Fatalf("validation extended shortened actual lifetime: %s %v", remaining, err)
	}
	first.cancel()
	<-first.done
	if _, err := first.ValidateLocalAddressLease(context.Background(), lease); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed lease accepted: %v", err)
	}
}

func TestLocalAddressLeaseRejectsReboundOrExpiredEntry(t *testing.T) {
	now := time.Now()
	s, scope := newLeaseOwner(t, now.Add(5*time.Second), now.Add(10*time.Second))
	lease, err := s.AllocateLocalAddressLease(context.Background(), "lease.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.call(context.Background(), func() { scope.expires = scope.expires.Add(time.Second) }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidateLocalAddressLease(context.Background(), lease); !errors.Is(err, ErrState) {
		t.Fatalf("rebound numeric address accepted old DNS lease: %v", err)
	}
	expired, _ := newLeaseOwner(t, now.Add(-time.Second), now.Add(10*time.Second))
	if _, err := expired.AllocateLocalAddressLease(context.Background(), "expired.test"); !errors.Is(err, ErrClosed) {
		t.Fatalf("expired map lease allocated: %v", err)
	}
}
