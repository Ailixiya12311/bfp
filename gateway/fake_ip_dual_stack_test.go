package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"bfp/internal/addressscope"
	"bfp/protocol"
)

func TestFakeIPBothFamiliesShareCapacityExpiryAndOwnership(t *testing.T) {
	scope, err := NewFakeIPScope(context.Background(), time.Minute, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer scope.Close()
	foreign, err := NewFakeIPScope(context.Background(), time.Minute, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	var last4, last6 netip.Addr
	for i := 0; i < 64; i++ {
		host := fmt.Sprintf("dual-%d.test", i)
		v6, until6, err := scope.AllocateSessionAddressLeaseForFamily(host, addressscope.IPv6)
		if err != nil {
			t.Fatal(err)
		}
		v4, until4, err := scope.AllocateSessionAddressLeaseForFamily(host, addressscope.IPv4)
		if err != nil || !until4.Equal(until6) {
			t.Fatalf("families split or extended entry: %v", err)
		}
		key, ok := addressscope.MappingAddress(v6)
		if !ok || key != v4 || !v6.Is6() {
			t.Fatal("families do not identify one logical mapping")
		}
		for _, ip := range []netip.Addr{v4, v6} {
			if resolved, err := scope.Resolve(ip); err != nil || resolved != host {
				t.Fatalf("reverse map %s: %q %v", ip, resolved, err)
			}
			if _, err := foreign.Resolve(ip); !errors.Is(err, ErrFakeIPUnmapped) {
				t.Fatalf("foreign scope accepted %s: %v", ip, err)
			}
			if expiry, err := scope.SessionAddressLeaseExpiry(ip); err != nil || !expiry.Equal(until4) {
				t.Fatal("alias owns a different expiry")
			}
		}
		last4, last6 = v4, v6
	}
	if hosts, ips, _ := fakeIPScopeState(scope); hosts != 64 || ips != 64 {
		t.Fatal("A/AAAA doubled mapping capacity")
	}
	if _, _, err := scope.AllocateSessionAddressLeaseForFamily("overflow.test", addressscope.IPv6); !errors.Is(err, ErrFakeIPCapacity) {
		t.Fatalf("capacity exceeded: %v", err)
	}
	for _, network := range []string{"tcp", "udp"} {
		target := protocol.Target{Network: network, Address: netip.AddrPortFrom(last6, 443).String(), Class: protocol.Bulk}
		restored, err := scope.RestoreTarget(target)
		expected := target
		expected.Address = "dual-63.test:443"
		if err != nil || restored != expected {
			t.Fatalf("IPv6 restoration changed target policy: %+v %v", restored, err)
		}
	}
	// Both aliases retire together even when external DNS still retains them.
	scope.mu.Lock()
	entry := scope.byHost["dual-63.test"]
	entry.expires = time.Now().Add(-time.Second)
	scope.byHost["dual-63.test"] = entry
	scope.mu.Unlock()
	for _, ip := range []netip.Addr{last4, last6} {
		if _, err := scope.Resolve(ip); !errors.Is(err, ErrFakeIPUnmapped) {
			t.Fatalf("expired alias usable: %s %v", ip, err)
		}
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []netip.Addr{last4, last6} {
		if _, err := scope.Resolve(ip); !errors.Is(err, ErrFakeIPScopeClosed) {
			t.Fatalf("closed scope alias usable: %s %v", ip, err)
		}
	}
}

func TestFakeIPIPv6UnknownAndZonedAliasesNeverFallThrough(t *testing.T) {
	scope, err := NewFakeIPScope(context.Background(), time.Minute, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer scope.Close()
	ip, _, err := scope.AllocateSessionAddressLeaseForFamily("known.test", addressscope.IPv6)
	if err != nil {
		t.Fatal(err)
	}
	for _, unknown := range []netip.Addr{ip.WithZone("lo"), ip.Next(), netip.MustParseAddr("fd42:6266:7000::1234")} {
		if _, err := scope.RestoreTarget(protocol.Target{Network: "tcp", Address: netip.AddrPortFrom(unknown, 443).String()}); !errors.Is(err, ErrFakeIPUnmapped) {
			t.Fatalf("invalid IPv6 alias fell through: %s %v", unknown, err)
		}
	}
	if _, _, err := scope.AllocateSessionAddressLeaseForFamily("invalid-family.test", 5); !errors.Is(err, ErrFakeIPConfig) {
		t.Fatal("invalid family created mapping")
	}
	if hosts, _, _ := fakeIPScopeState(scope); hosts != 1 {
		t.Fatal("invalid family consumed capacity")
	}
}
