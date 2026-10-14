package gateway

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
)

// The fake-IP allocator and reverse NAT belong to the selected Mihomo/sing-box
// adapter.  BFP only enforces the boundary: an address still in the upstream
// fake pool must never become an exit dial, including in explicitly private
// localhost fixtures.
func TestGatewayRejectsUnrestoredFakeIPEvenWithPrivatePolicy(t *testing.T) {
	d, err := New(Policy{AllowPrivate: true, AllowedCIDRs: []string{"198.18.0.0/15", "fd42:6266:7000::/96"}})
	if err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int32
	d.dial = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, nil
	}
	for _, address := range []string{
		"198.18.0.1:443",
		"198.19.255.254:443",
		"[::ffff:198.18.1.7]:443",
		"[fd42:6266:7000::c612:107]:443",
		"[fd42:6266:7000::1234]:443",
		"[fd42:6266:7000::c612:107%lo]:443",
	} {
		for _, network := range []string{"tcp", "udp"} {
			if _, err := d.DialContext(context.Background(), network, address); !errors.Is(err, ErrPolicyDenied) {
				t.Errorf("unrestored fake-IP %s %s was accepted: %v", network, address, err)
			}
		}
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("fake-IP rejection reached the OS dial hook %d times", got)
	}
	if !isFakeIP(netip.MustParseAddr("198.18.0.1")) || !isFakeIP(netip.MustParseAddr("::ffff:198.18.0.1")) {
		t.Fatal("fake-IP detector did not normalize IPv4-mapped input")
	}
}

func TestSessionDNSDoesNotCacheOrDialUnrestoredFakeIP(t *testing.T) {
	factory, err := New(Policy{AllowPrivate: true, AllowedCIDRs: []string{"198.18.0.0/15"}})
	if err != nil {
		t.Fatal(err)
	}
	var lookups, dials atomic.Int32
	factory.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		lookups.Add(1)
		return []net.IPAddr{{IP: net.ParseIP("198.18.1.9")}}, nil
	}
	factory.dial = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, nil
	}
	dialer, stop := factory.ForSession(context.Background(), nil)
	d := dialer.(*Dialer)
	defer stop()
	for i := 0; i < 2; i++ {
		if _, err := d.DialContext(context.Background(), "tcp", "still-fake.example:443"); !errors.Is(err, ErrPolicyDenied) {
			t.Fatalf("DNS fake-IP result was accepted on attempt %d: %v", i+1, err)
		}
	}
	if got := lookups.Load(); got != 2 {
		t.Fatalf("denied fake-IP answer was cached; lookups=%d", got)
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("denied fake-IP answer reached the OS dial hook %d times", got)
	}
	if entries, closed, _ := dnsState(d); entries != 0 || closed {
		t.Fatalf("denied fake-IP answer changed the live Session DNS cache: entries=%d closed=%v", entries, closed)
	}
}
