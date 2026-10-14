package gateway

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestRouteExclusionRejectsBeforeDialForIPv4AndIPv6(t *testing.T) {
	d, err := New(Policy{
		AllowPrivate:  true,
		AllowedCIDRs:  []string{"0.0.0.0/0", "::/0"},
		ExcludedCIDRs: []string{"8.8.8.0/24", "2001:4860::/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	d.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("excluded destination reached the socket dialer")
		return nil, nil
	}
	for _, address := range []string{"8.8.8.8:443", "[2001:4860:4860::8888]:443"} {
		if _, err := d.DialContext(context.Background(), "tcp", address); !errors.Is(err, ErrRouteExcluded) {
			t.Errorf("%s: got %v, want ErrRouteExcluded", address, err)
		}
	}
}

func TestRouteExclusionRejectsEveryAnswerBeforeDial(t *testing.T) {
	d, err := New(Policy{
		AllowedCIDRs:  []string{"0.0.0.0/0"},
		ExcludedCIDRs: []string{"8.8.8.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	lookups, dials := 0, 0
	d.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		lookups++
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}, {IP: net.ParseIP("8.8.8.8")}}, nil
	}
	d.dial = func(context.Context, string, string) (net.Conn, error) {
		dials++
		return nil, nil
	}
	if _, err := d.DialContext(context.Background(), "tcp", "mixed.example:443"); !errors.Is(err, ErrRouteExcluded) {
		t.Fatalf("mixed route result got %v, want ErrRouteExcluded", err)
	}
	if lookups != 1 || dials != 0 {
		t.Fatalf("resolver/dial side effects were not bounded: lookups=%d dials=%d", lookups, dials)
	}
}

func TestRouteExclusionMatchesIPv4MappedAddress(t *testing.T) {
	d, err := New(Policy{
		AllowPrivate:  true,
		AllowedCIDRs:  []string{"0.0.0.0/0"},
		ExcludedCIDRs: []string{"192.0.2.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	d.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("mapped IPv4 exclusion reached the socket dialer")
		return nil, nil
	}
	if _, err := d.DialContext(context.Background(), "tcp", "[::ffff:192.0.2.7]:443"); !errors.Is(err, ErrRouteExcluded) {
		t.Fatalf("mapped IPv4 exclusion got %v, want ErrRouteExcluded", err)
	}
}

func TestRouteExclusionAcceptsIPv4MappedCIDRSpelling(t *testing.T) {
	d, err := New(Policy{
		AllowPrivate:  true,
		ExcludedCIDRs: []string{"::ffff:192.0.2.7/120"},
	})
	if err != nil {
		t.Fatal(err)
	}
	d.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("mapped CIDR exclusion reached the socket dialer")
		return nil, nil
	}
	for _, address := range []string{"192.0.2.8:443", "[::ffff:192.0.2.8]:443"} {
		if _, err := d.DialContext(context.Background(), "tcp", address); !errors.Is(err, ErrRouteExcluded) {
			t.Errorf("%s: got %v, want ErrRouteExcluded", address, err)
		}
	}
}

func TestRouteExclusionStillRejectsUnmappedFakeIP(t *testing.T) {
	d, err := New(Policy{AllowPrivate: true, AllowedCIDRs: []string{"0.0.0.0/0"}})
	if err != nil {
		t.Fatal(err)
	}
	d.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("unmapped fake-IP reached the socket dialer")
		return nil, nil
	}
	if _, err := d.DialContext(context.Background(), "tcp", "198.18.0.1:443"); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("unmapped fake-IP got %v, want ErrPolicyDenied", err)
	}
}

func TestNewRejectsInvalidRouteExclusion(t *testing.T) {
	if _, err := New(Policy{ExcludedCIDRs: []string{"not-a-cidr"}}); err == nil {
		t.Fatal("invalid route exclusion was accepted")
	}
}

func TestNonExcludedAddressStillUsesAllowedRoute(t *testing.T) {
	d, err := New(Policy{
		AllowedCIDRs:  []string{"8.8.8.0/24"},
		ExcludedCIDRs: []string{"192.0.2.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	d.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "8.8.8.8:443" {
			t.Fatalf("unexpected allowed route dial: %s %s", network, address)
		}
		return nil, nil
	}
	if _, err := d.DialContext(context.Background(), "tcp", "8.8.8.8:443"); err != nil {
		t.Fatalf("non-excluded allowed destination failed: %v", err)
	}
}
