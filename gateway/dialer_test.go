package gateway

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewRejectsInvalidPolicy(t *testing.T) {
	for _, p := range []Policy{{AllowedCIDRs: []string{"bad"}}, {AllowedPorts: []int{0}}, {AllowedPorts: []int{65536}}, {Timeout: -1}, {MaxConcurrent: -1}} {
		if _, err := New(p); err == nil {
			t.Fatalf("accepted invalid policy: %+v", p)
		}
	}
}

func TestResolveOnceValidateAllAndDialNumeric(t *testing.T) {
	d, _ := New(Policy{})
	var lookups, dials int
	d.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		lookups++
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}
	d.dial = func(context.Context, string, string) (net.Conn, error) {
		dials++
		return nil, nil
	}
	if _, err := d.DialContext(context.Background(), "tcp", "mixed.example:443"); !errors.Is(err, ErrPolicyDenied) || dials != 0 || lookups != 1 {
		t.Fatalf("mixed DNS result was not rejected before dialing: %v, lookups=%d dials=%d", err, lookups, dials)
	}
	d.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		lookups++
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("1.1.1.1")}}, nil
	}
	d.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		dials++
		if network != "tcp" || address != "8.8.8.8:443" {
			t.Fatalf("dial was not pinned to the validated numeric peer: %s %s", network, address)
		}
		return nil, nil
	}
	if _, err := d.DialContext(context.Background(), "tcp", "public.example:443"); err != nil || dials != 1 || lookups != 2 {
		t.Fatalf("public DNS result failed: %v", err)
	}
}

func TestPolicyAddressesAndRestrictions(t *testing.T) {
	defaultDialer, _ := New(Policy{})
	for _, address := range []string{"127.0.0.1:80", "10.0.0.1:80", "169.254.169.254:80", "100.64.0.1:80", "[::1]:80", "[fc00::1]:80", "[::ffff:127.0.0.1]:80", "224.0.0.1:80", "255.255.255.255:80", "[fe80::1%eth0]:80"} {
		if _, err := defaultDialer.DialContext(context.Background(), "tcp", address); !errors.Is(err, ErrPolicyDenied) {
			t.Errorf("default policy allowed %s: %v", address, err)
		}
	}
	d, _ := New(Policy{AllowPrivate: true, AllowedCIDRs: []string{"127.0.0.0/8"}, AllowedPorts: []int{12345}})
	var dialed string
	d.dial = func(_ context.Context, _, address string) (net.Conn, error) { dialed = address; return nil, nil }
	if _, err := d.DialContext(context.Background(), "udp", "127.0.0.1:12345"); err != nil || dialed != "127.0.0.1:12345" {
		t.Fatalf("explicit loopback policy failed: %v", err)
	}
	for _, address := range []string{"127.0.0.1:80", "10.0.0.1:12345"} {
		if _, err := d.DialContext(context.Background(), "tcp", address); !errors.Is(err, ErrPolicyDenied) {
			t.Errorf("restriction allowed %s: %v", address, err)
		}
	}
}

func TestConcurrentDialsAreBoundedAndWaitCancelable(t *testing.T) {
	d, _ := New(Policy{AllowPrivate: true, MaxConcurrent: 1, Timeout: time.Second})
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var active atomic.Int32
	d.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		if active.Add(1) != 1 {
			t.Error("concurrent dial limit exceeded")
		}
		defer active.Add(-1)
		started <- struct{}{}
		select {
		case <-release:
			return nil, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	done := make(chan error, 1)
	go func() { _, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:12345"); done <- err }()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if _, err := d.DialContext(ctx, "tcp", "127.0.0.1:12345"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued dial did not cancel: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRealLoopbackTCPAndUDP(t *testing.T) {
	d, _ := New(Policy{AllowPrivate: true})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	(<-accepted).Close()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	u, err := d.DialContext(context.Background(), "udp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if _, err := u.Write([]byte("datagram")); err != nil {
		t.Fatal(err)
	}
	udp.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 32)
	n, _, err := udp.ReadFrom(b)
	if err != nil || string(b[:n]) != "datagram" {
		t.Fatalf("UDP boundary failed: %q %v", b[:n], err)
	}
}
