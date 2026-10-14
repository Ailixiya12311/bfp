package gateway

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fallbackAnswers(addresses ...string) []net.IPAddr {
	answers := make([]net.IPAddr, len(addresses))
	for i, address := range addresses {
		answers[i] = net.IPAddr{IP: net.ParseIP(address)}
	}
	return answers
}

func fallbackDialer(t *testing.T, policy Policy) *Dialer {
	t.Helper()
	d, err := New(policy)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func fallbackEcho(t *testing.T) (*net.TCPListener, *atomic.Int32) {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	accepted := &atomic.Int32{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.AcceptTCP()
		if err != nil {
			return
		}
		defer conn.Close()
		accepted.Add(1)
		_, _ = io.Copy(conn, conn)
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("owned echo did not join after close")
		}
	})
	return ln, accepted
}

func fallbackExchange(t *testing.T, conn net.Conn) {
	t.Helper()
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	payload := []byte("one successful numeric TCP candidate")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != string(payload) {
		t.Fatalf("real fallback echo got %q, err=%v", got, err)
	}
}

func TestTCPNumericFallbackRealLoopbackSecondAddress(t *testing.T) {
	ln, accepted := fallbackEcho(t)
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	d := fallbackDialer(t, Policy{AllowPrivate: true, Timeout: time.Second})
	lookups := 0
	d.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		lookups++
		return fallbackAnswers("127.0.0.2", "127.0.0.1"), nil
	}
	var attempts []string
	d.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		attempts = append(attempts, address)
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if len(attempts) == 1 && (conn != nil || err == nil) {
			if conn != nil {
				_ = conn.Close()
			}
			t.Fatal("first loopback address unexpectedly had a listener")
		}
		return conn, err
	}
	conn, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort("numeric-fallback.test", port))
	if err != nil || conn == nil {
		t.Fatalf("second real numeric candidate failed: %v", err)
	}
	fallbackExchange(t, conn)
	if lookups != 1 || strings.Join(attempts, ",") != "127.0.0.2:"+port+",127.0.0.1:"+port || accepted.Load() != 1 {
		t.Fatalf("fallback re-resolved or duplicated success: lookups=%d attempts=%v accepted=%d", lookups, attempts, accepted.Load())
	}
}

func TestTCPNumericFallbackActualLocalhostResolverEcho(t *testing.T) {
	ln, accepted := fallbackEcho(t)
	d := fallbackDialer(t, Policy{AllowPrivate: true, AllowedCIDRs: []string{"127.0.0.0/8", "::1/128"}, Timeout: time.Second})
	lookups := 0
	var actualAnswers []net.IPAddr
	d.lookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		lookups++
		answers, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		actualAnswers = append([]net.IPAddr(nil), answers...)
		return answers, err
	}
	var attempts []string
	d.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil || net.ParseIP(host) == nil {
			t.Fatalf("OS dial would resolve again: %q", address)
		}
		attempts = append(attempts, address)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	conn, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort("localhost", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)))
	if err != nil || conn == nil {
		t.Fatalf("actual localhost failed: answers=%v attempts=%v err=%v", actualAnswers, attempts, err)
	}
	fallbackExchange(t, conn)
	if lookups != 1 || accepted.Load() != 1 {
		t.Fatalf("actual localhost duplicated resolution/connection: lookups=%d accepted=%d", lookups, accepted.Load())
	}
	t.Logf("actual localhost answers=%v numeric attempts=%v", actualAnswers, attempts)
}

func TestTCPNumericFallbackValidatesAllPolicyAndExcludedAnswers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		policy  Policy
		answers []net.IPAddr
		want    error
		network string
	}{
		{"private", Policy{}, fallbackAnswers("8.8.8.8", "127.0.0.1"), ErrPolicyDenied, "tcp"},
		{"other-family-private", Policy{}, fallbackAnswers("8.8.8.8", "fc00::1"), ErrPolicyDenied, "tcp4"},
		{"excluded", Policy{ExcludedCIDRs: []string{"1.1.1.0/24"}}, fallbackAnswers("8.8.8.8", "1.1.1.1"), ErrRouteExcluded, "tcp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := fallbackDialer(t, tc.policy)
			lookups, dials := 0, 0
			d.lookup = func(context.Context, string) ([]net.IPAddr, error) { lookups++; return tc.answers, nil }
			d.dial = func(context.Context, string, string) (net.Conn, error) { dials++; return nil, nil }
			if conn, err := d.DialContext(context.Background(), tc.network, "all-policy.test:443"); conn != nil || !errors.Is(err, tc.want) || lookups != 1 || dials != 0 {
				t.Fatalf("policy allowed a candidate side effect: conn=%v err=%v lookups=%d dials=%d", conn, err, lookups, dials)
			}
		})
	}
}

func TestTCPNumericFallbackCancellationStopsBeforeNextAttempt(t *testing.T) {
	d := fallbackDialer(t, Policy{AllowPrivate: true})
	d.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return fallbackAnswers("127.0.0.2", "127.0.0.1"), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dials := 0
	d.dial = func(context.Context, string, string) (net.Conn, error) {
		dials++
		cancel()
		return nil, errors.New("first refused")
	}
	if conn, err := d.DialContext(ctx, "tcp", "cancel.test:443"); conn != nil || !errors.Is(err, context.Canceled) || dials != 1 || len(d.slots) != 0 {
		t.Fatalf("canceled fallback continued or retained permit: conn=%v err=%v dials=%d permits=%d", conn, err, dials, len(d.slots))
	}
}

func TestTCPNumericFallbackSessionGuardStopsBeforeNextAttempt(t *testing.T) {
	factory := fallbackDialer(t, Policy{AllowPrivate: true})
	factory.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return fallbackAnswers("127.0.0.2", "127.0.0.1"), nil
	}
	var revoked atomic.Bool
	revokedErr := errors.New("owner revoked")
	d, stop := scopedDNS(t, factory, context.Background(), func() error {
		if revoked.Load() {
			return revokedErr
		}
		return nil
	})
	defer stop()
	dials := 0
	d.dial = func(context.Context, string, string) (net.Conn, error) {
		dials++
		revoked.Store(true)
		return nil, errors.New("first refused")
	}
	if conn, err := d.DialContext(context.Background(), "tcp", "guard.test:443"); conn != nil || !errors.Is(err, revokedErr) || dials != 1 {
		t.Fatalf("Session guard was skipped: conn=%v err=%v dials=%d", conn, err, dials)
	}
}

type fallbackTrackedConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *fallbackTrackedConn) Close() error { c.closes.Add(1); return c.Conn.Close() }

func fallbackPipe(t *testing.T) *fallbackTrackedConn {
	t.Helper()
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
	return &fallbackTrackedConn{Conn: conn}
}

func TestTCPNumericFallbackClosesSocketPlusErrorBeforeNext(t *testing.T) {
	d := fallbackDialer(t, Policy{AllowPrivate: true})
	d.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return fallbackAnswers("127.0.0.2", "127.0.0.1", "127.0.0.3"), nil
	}
	failed, success := fallbackPipe(t), fallbackPipe(t)
	dials := 0
	d.dial = func(context.Context, string, string) (net.Conn, error) {
		dials++
		if dials == 1 {
			return failed, errors.New("socket plus error")
		}
		if dials != 2 || failed.closes.Load() != 1 {
			t.Fatal("failed socket was not closed before fallback or success was retried")
		}
		return success, nil
	}
	conn, err := d.DialContext(context.Background(), "tcp", "socket-error.test:443")
	if err != nil || conn != success || dials != 2 || success.closes.Load() != 0 {
		t.Fatalf("successful connection was not transferred once: conn=%v err=%v dials=%d success_closes=%d", conn, err, dials, success.closes.Load())
	}
}

func TestTCPNumericFallbackLateSocketClosedWithoutNext(t *testing.T) {
	for _, reason := range []string{"caller-cancel", "owner-cancel"} {
		t.Run(reason, func(t *testing.T) {
			ownerCtx, cancelOwner := context.WithCancel(context.Background())
			defer cancelOwner()
			factory := fallbackDialer(t, Policy{AllowPrivate: true})
			factory.lookup = func(context.Context, string) ([]net.IPAddr, error) {
				return fallbackAnswers("127.0.0.2", "127.0.0.1"), nil
			}
			d, stop := scopedDNS(t, factory, ownerCtx, nil)
			defer stop()
			ctx, cancelCaller := context.WithCancel(context.Background())
			defer cancelCaller()
			late := fallbackPipe(t)
			started, release := make(chan struct{}), make(chan struct{})
			var dials atomic.Int32
			d.dial = func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				close(started)
				<-release // Deliberately ignores cancellation to exercise late ownership.
				return late, nil
			}
			type result struct {
				conn net.Conn
				err  error
			}
			done := make(chan result, 1)
			go func() { conn, err := d.DialContext(ctx, "tcp", "late-socket.test:443"); done <- result{conn, err} }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("dial did not start")
			}
			if reason == "caller-cancel" {
				cancelCaller()
			} else {
				cancelOwner()
			}
			close(release)
			select {
			case got := <-done:
				if got.conn != nil || got.err == nil || late.closes.Load() != 1 || dials.Load() != 1 || len(d.slots) != 0 {
					t.Fatalf("late socket escaped owner: conn=%v err=%v closes=%d dials=%d permits=%d", got.conn, got.err, late.closes.Load(), dials.Load(), len(d.slots))
				}
			case <-time.After(time.Second):
				t.Fatal("late dial did not return after release")
			}
		})
	}
}

func TestTCPNumericFallbackAllFailuresReturnLastError(t *testing.T) {
	d := fallbackDialer(t, Policy{AllowPrivate: true})
	lookups, dials := 0, 0
	d.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		lookups++
		return fallbackAnswers("127.0.0.2", "127.0.0.1"), nil
	}
	first, last := errors.New("first refused"), errors.New("last refused")
	d.dial = func(context.Context, string, string) (net.Conn, error) {
		dials++
		if dials == 1 {
			return nil, first
		}
		return nil, last
	}
	if conn, err := d.DialContext(context.Background(), "tcp", "all-failed.test:443"); conn != nil || !errors.Is(err, last) || lookups != 1 || dials != 2 || len(d.slots) != 0 {
		t.Fatalf("all-failed result/budget incorrect: conn=%v err=%v lookups=%d dials=%d permits=%d", conn, err, lookups, dials, len(d.slots))
	}
}

func TestTCPNumericFallbackSharesDeadlineAndPermit(t *testing.T) {
	d := fallbackDialer(t, Policy{AllowPrivate: true, Timeout: 150 * time.Millisecond, MaxConcurrent: 1})
	d.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return fallbackAnswers("127.0.0.2", "127.0.0.1", "127.0.0.3"), nil
	}
	var firstContext context.Context
	var firstDeadline time.Time
	dials := 0
	d.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		dials++
		deadline, ok := ctx.Deadline()
		if !ok || len(d.slots) != 1 {
			t.Fatal("candidate lacked shared deadline/permit")
		}
		if dials == 1 {
			firstContext, firstDeadline = ctx, deadline
			select {
			case <-time.After(30 * time.Millisecond):
			case <-ctx.Done():
			}
			return nil, errors.New("first refused after spending budget")
		}
		if dials != 2 || ctx != firstContext || !deadline.Equal(firstDeadline) {
			t.Fatal("fallback renewed its deadline or permit context")
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if conn, err := d.DialContext(context.Background(), "tcp", "deadline.test:443"); conn != nil || !errors.Is(err, context.DeadlineExceeded) || dials != 2 || len(d.slots) != 0 {
		t.Fatalf("fallback exceeded original budget: conn=%v err=%v dials=%d permits=%d", conn, err, dials, len(d.slots))
	}
}

func TestTCPNumericFallbackRespectsRequestedFamily(t *testing.T) {
	for _, tc := range []struct {
		network  string
		answers  []net.IPAddr
		attempts []string
	}{
		{"tcp4", fallbackAnswers("::1", "127.0.0.2", "127.0.0.1"), []string{"127.0.0.2:443", "127.0.0.1:443"}},
		{"tcp6", fallbackAnswers("127.0.0.1", "::2", "::1"), []string{"[::2]:443", "[::1]:443"}},
	} {
		t.Run(tc.network, func(t *testing.T) {
			d := fallbackDialer(t, Policy{AllowPrivate: true})
			d.lookup = func(context.Context, string) ([]net.IPAddr, error) { return tc.answers, nil }
			var attempts []string
			d.dial = func(_ context.Context, network, address string) (net.Conn, error) {
				if network != tc.network {
					t.Fatalf("network family changed to %s", network)
				}
				attempts = append(attempts, address)
				if len(attempts) == 1 {
					return nil, errors.New("first candidate refused")
				}
				return nil, nil // Preserve the existing successful noSocket test seam.
			}
			if _, err := d.DialContext(context.Background(), tc.network, "family.test:443"); err != nil || strings.Join(attempts, ",") != strings.Join(tc.attempts, ",") {
				t.Fatalf("wrong family fallback: attempts=%v err=%v", attempts, err)
			}
		})
	}
}

func TestTCPNumericFallbackNoMatchingFamilyNeverDials(t *testing.T) {
	d := fallbackDialer(t, Policy{AllowPrivate: true})
	d.lookup = func(context.Context, string) ([]net.IPAddr, error) { return fallbackAnswers("127.0.0.1"), nil }
	d.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("non-matching family was dialed")
		return nil, nil
	}
	if _, err := d.DialContext(context.Background(), "tcp6", "no-family.test:443"); err == nil || !strings.Contains(err.Error(), "no address for requested network family") {
		t.Fatalf("no-family result incorrect: %v", err)
	}
}

func TestUDPNumericCandidateFailureNeverRetries(t *testing.T) {
	for _, network := range []string{"udp", "udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			d := fallbackDialer(t, Policy{AllowPrivate: true})
			lookups, dials := 0, 0
			d.lookup = func(context.Context, string) ([]net.IPAddr, error) {
				lookups++
				if network == "udp6" {
					return fallbackAnswers("::2", "::1"), nil
				}
				return fallbackAnswers("127.0.0.2", "127.0.0.1"), nil
			}
			chosenErr := errors.New("chosen UDP peer failed")
			failed := fallbackPipe(t)
			d.dial = func(context.Context, string, string) (net.Conn, error) { dials++; return failed, chosenErr }
			if conn, err := d.DialContext(context.Background(), network, "udp-one-peer.test:443"); conn != nil || !errors.Is(err, chosenErr) || lookups != 1 || dials != 1 || failed.closes.Load() != 1 {
				t.Fatalf("UDP retried or leaked failed socket: conn=%v err=%v lookups=%d dials=%d closes=%d", conn, err, lookups, dials, failed.closes.Load())
			}
		})
	}
}
