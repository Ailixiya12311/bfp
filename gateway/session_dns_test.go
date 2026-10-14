package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func scopedDNS(t *testing.T, factory *Dialer, ctx context.Context, valid func() error) (*Dialer, func()) {
	t.Helper()
	d, stop := factory.ForSession(ctx, valid)
	return d.(*Dialer), stop
}

func publicAnswers() []net.IPAddr {
	return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}
}

func noSocket(context.Context, string, string) (net.Conn, error) { return nil, nil }

func dnsState(d *Dialer) (int, bool, uint64) {
	d.dns.mu.Lock()
	defer d.dns.mu.Unlock()
	return len(d.dns.entries), d.dns.closed, d.dns.generation
}

func TestSessionDNSIsolationCacheTTLAndFactoryNoLookup(t *testing.T) {
	factory, _ := New(Policy{})
	var lookups atomic.Int32
	factory.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		lookups.Add(1)
		return publicAnswers(), nil
	}
	factory.dial = noSocket
	first, stopFirst := scopedDNS(t, factory, context.Background(), nil)
	defer stopFirst()
	second, stopSecond := scopedDNS(t, factory, context.Background(), nil)
	defer stopSecond()
	if lookups.Load() != 0 || first.dns == second.dns || first.slots != second.slots || first.resolverSlots != second.resolverSlots {
		t.Fatal("factory performed resolution or failed private-cache/shared-budget ownership")
	}
	now := time.Unix(100, 0)
	first.dns.now = func() time.Time { return now }
	for _, d := range []*Dialer{first, first, second} {
		if _, err := d.DialContext(context.Background(), "tcp", "example.test:443"); err != nil {
			t.Fatal(err)
		}
	}
	if lookups.Load() != 2 {
		t.Fatalf("cross-session cache reused or same-session miss: %d", lookups.Load())
	}
	now = now.Add(sessionDNSMaxAge)
	if _, err := first.DialContext(context.Background(), "tcp", "example.test:443"); err != nil || lookups.Load() != 3 {
		t.Fatalf("exact local max-age did not expire: %v, %d", err, lookups.Load())
	}
	stopFirst()
	if _, err := first.DialContext(context.Background(), "tcp", "example.test:443"); err == nil {
		t.Fatal("closed owner used cached answer")
	}
	if _, err := second.DialContext(context.Background(), "tcp", "example.test:443"); err != nil || lookups.Load() != 3 {
		t.Fatal("closing one Session invalidated the other Session cache")
	}
}

func TestSessionDNSBoundedEntriesAndDefensiveAddressCopies(t *testing.T) {
	factory, _ := New(Policy{})
	answer := publicAnswers()
	var lookups int
	factory.lookup = func(context.Context, string) ([]net.IPAddr, error) { lookups++; return answer, nil }
	var numeric string
	factory.dial = func(_ context.Context, _, address string) (net.Conn, error) { numeric = address; return nil, nil }
	d, stop := scopedDNS(t, factory, context.Background(), nil)
	defer stop()
	if _, err := d.DialContext(context.Background(), "tcp", "copied.test:443"); err != nil {
		t.Fatal(err)
	}
	copy(answer[0].IP, net.ParseIP("127.0.0.1"))
	if _, err := d.DialContext(context.Background(), "tcp", "copied.test:443"); err != nil || numeric != "8.8.8.8:443" || lookups != 1 {
		t.Fatalf("resolver memory changed cached peer: %v %s %d", err, numeric, lookups)
	}
	copyOfCache, _, err := d.dns.get("copied.test")
	if err != nil {
		t.Fatal(err)
	}
	copyOfCache[0] = netip.MustParseAddr("127.0.0.1")
	if _, err = d.DialContext(context.Background(), "tcp", "copied.test:443"); err != nil || numeric != "8.8.8.8:443" {
		t.Fatalf("returned address slice aliased private cache: %v %s", err, numeric)
	}
	factoryAnswer := publicAnswers()
	d.lookup = func(context.Context, string) ([]net.IPAddr, error) { return factoryAnswer, nil }
	for i := 0; i < sessionDNSEntries+10; i++ {
		if _, err := d.DialContext(context.Background(), "tcp", fmt.Sprintf("host%d.test:443", i)); err != nil {
			t.Fatal(err)
		}
	}
	if count, closed, _ := dnsState(d); count != sessionDNSEntries || closed {
		t.Fatalf("unbounded cache: entries=%d closed=%v", count, closed)
	}
	stop()
	count, closed, generation := dnsState(d)
	if count != 0 || !closed || generation != 2 {
		t.Fatal("close did not synchronously clear and invalidate")
	}
	stop()
	if _, _, next := dnsState(d); next != generation {
		t.Fatal("idempotent stop changed generation twice")
	}
}

func TestSessionDNSAllAnswersACLBeforeNumericDialAndNoNegativeCaching(t *testing.T) {
	for name, answers := range map[string][]net.IPAddr{
		"mixed":                {{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("127.0.0.1")}},
		"other-family-private": {{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("fc00::1")}},
		"zone":                 {{IP: net.ParseIP("8.8.8.8"), Zone: "eth0"}},
	} {
		t.Run(name, func(t *testing.T) {
			factory, _ := New(Policy{})
			var lookups, dials int
			factory.lookup = func(context.Context, string) ([]net.IPAddr, error) { lookups++; return answers, nil }
			factory.dial = func(context.Context, string, string) (net.Conn, error) { dials++; return nil, nil }
			d, stop := scopedDNS(t, factory, context.Background(), nil)
			defer stop()
			for i := 0; i < 2; i++ {
				if _, err := d.DialContext(context.Background(), "tcp4", "mixed.test:443"); !errors.Is(err, ErrPolicyDenied) {
					t.Fatalf("all-answer ACL weakened: %v", err)
				}
			}
			if count, _, _ := dnsState(d); count != 0 || lookups != 2 || dials != 0 {
				t.Fatal("denied result was cached or dialed")
			}
		})
	}
	factory, _ := New(Policy{})
	var numeric string
	factory.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("2001:4860:4860::8888")}, {IP: net.ParseIP("8.8.8.8")}}, nil
	}
	factory.dial = func(_ context.Context, _, address string) (net.Conn, error) { numeric = address; return nil, nil }
	d, stop := scopedDNS(t, factory, context.Background(), nil)
	defer stop()
	if _, err := d.DialContext(context.Background(), "tcp4", "numeric.test:443"); err != nil || numeric != "8.8.8.8:443" {
		t.Fatalf("numeric family selection: %v %s", err, numeric)
	}
}

func TestSessionDNSHostAnswerLimitsAndErrorsNeverCached(t *testing.T) {
	for name, lookup := range map[string]func(context.Context, string) ([]net.IPAddr, error){
		"no-answer":    func(context.Context, string) ([]net.IPAddr, error) { return nil, nil },
		"lookup-error": func(context.Context, string) ([]net.IPAddr, error) { return nil, errors.New("no answer") },
		"too-many": func(context.Context, string) ([]net.IPAddr, error) {
			return make([]net.IPAddr, sessionDNSAnswers+1), nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			factory, _ := New(Policy{})
			var lookups, dials int
			factory.lookup = func(ctx context.Context, host string) ([]net.IPAddr, error) { lookups++; return lookup(ctx, host) }
			factory.dial = func(context.Context, string, string) (net.Conn, error) { dials++; return nil, nil }
			d, stop := scopedDNS(t, factory, context.Background(), nil)
			defer stop()
			for i := 0; i < 2; i++ {
				if _, err := d.DialContext(context.Background(), "tcp", "error.test:443"); err == nil {
					t.Fatal("invalid DNS result accepted")
				}
			}
			if count, _, _ := dnsState(d); count != 0 || lookups != 2 || dials != 0 {
				t.Fatal("error caching or dial side effect")
			}
			if _, err := d.DialContext(context.Background(), "tcp", strings.Repeat("a", sessionDNSHostBytes+1)+":443"); !errors.Is(err, ErrDNSLimit) || lookups != 2 {
				t.Fatal("hostname bound did not apply before resolver")
			}
		})
	}
}

func TestSessionDNSLateResolverCannotRepopulateOrDial(t *testing.T) {
	for _, terminal := range []string{"close", "owner-cancel", "revoked", "expired"} {
		t.Run(terminal, func(t *testing.T) {
			factory, _ := New(Policy{})
			started, release := make(chan struct{}), make(chan struct{})
			factory.lookup = func(context.Context, string) ([]net.IPAddr, error) {
				close(started)
				<-release
				return publicAnswers(), nil
			}
			var dials atomic.Int32
			factory.dial = func(context.Context, string, string) (net.Conn, error) { dials.Add(1); return nil, nil }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var invalid atomic.Bool
			sentinel := errors.New(terminal)
			d, stop := scopedDNS(t, factory, ctx, func() error {
				if invalid.Load() {
					return sentinel
				}
				return nil
			})
			defer stop()
			done := make(chan error, 1)
			go func() { _, err := d.DialContext(context.Background(), "tcp", "late.test:443"); done <- err }()
			<-started
			if terminal == "close" {
				stop()
			} else if terminal == "owner-cancel" {
				cancel()
			} else {
				invalid.Store(true)
			}
			close(release)
			if err := <-done; err == nil {
				t.Fatal("late answer succeeded after invalidation")
			}
			if count, _, _ := dnsState(d); count != 0 || dials.Load() != 0 {
				t.Fatal("late resolution repopulated cache or dialed")
			}
		})
	}
}

func TestSessionDNSCachedHitCannotSurviveRevocationOrExpiry(t *testing.T) {
	for _, reason := range []string{"revoked", "expired"} {
		t.Run(reason, func(t *testing.T) {
			factory, _ := New(Policy{})
			var lookups, dials int
			factory.lookup = func(context.Context, string) ([]net.IPAddr, error) { lookups++; return publicAnswers(), nil }
			factory.dial = func(context.Context, string, string) (net.Conn, error) { dials++; return nil, nil }
			var invalid atomic.Bool
			d, stop := scopedDNS(t, factory, context.Background(), func() error {
				if invalid.Load() {
					return errors.New(reason)
				}
				return nil
			})
			defer stop()
			if _, err := d.DialContext(context.Background(), "tcp", "hit.test:443"); err != nil {
				t.Fatal(err)
			}
			invalid.Store(true)
			if _, err := d.DialContext(context.Background(), "tcp", "hit.test:443"); err == nil {
				t.Fatal("cache hit bypassed authorization/lifetime")
			}
			if _, err := d.DialContext(context.Background(), "tcp", "8.8.8.8:443"); err == nil {
				t.Fatal("numeric dial bypassed authorization/lifetime")
			}
			if count, closed, _ := dnsState(d); count != 0 || !closed || lookups != 1 || dials != 1 {
				t.Fatal("terminal hit failed synchronous invalidation")
			}
		})
	}
}

func TestSessionDNSGlobalDialAndResolverBudgetsNotMultiplied(t *testing.T) {
	t.Run("dial", func(t *testing.T) {
		factory, _ := New(Policy{MaxConcurrent: 1})
		factory.lookup = func(context.Context, string) ([]net.IPAddr, error) { return publicAnswers(), nil }
		started, release := make(chan struct{}), make(chan struct{})
		var dials atomic.Int32
		factory.dial = func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			close(started)
			<-release
			return nil, nil
		}
		one, stopOne := scopedDNS(t, factory, context.Background(), nil)
		defer stopOne()
		two, stopTwo := scopedDNS(t, factory, context.Background(), nil)
		defer stopTwo()
		done := make(chan error, 1)
		go func() { _, err := one.DialContext(context.Background(), "tcp", "one.test:443"); done <- err }()
		<-started
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		if _, err := two.DialContext(ctx, "tcp", "two.test:443"); !errors.Is(err, context.DeadlineExceeded) || dials.Load() != 1 {
			t.Fatal("Session clones multiplied dial budget")
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
	t.Run("actual-resolver-execution", func(t *testing.T) {
		factory, _ := New(Policy{MaxConcurrent: 4})
		factory.resolverSlots = make(chan struct{}, 1)
		started, release := make(chan struct{}), make(chan struct{})
		var lookups atomic.Int32
		factory.lookup = func(context.Context, string) ([]net.IPAddr, error) {
			lookups.Add(1)
			close(started)
			<-release
			return publicAnswers(), nil
		}
		factory.dial = noSocket
		one, stopOne := scopedDNS(t, factory, context.Background(), nil)
		defer stopOne()
		two, stopTwo := scopedDNS(t, factory, context.Background(), nil)
		defer stopTwo()
		done := make(chan error, 1)
		go func() { _, err := one.DialContext(context.Background(), "tcp", "one.test:443"); done <- err }()
		<-started
		stopOne() // Resolver deliberately ignores ctx; its actual slot stays held.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		if _, err := two.DialContext(ctx, "tcp", "two.test:443"); !errors.Is(err, context.DeadlineExceeded) || lookups.Load() != 1 || len(factory.resolverSlots) != 1 {
			t.Fatal("cancellation released actual execution permit too early")
		}
		close(release)
		if err := <-done; err == nil {
			t.Fatal("cancelled lookup delivered late answer")
		}
		if len(factory.resolverSlots) != 0 {
			t.Fatal("resolver permit leaked after execution finished")
		}
	})
}

func TestSessionDNSAlreadyStartedDialClosesLateSocket(t *testing.T) {
	factory, _ := New(Policy{})
	factory.lookup = func(context.Context, string) ([]net.IPAddr, error) { return publicAnswers(), nil }
	started, release := make(chan struct{}), make(chan struct{})
	conn, peer := net.Pipe()
	defer peer.Close()
	factory.dial = func(context.Context, string, string) (net.Conn, error) { close(started); <-release; return conn, nil }
	d, stop := scopedDNS(t, factory, context.Background(), nil)
	defer stop()
	done := make(chan error, 1)
	go func() {
		got, err := d.DialContext(context.Background(), "tcp", "racing.test:443")
		if got != nil {
			t.Error("terminal owner received late socket")
		}
		done <- err
	}()
	<-started
	stop()
	close(release)
	if err := <-done; err == nil {
		t.Fatal("late OS dial return accepted")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("late socket was not closed: %v", err)
	}
}

func TestSessionDNSCallerCancellationDoesNotDestroyLiveOwnerCache(t *testing.T) {
	factory, _ := New(Policy{})
	var lookups int
	factory.lookup = func(context.Context, string) ([]net.IPAddr, error) { lookups++; return publicAnswers(), nil }
	factory.dial = noSocket
	d, stop := scopedDNS(t, factory, context.Background(), nil)
	defer stop()
	if _, err := d.DialContext(context.Background(), "tcp", "live.test:443"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.DialContext(ctx, "tcp", "live.test:443"); !errors.Is(err, context.Canceled) {
		t.Fatal("caller cancellation ignored")
	}
	if _, err := d.DialContext(context.Background(), "tcp", "live.test:443"); err != nil || lookups != 1 {
		t.Fatal("one cancelled flow destroyed owner cache")
	}
}
