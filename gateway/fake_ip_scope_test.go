package gateway

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"bfp/protocol"
)

func TestFakeIPScopeAllocatesAndRestoresWithinSession(t *testing.T) {
	scope, err := NewFakeIPScope(context.Background(), time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer scope.Close()
	first, err := scope.Allocate("Example.TEST.")
	if err != nil {
		t.Fatal(err)
	}
	reused, err := scope.Allocate("example.test")
	if err != nil || reused != first {
		t.Fatalf("same hostname did not reuse mapping: first=%s reused=%s err=%v", first, reused, err)
	}
	host, err := scope.Resolve(first)
	if err != nil || host != "example.test" {
		t.Fatalf("resolve=%q err=%v", host, err)
	}
	for _, network := range []string{"tcp", "udp"} {
		target, err := scope.RestoreTarget(protocol.Target{Network: network, Address: netip.AddrPortFrom(first, 443).String()})
		if err != nil || target.Address != "example.test:443" || target.Network != network {
			t.Fatalf("network=%s target=%+v err=%v", network, target, err)
		}
	}
	// IPv4-mapped input is normalized before lookup.
	mapped := netip.MustParseAddr("::ffff:" + first.String())
	restored, err := scope.RestoreTarget(protocol.Target{Network: "tcp", Address: netip.AddrPortFrom(mapped, 8443).String()})
	if err != nil || restored.Address != "example.test:8443" {
		t.Fatalf("mapped restore=%+v err=%v", restored, err)
	}
	// Non-fake targets are not rewritten by this helper.
	normal := protocol.Target{Network: "tcp", Address: "203.0.113.7:443"}
	got, err := scope.RestoreTarget(normal)
	if err != nil || got != normal {
		t.Fatalf("normal target changed: %+v err=%v", got, err)
	}
}

func TestFakeIPScopeIsBoundedAndSessionPrivate(t *testing.T) {
	first, err := NewFakeIPScope(context.Background(), time.Minute, 64)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewFakeIPScope(context.Background(), time.Minute, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	defer second.Close()
	for i := 0; i < 64; i++ {
		if _, err := first.Allocate("host-" + string(rune('a'+i/26)) + string(rune('a'+i%26)) + ".test"); err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
	}
	if _, err := first.Allocate("overflow.test"); !errors.Is(err, ErrFakeIPCapacity) {
		t.Fatalf("overflow error=%v", err)
	}
	ip, err := second.Allocate("host-aa.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Resolve(ip); !errors.Is(err, ErrFakeIPUnmapped) {
		t.Fatalf("cross-session mapping resolved: %v", err)
	}
	if _, err := second.Resolve(ip); err != nil {
		t.Fatal(err)
	}
}

func TestFakeIPScopeExpiresAndClosesSynchronously(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	scope, err := NewFakeIPScope(parent, 20*time.Millisecond, 64)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := scope.Allocate("short.test")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(35 * time.Millisecond)
	if _, err := scope.Resolve(ip); !errors.Is(err, ErrFakeIPUnmapped) {
		t.Fatalf("expired mapping resolved: %v", err)
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := scope.Allocate("after-cancel.test"); errors.Is(err, ErrFakeIPScopeClosed) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := scope.Allocate("after-cancel.test"); !errors.Is(err, ErrFakeIPScopeClosed) {
		t.Fatalf("parent cancellation did not close scope: %v", err)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFakeIPScopeRejectsInvalidConfigAndHosts(t *testing.T) {
	for _, tc := range []struct {
		name string
		life time.Duration
		cap  int
	}{
		{"zero_lifetime", 0, 64},
		{"negative_lifetime", -time.Second, 64},
		{"unsupported_capacity", time.Minute, 32},
		{"too_large_capacity", time.Minute, 129},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewFakeIPScope(context.Background(), tc.life, tc.cap); !errors.Is(err, ErrFakeIPConfig) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	scope, err := NewFakeIPScope(context.Background(), time.Minute, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer scope.Close()
	for _, host := range []string{"", "127.0.0.1", "bad_name.test", "中文.test", "-bad.test", "bad..test", "a/../b"} {
		if _, err := scope.Allocate(host); !errors.Is(err, ErrFakeIPHost) {
			t.Errorf("host=%q err=%v", host, err)
		}
	}
	if _, err := scope.RestoreTarget(protocol.Target{Network: "tcp", Address: "198.18.0.200:443"}); !errors.Is(err, ErrFakeIPUnmapped) {
		t.Fatalf("unmapped fake target err=%v", err)
	}
}

func TestFakeIPScopeConcurrentSameHostname(t *testing.T) {
	scope, err := NewFakeIPScope(context.Background(), time.Minute, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer scope.Close()
	const workers = 32
	values := make([]netip.Addr, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := range values {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			values[i], errs[i] = scope.Allocate("parallel.test")
		}(i)
	}
	wg.Wait()
	for i := range values {
		if errs[i] != nil || values[i] != values[0] {
			t.Fatalf("worker=%d ip=%s err=%v first=%s", i, values[i], errs[i], values[0])
		}
	}
}
