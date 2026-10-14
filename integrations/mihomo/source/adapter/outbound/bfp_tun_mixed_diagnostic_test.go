package outbound

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bfp/gateway"
	"bfp/session"
	C "github.com/metacubex/mihomo/constant"
)

// One native ownership diagnostic: real encrypted BFP over loopback, synthetic
// fixture keys, local TCP/UDP targets and policy refusals. No TUN, public DNS,
// operator profiles, remote machine or release build participates in this test.
func TestBFPTUNMixedNativeSetupKeepsSharedSession(t *testing.T) {
	path, credentials := bfpPrivateFixture(t)
	f := bfpStartNativeFixture(t, credentials)
	bfpFixtureEndpoint(t, path, f.server.Addr().String())
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var targetWorkers sync.WaitGroup
	var targetMu sync.Mutex
	targets := make(map[net.Conn]struct{})
	acceptedDone := make(chan struct{})
	go func() {
		defer close(acceptedDone)
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			targetMu.Lock()
			targets[conn] = struct{}{}
			targetMu.Unlock()
			targetWorkers.Add(1)
			go func() {
				defer targetWorkers.Done()
				defer conn.Close()
				defer func() { targetMu.Lock(); delete(targets, conn); targetMu.Unlock() }()
				_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = echo.Close()
		<-acceptedDone
		targetMu.Lock()
		for conn := range targets {
			_ = conn.Close()
		}
		targetMu.Unlock()
		joined := make(chan struct{})
		go func() { targetWorkers.Wait(); close(joined) }()
		select {
		case <-joined:
		case <-time.After(2 * time.Second):
			t.Error("local echo workers did not join")
		}
	})
	_, echoPort, _ := net.SplitHostPort(echo.Addr().String())
	ports := []int{echo.Addr().(*net.TCPAddr).Port}
	for _, address := range f.udp {
		_, text, _ := net.SplitHostPort(address)
		port, _ := strconv.Atoi(text)
		ports = append(ports, port)
	}
	// The fixture alias resolves in bfpNativeBackend, and policy only admits our
	// exact local ports. Port 9 is deliberately refused before any target dial.
	f.backend.dialer, err = gateway.New(gateway.Policy{AllowPrivate: true,
		AllowedCIDRs: []string{"127.0.0.0/8"}, AllowedPorts: ports, MaxConcurrent: 16, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewBFP(BFPOption{Name: "tun-mixed-native-diagnostic", ClientConfigFile: path, UDP: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()

	var leases [2]C.SessionFakeIPLease
	for i := range leases {
		request, end := context.WithTimeout(ctx, time.Second)
		leases[i], err = h.AllocateSessionFakeIP(request, "service.bfp.invalid", i == 1)
		end()
		if err != nil {
			t.Fatalf("IPv%d fake-IP allocation: %v", 4+2*i, err)
		}
		lookup, err := h.LookupSessionFakeIP(ctx, leases[i].Address())
		if err != nil || lookup.Address() != leases[i].Address() || lookup.Host() != "service.bfp.invalid" {
			t.Fatalf("IPv%d fake-IP lookup after DNS context ended: %v", 4+2*i, err)
		}
	}
	if !leases[0].Address().Is4() || !leases[1].Address().Is6() {
		t.Fatal("fake-IP allocation did not retain requested families")
	}
	owner := h.client.Session()
	if owner == nil {
		t.Fatal("fake-IP allocation did not establish a Session")
	}
	checkAlive := func(stage string) {
		t.Helper()
		select {
		case <-owner.BusinessDone():
			source, recorded := owner.TerminationSource()
			t.Fatalf("stage=%s early_session_termination source=%q recorded=%v", stage, source, recorded)
		default:
		}
		if h.client.Session() != owner {
			t.Fatalf("stage=%s replaced the shared Session", stage)
		}
	}
	metadata := func(index int) *C.Metadata {
		if index%3 == 0 {
			return bfpNativeMetadata(t, echo.Addr().String(), C.TCP)
		}
		lease := leases[(index-1)%2]
		meta := bfpNativeMetadata(t, net.JoinHostPort(lease.Address().String(), echoPort), C.TCP)
		meta.Host, meta.SessionFakeIP = lease.Host(), lease
		return meta
	}
	exchange := func(conn net.Conn, payload string) error {
		if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		if _, err := conn.Write([]byte(payload)); err != nil {
			return err
		}
		actual := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, actual); err != nil {
			return err
		}
		if !bytes.Equal(actual, []byte(payload)) {
			return errors.New("local echo payload mismatch")
		}
		return nil
	}
	healthSetup, stopHealth := context.WithCancel(ctx)
	healthy, err := h.DialContext(healthSetup, metadata(1))
	stopHealth()
	if err != nil {
		t.Fatal("open retained healthy TCP", err)
	}
	t.Cleanup(func() { _ = healthy.Close() })
	if err := exchange(healthy, "healthy-before-mixed"); err != nil {
		t.Fatal(err)
	}
	packetSetup, stopPacket := context.WithCancel(ctx)
	borrowed, err := h.ListenPacketContext(packetSetup, bfpNativeMetadata(t, f.udp[0], C.UDP))
	stopPacket()
	if err != nil {
		t.Fatal("open borrowed packet connection", err)
	}
	t.Cleanup(func() { _ = borrowed.Close() })
	if borrowed.(*bfpMihomoPacketConn).logical.sessionOwner != owner {
		t.Fatal("native TCP and borrowed UDP selected different Sessions")
	}
	peer, _ := net.ResolveUDPAddr("udp4", f.udp[0])
	bfpNativeRoundTrip(t, borrowed, peer, []byte("udp-before-mixed"))

	// Retained TCP + one UDP target + 30 TCP = the actual default 32 slots.
	// Neither the client nor the server MaxFlows is increased for this test.
	held := make([]C.Conn, 30)
	heldErrors := make([]error, len(held))
	var wave sync.WaitGroup
	for i := range held {
		wave.Add(1)
		go func(i int) {
			defer wave.Done()
			setup, end := context.WithTimeout(ctx, 3*time.Second)
			defer end()
			held[i], heldErrors[i] = h.DialContext(setup, metadata(i))
		}(i)
	}
	wave.Wait()
	t.Cleanup(func() {
		for _, conn := range held {
			if conn != nil {
				_ = conn.Close()
			}
		}
	})
	checkAlive("fill_32")
	for i, err := range heldErrors {
		if err != nil {
			t.Fatalf("fill_32 flow=%d error=%v", i, err)
		}
	}
	if stats := owner.Stats(); stats.Flows != 32 {
		t.Fatalf("admitted flow slots=%d want=32", stats.Flows)
	}
	var limited, timedOut, refused, opened atomic.Int32
	for i := 0; i < 8; i++ {
		wave.Add(1)
		go func(i int) {
			defer wave.Done()
			conn, err := h.DialContext(ctx, metadata(i))
			if errors.Is(err, session.ErrLimit) {
				limited.Add(1)
			}
			if conn != nil {
				_ = conn.Close()
			}
		}(i)
	}
	wave.Wait()
	checkAlive("eight_excess_opens")
	if limited.Load() != 8 {
		t.Fatalf("excess OPEN ErrLimit count=%d want=8", limited.Load())
	}
	for i := 0; i < 16; i++ {
		_ = held[i].Close()
	}
	// Concurrent background work deliberately mixes timed-out callers, exact
	// policy refusals, native numeric destinations and both fake-IP families.
	for i := 0; i < 24; i++ {
		wave.Add(1)
		go func(i int) {
			defer wave.Done()
			duration := 3 * time.Second
			meta := metadata(i)
			if i%3 == 0 {
				duration = time.Nanosecond
			} else if i%3 == 1 {
				meta = bfpNativeMetadata(t, "127.0.0.1:9", C.TCP)
			}
			setup, end := context.WithTimeout(ctx, duration)
			defer end()
			conn, err := h.DialContext(setup, meta)
			if errors.Is(err, context.DeadlineExceeded) {
				timedOut.Add(1)
			} else if errors.Is(err, session.ErrLimit) {
				limited.Add(1)
			} else if err != nil && strings.Contains(err.Error(), "target refused") {
				refused.Add(1)
			} else if err != nil {
				heldErrors[i] = err
			} else {
				opened.Add(1)
				_ = conn.Close()
			}
		}(i)
	}
	wave.Wait()
	checkAlive("mixed_24_open_close_wave")
	for _, err := range heldErrors {
		if err != nil {
			t.Fatal("unexpected mixed OPEN error", err)
		}
	}
	// Twelve more callers: contexts that genuinely expire after successful
	// setup, deterministic policy rejection, and ordinary short-lived echo.
	for i := 0; i < 12; i++ {
		setup, end := context.WithTimeout(ctx, 60*time.Millisecond)
		meta := metadata(i)
		if i%3 == 1 {
			meta = bfpNativeMetadata(t, "127.0.0.1:9", C.TCP)
		}
		conn, err := h.DialContext(setup, meta)
		if i%3 == 1 {
			if err == nil || !strings.Contains(err.Error(), "target refused") {
				end()
				if conn != nil {
					_ = conn.Close()
				}
				t.Fatalf("controlled refusal caller=%d err=%v", i, err)
			}
			refused.Add(1)
		} else {
			if err != nil {
				end()
				t.Fatalf("post-wave setup caller=%d err=%v", i, err)
			}
			if i%3 == 0 {
				<-setup.Done()
				timedOut.Add(1)
			}
			if err := exchange(conn, fmt.Sprintf("caller-%d-after-context", i)); err != nil {
				_ = conn.Close()
				end()
				checkAlive("post_context_echo_failure")
				t.Fatal(err)
			}
			opened.Add(1)
			_ = conn.Close()
		}
		end()
		checkAlive("post_wave_caller")
	}
	if timedOut.Load() != 12 || refused.Load() < 4 {
		t.Fatalf("required timeout/refusal coverage missing timeouts=%d refused=%d", timedOut.Load(), refused.Load())
	}
	if err := borrowed.Close(); err != nil {
		t.Fatal("close borrowed UDP", err)
	}
	checkAlive("borrowed_packet_close")
	if err := exchange(healthy, "healthy-after-all-76-operations"); err != nil {
		checkAlive("healthy_echo_failure")
		t.Fatal("original healthy TCP stopped echoing", err)
	}
	for i, lease := range leases {
		if _, err := lease.Remaining(ctx); err != nil {
			t.Fatalf("IPv%d lease retired after single-flow cancellation: %v", 4+2*i, err)
		}
	}
	checkAlive("final")
	source, recorded := owner.TerminationSource()
	t.Logf("native_mixed_operations=76 tcp_open_attempts=75 udp_writes=1 dns_families=2 excess_limited=8 limited_total=%d timed_out_contexts=%d refused=%d opened_churn=%d healthy_echo=true same_session=true terminated=false source=%q recorded=%v", limited.Load(), timedOut.Load(), refused.Load(), opened.Load(), source, recorded)
}
