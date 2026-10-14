package gateway

import (
	"bfp/session"
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// This separately named, intentionally long local scene keeps the actual
// production 15s UDP watchdog, 30s retention and 3s CloseTimeout defaults. Its
// 60s context is independent of the existing 5s DNS business scenes, 8s active
// recovery operation and 35s WAN scenes; none of their deadlines is changed.
func TestSessionDNSRuntimeDefaultBlackholeWatchdogAndRetention(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	port, targets, targetClosed := sessionDNSTerminationEcho(t, deadline)
	base, err := New(Policy{AllowPrivate: true, AllowedCIDRs: []string{"127.0.0.0/8"},
		AllowedPorts: []int{port}, MaxConcurrent: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	const hostname = "session-default-blackhole.test"
	var lookups atomic.Int32
	base.lookup = func(ctx context.Context, name string) ([]net.IPAddr, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lookups.Add(1)
		if name != hostname {
			return nil, errors.New("test: blackholed old scope performed a new lookup")
		}
		return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
	}
	factory := &sessionDNSCloseFactory{sessionDNSRuntimeFactory: &sessionDNSRuntimeFactory{base: base}}
	server, credentials := sessionDNSCloseServer(t, ctx, factory, session.Options{})
	proxy := newSessionDNSCloseUDPProxy(t, server.Addr())
	client, err := session.NewClient(session.ClientConfig{Server: proxy.front.LocalAddr().String(),
		TCPServer: server.Addr().String(), Credentials: credentials})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil && !errors.Is(err, session.ErrCloseUnconfirmed) {
			t.Errorf("owned default-blackhole client cleanup failed: %v", err)
		}
	})
	connected, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if connected.Stats().Carrier != "udp" {
		t.Fatal("default-blackhole fixture did not establish actual encrypted UDP")
	}
	destination := net.JoinHostPort(hostname, strconv.Itoa(port))
	flow := sessionDNSRuntimeExchange(t, ctx, client, destination, []byte("default watchdog scene: live scoped DNS and actual numeric TCP echo"))
	scopes := factory.snapshot()
	if len(scopes) != 1 || lookups.Load() != 1 || targets.Load() != 1 || factory.closes.Load() != 0 {
		t.Fatal("default-blackhole scene did not start with one populated scoped cache and live numeric target")
	}
	scope := scopes[0]
	entries, closed, generation := dnsState(scope.dialer)
	if entries != 1 || closed || scope.stops.Load() != 0 {
		t.Fatal("default-blackhole scene did not retain its original positive DNS answer")
	}
	snapshot := func() (session.Stats, bool) {
		for _, stats := range server.Snapshot() {
			if stats.ID == connected.Stats().ID {
				return stats, true
			}
		}
		return session.Stats{}, false
	}
	// Wait for completed OPEN/class/packet acknowledgements, establishing the
	// no-inflight starting state. This is passive observation, not a test retry.
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	baselineDeadline := time.NewTimer(3 * time.Second)
	defer baselineDeadline.Stop()
	var baseline session.Stats
	stableSamples := 0
	for stableSamples < 2 {
		stats, found := snapshot()
		if !found || stats.Carrier != "udp" || stats.UDPStalled != 0 {
			t.Fatal("actual Session disappeared or stalled before blackout")
		}
		views, err := server.ClassificationSnapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		classStable := len(views[stats.ID]) == 1 && !views[stats.ID][0].TXPending
		if stats.UDPFlightBytes == 0 && stats.UDPPathActive && classStable {
			stableSamples++
			baseline = stats
		} else {
			stableSamples = 0
		}
		if stableSamples == 2 {
			break
		}
		select {
		case <-tick.C:
		case <-baselineDeadline.C:
			t.Fatal("original fresh default scene never reached observed no-inflight and acknowledged class state")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	blackholeStarted := time.Now()
	proxy.dropClient.Store(true)
	proxy.dropResponder.Store(true)
	localResult := make(chan error, 1)
	go func() { localResult <- client.Close() }()
	t.Logf("blackout baseline: flight=%d active=%t non-feedback records=%d transport progress=%d no-progress age=%dms; configured defaults watchdog=15s retention=30s close=3s",
		baseline.UDPFlightBytes, baseline.UDPPathActive, baseline.UDPNonFeedbackRecords, baseline.UDPTransportProgress, baseline.UDPNoProgressAgeMS)
	var firstInflight, observedSuspend, observedCleanup, partialCleanup time.Time
	var suspendedStats session.Stats
	localFinished := false
	for observedCleanup.IsZero() {
		now := time.Now()
		stats, found := snapshot()
		entries, cacheClosed, _ := dnsState(scope.dialer)
		if firstInflight.IsZero() && found && stats.UDPFlightBytes > 0 && stats.UDPNonFeedbackRecords > baseline.UDPNonFeedbackRecords {
			firstInflight = now
			t.Logf("first unconfirmed normal server record: t=%v flight=%d no-progress age=%dms non-feedback records=%d",
				now.Sub(blackholeStarted), stats.UDPFlightBytes, stats.UDPNoProgressAgeMS, stats.UDPNonFeedbackRecords)
		}
		if observedSuspend.IsZero() && found && stats.UDPStalled > baseline.UDPStalled && !stats.UDPPathActive && stats.Carrier == "suspended" {
			observedSuspend, suspendedStats = now, stats
			if firstInflight.IsZero() || stats.UDPNoProgressAgeMS < 14900 || stats.UDPNoProgressAgeMS > 16000 {
				t.Fatalf("default watchdog suspension lacks original unconfirmed-record/15s progress evidence: inflight=%t age=%dms", !firstInflight.IsZero(), stats.UDPNoProgressAgeMS)
			}
			if entries != 1 || cacheClosed || scope.stops.Load() != 0 || factory.closes.Load() != 0 {
				t.Fatal("watchdog suspension prematurely destroyed retained Session cache or target")
			}
			t.Logf("first observed default watchdog suspension: t=%v since first in-flight=%v age=%dms stalled=%d PTO=%d probes=%d; retain origin lies within preceding100ms observation interval",
				now.Sub(blackholeStarted), now.Sub(firstInflight), stats.UDPNoProgressAgeMS, stats.UDPStalled, stats.UDPPTODue, stats.UDPProbeSent)
		}
		select {
		case <-targetClosed:
			if entries == 0 && cacheClosed && scope.stops.Load() == 1 && factory.closes.Load() == 1 {
				observedCleanup = now
			}
		default:
		}
		if observedCleanup.IsZero() && (entries != 1 || cacheClosed || scope.stops.Load() != 0 || factory.closes.Load() != 0) {
			if observedSuspend.IsZero() || now.Sub(observedSuspend) < 29*time.Second {
				t.Fatal("premature target/cache cleanup occurred before default retain boundary")
			}
			if partialCleanup.IsZero() {
				partialCleanup = now
			} else if now.Sub(partialCleanup) > time.Second {
				t.Fatal("default retain transition did not finish both target and cache cleanup within fixed1s")
			}
		}
		if !localFinished && now.Sub(blackholeStarted) > 3500*time.Millisecond {
			t.Fatal("fully lost Close exceeded default3s local deadline plus fixed500ms observation")
		}
		if firstInflight.IsZero() && now.Sub(blackholeStarted) > 2*time.Second {
			t.Fatal("no ordinary unconfirmed server record established default watchdog origin within fixed2s")
		}
		if observedSuspend.IsZero() && now.Sub(blackholeStarted) > 18*time.Second {
			t.Fatal("default15s watchdog did not suspend within fixed18s observation from idle blackout")
		}
		if !observedSuspend.IsZero() && observedCleanup.IsZero() && now.Sub(observedSuspend) > 31500*time.Millisecond {
			t.Fatal("original30s retention did not terminate within fixed31.5s observation from measured suspension")
		}
		if !observedCleanup.IsZero() {
			break
		}
		select {
		case err := <-localResult:
			if localFinished || !errors.Is(err, session.ErrCloseUnconfirmed) || now.Sub(blackholeStarted) > 3500*time.Millisecond {
				t.Fatalf("fully lost Close did not preserve bounded default local unconfirmed result: error=%v elapsed=%v", err, now.Sub(blackholeStarted))
			}
			localFinished = true
			localResult = nil
			if entries != 1 || cacheClosed || factory.closes.Load() != 0 {
				t.Fatal("local Close result falsely implied remote default-retention cleanup")
			}
			t.Log("default local3s close returned unconfirmed; unreachable remote cache and target correctly remain retained")
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("separate60s default-lifecycle scene deadline elapsed")
		}
	}
	if !localFinished || observedSuspend.IsZero() || observedCleanup.Sub(observedSuspend) < 29*time.Second || observedCleanup.Sub(observedSuspend) > 31500*time.Millisecond {
		t.Fatalf("default remote lifetime evidence incomplete: local closed=%t suspension seen=%t measured retain interval=%v", localFinished, !observedSuspend.IsZero(), observedCleanup.Sub(observedSuspend))
	}
	if entries, closed, current := dnsState(scope.dialer); entries != 0 || !closed || current != generation+1 || scope.stops.Load() != 1 {
		t.Fatal("default retention did not clear original DNS generation exactly once")
	}
	for _, name := range []string{hostname, "uncached-default-blackhole.test"} {
		conn, err := scope.dialer.DialContext(ctx, "tcp", net.JoinHostPort(name, strconv.Itoa(port)))
		if conn != nil {
			conn.Close()
			t.Fatal("default retention's old scope returned another numeric target")
		}
		if !errors.Is(err, ErrSessionBackendClosed) {
			t.Fatalf("default-retained scope was not permanently invalidated: %v", err)
		}
	}
	sessionDNSTerminationFlowFailure(t, ctx, flow, true)
	if lookups.Load() != 1 || targets.Load() != 1 || factory.closes.Load() != 1 ||
		scope.stops.Load() != 1 || proxy.droppedRecords.Load() == 0 {
		t.Fatal("default blackhole lifecycle changed target/cache ownership or lacked actual discarded server records")
	}
	t.Logf("actual encrypted UDP default lifecycle: idle blackout→unconfirmed normal record→watchdog suspension→retention cleanup; total=%v measured retain=%v watchdog age=%dms targetClose=1 scopeStop=1 discarded=%d;100ms snapshot uncertainty, no claim about other starting states or WAN",
		observedCleanup.Sub(blackholeStarted), observedCleanup.Sub(observedSuspend), suspendedStats.UDPNoProgressAgeMS, proxy.droppedRecords.Load())
}
