package main

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type probeRecordedDeadline struct {
	kind string
	when time.Time
}

// This transport wraps a real net.Pipe. Only its first deadline setter is
// paused, letting the test force cancellation to race the exact production
// wrapper's in-progress setter without reproducing wrapper logic.
type probeBarrierConn struct {
	net.Conn
	blocked     atomic.Bool
	entered     chan struct{}
	release     chan struct{}
	cancelWrite chan struct{}
	cancelOnce  sync.Once
	mu          sync.Mutex
	deadlineLog []probeRecordedDeadline
}

func (c *probeBarrierConn) record(kind string, deadline time.Time, set func(time.Time) error) error {
	if c.blocked.CompareAndSwap(true, false) {
		close(c.entered)
		<-c.release
	}
	err := set(deadline)
	c.mu.Lock()
	c.deadlineLog = append(c.deadlineLog, probeRecordedDeadline{kind, deadline})
	c.mu.Unlock()
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		c.cancelOnce.Do(func() { close(c.cancelWrite) })
	}
	return err
}

func (c *probeBarrierConn) SetDeadline(deadline time.Time) error {
	return c.record("both", deadline, c.Conn.SetDeadline)
}

func (c *probeBarrierConn) SetReadDeadline(deadline time.Time) error {
	return c.record("read", deadline, c.Conn.SetReadDeadline)
}

func (c *probeBarrierConn) SetWriteDeadline(deadline time.Time) error {
	return c.record("write", deadline, c.Conn.SetWriteDeadline)
}

func TestProbeContextConnCancellationCannotBeOverwrittenByFutureSetter(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	raw := &probeBarrierConn{Conn: local, entered: make(chan struct{}), release: make(chan struct{}), cancelWrite: make(chan struct{})}
	raw.blocked.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := newProbeContextConn(ctx, raw)
	defer conn.stopCancellation()
	future := time.Now().Add(time.Hour)
	setDone := make(chan error, 1)
	go func() { setDone <- conn.SetDeadline(future) }()
	select {
	case <-raw.entered:
	case <-time.After(time.Second):
		t.Fatal("future setter did not reach the transport barrier")
	}
	cancel()
	// The raw future setter is still paused. Release it and require a later
	// cancellation deadline to reach the same real transport.
	close(raw.release)
	select {
	case err := <-setDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("future setter remained blocked")
	}
	select {
	case <-raw.cancelWrite:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not follow the in-progress setter")
	}
	// Re-setting or clearing any deadline after cancellation must be clamped
	// by the wrapper; these are the actual setters used by TCP and UDP probes.
	for _, set := range []func(time.Time) error{conn.SetDeadline, conn.SetReadDeadline, conn.SetWriteDeadline} {
		if err := set(future); err != nil {
			t.Fatal(err)
		}
		if err := set(time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	raw.mu.Lock()
	log := append([]probeRecordedDeadline(nil), raw.deadlineLog...)
	raw.mu.Unlock()
	if len(log) < 8 || !log[0].when.Equal(future) {
		t.Fatalf("forced setter interleaving was not observed: %v", log)
	}
	for _, entry := range log[1:] {
		if entry.when.IsZero() || entry.when.After(time.Now()) {
			t.Fatalf("cancelled %s deadline was extended: %v", entry.kind, entry.when)
		}
	}
}

func TestProbeContextConnEverySetterRespectsContextDeadline(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	raw := &probeBarrierConn{Conn: local, entered: make(chan struct{}), release: make(chan struct{}), cancelWrite: make(chan struct{})}
	limit := time.Now().Add(time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), limit)
	defer cancel()
	conn := newProbeContextConn(ctx, raw)
	defer conn.stopCancellation()
	for _, set := range []func(time.Time) error{conn.SetDeadline, conn.SetReadDeadline, conn.SetWriteDeadline} {
		if err := set(time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := set(time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	raw.mu.Lock()
	log := append([]probeRecordedDeadline(nil), raw.deadlineLog...)
	raw.mu.Unlock()
	if len(log) != 6 {
		t.Fatalf("deadline setters missing: %v", log)
	}
	for _, entry := range log {
		if !entry.when.Equal(limit) {
			t.Fatalf("%s setter escaped context ceiling: %v, want %v", entry.kind, entry.when, limit)
		}
	}
}
