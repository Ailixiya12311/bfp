package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This is one bounded loopback diagnostic, not a Windows TUN acceptance test.
// The real UDP handshake, record encryption, replay checks and actors are reused.
// Only inbound carrier delivery is delayed: its 120-160ms delay supplies the
// requested RTT without changing records or introducing synthetic frame errors.
type tunCancelDelayedRecord struct {
	wire []byte
	due  time.Time
	seq  uint64
	err  error
}

type tunCancelDelayedConn struct {
	net.Conn
	incoming  chan tunCancelDelayedRecord
	stopped   chan struct{}
	pumpDone  chan struct{}
	once      sync.Once
	pending   []tunCancelDelayedRecord // confined to Session's one Read worker
	lastSeq   uint64
	received  atomic.Uint64
	reordered atomic.Uint64
}

func newTunCancelDelayedConn(inner net.Conn) *tunCancelDelayedConn {
	c := &tunCancelDelayedConn{Conn: inner, incoming: make(chan tunCancelDelayedRecord, 256),
		stopped: make(chan struct{}), pumpDone: make(chan struct{})}
	go func() {
		defer close(c.pumpDone)
		for seq := uint64(1); ; seq++ {
			buf := make([]byte, 2048)
			n, err := inner.Read(buf)
			delay := 120 * time.Millisecond
			if seq%11 == 0 {
				delay += 40 * time.Millisecond
			}
			record := tunCancelDelayedRecord{wire: buf[:n], due: time.Now().Add(delay), seq: seq, err: err}
			select {
			case c.incoming <- record:
				c.received.Add(1)
			case <-c.stopped:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return c
}

func (c *tunCancelDelayedConn) Read(buf []byte) (int, error) {
	for {
		if len(c.pending) == 0 {
			select {
			case record := <-c.incoming:
				c.pending = append(c.pending, record)
			case <-c.stopped:
				return 0, net.ErrClosed
			}
		}
		best := 0
		for i := range c.pending {
			if c.pending[i].due.Before(c.pending[best].due) {
				best = i
			}
		}
		wait := time.Until(c.pending[best].due)
		if wait <= 0 {
			record := c.pending[best]
			c.pending = append(c.pending[:best], c.pending[best+1:]...)
			if record.seq < c.lastSeq {
				c.reordered.Add(1)
			}
			c.lastSeq = record.seq
			return copy(buf, record.wire), record.err
		}
		timer := time.NewTimer(wait)
		select {
		case record := <-c.incoming:
			timer.Stop()
			if len(c.pending) >= 512 {
				return 0, errors.New("bounded TUN diagnostic relay queue exceeded")
			}
			c.pending = append(c.pending, record)
		case <-timer.C:
		case <-c.stopped:
			timer.Stop()
			return 0, net.ErrClosed
		}
	}
}

func (c *tunCancelDelayedConn) Close() error {
	var err error
	c.once.Do(func() {
		close(c.stopped)
		err = c.Conn.Close()
		<-c.pumpDone
	})
	return err
}

type tunCancelDiagnosticBackend struct {
	Backend
	refused string
}

func (b *tunCancelDiagnosticBackend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if address == b.refused {
		return nil, errors.New("bounded diagnostic target deliberately refused")
	}
	return b.Backend.DialContext(ctx, network, address)
}

func TestTUNBoundedConcurrentOpenDoesNotCancelSession(t *testing.T) {
	var relay *tunCancelDelayedConn
	opts := Options{MaxFlows: 32, HandshakeTimeout: time.Second, ProbeInterval: 100 * time.Millisecond,
		FailureTimeout: 3 * time.Second, RetainTimeout: 30 * time.Second,
		KeyUpdateBytes: 1 << 30, KeyUpdateInterval: time.Hour}
	f := newRuntimeFixtureWith(t, "udp", opts, func(s *Session, c *carrier) {
		relay = newTunCancelDelayedConn(c.conn)
		c.conn = relay
		s.startReader(c)
	})
	t.Cleanup(func() { _ = relay.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	refused := "127.0.0.1:9"
	if err := f.peer.call(ctx, func() { f.peer.backend = &tunCancelDiagnosticBackend{Backend: f.peer.backend, refused: refused} }); err != nil {
		t.Fatal(err)
	}
	fast, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fastDone := make(chan struct{})
	go func() {
		defer close(fastDone)
		for {
			conn, err := fast.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = fast.Close(); <-fastDone })
	checkAlive := func(stage string) {
		t.Helper()
		for label, owner := range map[string]*Session{"client": f.client, "server": f.peer} {
			select {
			case <-owner.BusinessDone():
				source, recorded := owner.TerminationSource()
				t.Fatalf("stage=%s endpoint=%s early_session_termination source=%q recorded=%v", stage, label, source, recorded)
			default:
			}
		}
	}
	// Fill the 32 admitted slots with live local echo connections. Each caller
	// has its own setup context, matching native outbound DialContext ownership.
	held := make([]net.Conn, 32)
	errs := make([]error, 32)
	var wave sync.WaitGroup
	for i := range held {
		wave.Add(1)
		go func(i int) {
			defer wave.Done()
			setup, stop := context.WithTimeout(ctx, 6*time.Second)
			defer stop()
			held[i], errs[i] = f.client.DialContext(setup, "tcp", f.target)
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
	for i, err := range errs {
		if err != nil {
			t.Fatalf("fill_32 flow=%d error=%v", i, err)
		}
	}
	var limited atomic.Int32
	for i := 0; i < 8; i++ {
		wave.Add(1)
		go func() {
			defer wave.Done()
			conn, err := f.client.DialContext(ctx, "tcp", f.target)
			if errors.Is(err, ErrLimit) {
				limited.Add(1)
			}
			if conn != nil {
				_ = conn.Close()
			}
		}()
	}
	wave.Wait()
	checkAlive("eight_excess_opens")
	if limited.Load() != 8 {
		t.Fatalf("excess admission limit_count=%d want=8", limited.Load())
	}
	// Release half the slots quickly, then one concurrent wave of successful,
	// immediate-EOF and deliberately refused targets. Remaining held flows must
	// keep working; this checks Session ownership, not merely absence of a panic.
	for i := 0; i < 16; i++ {
		_ = held[i].Close()
	}
	var opened, failures, churnLimited atomic.Int32
	for i := 0; i < 24; i++ {
		wave.Add(1)
		go func(i int) {
			defer wave.Done()
			target := []string{f.target, fast.Addr().String(), refused}[i%3]
			setup, stop := context.WithTimeout(ctx, 6*time.Second)
			defer stop()
			conn, err := f.client.DialContext(setup, "tcp", target)
			if err != nil {
				failures.Add(1)
				if errors.Is(err, ErrLimit) {
					churnLimited.Add(1)
				}
				return
			}
			opened.Add(1)
			_ = conn.Close()
		}(i)
	}
	wave.Wait()
	checkAlive("mixed_24_open_close_wave")
	for i := 16; i < 20; i++ {
		if err := runtimeExchangeErr(held[i], []byte(fmt.Sprintf("held-flow-%d", i))); err != nil {
			checkAlive("held_echo_failure")
			t.Fatalf("held flow=%d echo error=%v", i, err)
		}
	}
	select {
	case <-time.After(300 * time.Millisecond):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	checkAlive("final_settle")
	cs, cr := f.client.TerminationSource()
	ss, sr := f.peer.TerminationSource()
	t.Logf("bounded_local_diagnostic attempted_opens=64 held=32 excess_limited=%d churn_opened=%d churn_failed=%d churn_limited=%d inbound_delay_ms=120..160 received_records=%d reordered_records=%d client_source=%q client_recorded=%v server_source=%q server_recorded=%v", limited.Load(), opened.Load(), failures.Load(), churnLimited.Load(), relay.received.Load(), relay.reordered.Load(), cs, cr, ss, sr)
	if relay.reordered.Load() == 0 {
		t.Fatal("diagnostic did not exercise record reordering")
	}
}
