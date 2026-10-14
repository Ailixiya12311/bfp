package session

import (
	"bfp/obfuscation"
	"bfp/protocol"
	"bfp/security"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This fixture starts two real Session actors and authenticated record ciphers
// over loopback UDP or TCP. It does not exercise bootstrap, Client recovery,
// Server registry maintenance, or gateway DNS: those need separate integration
// evidence. TCP relay terminates only outer framing and forwards the unchanged
// inner authenticated records; UDP relay forwards the actual datagrams.
type closeWireRecord struct {
	direction int
	frame     protocol.Frame
	meta      security.RecordMeta
	wire      []byte
	at        time.Time
}

type closeTestRelay struct {
	udp       *net.UDPConn
	addresses [2]*net.UDPAddr
	framers   [2]*security.Framer
	conns     []net.Conn
	shadows   [2]*security.RecordCipher
	wg        sync.WaitGroup
	mu        sync.Mutex
	records   []closeWireRecord
	firstDrop [2]protocol.Kind
	dropped   [2]bool
	// Immutable standalone-only loss avoids releasing an older UDP request
	// that reached the relay socket before the hold gate opened but was read late.
	dropStandaloneClose [2]bool
	dropClose           [2]atomic.Bool
	dropAck             [2]atomic.Bool
	// The hold gate and retained first standalone request are protected by mu.
	// Captured ciphertext is released unchanged, outside inspect/Open, once the
	// test has established both local intents. Other held retries are discarded.
	holdClose [2]bool
	heldClose [2]*closeWireRecord
	replay    [2]atomic.Bool
	stop      sync.Once
	decodeErr error
}

func (r *closeTestRelay) inspect(direction int, wire []byte) (drop, duplicate bool) {
	plain, meta, err := r.shadows[direction].Open(wire)
	if err == nil {
		plain, err = obfuscation.Unpad(plain)
	}
	var frames []protocol.Frame
	if err == nil {
		frames, err = protocol.Decode(plain)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		if r.decodeErr == nil {
			r.decodeErr = err
		}
		return false, false
	}
	hasClose := false
	for _, f := range frames {
		r.records = append(r.records, closeWireRecord{direction: direction, frame: f, meta: meta, wire: append([]byte(nil), wire...), at: time.Now()})
		if f.Kind == r.firstDrop[direction] && !r.dropped[direction] {
			r.dropped[direction], drop = true, true
		}
		if f.Kind == protocol.SessionClose {
			hasClose = true
			drop = drop || r.dropClose[direction].Load()
			duplicate = duplicate || r.replay[direction].Load()
		}
		if f.Kind == protocol.SessionCloseAck {
			drop = drop || r.dropAck[direction].Load()
		}
	}
	if r.dropStandaloneClose[direction] && len(frames) == 1 && frames[0].Kind == protocol.SessionClose {
		drop = true
	}
	if r.holdClose[direction] && hasClose {
		if r.heldClose[direction] == nil && len(frames) == 1 && frames[0].Kind == protocol.SessionClose {
			r.heldClose[direction] = &closeWireRecord{direction: direction, frame: frames[0], meta: meta, wire: append([]byte(nil), wire...), at: time.Now()}
		}
		drop = true
	}
	return drop, duplicate
}

func (r *closeTestRelay) heldRequests() (requests [2]closeWireRecord, ready bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range requests {
		if r.heldClose[i] == nil {
			return requests, false
		}
		requests[i] = *r.heldClose[i]
	}
	return requests, true
}

func closeAwaitHeldRequests(t *testing.T, f *closeTestFixture) {
	t.Helper()
	runtimeWait(t, "both local intents and original standalone Close captures", func() bool {
		_, ready := f.relay.heldRequests()
		return ready && f.sessions[0].localClose.Load() && f.sessions[1].localClose.Load()
	})
}

func closeReleaseHeldRequests(t *testing.T, f *closeTestFixture, directions ...int) {
	t.Helper()
	requests, ready := f.relay.heldRequests()
	if !ready {
		t.Fatal("release requires both original standalone Close ciphertexts")
	}
	for _, direction := range directions {
		request := requests[direction]
		if err := f.relay.forward(direction, request.wire); err != nil {
			t.Fatal(err)
		}
		t.Logf("fixture released original standalone Close ciphertext: direction=%d record-number=%d bytes=%d", direction, request.meta.Number, len(request.wire))
	}
	// A successful UDP write proves injection, not receipt. Read the real
	// receiving actor to establish the authenticated request was processed.
	runtimeWait(t, "injected original Close received by each selected peer", func() bool {
		for _, direction := range directions {
			s := f.sessions[1-direction]
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			var received bool
			err := s.call(ctx, func() { received = s.closing.peerRequested })
			cancel()
			if err != nil || !received {
				return false
			}
		}
		return true
	})
	for _, direction := range directions {
		t.Logf("fixture established authenticated peer Close receipt: sender-direction=%d receiver=%d", direction, 1-direction)
	}
}

func (r *closeTestRelay) releaseCloseGates() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.holdClose = [2]bool{}
}

func (r *closeTestRelay) selected(direction int, kind protocol.Kind) []closeWireRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []closeWireRecord
	for _, p := range r.records {
		if p.direction == direction && p.frame.Kind == kind {
			out = append(out, p)
		}
	}
	return out
}

func (r *closeTestRelay) forward(direction int, wire []byte) error {
	if r.udp != nil {
		_, err := r.udp.WriteToUDP(wire, r.addresses[1-direction])
		return err
	}
	return r.framers[1-direction].Write(wire)
}

func (r *closeTestRelay) shutdown() {
	r.stop.Do(func() {
		if r.udp != nil {
			r.udp.Close()
		}
		for _, c := range r.conns {
			c.Close()
		}
	})
	r.wg.Wait()
}

type closeTestBackend struct {
	dialer   net.Dialer
	dials    atomic.Int32
	closed   atomic.Int32
	cleanups atomic.Int32
}

func (b *closeTestBackend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := b.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	b.dials.Add(1)
	return &closeCountConn{Conn: c, count: &b.closed}, nil
}

func (b *closeTestBackend) ForSession(ctx context.Context, valid func() error) (Backend, func()) {
	return &closeScopedBackend{base: b, ctx: ctx, valid: valid}, func() { b.cleanups.Add(1) }
}

type closeScopedBackend struct {
	base  *closeTestBackend
	ctx   context.Context
	valid func() error
}

func (b *closeScopedBackend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := b.valid(); err != nil {
		return nil, err
	}
	if b.ctx.Err() != nil {
		return nil, ErrClosed
	}
	return b.base.DialContext(ctx, network, address)
}

type closeCountConn struct {
	net.Conn
	count *atomic.Int32
	once  sync.Once
}

func (c *closeCountConn) Close() error {
	c.once.Do(func() { c.count.Add(1) })
	return c.Conn.Close()
}

func (c *closeCountConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

type closeTestFixture struct {
	sessions [2]*Session
	carriers [2]*carrier
	relay    *closeTestRelay
	backend  *closeTestBackend
	target   string
}

func newCloseTestFixture(t *testing.T, kind string, timeout time.Duration, configure func(*closeTestRelay)) *closeTestFixture {
	t.Helper()
	r := &closeTestRelay{}
	if configure != nil {
		configure(r)
	}
	keys := [2]security.TransportKeys{}
	for i := range keys[0].Send {
		keys[0].Send[i], keys[0].Receive[i] = byte(i+1), byte(i+71)
		keys[1].Send[i], keys[1].Receive[i] = keys[0].Receive[i], keys[0].Send[i]
	}
	var handle [16]byte
	copy(handle[:], []byte("close-fixture-v3!"))
	for i := range r.shadows {
		var err error
		r.shadows[i], err = security.NewRecordCipher(keys[i].Send[:], handle, 0)
		if err != nil {
			t.Fatal(err)
		}
	}
	var endpoints [2]net.Conn
	if kind == "udp" {
		var err error
		r.udp, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		for i := range endpoints {
			c, err := net.DialUDP("udp", nil, r.udp.LocalAddr().(*net.UDPAddr))
			if err != nil {
				r.shutdown()
				t.Fatal(err)
			}
			endpoints[i], r.addresses[i] = c, c.LocalAddr().(*net.UDPAddr)
			r.conns = append(r.conns, c)
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			buf := make([]byte, security.MaxUDPRecordSize+1)
			for {
				n, from, err := r.udp.ReadFromUDP(buf)
				if err != nil {
					return
				}
				direction := 0
				if from.String() == r.addresses[1].String() {
					direction = 1
				} else if from.String() != r.addresses[0].String() {
					continue
				}
				wire := buf[:n]
				drop, duplicate := r.inspect(direction, wire)
				if drop {
					continue
				}
				if err := r.forward(direction, wire); err != nil {
					return
				}
				if duplicate {
					_ = r.forward(direction, wire)
				}
			}
		}()
	} else {
		for i := range endpoints {
			endpoint, proxy := transportTCPPair(t)
			endpoints[i] = endpoint
			r.conns = append(r.conns, endpoint, proxy)
			var err error
			r.framers[i], err = security.NewFramer(proxy, keys[i].Receive[:], keys[i].Send[:])
			if err != nil {
				t.Fatal(err)
			}
		}
		for i := range endpoints {
			r.wg.Add(1)
			go func(direction int) {
				defer r.wg.Done()
				for {
					wire, err := r.framers[direction].Read()
					if err != nil {
						return
					}
					drop, duplicate := r.inspect(direction, wire)
					if drop {
						continue
					}
					if err := r.forward(direction, wire); err != nil {
						return
					}
					if duplicate {
						_ = r.forward(direction, wire)
					}
				}
			}(i)
		}
	}
	t.Cleanup(r.shutdown)
	backend := &closeTestBackend{}
	parent, cancel := context.WithCancel(context.Background())
	opts := Options{CloseTimeout: timeout, ProbeInterval: time.Hour, FailureTimeout: 5 * time.Second, KeyUpdateBytes: 1 << 30, KeyUpdateInterval: time.Hour}
	f := &closeTestFixture{relay: r, backend: backend}
	for i := range f.sessions {
		var b Backend
		if i == 1 {
			b = backend
		}
		info := sessionInfo{ID: "close-fixture", Profile: ProfileClassAnnouncementV1, Capabilities: CapabilityClassAnnouncementV1}
		f.sessions[i] = newSession(parent, info, opts, i == 0, b)
		c, err := makeCarrier(kind, 1, handle[:], &keys[i], endpoints[i], nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		c.profile, c.capabilities = info.Profile, info.Capabilities
		f.carriers[i] = c
		if err := f.sessions[i].attach(c, 0); err != nil {
			t.Fatal(err)
		}
		f.sessions[i].startReader(c)
	}
	t.Cleanup(func() {
		cancel()
		for _, s := range f.sessions {
			select {
			case <-s.done:
			case <-time.After(time.Second):
				t.Error("bounded-close fixture actor did not stop on parent cancellation")
			}
		}
	})
	for i := range f.sessions {
		f.sessions[i].activate(f.carriers[i])
	}
	runtimeWait(t, "close fixture authenticated synchronization", func() bool { return runtimeReady(f.sessions[0]) && runtimeReady(f.sessions[1]) })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.target = listener.Addr().String()
	var targetMu sync.Mutex
	targets := map[net.Conn]bool{}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			targetMu.Lock()
			targets[c] = true
			targetMu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				defer func() { targetMu.Lock(); delete(targets, c); targetMu.Unlock() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		targetMu.Lock()
		for c := range targets {
			c.Close()
		}
		targetMu.Unlock()
		workers.Wait()
	})
	return f
}

func (f *closeTestFixture) flow(t *testing.T) *Flow {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := f.sessions[0].DialContext(ctx, "tcp", f.target)
	if err != nil {
		t.Fatal(err)
	}
	flow := conn.(*Flow)
	if err := runtimeExchangeErr(flow, []byte("live-before-close")); err != nil {
		t.Fatal(err)
	}
	return flow
}

func closeTestResult(t *testing.T, s *Session, want error, bound time.Duration) {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- s.Close() }()
	select {
	case err := <-result:
		if !errors.Is(err, want) {
			t.Fatalf("Close result %v, want %v", err, want)
		}
	case <-time.After(bound):
		t.Fatal("Close exceeded independent observation bound")
	}
}

func closeAssertRecords(t *testing.T, records []closeWireRecord, minCount, maxCount int) {
	t.Helper()
	if len(records) < minCount || len(records) > maxCount {
		t.Fatalf("observed authenticated close records %d, want [%d,%d]", len(records), minCount, maxCount)
	}
	metas := map[security.RecordMeta]bool{}
	wireBytes := 0
	for _, r := range records {
		f := r.frame
		if f.Flags != 0 || f.Flow != 0 || f.Offset != 0 || f.Value != 0 || len(f.Data) != 0 {
			t.Errorf("noncanonical close-control record: kind=%d flags=%d flow=%d offset=%d value=%d bytes=%d", f.Kind, f.Flags, f.Flow, f.Offset, f.Value, len(f.Data))
		}
		if metas[r.meta] {
			t.Error("logical close retry reused an authenticated record number")
		}
		metas[r.meta] = true
		wireBytes += len(r.wire)
		if len(r.wire) > 332 {
			t.Errorf("close-control record exceeded fixed LIGHT envelope: %d", len(r.wire))
		}
	}
	if len(records) > 0 {
		t.Logf("authenticated close capture: direction=%d kind=%d records=%d unique-record-numbers=%d record-bytes=%d first-number=%d last-number=%d", records[0].direction, records[0].frame.Kind, len(records), len(metas), wireBytes, records[0].meta.Number, records[len(records)-1].meta.Number)
	}
}

func TestBoundedCloseNormalAuthenticatedCarriers(t *testing.T) {
	for _, kind := range []string{"udp", "tcp"} {
		for _, initiator := range []int{0, 1} {
			t.Run(kind+"/initiator-"+string(rune('0'+initiator)), func(t *testing.T) {
				f := newCloseTestFixture(t, kind, 700*time.Millisecond, nil)
				flow := f.flow(t)
				closeTestResult(t, f.sessions[initiator], nil, 1500*time.Millisecond)
				runtimeWait(t, "peer immediate owned target cleanup", func() bool { return f.backend.closed.Load() == 1 && f.backend.cleanups.Load() == 1 })
				flow.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				if _, err := flow.Read(make([]byte, 1)); !errors.Is(err, ErrClosed) {
					t.Fatalf("Flow waiter after close: %v", err)
				}
				closeAssertRecords(t, f.relay.selected(initiator, protocol.SessionClose), 1, 5)
				closeAssertRecords(t, f.relay.selected(1-initiator, protocol.SessionCloseAck), 1, 8)
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
				if _, err := f.sessions[0].DialContext(ctx, "tcp", f.target); !errors.Is(err, ErrClosed) {
					t.Fatalf("new Dial admitted after close: %v", err)
				}
			})
		}
	}
}

func TestBoundedCloseFirstRequestOrAckLoss(t *testing.T) {
	for _, kind := range []string{"udp", "tcp"} {
		for _, lost := range []protocol.Kind{protocol.SessionClose, protocol.SessionCloseAck} {
			name := "request"
			if lost == protocol.SessionCloseAck {
				name = "ack"
			}
			t.Run(kind+"/"+name, func(t *testing.T) {
				f := newCloseTestFixture(t, kind, 900*time.Millisecond, func(r *closeTestRelay) {
					direction := 0
					if lost == protocol.SessionCloseAck {
						direction = 1
					}
					r.firstDrop[direction] = lost
				})
				f.flow(t)
				closeTestResult(t, f.sessions[0], nil, 1700*time.Millisecond)
				closeAssertRecords(t, f.relay.selected(0, protocol.SessionClose), 2, 5)
				minAck := 1
				if lost == protocol.SessionCloseAck {
					minAck = 2
				}
				closeAssertRecords(t, f.relay.selected(1, protocol.SessionCloseAck), minAck, 8)
				if f.backend.closed.Load() != 1 || f.backend.cleanups.Load() != 1 {
					t.Fatalf("duplicate close repeated or omitted cleanup: target=%d scope=%d", f.backend.closed.Load(), f.backend.cleanups.Load())
				}
			})
		}
	}
}

func TestBoundedCloseAllAckLossKeepsPeerCleanup(t *testing.T) {
	f := newCloseTestFixture(t, "udp", 850*time.Millisecond, func(r *closeTestRelay) { r.dropAck[1].Store(true) })
	flow := f.flow(t)
	started := time.Now()
	closeTestResult(t, f.sessions[0], ErrCloseUnconfirmed, 1500*time.Millisecond)
	if elapsed := time.Since(started); elapsed < 750*time.Millisecond || elapsed > 1350*time.Millisecond {
		t.Errorf("all-ACK-loss close elapsed %v outside fixed deadline observation", elapsed)
	}
	closeAssertRecords(t, f.relay.selected(0, protocol.SessionClose), 3, 5)
	closeAssertRecords(t, f.relay.selected(1, protocol.SessionCloseAck), 1, 8)
	if f.backend.closed.Load() != 1 || f.backend.cleanups.Load() != 1 {
		t.Fatalf("lost ACK must preserve already committed peer cleanup: target=%d scope=%d", f.backend.closed.Load(), f.backend.cleanups.Load())
	}
	flow.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := flow.Write([]byte("forbidden-after-close")); !errors.Is(err, ErrClosed) {
		t.Fatalf("business Write after terminal decision: %v", err)
	}
}

func TestBoundedCloseAllRequestLossHonestResultAndBudget(t *testing.T) {
	f := newCloseTestFixture(t, "udp", 2800*time.Millisecond, func(r *closeTestRelay) { r.dropClose[0].Store(true) })
	f.flow(t)
	started := time.Now()
	closeTestResult(t, f.sessions[0], ErrCloseUnconfirmed, 3500*time.Millisecond)
	closeAssertRecords(t, f.relay.selected(0, protocol.SessionClose), 5, 5)
	if len(f.relay.selected(1, protocol.SessionCloseAck)) != 0 {
		t.Fatal("peer acknowledged a request that never reached it")
	}
	if f.backend.closed.Load() != 0 || f.backend.cleanups.Load() != 0 || f.sessions[1].terminating() {
		t.Fatal("local Close result falsely implied unreachable peer terminal cleanup")
	}
	if elapsed := time.Since(started); elapsed < 2600*time.Millisecond || elapsed > 3300*time.Millisecond {
		t.Errorf("all-request-loss elapsed %v outside fixed deadline observation", elapsed)
	}
}

func TestBoundedCloseConcurrentCallsShareUnconfirmedResult(t *testing.T) {
	f := newCloseTestFixture(t, "udp", 600*time.Millisecond, func(r *closeTestRelay) { r.dropAck[1].Store(true) })
	const callers = 12
	results := make(chan error, callers)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		go func() { <-start; results <- f.sessions[0].Close() }()
	}
	started := time.Now()
	close(start)
	deadline := time.NewTimer(1300 * time.Millisecond)
	defer deadline.Stop()
	for i := 0; i < callers; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, ErrCloseUnconfirmed) {
				t.Fatalf("concurrent caller %d obtained misleading result %v", i, err)
			}
		case <-deadline.C:
			t.Fatal("concurrent Close callers did not share bounded completion")
		}
	}
	if time.Since(started) < 500*time.Millisecond {
		t.Fatal("a duplicate Close returned before shared confirmation decision")
	}
	closeTestResult(t, f.sessions[0], ErrCloseUnconfirmed, 100*time.Millisecond)
	closeAssertRecords(t, f.relay.selected(0, protocol.SessionClose), 2, 5)
}

func TestBoundedCloseSimultaneousRequests(t *testing.T) {
	for _, loss := range []string{"none", "one-ack-direction", "both-ack-directions"} {
		t.Run(loss, func(t *testing.T) {
			f := newCloseTestFixture(t, "udp", 700*time.Millisecond, func(r *closeTestRelay) {
				// Retain both original standalone requests until both application
				// intents and ciphertexts exist. Merely dropping the first requests
				// and opening the gate can leave only a paired Close+Ack retry,
				// which whole-record ACK loss also prevents the peer from seeing.
				r.holdClose = [2]bool{true, true}
				if loss != "none" {
					r.dropAck[1].Store(true)
				}
				if loss == "both-ack-directions" {
					r.dropAck[0].Store(true)
				}
			})
			start := make(chan struct{})
			results := [2]chan error{make(chan error, 1), make(chan error, 1)}
			for i := range f.sessions {
				go func(direction int) { <-start; results[direction] <- f.sessions[direction].Close() }(i)
			}
			close(start)
			closeAwaitHeldRequests(t, f)
			closeReleaseHeldRequests(t, f, 0, 1)
			f.relay.releaseCloseGates()
			for i := range results {
				var want error
				if loss == "both-ack-directions" || loss == "one-ack-direction" && i == 0 {
					want = ErrCloseUnconfirmed
				}
				select {
				case err := <-results[i]:
					if !errors.Is(err, want) {
						t.Errorf("simultaneous close direction %d result %v want %v", i, err, want)
					}
				case <-time.After(1300 * time.Millisecond):
					t.Fatal("simultaneous Close exceeded bounded drain")
				}
				closeAssertRecords(t, f.relay.selected(i, protocol.SessionClose), 1, 5)
				closeAssertRecords(t, f.relay.selected(i, protocol.SessionCloseAck), 1, 8)
			}
		})
	}
}

func TestBoundedClosePairedRequestAckRecordLoss(t *testing.T) {
	f := newCloseTestFixture(t, "udp", 700*time.Millisecond, func(r *closeTestRelay) {
		r.holdClose = [2]bool{true, true}
		r.dropStandaloneClose[1] = true
		r.dropAck[1].Store(true)
	})
	flow := f.flow(t)
	start := make(chan struct{})
	results := [2]chan error{make(chan error, 1), make(chan error, 1)}
	for i := range f.sessions {
		go func(direction int) { <-start; results[direction] <- f.sessions[direction].Close() }(i)
	}
	started := time.Now()
	close(start)
	closeAwaitHeldRequests(t, f)
	// Only direction 0's original request is released. Direction 1's original
	// standalone requests stay lost, including old retries read late by the
	// relay. Its next Close+Ack is one AEAD record,
	// so dropping that ACK also drops the request. There is no two-sided receipt
	// premise and direction 0 must not invent a reply to an unseen request.
	closeReleaseHeldRequests(t, f, 0)
	f.relay.releaseCloseGates()
	deadline := time.NewTimer(1300 * time.Millisecond)
	defer deadline.Stop()
	for i := range results {
		select {
		case err := <-results[i]:
			if !errors.Is(err, ErrCloseUnconfirmed) {
				t.Errorf("whole paired-record loss direction %d result %v want %v", i, err, ErrCloseUnconfirmed)
			}
		case <-deadline.C:
			t.Fatal("whole paired-record loss exceeded bounded close drain")
		}
	}
	if elapsed := time.Since(started); elapsed > 1300*time.Millisecond {
		t.Errorf("whole paired-record loss exceeded shared observation bound: %v", elapsed)
	}
	closeAssertRecords(t, f.relay.selected(0, protocol.SessionClose), 1, 5)
	closeAssertRecords(t, f.relay.selected(0, protocol.SessionCloseAck), 0, 0)
	closeAssertRecords(t, f.relay.selected(1, protocol.SessionClose), 2, 5)
	acks := f.relay.selected(1, protocol.SessionCloseAck)
	closeAssertRecords(t, acks, 1, 8)
	f.relay.mu.Lock()
	var firstPair []protocol.Kind
	for _, record := range f.relay.records {
		if record.direction == 1 && record.meta == acks[0].meta {
			firstPair = append(firstPair, record.frame.Kind)
		}
	}
	f.relay.mu.Unlock()
	if len(firstPair) != 2 || firstPair[0] != protocol.SessionClose || firstPair[1] != protocol.SessionCloseAck {
		t.Fatalf("lost first ACK must be an unchanged ordered Close+Ack record, got %v", firstPair)
	}
	t.Logf("whole-record ACK loss also withheld peer request: sender-direction=1 record-number=%d frames=%v; receiver-direction=0 emitted zero ACKs", acks[0].meta.Number, firstPair)
	if f.backend.closed.Load() != 1 || f.backend.cleanups.Load() != 1 {
		t.Fatalf("local close cleanup repeated or omitted under whole-record loss: target=%d scope=%d", f.backend.closed.Load(), f.backend.cleanups.Load())
	}
	if f.sessions[0].closing.peerRequested || !f.sessions[1].closing.peerRequested {
		t.Fatal("whole paired-record loss did not preserve the actual one-sided request receipt")
	}
	f.relay.mu.Lock()
	decodeErr := f.relay.decodeErr
	f.relay.mu.Unlock()
	if decodeErr != nil {
		t.Fatalf("whole-record loss relay failed to decode an emitted authenticated record: %v", decodeErr)
	}
	for i, s := range f.sessions {
		if !s.closed() || s.closing.requestAttempts > maxCloseRequests || s.closing.ackAttempts > maxCloseResponses || s.closing.attemptedBytes > maxCloseWireBytes {
			t.Errorf("whole-record loss left owner or control budget unbounded: direction=%d closed=%v state=%+v", i, s.closed(), s.closing)
		}
		if s.streams != nil || s.queue != nil || s.pending != nil || s.backend != nil || s.closeBackend != nil || s.stats.TXBuffered != 0 || s.stats.RXBuffered != 0 {
			t.Errorf("whole-record loss retained owned business resources after close: direction=%d", i)
		}
		closeTestResult(t, s, ErrCloseUnconfirmed, 100*time.Millisecond)
	}
	flow.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := flow.Write([]byte("forbidden-after-paired-record-loss")); !errors.Is(err, ErrClosed) {
		t.Fatalf("business Write after whole paired-record loss: %v", err)
	}
}

func TestBoundedCloseCiphertextReplayDoesNotDuplicateCleanupOrAck(t *testing.T) {
	f := newCloseTestFixture(t, "udp", 550*time.Millisecond, func(r *closeTestRelay) { r.replay[0].Store(true) })
	f.flow(t)
	closeTestResult(t, f.sessions[0], nil, 1300*time.Millisecond)
	if f.backend.closed.Load() != 1 || f.backend.cleanups.Load() != 1 {
		t.Fatal("ciphertext replay repeated owned cleanup")
	}
	closeAssertRecords(t, f.relay.selected(0, protocol.SessionClose), 1, 1)
	closeAssertRecords(t, f.relay.selected(1, protocol.SessionCloseAck), 1, 1)
}

func closeInjectFrames(t *testing.T, s *Session, frames ...protocol.Frame) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var sendErr error
	if err := s.call(ctx, func() {
		if s.current.kind == "udp" && len(frames) == 1 {
			// Single injected frames use the ordinary transport publication
			// path so a receiver PacketAck cannot acknowledge an artificial
			// unsent hole in this fixture's still-open sender ledger.
			sent, err := s.udpSend(frames[0], false, false, false)
			if err == nil && !sent {
				err = ErrLimit
			}
			sendErr = err
			return
		}
		plain, err := protocol.Encode(frames)
		if err == nil {
			plain, err = obfuscation.Pad(plain, security.MaxRecordSize-security.RecordOverhead)
		}
		var wire []byte
		if err == nil {
			wire, _, err = s.current.tx.Seal(plain)
		}
		if err == nil {
			err = s.current.write(wire)
		}
		sendErr = err
	}); err != nil {
		t.Fatal(err)
	}
	if sendErr != nil {
		t.Fatal(sendErr)
	}
}

func TestBoundedCloseRecordStopsFollowingOpen(t *testing.T) {
	f := newCloseTestFixture(t, "udp", 500*time.Millisecond, nil)
	target := protocol.Target{Network: "tcp", Address: f.target, Class: protocol.Normal}
	encoded := encodeJSON(target)
	closeInjectFrames(t, f.sessions[0], protocol.Frame{Kind: protocol.SessionClose}, protocol.Frame{Kind: protocol.Open, Flow: 81, Data: encoded}, protocol.Frame{Kind: protocol.StreamData, Flow: 81, Data: []byte("must-never-reach-target")})
	runtimeWait(t, "receiver terminal intent", f.sessions[1].terminating)
	select {
	case <-f.sessions[1].done:
	case <-time.After(1200 * time.Millisecond):
		t.Fatal("receiver close drain never terminated")
	}
	if f.backend.dials.Load() != 0 || f.backend.cleanups.Load() != 1 {
		t.Fatalf("business frame after authenticated Close allocated backend state: dials=%d cleanups=%d", f.backend.dials.Load(), f.backend.cleanups.Load())
	}
	if len(f.relay.selected(1, protocol.OpenResult)) != 0 {
		t.Fatal("OPEN after Close generated business response")
	}
}

func TestBoundedCloseUnassociatedAckDoesNotCloseSession(t *testing.T) {
	f := newCloseTestFixture(t, "udp", 600*time.Millisecond, nil)
	closeInjectFrames(t, f.sessions[1], protocol.Frame{Kind: protocol.SessionCloseAck})
	// A subsequent real echo establishes processing progressed beyond the
	// unassociated ACK; a timed sleep cannot prove the peer consumed the record.
	flow := f.flow(t)
	if err := runtimeExchangeErr(flow, bytes.Repeat([]byte("alive"), 8)); err != nil {
		t.Fatal(err)
	}
	if f.sessions[0].terminating() || f.sessions[0].closed() {
		t.Fatal("unassociated ACK terminated an open Session")
	}
	closeTestResult(t, f.sessions[0], nil, 1300*time.Millisecond)
}

func TestBoundedCloseDelayedAckBeforeAndAfterDeadline(t *testing.T) {
	for _, mode := range []string{"before-deadline", "after-deadline"} {
		t.Run(mode, func(t *testing.T) {
			f := newCloseTestFixture(t, "udp", 650*time.Millisecond, func(r *closeTestRelay) { r.dropAck[1].Store(true) })
			f.flow(t)
			result := make(chan error, 1)
			go func() { result <- f.sessions[0].Close() }()
			runtimeWait(t, "first held authenticated ACK", func() bool { return len(f.relay.selected(1, protocol.SessionCloseAck)) > 0 })
			ack := f.relay.selected(1, protocol.SessionCloseAck)[0]
			if mode == "before-deadline" {
				if err := f.relay.forward(1, ack.wire); err != nil {
					t.Fatal(err)
				}
			}
			var want error
			if mode == "after-deadline" {
				want = ErrCloseUnconfirmed
			}
			select {
			case err := <-result:
				if !errors.Is(err, want) {
					t.Fatalf("held ACK close result %v want %v", err, want)
				}
			case <-time.After(1400 * time.Millisecond):
				t.Fatal("held ACK scenario exceeded bounded close deadline")
			}
			if mode == "after-deadline" {
				// The local actor/socket has stopped. A late authenticated record
				// remains unable to change the immutable unconfirmed API result.
				if err := f.relay.forward(1, ack.wire); err != nil {
					t.Fatal(err)
				}
				closeTestResult(t, f.sessions[0], ErrCloseUnconfirmed, 100*time.Millisecond)
			}
			if f.backend.closed.Load() != 1 || f.backend.cleanups.Load() != 1 || !f.sessions[0].closed() {
				t.Fatal("delayed ACK changed terminal resource decision")
			}
		})
	}
}
