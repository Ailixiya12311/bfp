package session

import (
	"bfp/internal/operation"
	"bfp/obfuscation"
	"bfp/protocol"
	"bfp/scheduler"
	"bfp/security"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// Owner-only transition tests use a virtual clock and an explicit successful
// or short-writing carrier. They prove publication/accounting and monotonic
// deadlines, not network latency, server registry cleanup, or wire admission.
type closeCaptureConn struct {
	writes [][]byte
	short  bool
}

func (c *closeCaptureConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	if c.short {
		return len(p) - 1, nil
	}
	return len(p), nil
}

func (c *closeCaptureConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *closeCaptureConn) Close() error                     { return nil }
func (c *closeCaptureConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *closeCaptureConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *closeCaptureConn) SetDeadline(time.Time) error      { return nil }
func (c *closeCaptureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *closeCaptureConn) SetWriteDeadline(time.Time) error { return nil }

func closeOwnerFixture(t *testing.T, short bool) (*Session, *closeCaptureConn, *security.RecordCipher, time.Time) {
	t.Helper()
	s, _ := stateSession(t, "tcp")
	businessCancel := s.cancel
	control, controlCancel := context.WithCancel(context.Background())
	t.Cleanup(controlCancel)
	s.controlCtx, s.stopBusiness, s.stopControl = control, businessCancel, controlCancel
	s.cancel = func() { businessCancel(); controlCancel() }
	s.opts.CloseTimeout = 3 * time.Second
	s.closeWake = make(chan struct{}, 1)
	s.closeErr = ErrCloseUnconfirmed
	now := time.Unix(1700000000, 0)
	s.transportNow = func() time.Time { return now }
	// Pure owner transitions explicitly simulate both clocks; runtime actors
	// leave closeNow nil so diagnostic time cannot postpone graceful cleanup.
	s.closeNow = s.transportNow
	conn := &closeCaptureConn{short: short}
	keys := &security.TransportKeys{}
	for i := range keys.Send {
		keys.Send[i], keys.Receive[i] = byte(i+1), byte(i+51)
	}
	handle := make([]byte, 16)
	copy(handle, []byte("owner-close-v3!!"))
	c, err := makeCarrier("udp", 1, handle, keys, conn, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.current = c
	shadow, err := security.NewRecordCipher(keys.Send[:], c.handle, 0)
	if err != nil {
		t.Fatal(err)
	}
	return s, conn, shadow, now
}

func TestBoundedCloseAckRequiresCompletePublication(t *testing.T) {
	s, conn, _, now := closeOwnerFixture(t, true)
	s.requestClose(true, now)
	s.handleCloseControl(protocol.Frame{Kind: protocol.SessionCloseAck}, now)
	if s.closing.localAcked || s.controlContext().Err() != nil || !errors.Is(s.closeErr, ErrCloseUnconfirmed) {
		t.Fatal("ACK before any record write falsely completed local close")
	}
	s.closeTick(now)
	if len(conn.writes) != 1 || s.closing.localPublished || s.closing.successfulBytes != 0 {
		t.Fatal("short write was counted as complete publication")
	}
	if s.closing.requestAttempts != 1 || s.closing.attemptedBytes != len(conn.writes[0]) {
		t.Fatal("failed write escaped fixed attempt/byte accounting")
	}
	s.handleCloseControl(protocol.Frame{Kind: protocol.SessionCloseAck}, now.Add(10*time.Millisecond))
	if s.closing.localAcked || !errors.Is(s.closeErr, ErrCloseUnconfirmed) {
		t.Fatal("ACK following failed publication produced a successful result")
	}
}

func TestBoundedCloseVirtualFloodHasFixedBudgetAndDeadline(t *testing.T) {
	s, conn, shadow, start := closeOwnerFixture(t, false)
	s.requestClose(true, start)
	s.handleCloseControl(protocol.Frame{Kind: protocol.SessionClose}, start)
	s.closeTick(start)
	wantDeadline := start.Add(3 * time.Second)
	for step := 1; step <= 29; step++ {
		now := start.Add(time.Duration(step) * 100 * time.Millisecond)
		// Repeated fresh authenticated requests are represented here by
		// serialized state inputs; real ciphertext replay is a separate test.
		for flood := 0; flood < 25; flood++ {
			s.handleCloseControl(protocol.Frame{Kind: protocol.SessionClose}, now)
		}
		s.closeTick(now)
		if s.closing.deadline != wantDeadline || s.closing.started != start {
			t.Fatal("duplicate request renewed first close deadline")
		}
	}
	s.closeTick(wantDeadline)
	if s.controlContext().Err() == nil {
		t.Fatal("virtual close remained live at absolute deadline")
	}
	if len(conn.writes) == 0 || len(conn.writes) > maxCloseRequests+maxCloseResponses {
		t.Fatalf("physical close records %d exceed logical request+response attempt budget", len(conn.writes))
	}
	kinds := map[protocol.Kind]int{}
	metas := map[security.RecordMeta]bool{}
	bytes := 0
	for _, wire := range conn.writes {
		plain, meta, err := shadow.Open(wire)
		if err == nil {
			plain, err = obfuscation.Unpad(plain)
		}
		if err != nil {
			t.Fatal(err)
		}
		frames, err := protocol.Decode(plain)
		if err != nil || len(frames) < 1 || len(frames) > 2 {
			t.Fatalf("captured close wire failed independent decode: frames=%d err=%v", len(frames), err)
		}
		if len(frames) == 2 && (frames[0].Kind != protocol.SessionClose || frames[1].Kind != protocol.SessionCloseAck) {
			t.Fatal("captured paired close transaction is not [Close, CloseAck]")
		}
		for _, f := range frames {
			if !canonicalClose(f) {
				t.Fatal("captured close wire has noncanonical semantic fields")
			}
			kinds[f.Kind]++
		}
		if metas[meta] {
			t.Fatal("retry reused record number")
		}
		metas[meta] = true
		bytes += len(wire)
		if len(wire) > 332 {
			t.Fatal("record exceeds documented LIGHT bound")
		}
	}
	if kinds[protocol.SessionClose] != maxCloseRequests || kinds[protocol.SessionCloseAck] < 1 || kinds[protocol.SessionCloseAck] > maxCloseResponses || bytes > maxCloseWireBytes {
		t.Fatalf("wire budget changed: requests=%d responses=%d bytes=%d", kinds[protocol.SessionClose], kinds[protocol.SessionCloseAck], bytes)
	}
	if kinds[protocol.SessionClose] != s.closing.requestAttempts || kinds[protocol.SessionCloseAck] != s.closing.ackAttempts {
		t.Fatal("decoded logical attempt counts differ from close owner accounting")
	}
	if bytes != s.closing.attemptedBytes || bytes != s.closing.successfulBytes {
		t.Fatal("wire evidence differs from fixed close accounting")
	}
	before := len(conn.writes)
	s.requestClose(true, wantDeadline.Add(time.Hour))
	s.handleCloseControl(protocol.Frame{Kind: protocol.SessionCloseAck}, wantDeadline.Add(time.Hour))
	s.closeTick(wantDeadline.Add(time.Hour))
	if s.closing.deadline != wantDeadline || len(conn.writes) != before || s.closing.localAcked {
		t.Fatal("late Close/ACK renewed or revived expired close state")
	}
}

func TestBoundedCloseCanonicalFieldsOnAuthenticatedCarriers(t *testing.T) {
	for _, kind := range []protocol.Kind{protocol.SessionClose, protocol.SessionCloseAck} {
		for _, field := range []string{"flags", "flow", "offset", "value", "data"} {
			name := "close"
			if kind == protocol.SessionCloseAck {
				name = "ack"
			}
			t.Run(name+"/"+field, func(t *testing.T) {
				f := newCloseTestFixture(t, "udp", 500*time.Millisecond, nil)
				frame := protocol.Frame{Kind: kind}
				switch field {
				case "flags":
					frame.Flags = 1
				case "flow":
					frame.Flow = 1
				case "offset":
					frame.Offset = 1
				case "value":
					frame.Value = 1
				case "data":
					frame.Data = []byte{1}
				}
				closeInjectFrames(t, f.sessions[0], frame)
				select {
				case <-f.sessions[1].done:
				case <-time.After(time.Second):
					t.Fatal("authenticated noncanonical control did not abort")
				}
				if !errors.Is(f.sessions[1].closeErr, ErrCloseUnconfirmed) || f.sessions[1].closing.localAcked {
					t.Fatal("noncanonical control established a successful confirmation")
				}
				if len(f.relay.selected(1, protocol.SessionCloseAck)) != 0 {
					t.Fatal("malformed Close generated success ACK")
				}
			})
		}
	}
}

func TestBoundedCloseReserveBypassesBusinessSaturationAndSync(t *testing.T) {
	f := newCloseTestFixture(t, "udp", 600*time.Millisecond, nil)
	s := f.sessions[0]
	var beforeFlight, beforeCwnd int
	var beforePacer float64
	if err := s.call(context.Background(), func() {
		s.synced, s.peerDone, s.localDoneAck = false, false, false
		s.flight = s.cwnd
		s.paceTokens = 0
		beforeFlight, beforeCwnd, beforePacer = s.flight, s.cwnd, s.paceTokens
		s.queue = scheduler.New[protocol.Frame](1200, 64)
		if err := s.queue.Push(81, protocol.Normal, 64, protocol.Frame{Kind: protocol.StreamData, Flow: 81, Data: []byte("forbidden-business")}); err != nil {
			t.Error(err)
		}
		cfg := operation.DefaultConfig()
		cfg.MaxOperations = 1
		var err error
		s.operations, err = operation.New(cfg)
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := s.operations.Start(operation.Key{Kind: protocol.Open, Flow: 81}, 0); err != nil {
			t.Error(err)
		}
		if _, err := s.operations.Start(operation.Key{Kind: protocol.Open, Flow: 82}, 0); !errors.Is(err, operation.ErrLimit) {
			t.Errorf("operation table not full: %v", err)
		}
		// Same owner callback publishes intent before normal flush can use the
		// deliberately saturated business state.
		s.requestClose(true, s.transportTime())
	}); err != nil {
		t.Fatal(err)
	}
	closeTestResult(t, s, nil, 1300*time.Millisecond)
	closeAssertRecords(t, f.relay.selected(0, protocol.SessionClose), 1, 5)
	if s.flight != beforeFlight || s.cwnd != beforeCwnd || s.paceTokens != beforePacer {
		t.Fatal("close reserve fabricated ordinary cwnd/flight/pacer availability")
	}
	for _, p := range f.relay.selected(0, protocol.StreamData) {
		if p.frame.Flow == 81 {
			t.Fatal("saturated business frame escaped terminal cleanup")
		}
	}
}

func TestBoundedCloseFirstPeerIntentIsNotUpgradedByApplication(t *testing.T) {
	f := newCloseTestFixture(t, "udp", 500*time.Millisecond, nil)
	closeInjectFrames(t, f.sessions[0], protocol.Frame{Kind: protocol.SessionClose})
	runtimeWait(t, "peer-first close intent", f.sessions[1].terminating)
	closeTestResult(t, f.sessions[1], nil, 1200*time.Millisecond)
	if f.sessions[1].localClose.Load() || len(f.relay.selected(1, protocol.SessionClose)) != 0 {
		t.Fatal("later application Close created a second logical close request")
	}
	closeAssertRecords(t, f.relay.selected(1, protocol.SessionCloseAck), 1, 8)
}

type closeWriteWatchConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *closeWriteWatchConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

func TestBoundedCloseClampsAlreadyBlockedTCPWrite(t *testing.T) {
	// A private pipe has real concurrent deadline support. The peer deliberately
	// never reads; neither a custom blocking callback nor sleep supplies the
	// unblocking behavior. This tests the existing ordinary write's 2s deadline
	// being tightened when the application publishes close intent.
	left, right := net.Pipe()
	t.Cleanup(func() { left.Close(); right.Close() })
	watch := &closeWriteWatchConn{Conn: left, started: make(chan struct{})}
	parent, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	info := sessionInfo{ID: "blocked-tcp-close", Profile: ProfileClassAnnouncementV1, Capabilities: CapabilityClassAnnouncementV1}
	s := newSession(parent, info, Options{CloseTimeout: 150 * time.Millisecond, ProbeInterval: time.Hour, KeyUpdateInterval: time.Hour}, true, nil)
	t.Cleanup(func() {
		cancel()
		select {
		case <-s.done:
		case <-time.After(time.Second):
			t.Error("blocked-write close actor did not stop")
		}
	})
	keys := &security.TransportKeys{}
	c, err := makeCarrier("tcp", 1, make([]byte, 16), keys, watch, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.profile, c.capabilities = info.Profile, info.Capabilities
	if err := s.attach(c, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.call(context.Background(), func() {
		s.active, s.synced, s.peerDone, s.localDoneAck = true, true, true, true
		s.enqueue(protocol.Frame{Kind: protocol.Ping, Value: 17}, protocol.Interactive)
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-watch.started:
	case <-time.After(time.Second):
		t.Fatal("ordinary framed TCP write did not enter actual blocked pipe")
	}
	started := time.Now()
	closeTestResult(t, s, ErrCloseUnconfirmed, 600*time.Millisecond)
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Errorf("already blocked TCP write exceeded close deadline observation: %v", elapsed)
	}
	if !s.terminating() || !s.closed() || s.closing.localPublished {
		t.Fatal("blocked carrier either reopened business or claimed unpublished confirmation")
	}
}

func TestBoundedCloseRejectsOldCarrierAck(t *testing.T) {
	s, _, _, start := closeOwnerFixture(t, false)
	s.requestClose(true, start)
	s.closeTick(start)
	plain, err := protocol.Encode([]protocol.Frame{{Kind: protocol.SessionCloseAck}})
	if err == nil {
		plain, err = obfuscation.Pad(plain, security.MaxUDPRecordSize-security.RecordOverhead)
	}
	if err != nil {
		t.Fatal(err)
	}
	peer, err := security.NewRecordCipher(s.current.keys.Receive[:], s.current.handle, 0)
	if err != nil {
		t.Fatal(err)
	}
	wire, _, err := peer.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	old := &carrier{kind: "udp", generation: 0, handle: s.current.handle}
	s.receive(packet{c: old, wire: wire})
	if s.closing.localAcked || s.controlContext().Err() != nil || !errors.Is(s.closeErr, ErrCloseUnconfirmed) {
		t.Fatal("old carrier ACK confirmed currently bound close operation")
	}
	// The old pointer was rejected before current cipher/replay admission; the
	// exact valid record still succeeds when delivered on its bound carrier.
	s.receive(packet{c: s.current, wire: wire})
	if !s.closing.localAcked || s.closeErr != nil || s.controlContext().Err() == nil {
		t.Fatal("current authenticated carrier ACK failed exact publication association")
	}
}

func TestBoundedCloseDeadlineNeverExtendsAuthorityOrRetention(t *testing.T) {
	for _, mode := range []string{"immutable-lifetime", "already-suspended-retention"} {
		t.Run(mode, func(t *testing.T) {
			s, conn, _, start := closeOwnerFixture(t, false)
			want := start.Add(450 * time.Millisecond)
			if mode == "immutable-lifetime" {
				s.info.lifetimeUntil = want
			} else {
				s.opts.RetainTimeout = 30 * time.Second
				s.suspendedAt = want.Add(-s.opts.RetainTimeout)
			}
			s.requestClose(true, start)
			s.closeTick(start)
			if s.closing.deadline != want {
				t.Fatalf("close extended prior cutoff: got=%v want=%v", s.closing.deadline, want)
			}
			s.closeTick(start.Add(200 * time.Millisecond))
			s.handleCloseControl(protocol.Frame{Kind: protocol.SessionClose}, want.Add(-time.Nanosecond))
			if s.closing.deadline != want {
				t.Fatal("fresh peer request extended authority/retention cutoff")
			}
			s.closeTick(want)
			before := len(conn.writes)
			s.closeTick(want.Add(time.Hour))
			if s.controlContext().Err() == nil || len(conn.writes) != before || !errors.Is(s.closeErr, ErrCloseUnconfirmed) {
				t.Fatal("existing cutoff did not stop and retain unconfirmed result")
			}
		})
	}
}

func TestBoundedCloseUnavailableCarrierHasNoPublication(t *testing.T) {
	for _, mode := range []string{"absent", "closed", "unsupported-kind"} {
		t.Run(mode, func(t *testing.T) {
			s, conn, _, start := closeOwnerFixture(t, false)
			switch mode {
			case "absent":
				s.current = nil
			case "closed":
				s.current.close()
			case "unsupported-kind":
				s.current.kind = "unbound"
			}
			s.requestClose(true, start)
			s.closeTick(start)
			if !s.businessCleaned || s.controlContext().Err() == nil || len(conn.writes) != 0 || s.closing.localPublished || !errors.Is(s.closeErr, ErrCloseUnconfirmed) {
				t.Fatal("unavailable authenticated carrier fabricated publication or deferred cleanup")
			}
		})
	}
}
