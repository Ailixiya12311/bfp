package session

import (
	"bfp/classification"
	"bfp/protocol"
	"bfp/scheduler"
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

type classFixture struct {
	server      *Server
	client      *Client
	local, peer *Session
	backend     *runtimeBackend
	address     string
	accepted    chan net.Conn
}

func classPolicy() classification.Config {
	cfg := classification.DefaultConfig()
	cfg.Behavior = classification.BehaviorConfig{Enabled: true, Window: 400 * time.Millisecond, Bucket: 100 * time.Millisecond, MinTotalBytes: 1000, BulkBytesPerSecond: 1000, BulkSustain: 300 * time.Millisecond, ActivityGap: 100 * time.Millisecond, Restore: true, RestoreBytesPerSecond: 100, RestoreSustain: 300 * time.Millisecond}
	return cfg
}

func newClassFixture(t *testing.T, kind string, local, peer *classification.Config) *classFixture {
	t.Helper()
	seed, cred := newSecurityTestServer(t)
	sc := seed.cfg.Credentials
	seed.Close()
	backend := &runtimeBackend{}
	opts := Options{HandshakeTimeout: 250 * time.Millisecond, ProbeInterval: 100 * time.Millisecond, FailureTimeout: 5 * time.Second, RetainTimeout: 5 * time.Second, KeyUpdateBytes: 1 << 30, KeyUpdateInterval: time.Hour}
	server, err := NewServer(ServerConfig{Listen: "127.0.0.1:0", Credentials: sc, Backend: backend, Options: opts, Classification: peer})
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background()) }()
	t.Cleanup(func() {
		server.Close()
		select {
		case e := <-serveDone:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(time.Second):
			t.Error("classification server did not stop")
		}
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 32)
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			connections[c] = true
			mu.Unlock()
			accepted <- c
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-acceptDone
		mu.Lock()
		defer mu.Unlock()
		for c := range connections {
			c.Close()
		}
	})
	udpAddress := server.Addr().String()
	if kind == "tcp" {
		unused, e := net.ListenPacket("udp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		udpAddress = unused.LocalAddr().String()
		unused.Close()
	}
	client, err := NewClient(ClientConfig{Server: udpAddress, TCPServer: server.Addr().String(), Credentials: cred, Options: opts, Classification: local})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sid := s.Stats().ID
	server.mu.Lock()
	p := server.sessions[sid]
	server.mu.Unlock()
	if p == nil {
		t.Fatal("server session missing")
	}
	runtimeWait(t, "classification synchronization", func() bool { return runtimeReady(s) && runtimeReady(p) })
	if s.Stats().Carrier != kind {
		t.Fatalf("carrier %s want%s", s.Stats().Carrier, kind)
	}
	return &classFixture{server: server, client: client, local: s, peer: p, backend: backend, address: ln.Addr().String(), accepted: accepted}
}

func (f *classFixture) dial(t *testing.T, mode string, meta classification.Metadata) (*Flow, net.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	meta.Target.Network, meta.Target.Address = "tcp", f.address
	var c net.Conn
	var err error
	switch mode {
	case "class":
		c, err = f.client.DialClass(ctx, meta.Target)
	case "metadata":
		c, err = f.client.DialMetadata(ctx, meta)
	default:
		c, err = f.client.DialContext(ctx, "tcp", f.address)
	}
	if err != nil {
		t.Fatal(err)
	}
	flow := c.(*Flow)
	flow.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { flow.Close() })
	select {
	case target := <-f.accepted:
		target.SetDeadline(time.Now().Add(3 * time.Second))
		return flow, target
	case <-ctx.Done():
		t.Fatal("target not accepted")
		return nil, nil
	}
}

func classSnapshot(t *testing.T, s *Session, id uint64) FlowClassification {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out, err := s.FlowClassification(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func setClassClock(t *testing.T, s *Session) *atomic.Int64 {
	t.Helper()
	clock := &atomic.Int64{}
	if err := s.call(context.Background(), func() {
		origin := s.classOrigin
		clock.Store(int64(s.classTime()))
		s.classNow = func() time.Time { return origin.Add(time.Duration(clock.Load())) }
	}); err != nil {
		t.Fatal(err)
	}
	return clock
}

func transferClassBytes(t *testing.T, from net.Conn, to net.Conn, n int) {
	t.Helper()
	payload := bytes.Repeat([]byte{0xA7}, n)
	if count, err := from.Write(payload); err != nil || count != n {
		t.Fatalf("transfer write %d %v", count, err)
	}
	got := make([]byte, n)
	if _, err := io.ReadFull(to, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("transfer read %v", err)
	}
}

func TestClassificationRuntimeLocalRulesHintsAndWireTrust(t *testing.T) {
	local, peer := classification.DefaultConfig(), classification.DefaultConfig()
	local.Behavior.Enabled, peer.Behavior.Enabled = false, false
	local.HighestAllowed = protocol.Normal
	local.Rules = []classification.Rule{{Name: "trusted-domain", DomainSuffix: "example.test", Class: protocol.Interactive}, {Name: "tcp", Network: "tcp", Class: protocol.Bulk}}
	peer.Rules = []classification.Rule{{Name: "peer-tag-is-untrusted", RuleTag: "calls", Class: protocol.Interactive}, {Name: "peer-domain-is-untrusted", DomainSuffix: "example.test", Class: protocol.Interactive}}
	f := newClassFixture(t, "tcp", &local, &peer)
	// Constructor-owned compiled rules must not alias caller config.
	local.Rules[1].Class = protocol.Interactive
	peer.DefaultClass = protocol.Bulk
	plain, _ := f.dial(t, "default", classification.Metadata{})
	if snap := classSnapshot(t, f.local, plain.id); snap.LocalTX.Class != protocol.Bulk || snap.LocalTX.Baseline.Rule != "tcp" {
		t.Fatalf("default dial bypassed rules/aliasedconfig: %+v", snap)
	}
	hinted, _ := f.dial(t, "class", classification.Metadata{Target: protocol.Target{Class: protocol.Interactive, Domain: "chat.example.test", RuleTag: "calls"}})
	if snap := classSnapshot(t, f.local, hinted.id); snap.LocalTX.Class != protocol.Normal || snap.LocalTX.Baseline.Source != classification.SourceHint {
		t.Fatalf("hint cap: %+v", snap)
	}
	trusted, target := f.dial(t, "metadata", classification.Metadata{Target: protocol.Target{Domain: "chat.example.test", RuleTag: "calls", Class: protocol.Normal}, DomainTrusted: true, RuleTagTrusted: true})
	setClassClock(t, f.local)
	setClassClock(t, f.peer)
	if snap := classSnapshot(t, f.local, trusted.id); snap.LocalTX.Class != protocol.Normal || snap.LocalTX.Baseline.Rule != "trusted-domain" {
		t.Fatalf("trusted local rule: %+v", snap)
	}
	if snap := classSnapshot(t, f.peer, trusted.id); snap.LocalTX.Class != protocol.Normal || snap.LocalTX.Baseline.Source != classification.SourceDefault {
		t.Fatalf("wire metadata inherited trust/client policy: %+v", snap)
	}
	transferClassBytes(t, trusted, target, 37)
	before := classSnapshot(t, f.local, trusted.id)
	copy := before
	copy.LocalTX.Class = protocol.Interactive
	copy.LocalTX.Baseline.Class = protocol.Interactive
	if got := classSnapshot(t, f.local, trusted.id); got.LocalTX != before.LocalTX {
		t.Fatal("query mutated or exposed state")
	}
	// Real encrypted peer TX announcements cannot promote or downgrade local
	// policy. The peer may claim arbitrary classes; it publishes each version
	// through the normal exact-ACK control path.
	for _, class := range []protocol.Class{protocol.Interactive, protocol.Bulk} {
		if err := f.peer.call(context.Background(), func() {
			state, _, err := f.peer.classTable.Update(trusted.id, class, f.peer.classStamp())
			if err != nil {
				t.Error(err)
				return
			}
			f.peer.streams[trusted.id].classTX = state
		}); err != nil {
			t.Fatal(err)
		}
		runtimeWait(t, "peer announcement", func() bool {
			view := classSnapshot(t, f.local, trusted.id)
			return view.PeerTX.Known && view.PeerTX.Class == class
		})
		transferClassBytes(t, target, trusted, 9) // Ordered server traffic follows update.
		if got := classSnapshot(t, f.local, trusted.id); got.LocalTX.Class != protocol.Normal || got.LocalTX.TotalBytes != 37 {
			t.Fatalf("peer overwrote local TX: %+v", got)
		}
	}
	if _, err := f.local.FlowClassification(context.Background(), 123456); !errors.Is(err, ErrFlowUnknown) {
		t.Fatalf("unknown query: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := trusted.Classification(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled query: %v", err)
	}
	var original protocol.Target
	_ = f.peer.call(context.Background(), func() {
		original = f.peer.streams[trusted.id].target
		f.peer.handleOpen(protocol.Frame{Kind: protocol.Open, Flow: trusted.id, Data: encodeJSON(original)})
	})
	if f.backend.dials.Load() != 3 || f.peer.ctx.Err() != nil {
		t.Fatal("duplicate OPEN after classification redialed/failed")
	}
}

func TestClassificationRuntimeDirectionsAndIdleTick(t *testing.T) {
	for _, direction := range []string{"upload", "download"} {
		t.Run(direction, func(t *testing.T) {
			cfg := classPolicy()
			f := newClassFixture(t, "tcp", &cfg, &cfg)
			flow, target := f.dial(t, "default", classification.Metadata{})
			localClock, peerClock := setClassClock(t, f.local), setClassClock(t, f.peer)
			for n := 0; n < 9; n++ {
				localClock.Add(int64(100 * time.Millisecond))
				peerClock.Add(int64(100 * time.Millisecond))
				if direction == "upload" {
					transferClassBytes(t, flow, target, 500)
				} else {
					transferClassBytes(t, target, flow, 500)
				}
			}
			localSnap, peerSnap := classSnapshot(t, f.local, flow.id), classSnapshot(t, f.peer, flow.id)
			busy, idle := localSnap, peerSnap
			if direction == "download" {
				busy, idle = peerSnap, localSnap
			}
			if busy.LocalTX.Class != protocol.Bulk || busy.LocalTX.TotalBytes != 4500 || idle.LocalTX.Class != protocol.Normal || idle.LocalTX.TotalBytes != 0 {
				t.Fatalf("direction coupling or double count: busy=%+v idle=%+v", busy, idle)
			}
			for n := 0; n < 9; n++ {
				localClock.Add(int64(100 * time.Millisecond))
				peerClock.Add(int64(100 * time.Millisecond))
				_ = f.local.call(context.Background(), func() { f.local.maintain(time.Now().Add(-time.Hour)) })
				_ = f.peer.call(context.Background(), func() { f.peer.maintain(time.Now().Add(-time.Hour)) })
			}
			// Old ticker values must not be passed into class time, and Tick does
			// not add bytes even when it restores an otherwise idle flow.
			if got := classSnapshot(t, f.local, flow.id); got.LocalTX.Class != protocol.Normal {
				t.Fatalf("local idle restore: %+v", got)
			}
			if got := classSnapshot(t, f.peer, flow.id); got.LocalTX.Class != protocol.Normal {
				t.Fatalf("peer idle restore: %+v", got)
			}
			if f.backend.dials.Load() != 1 {
				t.Fatal("class change redialed target")
			}
		})
	}
}

func TestClassificationRuntimeAtomicDatagramAdmission(t *testing.T) {
	cfg := classification.DefaultConfig()
	cfg.Behavior.Enabled = false
	f := newClassFixture(t, "tcp", &cfg, &cfg)
	address, received := transportUDPEcho(t)
	conn, err := f.client.DialContext(context.Background(), "udp", address)
	if err != nil {
		t.Fatal(err)
	}
	flow := conn.(*Flow)
	t.Cleanup(func() { flow.Close() })
	flow.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16<<10)
	for _, size := range []int{1800, 0} {
		payload := bytes.Repeat([]byte{0x45}, size)
		if n, e := flow.Write(payload); e != nil || n != size {
			t.Fatalf("datagram write %d %v", n, e)
		}
		if n, e := flow.Read(buf); e != nil || n != size || !bytes.Equal(buf[:n], payload) {
			t.Fatalf("datagram boundary %d %v", n, e)
		}
	}
	if got := classSnapshot(t, f.local, flow.id); got.LocalTX.TotalBytes != 1800 {
		t.Fatalf("fragment/empty accounting: %+v", got)
	}
	for _, tc := range []struct {
		name   string
		limits scheduler.Limits
	}{
		{"flow-bytes", scheduler.Limits{MaxBytes: 1 << 20, MaxFlowBytes: 1000}},
		{"class-bytes", scheduler.Limits{MaxBytes: 1 << 20, MaxClassBytes: 1000}},
		{"total-items", scheduler.Limits{MaxBytes: 1 << 20, MaxItems: 2}},
		{"flow-items", scheduler.Limits{MaxBytes: 1 << 20, MaxFlowItems: 2}},
		{"class-items", scheduler.Limits{MaxBytes: 1 << 20, MaxClassItems: 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var message uint64
			var classifier *classification.Flow
			var queue *scheduler.Queue[protocol.Frame]
			var doneAck bool
			var lastSync, lastProbe time.Time
			old := protocol.Frame{Kind: protocol.Datagram, Flow: flow.id, Offset: 999, Data: []byte("old")}
			// Hold emission behind the existing synchronization gate while this
			// live Session's admission remains enabled. Freeze sync/probe timers so
			// their controls do not disturb the isolated pending queue.
			if e := f.local.call(context.Background(), func() {
				st := f.local.streams[flow.id]
				message = st.messageNext
				classifier = st.txClassifier
				queue = f.local.queue
				doneAck, lastSync, lastProbe = f.local.localDoneAck, f.local.lastSync, f.local.lastProbe
				f.local.localDoneAck = false
				f.local.lastSync, f.local.lastProbe = time.Now().Add(time.Hour), time.Now().Add(time.Hour)
				f.local.queue = scheduler.NewWithLimits[protocol.Frame](1200, tc.limits)
				if !f.local.enqueue(old, protocol.Normal) {
					t.Error("seed admission failed")
				}
			}); e != nil {
				t.Fatal(e)
			}
			restore := func() {
				f.local.queue = queue
				f.local.localDoneAck = doneAck
				f.local.lastSync, f.local.lastProbe = lastSync, lastProbe
			}
			t.Cleanup(func() { _ = f.local.call(context.Background(), restore) })
			if n, e := flow.Write(bytes.Repeat([]byte{1}, 1800)); n != 0 || !errors.Is(e, ErrLimit) {
				t.Fatalf("batch accepted: %d %v", n, e)
			}
			if e := f.local.call(context.Background(), func() {
				st := f.local.streams[flow.id]
				if st.messageNext != message || st.txClassifier != classifier || st.txClassifier.Snapshot().TotalBytes != 1800 {
					t.Error("failed batch changed id/classifier")
				}
				if f.local.queue.Len() != 1 || f.local.queue.Bytes() != frameCost(old) {
					t.Error("failure changed previous queue budget")
				}
				got, ok := f.local.queue.Pop()
				if !ok || got.Kind != old.Kind || got.Offset != old.Offset || !bytes.Equal(got.Data, old.Data) {
					t.Error("failure changed previous value")
				}
				restore()
			}); e != nil {
				t.Fatal(e)
			}
		})
	}
	if received.Load() != 2 {
		t.Fatalf("failed batch reached target: %d", received.Load())
	}
}

func TestClassificationRuntimeTCPPartialAdmissionAndDeadline(t *testing.T) {
	cfg := classification.DefaultConfig()
	cfg.Behavior.Enabled = false
	f := newClassFixture(t, "tcp", &cfg, &cfg)
	flow, target := f.dial(t, "default", classification.Metadata{})
	var maxRemote, sessionMax uint64
	var doneAck bool
	var lastSync, lastProbe time.Time
	if e := f.local.call(context.Background(), func() {
		st := f.local.streams[flow.id]
		maxRemote, sessionMax = st.maxRemote, f.local.peerSessionMax
		doneAck, lastSync, lastProbe = f.local.localDoneAck, f.local.lastSync, f.local.lastProbe
		// The live peer cannot return new credit until buffered data is emitted.
		// Admit exactly the first 900-byte part and hold emission at sync.
		st.maxRemote, f.local.peerSessionMax = st.sendNext+900, f.local.totalSent+900
		f.local.localDoneAck = false
		f.local.lastSync, f.local.lastProbe = time.Now().Add(time.Hour), time.Now().Add(time.Hour)
	}); e != nil {
		t.Fatal(e)
	}
	restore := func() {
		f.local.streams[flow.id].maxRemote, f.local.peerSessionMax = maxRemote, sessionMax
		f.local.localDoneAck = doneAck
		f.local.lastSync, f.local.lastProbe = lastSync, lastProbe
	}
	t.Cleanup(func() { _ = f.local.call(context.Background(), restore) })
	flow.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	payload := bytes.Repeat([]byte{0x72}, 1800)
	if n, e := flow.Write(payload); n != 900 || !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("partial admission deadline: n=%d err=%v", n, e)
	}
	if got := classSnapshot(t, f.local, flow.id); got.LocalTX.TotalBytes != 900 {
		t.Fatalf("blocked/unaccepted part counted: %+v", got)
	}
	if e := f.local.call(context.Background(), restore); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, 900)
	if _, e := io.ReadFull(target, got); e != nil || !bytes.Equal(got, payload[:900]) {
		t.Fatalf("accepted prefix: %v", e)
	}
	flow.SetWriteDeadline(time.Now().Add(time.Second))
	transferClassBytes(t, flow, target, 900)
	if snap := classSnapshot(t, f.local, flow.id); snap.LocalTX.TotalBytes != 1800 {
		t.Fatalf("partial retry double count: %+v", snap)
	}
}

func TestClassificationRuntimeRecoveryPreservesDirectionState(t *testing.T) {
	cfg := classPolicy()
	f := newClassFixture(t, "udp", &cfg, &cfg)
	flow, target := f.dial(t, "default", classification.Metadata{})
	clock := setClassClock(t, f.local)
	setClassClock(t, f.peer)
	for n := 0; n < 9; n++ {
		clock.Add(int64(100 * time.Millisecond))
		transferClassBytes(t, flow, target, 500)
	}
	before := classSnapshot(t, f.local, flow.id)
	if before.LocalTX.Class != protocol.Bulk {
		t.Fatal("recovery baseline is not classified Bulk")
	}
	runtimeWait(t, "Bulk announcement installed before recovery", func() bool {
		view := classSnapshot(t, f.local, flow.id)
		peer := classSnapshot(t, f.peer, flow.id)
		return view.TXVersion == 2 && view.TXAckedVersion == 2 && !view.TXPending && peer.PeerTX.Known && peer.PeerTX.Version == 2 && peer.PeerTX.Class == protocol.Bulk
	})
	before = classSnapshot(t, f.local, flow.id)
	var localClassifier, peerClassifier *classification.Flow
	var origin time.Time
	generation := f.local.Stats().Generation
	if e := f.local.call(context.Background(), func() {
		localClassifier = f.local.streams[flow.id].txClassifier
		origin = f.local.classOrigin
		f.local.suspend()
	}); e != nil {
		t.Fatal(e)
	}
	if e := f.peer.call(context.Background(), func() { peerClassifier = f.peer.streams[flow.id].txClassifier }); e != nil {
		t.Fatal(e)
	}
	payload := []byte("accepted once while the original carrier is suspended")
	if n, e := flow.Write(payload); e != nil || n != len(payload) {
		t.Fatalf("retained write: %d %v", n, e)
	}
	runtimeWait(t, "actual Client recovery over TCP", func() bool {
		return f.local.Stats().Generation > generation && runtimeReady(f.local) && runtimeReady(f.peer)
	})
	if f.local.Stats().Carrier != "tcp" {
		t.Fatal("recovery did not attach TCP carrier")
	}
	got := make([]byte, len(payload))
	if _, e := io.ReadFull(target, got); e != nil || !bytes.Equal(got, payload) {
		t.Fatalf("retained target transfer: %v", e)
	}
	after := classSnapshot(t, f.local, flow.id)
	if after.LocalTX.Baseline != before.LocalTX.Baseline || after.LocalTX.Class != before.LocalTX.Class || after.LocalTX.TotalBytes != before.LocalTX.TotalBytes+uint64(len(payload)) {
		t.Fatalf("recovery replaced/double-counted classification: before=%+v after=%+v", before, after)
	}
	if after.TXVersion != before.TXVersion || after.TXPublishedVersion != before.TXPublishedVersion || after.TXAckedVersion != before.TXAckedVersion || after.TXPending {
		t.Fatalf("carrier replacement changed acknowledged TX state: before=%+v after=%+v", before, after)
	}
	if peer := classSnapshot(t, f.peer, flow.id); !peer.PeerTX.Known || peer.PeerTX.Version != after.TXVersion || peer.PeerTX.Class != after.LocalTX.Class {
		t.Fatalf("recovery peer view diverged: %+v", peer)
	}
	if e := f.local.call(context.Background(), func() {
		if f.local.streams[flow.id].txClassifier != localClassifier || !f.local.classOrigin.Equal(origin) {
			t.Error("recovery replaced local classifier/origin")
		}
	}); e != nil {
		t.Fatal(e)
	}
	if e := f.peer.call(context.Background(), func() {
		if f.peer.streams[flow.id].txClassifier != peerClassifier {
			t.Error("recovery replaced peer classifier")
		}
	}); e != nil {
		t.Fatal(e)
	}
	transferClassBytes(t, target, flow, 37)
	if snap := classSnapshot(t, f.peer, flow.id); snap.LocalTX.TotalBytes != 37 {
		t.Fatalf("download mixed with recovery upload: %+v", snap)
	}
	if f.backend.dials.Load() != 1 {
		t.Fatal("recovery redialed existing target")
	}
}

func TestClassificationRuntimeRealClockIdleRestoreAndLockedHint(t *testing.T) {
	cfg := classPolicy()
	cfg.Behavior.ActivityGap = 150 * time.Millisecond
	f := newClassFixture(t, "tcp", &cfg, &cfg)
	flow, target := f.dial(t, "default", classification.Metadata{})
	locked, lockedTarget := f.dial(t, "metadata", classification.Metadata{Hint: &classification.ClassHint{Class: protocol.Interactive, Trusted: true, Locked: true}})
	ticker := time.NewTicker(60 * time.Millisecond)
	defer ticker.Stop()
	for n := 0; n < 16; n++ {
		<-ticker.C
		transferClassBytes(t, flow, target, 500)
		transferClassBytes(t, locked, lockedTarget, 500)
	}
	if snap := classSnapshot(t, f.local, flow.id); snap.LocalTX.Class != protocol.Bulk || snap.LocalTX.TotalBytes != 8000 {
		t.Fatalf("real time sustained transfer: %+v", snap)
	}
	if snap := classSnapshot(t, f.local, locked.id); snap.LocalTX.Class != protocol.Interactive || !snap.LocalTX.Baseline.Locked || snap.LocalTX.TotalBytes != 8000 {
		t.Fatalf("trusted locked hint adjusted: %+v", snap)
	}
	// No test invokes maintain/Tick. The production actor's 10ms ticker must
	// expire the window and restore the baseline during a truly idle interval.
	runtimeWait(t, "real actor timer idle restore", func() bool { return classSnapshot(t, f.local, flow.id).LocalTX.Class == protocol.Normal })
	if snap := classSnapshot(t, f.local, flow.id); snap.LocalTX.TotalBytes != 8000 {
		t.Fatal("idle Tick added bytes")
	}
}
