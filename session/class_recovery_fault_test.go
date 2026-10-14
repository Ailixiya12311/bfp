package session

import (
	"bfp/classification"
	"bfp/internal/classcontrol"
	"bfp/obfuscation"
	"bfp/protocol"
	"bfp/security"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The relay exercises NewClient.Connect and its real recover goroutine. UDP
// forwards the original datagrams. TCP terminates only the outer authenticated
// framing envelope and forwards the original inner encrypted record unchanged.
// Its separate cipher opens a copy solely to choose deterministic loss events;
// both endpoints still authenticate, replay-check, decode and install the input.
// Direction 0 is client -> server; direction 1 is server -> client.
type classRecoveryRelay struct {
	server *Server
	udp    *net.UDPConn
	upUDP  *net.UDPConn
	tcp    net.Listener
	wg     sync.WaitGroup
	mu     sync.Mutex
	peer   *net.UDPAddr
	conns  map[net.Conn]struct{}

	blackholeUDP atomic.Bool
	holdAnn      [2]atomic.Bool
	holdACK      [2]atomic.Bool
	holdDone     [2]atomic.Bool
	annDropped   [2]atomic.Uint64
	ackDropped   [2]atomic.Uint64
	doneDropped  [2]atomic.Uint64
	annSeen      [2]atomic.Uint64
	ackSeen      [2]atomic.Uint64
	snapshots    [2]classWireSnapshot
}

func newClassRecoveryRelay(t *testing.T, server *Server) *classRecoveryRelay {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	address, err := net.ResolveUDPAddr("udp", server.Addr().String())
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	up, err := net.DialUDP("udp", nil, address)
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		udp.Close()
		up.Close()
		t.Fatal(err)
	}
	r := &classRecoveryRelay{server: server, udp: udp, upUDP: up, tcp: tcp, conns: make(map[net.Conn]struct{})}
	r.wg.Add(3)
	go r.readUDP(0)
	go r.readUDP(1)
	go func() {
		defer r.wg.Done()
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			r.mu.Lock()
			r.conns[conn] = struct{}{}
			r.mu.Unlock()
			r.wg.Add(1)
			go func() { defer r.wg.Done(); r.forwardTCP(conn) }()
		}
	}()
	t.Cleanup(func() {
		udp.Close()
		up.Close()
		tcp.Close()
		r.mu.Lock()
		for conn := range r.conns {
			conn.Close()
		}
		r.mu.Unlock()
		done := make(chan struct{})
		go func() { r.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("classification fault relay did not stop")
		}
	})
	return r
}

func (r *classRecoveryRelay) binding(handle [16]byte) *carrier {
	r.server.mu.Lock()
	p := r.server.handles[handle]
	r.server.mu.Unlock()
	if p == nil {
		return nil
	}
	p.mu.Lock()
	c := p.carrier
	p.mu.Unlock()
	return c
}

func (r *classRecoveryRelay) selectDrop(c *carrier, direction int, wire []byte, shadows map[[16]byte]*security.RecordCipher) bool {
	shadow := shadows[c.handle]
	if shadow == nil {
		key := c.keys.Receive[:]
		if direction == 1 {
			key = c.keys.Send[:]
		}
		var err error
		shadow, err = security.NewRecordCipher(key, c.handle, 0)
		if err != nil {
			return false
		}
		shadows[c.handle] = shadow
	}
	plain, _, err := shadow.Open(wire)
	if err != nil {
		return false
	}
	plain, err = obfuscation.Unpad(plain)
	if err != nil {
		return false
	}
	frames, err := protocol.Decode(plain)
	if err != nil || len(frames) != 1 {
		return false
	}
	f := frames[0]
	switch f.Kind {
	case protocol.ClassUpdate:
		if f.Flags == 0 {
			r.annSeen[direction].Add(1)
			if r.holdAnn[direction].Load() {
				r.annDropped[direction].Add(1)
				return true
			}
		} else if f.Flags == 1 {
			r.ackSeen[direction].Add(1)
			if r.holdACK[direction].Load() {
				r.ackDropped[direction].Add(1)
				return true
			}
		}
	case protocol.ResumeState:
		if f.Flags == 0 && f.Value > 1 {
			var snap flowSnapshot
			if decodeJSON(f.Data, &snap) == nil && snap.TXClass != nil {
				r.mu.Lock()
				r.snapshots[direction] = *snap.TXClass
				r.mu.Unlock()
			}
		}
	case protocol.ResumeDone:
		if f.Offset > 1 && r.holdDone[direction].Load() {
			r.doneDropped[direction].Add(1)
			return true
		}
	}
	return false
}

func (r *classRecoveryRelay) readUDP(direction int) {
	defer r.wg.Done()
	shadows := make(map[[16]byte]*security.RecordCipher)
	buf := make([]byte, security.MaxUDPRecordSize+1)
	for {
		var n int
		var err error
		if direction == 0 {
			var peer *net.UDPAddr
			n, peer, err = r.udp.ReadFromUDP(buf)
			if err == nil {
				r.mu.Lock()
				r.peer = peer
				r.mu.Unlock()
			}
		} else {
			n, err = r.upUDP.Read(buf)
		}
		if err != nil {
			return
		}
		if r.blackholeUDP.Load() {
			continue
		}
		wire := buf[:n]
		if n >= 16 {
			var handle [16]byte
			copy(handle[:], wire[:16])
			if c := r.binding(handle); c != nil && r.selectDrop(c, direction, wire, shadows) {
				continue
			}
		}
		if direction == 0 {
			_, err = r.upUDP.Write(wire)
		} else {
			r.mu.Lock()
			peer := r.peer
			r.mu.Unlock()
			if peer != nil {
				_, err = r.udp.WriteToUDP(wire, peer)
			}
		}
		if err != nil {
			return
		}
	}
}

func (r *classRecoveryRelay) forwardTCP(client net.Conn) {
	defer client.Close()
	defer func() { r.mu.Lock(); delete(r.conns, client); r.mu.Unlock() }()
	up, err := net.DialTimeout("tcp", r.server.Addr().String(), time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	r.mu.Lock()
	r.conns[up] = struct{}{}
	r.mu.Unlock()
	defer func() { r.mu.Lock(); delete(r.conns, up); r.mu.Unlock() }()
	admit := r.server.cfg.Credentials.Admission
	var confirmation boot
	// The two request/response exchanges are genuine endpoint handshakes.
	// Resealing bootstrap envelopes leaves their authenticated Noise messages
	// and source-bound server confirmation unchanged.
	for exchange := 0; exchange < 2; exchange++ {
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		plain, err := security.ReadBootstrap(client, admit)
		if err != nil {
			return
		}
		if exchange == 1 && decodeJSON(plain, &confirmation) != nil {
			return
		}
		wire, err := security.SealBootstrap(admit, plain, security.MaxBootstrapSize)
		if err != nil || security.WriteBootstrap(up, wire) != nil {
			return
		}
		_ = up.SetReadDeadline(time.Now().Add(time.Second))
		plain, err = security.ReadBootstrap(up, admit)
		if err != nil {
			return
		}
		wire, err = security.SealBootstrap(admit, plain, security.MaxBootstrapSize)
		if err != nil || security.WriteBootstrap(client, wire) != nil {
			return
		}
	}
	_ = client.SetReadDeadline(time.Time{})
	_ = up.SetReadDeadline(time.Time{})
	var handle [16]byte
	copy(handle[:], confirmation.Handle)
	c := r.binding(handle)
	if c == nil {
		return
	}
	clientFrames, err := security.NewFramer(client, c.keys.Send[:], c.keys.Receive[:])
	if err != nil {
		return
	}
	serverFrames, err := security.NewFramer(up, c.keys.Receive[:], c.keys.Send[:])
	if err != nil {
		return
	}
	copyRecords := func(direction int, from, to *security.Framer) {
		shadows := make(map[[16]byte]*security.RecordCipher)
		for {
			wire, err := from.Read()
			if err != nil {
				return
			}
			if r.selectDrop(c, direction, wire, shadows) {
				continue
			}
			if err := to.Write(wire); err != nil {
				return
			}
		}
	}
	done := make(chan struct{})
	go func() { copyRecords(1, serverFrames, clientFrames); close(done) }()
	copyRecords(0, clientFrames, serverFrames)
	client.Close()
	up.Close()
	<-done
}

func newClassRecoveryFixture(t *testing.T, initialTCP, activeBlackhole bool) (*classFixture, *classRecoveryRelay) {
	return newClassRecoveryFixtureWithCarrier(t, initialTCP, activeBlackhole, nil)
}

func newClassRecoveryFixtureWithCarrier(t *testing.T, initialTCP, activeBlackhole bool, configure func(*ClientConfig)) (*classFixture, *classRecoveryRelay) {
	t.Helper()
	clientKey, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	admit := randomBytes(32)
	credentials := Credentials{Admission: admit, Private: serverKey.Private, Public: serverKey.Public, AllowedClients: [][]byte{clientKey.Public}}
	cred := Credentials{Admission: admit, Private: clientKey.Private, Public: clientKey.Public, ServerPublic: serverKey.Public}
	cfg := classPolicy()
	// Trigger Bulk at the final application sample. Holding all announcements
	// across a long tail of later data would otherwise create many independent
	// packet-loss reports and nondeterministically spend most of the retry budget
	// before the assertion can isolate the first announcement/ACK loss.
	cfg.Behavior.BulkSustain = 500 * time.Millisecond
	backend := &runtimeBackend{}
	// These are this fixture's fixed fault deadlines. No original integration
	// deadline or production default is widened to accommodate the scenario.
	opts := Options{HandshakeTimeout: 350 * time.Millisecond, ProbeInterval: 100 * time.Millisecond,
		FailureTimeout: 5 * time.Second,
		RetainTimeout:  5 * time.Second, KeyUpdateBytes: 1 << 30, KeyUpdateInterval: time.Hour}
	if activeBlackhole {
		opts.UDPFailureBudget = 600 * time.Millisecond
	}
	// One constructor owns both sockets continuously. A failed test is never
	// retried, and the fixture's fixed fault deadlines remain unchanged.
	server, err := NewServer(ServerConfig{Listen: "127.0.0.1:0", Credentials: credentials, Backend: backend, Options: opts, Classification: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background()) }()
	t.Cleanup(func() {
		server.Close()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("classification recovery server did not stop")
		}
	})
	relay := newClassRecoveryRelay(t, server)
	relay.blackholeUDP.Store(initialTCP)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	var target net.Conn
	var targetMu sync.Mutex
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		conn, err := listener.Accept()
		if err == nil {
			targetMu.Lock()
			target = conn
			targetMu.Unlock()
			accepted <- conn
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-acceptDone
		targetMu.Lock()
		if target != nil {
			target.Close()
		}
		targetMu.Unlock()
	})
	clientConfig := ClientConfig{Server: relay.udp.LocalAddr().String(), TCPServer: relay.tcp.Addr().String(), Credentials: cred, Options: opts, Classification: &cfg}
	if configure != nil {
		configure(&clientConfig)
	}
	client, err := NewClient(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	local, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	peer := server.sessions[local.Stats().ID]
	server.mu.Unlock()
	if peer == nil {
		t.Fatal("real Client handshake did not retain the server Session")
	}
	runtimeWait(t, "real Client initial synchronization", func() bool { return runtimeReady(local) && runtimeReady(peer) })
	want := "udp"
	if initialTCP {
		want = "tcp"
	}
	if local.Stats().Carrier != want {
		t.Fatalf("initial Client carrier %q, want %q", local.Stats().Carrier, want)
	}
	return &classFixture{server: server, client: client, local: local, peer: peer, backend: backend, address: listener.Addr().String(), accepted: accepted}, relay
}

func classRecoveryInitial(t *testing.T, f *classFixture, id uint64) {
	t.Helper()
	runtimeWait(t, "both initial versions have exact announcement ACKs", func() bool {
		return classRuntimeConverged(f.local, id, 1) && classRuntimeConverged(f.peer, id, 1)
	})
}

func classRecoveryBulk(t *testing.T, f *classFixture, flow *Flow, target net.Conn, clocks [2]*atomic.Int64) {
	t.Helper()
	for n := 0; n < 9; n++ {
		clocks[0].Add(int64(100 * time.Millisecond))
		clocks[1].Add(int64(100 * time.Millisecond))
		transferClassBytes(t, flow, target, 500)
		transferClassBytes(t, target, flow, 500)
	}
	for _, endpoint := range []*Session{f.local, f.peer} {
		view := classSnapshot(t, endpoint, flow.id)
		if view.LocalTX.Class != protocol.Bulk || view.TXVersion != 2 || view.LocalTX.TotalBytes != 4500 {
			t.Fatalf("actual application admission did not classify its own TX: %+v", view)
		}
	}
}

// A shadow-observed dropped publication gives the fixture a concrete loss
// event. Feed that event through the real logical-ref path when opening the
// gate, instead of waiting for an increasingly backed-off wall-clock timer.
// This changes only eligibility: no publication, ACK or lifetime is fabricated.
func classRecoveryRetryLost(t *testing.T, endpoint *Session, id uint64) {
	t.Helper()
	var stateErr error
	if err := endpoint.call(context.Background(), func() {
		before, err := endpoint.classTable.Snapshot(id)
		if err != nil {
			stateErr = err
			return
		}
		endpoint.queueRetry(makeRef(classFrame(before.Local, 0)))
		after, err := endpoint.classTable.Snapshot(id)
		if err != nil || before != after {
			stateErr = ErrState
		}
	}); err != nil || stateErr != nil {
		t.Fatalf("loss reference altered publication proof/budget: command=%v state=%v", err, stateErr)
	}
}

func classRecoveryFailureDiagnostics(t *testing.T, f *classFixture, relay *classRecoveryRelay, id uint64) {
	t.Helper()
	if !t.Failed() {
		return
	}
	for i, endpoint := range []*Session{f.local, f.peer} {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		var state classcontrol.Snapshot
		var stateErr error
		err := endpoint.call(ctx, func() { state, stateErr = endpoint.classTable.Snapshot(id) })
		cancel()
		t.Logf("fault diagnostics direction=%d query=%v stateErr=%v class=%+v stats=%+v annSeen=%d annDropped=%d ackSeen=%d ackDropped=%d doneDropped=%d",
			i, err, stateErr, state, endpoint.Stats(), relay.annSeen[i].Load(), relay.annDropped[i].Load(), relay.ackSeen[i].Load(), relay.ackDropped[i].Load(), relay.doneDropped[i].Load())
	}
}

// This is a separate natural-timer scenario contract, not an extension of the
// initial two-second observation experiment retained in attempt-01.log. Every
// phase shares one fixed 20 s deadline, below the table's 30 s no-progress
// limit. It accommodates the specified 8 s maximum retry interval without
// manufacturing a logical loss signal or renewing the phase budget.
func classRecoveryNaturalWaiter(t *testing.T) func(string, func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	return func(description string, predicate func() bool) {
		t.Helper()
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		poll := time.NewTicker(2 * time.Millisecond)
		defer poll.Stop()
		for {
			if predicate() {
				return
			}
			select {
			case <-timer.C:
				t.Fatal("fixed natural retry contract expired: " + description)
			case <-poll.C:
			}
		}
	}
}

func classRecoveryLogTimers(t *testing.T, f *classFixture, id uint64, phase string) {
	t.Helper()
	for i, endpoint := range []*Session{f.local, f.peer} {
		state := classRecoveryActor(t, endpoint, id)
		t.Logf("%s direction=%d version=%d published=%d acked=%d pending=%v started=%s now=%s attempts=%d retries=%d nextSend=%s remaining=%s",
			phase, i, state.class.Local.Version, state.class.Published.Version, state.class.Acked.Version, state.class.Pending,
			state.class.Started, state.controlNow, state.class.Attempts, state.class.Retries, state.class.NextSend, state.class.NextSend-state.controlNow)
	}
}

func TestClassRecoveryRealClientInitialUDPFailureFallsBackToTCP(t *testing.T) {
	f, _ := newClassRecoveryFixture(t, true, false)
	flow, target := f.dial(t, "default", classification.Metadata{})
	classRecoveryInitial(t, f, flow.id)
	clocks := [2]*atomic.Int64{setClassClock(t, f.local), setClassClock(t, f.peer)}
	classRecoveryBulk(t, f, flow, target, clocks)
	runtimeWait(t, "classification converges after initial UDP fallback", func() bool {
		return classRuntimeConverged(f.local, flow.id, 2) && classRuntimeConverged(f.peer, flow.id, 2)
	})
	if f.local.Stats().Generation != 1 || f.local.Stats().Switches != 0 || f.backend.dials.Load() != 1 {
		t.Fatalf("initial fallback created extra Session/Flow state: generation=%d switches=%d dials=%d", f.local.Stats().Generation, f.local.Stats().Switches, f.backend.dials.Load())
	}
	if f.client.Session() != f.local {
		t.Fatal("Client did not retain its initially selected TCP Session")
	}
}

func TestClassRecoveryEncryptedAnnouncementThenACKLossWithObservedLossSignal(t *testing.T) {
	for _, kind := range []string{"udp", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			classRecoveryAnnouncementLossScenario(t, kind, true, func(description string, predicate func() bool) { runtimeWait(t, description, predicate) })
		})
	}
}

func TestClassRecoveryEncryptedAnnouncementThenACKLossNaturalBackoff(t *testing.T) {
	for _, kind := range []string{"udp", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			classRecoveryAnnouncementLossScenario(t, kind, false, classRecoveryNaturalWaiter(t))
		})
	}
}

func classRecoveryAnnouncementLossScenario(t *testing.T, kind string, observedLossSignal bool, wait func(string, func() bool)) {
	t.Helper()
	f, relay := newClassRecoveryFixture(t, kind == "tcp", false)
	flow, target := f.dial(t, "default", classification.Metadata{})
	defer classRecoveryFailureDiagnostics(t, f, relay, flow.id)
	classRecoveryInitial(t, f, flow.id)
	clocks := [2]*atomic.Int64{setClassClock(t, f.local), setClassClock(t, f.peer)}
	for i := 0; i < 2; i++ {
		relay.holdAnn[i].Store(true)
	}
	classRecoveryBulk(t, f, flow, target, clocks)
	wait("encrypted announcements are dropped independently in both directions", func() bool {
		return relay.annDropped[0].Load() > 0 && relay.annDropped[1].Load() > 0
	})
	var pending [2]classcontrol.Snapshot
	for i, endpoint := range []*Session{f.local, f.peer} {
		pending[i] = classRuntimeTableSnapshot(t, endpoint, flow.id)
		if !pending[i].Pending || pending[i].Published.Version != 2 || pending[i].Acked.Version != 1 || pending[i].Peer.State.Version != 1 {
			t.Fatalf("lost announcement installed peer view or exact ACK: direction=%d state=%+v", i, pending[i])
		}
	}
	for i := 0; i < 2; i++ {
		relay.holdACK[i].Store(true)
	}
	classRecoveryLogTimers(t, f, flow.id, "announcement gate opens")
	for i, endpoint := range []*Session{f.local, f.peer} {
		relay.holdAnn[i].Store(false)
		if observedLossSignal {
			classRecoveryRetryLost(t, endpoint, flow.id)
		}
	}
	wait("delivered latest announcements install peer views while exact ACKs are lost", func() bool {
		return classSnapshot(t, f.local, flow.id).PeerTX.Version == 2 && classSnapshot(t, f.peer, flow.id).PeerTX.Version == 2 &&
			relay.ackDropped[0].Load() > 0 && relay.ackDropped[1].Load() > 0
	})
	for i, endpoint := range []*Session{f.local, f.peer} {
		view := classRuntimeTableSnapshot(t, endpoint, flow.id)
		if !view.Pending || view.Acked.Version != 1 || view.Started != pending[i].Started || view.Attempts < pending[i].Attempts || view.Retries < pending[i].Retries {
			t.Fatalf("lost ACK completed or renewed pending publication: direction=%d before=%+v after=%+v", i, pending[i], view)
		}
	}
	for i := 0; i < 2; i++ {
		relay.holdACK[i].Store(false)
	}
	classRecoveryLogTimers(t, f, flow.id, "ACK gate opens")
	for _, endpoint := range []*Session{f.local, f.peer} {
		if observedLossSignal {
			classRecoveryRetryLost(t, endpoint, flow.id)
		}
	}
	wait("exact ACKs converge after their loss gates open", func() bool {
		return classRuntimeConverged(f.local, flow.id, 2) && classRuntimeConverged(f.peer, flow.id, 2)
	})
	for _, endpoint := range []*Session{f.local, f.peer} {
		view := classSnapshot(t, endpoint, flow.id)
		if view.LocalTX.TotalBytes != 4500 || view.LocalTX.Class != protocol.Bulk || view.PeerTX.Class != protocol.Bulk {
			t.Fatalf("control retransmission changed admitted bytes or local policy: %+v", view)
		}
	}
	if f.backend.dials.Load() != 1 {
		t.Fatal("announcement/ACK loss redialed the established backend")
	}
}

type classRecoveryActorState struct {
	classifier *classification.Flow
	flow       *Flow
	target     net.Conn
	origin     time.Time
	policy     classification.Snapshot
	controlNow time.Duration
	class      classcontrol.Snapshot
	snapshot   classWireSnapshot
	gate       bool
	syncAck    bool
	syncRead   bool
}

func classRecoveryActor(t *testing.T, s *Session, id uint64) classRecoveryActorState {
	t.Helper()
	var out classRecoveryActorState
	var stateErr error
	if err := s.call(context.Background(), func() {
		st := s.streams[id]
		out = classRecoveryActorState{classifier: st.txClassifier, flow: st.flow, target: st.targetConn, origin: s.classOrigin,
			policy: st.txClassifier.Snapshot(), controlNow: s.classStamp(),
			gate: s.peerDone && s.localDoneAck, syncAck: s.syncAck[id], syncRead: s.syncReceived[id]}
		out.class, stateErr = s.classTable.Snapshot(id)
		for _, frame := range s.syncFrames {
			if frame.Flow == id {
				var snap flowSnapshot
				if err := decodeJSON(frame.Data, &snap); err != nil || snap.TXClass == nil {
					stateErr = ErrState
				} else {
					out.snapshot = *snap.TXClass
				}
			}
		}
	}); err != nil || stateErr != nil {
		t.Fatalf("recovery owner state: command=%v state=%v", err, stateErr)
	}
	return out
}

func TestClassRecoveryRealClientUDPToTCPPendingVersionsSurviveFrozenSnapshotWithObservedLossSignal(t *testing.T) {
	classRecoveryPendingVersionScenario(t, true, func(description string, predicate func() bool) { runtimeWait(t, description, predicate) })
}

func TestClassRecoveryRealClientUDPToTCPPendingVersionsSurviveFrozenSnapshotNaturalBackoff(t *testing.T) {
	classRecoveryPendingVersionScenario(t, false, classRecoveryNaturalWaiter(t))
}

func classRecoveryPendingVersionScenario(t *testing.T, observedLossSignal bool, wait func(string, func() bool)) {
	t.Helper()
	f, relay := newClassRecoveryFixture(t, false, true)
	flow, target := f.dial(t, "default", classification.Metadata{})
	defer classRecoveryFailureDiagnostics(t, f, relay, flow.id)
	classRecoveryInitial(t, f, flow.id)
	clocks := [2]*atomic.Int64{setClassClock(t, f.local), setClassClock(t, f.peer)}
	for i := 0; i < 2; i++ {
		relay.holdAnn[i].Store(true)
		relay.holdDone[i].Store(true)
	}
	classRecoveryBulk(t, f, flow, target, clocks)
	wait("both pending UDP versions have real publication evidence", func() bool {
		return relay.annDropped[0].Load() > 0 && relay.annDropped[1].Load() > 0
	})
	before := [2]classRecoveryActorState{classRecoveryActor(t, f.local, flow.id), classRecoveryActor(t, f.peer, flow.id)}
	generation := f.local.Stats().Generation
	relay.blackholeUDP.Store(true)
	// No direct suspend/attach, custom recovery goroutine or replacement Session:
	// a real UDP blackhole triggers the configured watchdog and Client.recover.
	wait("actual Client watchdog attaches TCP while ResumeDone remains lost", func() bool {
		return f.local.Stats().Generation > generation && f.local.Stats().Carrier == "tcp" &&
			relay.doneDropped[0].Load() > 0 && relay.doneDropped[1].Load() > 0
	})
	wait("both frozen snapshots and their operation receipts cross the encrypted carrier", func() bool {
		left, right := classRecoveryActor(t, f.local, flow.id), classRecoveryActor(t, f.peer, flow.id)
		return left.syncAck && left.syncRead && right.syncAck && right.syncRead
	})
	var rebound [2]classRecoveryActorState
	relay.mu.Lock()
	wireSnapshots := relay.snapshots
	relay.mu.Unlock()
	for i, endpoint := range []*Session{f.local, f.peer} {
		rebound[i] = classRecoveryActor(t, endpoint, flow.id)
		if rebound[i].gate || rebound[i].snapshot.Version != 2 || rebound[i].snapshot.Class != uint64(protocol.Bulk) || wireSnapshots[i] != rebound[i].snapshot ||
			rebound[i].class.Local != before[i].class.Local || rebound[i].class.Published != before[i].class.Published ||
			rebound[i].class.Acked != before[i].class.Acked || !rebound[i].class.Pending || rebound[i].class.Started != before[i].class.Started ||
			rebound[i].class.Attempts < before[i].class.Attempts || rebound[i].class.Retries < before[i].class.Retries {
			t.Fatalf("carrier rebind or snapshot receipt changed exact publication lifecycle: direction=%d before=%+v after=%+v", i, before[i], rebound[i])
		}
		if !rebound[i].class.Peer.Known || rebound[i].class.Peer.State.Version != 2 || rebound[i].class.Peer.State.Class != protocol.Bulk {
			t.Fatalf("frozen snapshot did not update the shared read-only peer view: direction=%d state=%+v", i, rebound[i])
		}
	}
	// After activation froze v2, ordinary local idle behavior restores Normal.
	// Tick changes policy/version without observing any control bytes; holding
	// both real ResumeDone directions keeps v3 unpublished on TCP.
	for n := 0; n < 9; n++ {
		for i, endpoint := range []*Session{f.local, f.peer} {
			clocks[i].Add(int64(100 * time.Millisecond))
			if err := endpoint.call(context.Background(), func() { endpoint.tickClassification() }); err != nil {
				t.Fatal(err)
			}
		}
	}
	var latest [2]classRecoveryActorState
	for i, endpoint := range []*Session{f.local, f.peer} {
		latest[i] = classRecoveryActor(t, endpoint, flow.id)
		if latest[i].snapshot != rebound[i].snapshot || latest[i].class.Local.Version != 3 || latest[i].class.Local.Class != protocol.Normal ||
			latest[i].class.Published.Version != 2 || latest[i].class.Acked.Version != 1 || !latest[i].class.Pending ||
			latest[i].class.Started != before[i].class.Started || latest[i].class.Attempts != rebound[i].class.Attempts || latest[i].class.Retries != rebound[i].class.Retries {
			t.Fatalf("new TX escaped recovery gate or refreshed pending lifetime: direction=%d rebound=%+v latest=%+v", i, rebound[i], latest[i])
		}
		if latest[i].classifier != before[i].classifier || latest[i].flow != before[i].flow || latest[i].target != before[i].target || !latest[i].origin.Equal(before[i].origin) ||
			latest[i].policy.TotalBytes != 4500 || latest[i].policy.Baseline != before[i].policy.Baseline {
			t.Fatalf("TCP attach replaced classifier/Flow/target or counted replayed controls: direction=%d", i)
		}
	}
	for i := 0; i < 2; i++ {
		relay.holdACK[i].Store(true)
		relay.holdAnn[i].Store(false)
		relay.holdDone[i].Store(false)
	}
	wait("ResumeDone completes and current v3 announcements pass in both directions", func() bool {
		return runtimeReady(f.local) && runtimeReady(f.peer) &&
			classSnapshot(t, f.local, flow.id).PeerTX.Version == 3 && classSnapshot(t, f.peer, flow.id).PeerTX.Version == 3 &&
			relay.ackDropped[0].Load() > 0 && relay.ackDropped[1].Load() > 0
	})
	for i, endpoint := range []*Session{f.local, f.peer} {
		state := classRuntimeTableSnapshot(t, endpoint, flow.id)
		if state.Published.Version != 3 || state.Acked.Version != 1 || !state.Pending || state.Started != before[i].class.Started || state.Peer.State.Class != protocol.Normal {
			t.Fatalf("snapshot/Done receipt consumed exact latest ACK proof: direction=%d state=%+v", i, state)
		}
	}
	for i := 0; i < 2; i++ {
		relay.holdACK[i].Store(false)
	}
	classRecoveryLogTimers(t, f, flow.id, "post-ResumeDone ACK gate opens")
	for _, endpoint := range []*Session{f.local, f.peer} {
		if observedLossSignal {
			classRecoveryRetryLost(t, endpoint, flow.id)
		}
	}
	wait("post-ResumeDone exact latest classification ACKs converge bidirectionally", func() bool {
		return classRuntimeConverged(f.local, flow.id, 3) && classRuntimeConverged(f.peer, flow.id, 3)
	})
	_ = flow.SetDeadline(time.Now().Add(2 * time.Second))
	_ = target.SetDeadline(time.Now().Add(2 * time.Second))
	transferClassBytes(t, flow, target, 37)
	transferClassBytes(t, target, flow, 29)
	if got := classSnapshot(t, f.local, flow.id).LocalTX.TotalBytes; got != 4537 {
		t.Fatalf("recovery upload bytes=%d, want 4537", got)
	}
	if got := classSnapshot(t, f.peer, flow.id).LocalTX.TotalBytes; got != 4529 {
		t.Fatalf("recovery download bytes=%d, want 4529", got)
	}
	if f.client.Session() != f.local || f.backend.dials.Load() != 1 || f.local.Stats().Switches != 1 {
		t.Fatalf("real recovery replaced Session/redialed backend: dials=%d switches=%d", f.backend.dials.Load(), f.local.Stats().Switches)
	}
}
