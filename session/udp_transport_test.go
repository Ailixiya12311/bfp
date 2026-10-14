package session

import (
	"bytes"
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"bfp/internal/udptransport"
	"bfp/obfuscation"
	"bfp/protocol"
	"bfp/security"
)

// Virtual owner time with a real local UDP socket: transport state is driven
// deterministically while successful carrier commits still perform actual I/O.
func udpOwner(t *testing.T) (*Session, *time.Time, *net.UDPConn) {
	t.Helper()
	s, _ := stateSession(t, "tcp")
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { receiver.Close() })
	conn, err := net.DialUDP("udp", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	keys := &security.TransportKeys{}
	keys.Send[0] = 1
	keys.Receive[0] = 2
	c, err := makeCarrier("udp", 1, bytes.Repeat([]byte{3}, 16), keys, conn, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.close)
	now := time.Unix(100, 0)
	s.transportNow = func() time.Time { return now }
	s.current = c
	s.resetTransport(now)
	s.active = true
	s.peerDone = true
	s.localDoneAck = true
	s.suspendedAt = time.Time{}
	s.lastKey = now
	s.lastProbe = now
	s.lastSync = now.Add(time.Hour)
	s.opts.KeyUpdateBytes = 1 << 60
	s.opts.KeyUpdateInterval = time.Hour
	return s, &now, receiver
}
func receiveOwnerWire(t *testing.T, s *Session, frames []protocol.Frame) {
	t.Helper()
	tx, err := security.NewRecordCipher(s.current.keys.Receive[:], s.current.handle, s.current.rx.Epoch())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := protocol.Encode(frames)
	if err != nil {
		t.Fatal(err)
	}
	plain, err = obfuscation.Pad(plain, 1100)
	if err != nil {
		t.Fatal(err)
	}
	wire, _, err := tx.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	s.receive(packet{c: s.current, wire: wire})
}
func ownerACK(t *testing.T, s *Session, n uint64) {
	t.Helper()
	f, err := udptransport.EncodeACK(udptransport.ACK{Epoch: s.current.tx.Epoch(), Largest: n, Ranges: []udptransport.Range{{First: n, Last: n}}})
	if err != nil {
		t.Fatal(err)
	}
	s.receiveUDPACK(f)
}

func TestUDPTransportOneHistoryPerRecordAndACKReserve(t *testing.T) {
	s, now, receiver := udpOwner(t)
	receiveOwnerWire(t, s, []protocol.Frame{{Kind: protocol.Ping, Value: 3}, {Kind: protocol.Ping, Value: 4}})
	if s.ctx.Err() != nil {
		t.Fatal(s.ctx.Err())
	}
	snap, ok, err := s.udpPath.history.Snapshot(s.udpPath.scope(0), 0)
	if err != nil || !ok || snap.Revision != 1 || len(snap.ACK.Ranges) != 1 {
		t.Fatal(snap, ok, err)
	}
	s.paceTokens = 0
	s.cwnd = 2
	s.flight = 2
	*now = now.Add(25 * time.Millisecond)
	s.paceTime = *now
	s.flushUDP()
	if s.stats.UDPACKSent != 1 || s.udpPath.ledger.Snapshot().Live != 0 || s.queue.Len() != 2 {
		t.Fatalf("ACK budget not independent: %+v queue%d", s.stats, s.queue.Len())
	}
	_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1200)
	n, _, err := receiver.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	rx, _ := security.NewRecordCipher(s.current.keys.Send[:], s.current.handle, 0)
	plain, _, err := rx.Open(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	plain, err = obfuscation.Unpad(plain)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := protocol.Decode(plain)
	if err != nil || len(frames) != 1 {
		t.Fatal(err)
	}
	a, err := udptransport.DecodeACK(frames[0])
	if err != nil || a.Delay != 25*time.Millisecond || a.Largest != 0 {
		t.Fatal(a, err)
	}
	if n > protocol.HeaderSize+len(frames[0].Data)+security.RecordOverhead+66 {
		t.Fatal("ACK padding budget exceeded")
	}
	s.udpPath.ackTokens = 0
	_, _ = s.udpPath.history.Observe(s.udpPath.scope(0), 2, 25*time.Millisecond, true)
	s.flushUDP()
	if s.stats.UDPACKSent != 1 || s.stats.UDPACKCoalesced == 0 {
		t.Fatal("reserve bypass was unlimited")
	}
}

func TestUDPTransportACKOnlyDoesNotCreateFeedback(t *testing.T) {
	s, _, _ := udpOwner(t)
	// Use an old retired epoch ACK so there is no unsent semantic violation.
	f, _ := udptransport.EncodeACK(udptransport.ACK{Epoch: 0, Largest: 0, Ranges: []udptransport.Range{{First: 0, Last: 0}}})
	s.udpPath.ledger, _ = udptransport.NewLedger(1, 1)
	receiveOwnerWire(t, s, []protocol.Frame{f})
	if s.ctx.Err() != nil {
		t.Fatal(s.ctx.Err())
	}
	if _, ok, _ := s.udpPath.history.Snapshot(s.udpPath.scope(0), 0); ok {
		t.Fatal("ACK of ACK")
	}
}

func TestUDPTransportFailedWriteNeverCommitsAndFutureHoleRejectsAtomically(t *testing.T) {
	s, now, receiver := udpOwner(t)
	s.current.conn.Close()
	before := s.udpPath.ledger.Snapshot()
	sent, err := s.udpSend(protocol.Frame{Kind: protocol.Ping, Value: 1}, false, false, false)
	if sent || err == nil || s.udpPath.ledger.Snapshot() != before || s.stats.WireSent != 0 {
		t.Fatal("failed write committed", sent, err)
	}
	if s.current.tx.NextMeta().Number != 1 {
		t.Fatal("seal nonce not consumed")
	}
	conn, err := net.DialUDP("udp", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	s.current.conn = conn
	*now = now.Add(time.Millisecond)
	sent, err = s.udpSend(protocol.Frame{Kind: protocol.Ping, Value: 2}, false, false, false)
	if !sent || err != nil {
		t.Fatal(sent, err)
	}
	before = s.udpPath.ledger.Snapshot()
	rt := s.udpPath.rtt.Snapshot()
	refs := len(s.udpPath.refs)
	a := udptransport.ACK{Epoch: 0, Largest: 1, Ranges: []udptransport.Range{{First: 0, Last: 1}}}
	_, err = s.udpPath.ledger.ApplyACK(s.udpPath.scope(0), a, 2*time.Millisecond, &s.udpPath.rtt)
	if !errors.Is(err, udptransport.ErrUnsent) || s.udpPath.ledger.Snapshot() != before || s.udpPath.rtt.Snapshot() != rt || len(s.udpPath.refs) != refs {
		t.Fatal("hole ACK partially mutated")
	}
}

func TestUDPTransportOrdinarySendDoesNotDelayPTOAndProbeHasFiniteDebt(t *testing.T) {
	s, now, _ := udpOwner(t)
	if sent, err := s.udpSend(protocol.Frame{Kind: protocol.Ping}, false, false, false); !sent || err != nil {
		t.Fatal(sent, err)
	}
	first := s.udpPath.deadline
	if first.Sub(*now) != 625*time.Millisecond {
		t.Fatal(first.Sub(*now))
	}
	for i := 0; i < 3; i++ {
		*now = now.Add(100 * time.Millisecond)
		s.paceTokens = 4800
		if sent, err := s.udpSend(protocol.Frame{Kind: protocol.Ping, Value: uint64(i + 1)}, false, false, false); !sent || err != nil {
			t.Fatal(sent, err)
		}
		if s.udpPath.deadline != first {
			t.Fatal("ordinary send extended deadline")
		}
	}
	*now = first
	s.maintainUDP(*now)
	if s.stats.UDPPTODue != 1 || s.udpPath.probeRemaining != 1 || s.udpPath.pto.Rounds() != 1 {
		t.Fatal("PTO did not grant once")
	}
	s.maintainUDP(*now)
	if s.stats.UDPPTODue != 1 {
		t.Fatal("duplicate expiry grant")
	}
	s.paceTokens = 0
	s.paceTime = *now
	s.flushUDP()
	if s.stats.UDPProbeSent != 1 || s.paceTokens >= 0 || s.paceTokens < -2400 || s.udpPath.deadline.Sub(*now) != 1250*time.Millisecond {
		t.Fatal("probe debt/backoff", s.paceTokens, s.udpPath.deadline.Sub(*now))
	}
	s.flushUDP()
	if s.stats.UDPProbeSent != 1 {
		t.Fatal("flush replenished probe grant")
	}
}

func TestUDPTransportThirdDeadlineWatchdogAndHealthProgressSeparation(t *testing.T) {
	s, now, _ := udpOwner(t)
	s.udpPath.rtt.Observe(time.Second, 0, true)
	if sent, err := s.udpSend(protocol.Frame{Kind: protocol.Ping}, false, false, false); !sent || err != nil {
		t.Fatal(sent, err)
	}
	start := *now
	for i, want := range []time.Duration{2 * time.Second, 6 * time.Second, 14 * time.Second} {
		*now = s.udpPath.deadline
		if now.Sub(start) != want {
			t.Fatalf("deadline%d =%s want%s", i, now.Sub(start), want)
		}
		s.maintainUDP(*now)
		s.paceTokens = 0
		s.paceTime = *now
		s.flushUDP()
		if s.udpSuspect != (i == 2) || !s.active {
			t.Fatal("wrong third deadline or closed candidate path")
		}
	}
	if s.stats.UDPPTODue != 3 {
		t.Fatal(s.stats)
	}
	// A fresh matching Pong progresses; an unrelated authenticated response
	// updates health but cannot clear backoff or watchdog progress time.
	token := s.udpPath.probeSerial
	before := s.udpPath.lastProgress
	s.udpPath.lastHealth = now.Add(time.Millisecond)
	s.receiveUDPPong(token+100, *now)
	if s.udpPath.lastProgress != before || s.udpPath.pto.Rounds() != 3 {
		t.Fatal("unrelated Pong reset progress")
	}
	s.receiveUDPPong(token, *now)
	if s.udpSuspect || s.udpPath.pto.Rounds() != 0 {
		t.Fatal("fresh Pong did not recover")
	}
	*now = now.Add(15 * time.Second)
	s.udpPath.lastHealth = *now
	s.maintainUDP(*now)
	if s.active || s.stats.UDPStalled != 1 {
		t.Fatal("health masked no-progress watchdog")
	}
}

func TestUDPTransportLateHealthSeparatesPTORoundsFromWatchdogAndPreservesFlow(t *testing.T) {
	s, now, _ := udpOwner(t)
	if s.opts.UDPFailureBudget != 15*time.Second {
		t.Fatal("default UDP failure policy changed")
	}
	s.udpPath.rtt.Observe(time.Second, 0, true) // Clamp base PTO to 2 seconds.
	st := s.streams[1]
	st.sendNext, st.sendAck, st.receiveNext = 12, 4, 3
	st.chunks = []chunk{{offset: 4, data: []byte("retained"), sentGeneration: 1}}
	s.stats.TXBuffered = 8
	target, peer := net.Pipe()
	defer target.Close()
	defer peer.Close()
	st.targetConn = target
	chunks := append([]chunk(nil), st.chunks...)
	start := *now
	if sent, err := s.udpSend(protocol.Frame{Kind: protocol.Ping}, false, false, false); !sent || err != nil {
		t.Fatal(sent, err)
	}

	// A late, authenticated but unmatched Pong gives path health without ACK
	// or fresh-probe progress. This must not move the independent watchdog.
	*now = start.Add(time.Second)
	receiveOwnerWire(t, s, []protocol.Frame{{Kind: protocol.Pong, Value: 1000}})
	if s.udpPath.lastHealth != *now || s.udpPath.lastProgress != start {
		t.Fatal("authenticated health incorrectly became transport progress")
	}
	for i, want := range []time.Duration{2 * time.Second, 6 * time.Second, 14 * time.Second} {
		*now = s.udpPath.deadline
		if now.Sub(start) != want {
			t.Fatalf("deadline %d=%s want=%s", i, now.Sub(start), want)
		}
		s.maintainUDP(*now)
		s.paceTokens = 0
		s.paceTime = *now
		s.flushUDP()
		stats := s.snapshotStats(*now)
		if !s.active || stats.UDPSuspect || stats.UDPPTORounds != uint8(i+1) || stats.UDPNoResponseDeadlines != uint8(i) {
			t.Fatalf("health and PTO counters were conflated: %+v", stats)
		}
	}
	stats := s.snapshotStats(*now)
	if stats.UDPPTODue != 3 || stats.UDPProbeSent != 3 || !stats.UDPPathPresent || stats.UDPBasePTOMS != 2000 || stats.UDPDeadlineRemainingMS != 8000 || stats.UDPNoProgressAgeMS != 14000 {
		t.Fatalf("incomplete third-PTO diagnostics: %+v", stats)
	}

	*now = start.Add(15 * time.Second)
	s.maintainUDP(*now)
	stats = s.snapshotStats(*now)
	if s.active || stats.Carrier != "suspended" || stats.UDPStalled != 1 || stats.UDPNoProgressAgeMS != 15000 || stats.UDPPTORounds != 3 || stats.UDPNoResponseDeadlines != 2 {
		t.Fatalf("late health masked the independent 15-second watchdog: %+v", stats)
	}
	if s.streams[1] != st || st.targetConn != target || st.sendNext != 12 || st.sendAck != 4 || st.receiveNext != 3 || st.reset || !reflect.DeepEqual(st.chunks, chunks) || stats.TXBuffered != 8 || stats.Flows != 1 || s.ctx.Err() != nil {
		t.Fatal("watchdog discarded retained flow state needed for carrier recovery")
	}

	// Gauges never wrap when a deadline has expired or the test clock is early.
	stats = s.snapshotStats(start.Add(30 * time.Second))
	if stats.UDPDeadlineRemainingMS != 0 {
		t.Fatal("expired deadline wrapped into a remaining duration")
	}
	stats = s.snapshotStats(start.Add(-time.Second))
	if stats.UDPNoProgressAgeMS != 0 {
		t.Fatal("negative progress age wrapped")
	}
	s.udpPath = nil
	stats = s.snapshotStats(*now)
	if stats.UDPPathPresent || stats.UDPSuspect || stats.UDPPTORounds != 0 || stats.UDPNoResponseDeadlines != 0 || stats.UDPBasePTOMS != 0 || stats.UDPDeadlineRemainingMS != 0 || stats.UDPNoProgressAgeMS != 0 {
		t.Fatal("retired path leaked current-carrier gauges")
	}
}

func TestUDPTransportBusyCwndEntersRecoveryCandidateOnThirdPTO(t *testing.T) {
	s, now, _ := udpOwner(t)
	if sent, err := s.udpSend(protocol.Frame{Kind: protocol.Ping, Value: 91}, false, false, false); !sent || err != nil {
		t.Fatal(sent, err)
	}
	// Keep one application/control item queued behind a full cwnd. Probes have
	// their own bounded admission, while the ordinary queue records the
	// congestion episode that makes the earlier recovery signal useful.
	s.cwnd = 1
	s.flight = 1
	if !s.enqueue(protocol.Frame{Kind: protocol.Ping, Value: 92}, protocol.Interactive) {
		t.Fatal("failed to retain busy queue")
	}
	for round := 0; round < 3; round++ {
		*now = s.udpPath.deadline
		s.maintainUDP(*now)
		s.paceTokens = 4800
		s.paceTime = *now
		s.flushUDP()
	}
	if !s.active || !s.udpSuspect || s.udpPath.pto.Rounds() != 3 || s.udpPath.noResponseDeadlines < 2 {
		t.Fatalf("busy path did not become a recovery candidate: active=%v suspect=%v pto=%d no_response=%d stats=%+v", s.active, s.udpSuspect, s.udpPath.pto.Rounds(), s.udpPath.noResponseDeadlines, s.stats)
	}
}

func TestTCPRecoveryTelemetryHasBoundedCountersAndOneFinish(t *testing.T) {
	s, _ := stateSession(t, "tcp")
	s.beginRecoveryAttempt()
	if s.stats.TCPRecoveryAttempts != 1 || !s.stats.TCPRecoveryInFlight || s.stats.TCPRecoveryFailures != 0 {
		t.Fatal("candidate start not reflected")
	}
	s.finishRecoveryAttempt(true)
	s.finishRecoveryAttempt(true)
	if s.stats.TCPRecoveryFailures != 1 || s.stats.TCPRecoveryInFlight {
		t.Fatal("candidate completion double counted")
	}
	s.beginRecoveryAttempt()
	s.finishRecoveryAttempt(false)
	if s.stats.TCPRecoveryAttempts != 2 || s.stats.TCPRecoveryFailures != 1 || s.stats.TCPRecoveryInFlight {
		t.Fatal("successful candidate counted as failure")
	}
	s.stats.TCPRecoveryAttempts, s.stats.TCPRecoveryFailures = ^uint64(0), ^uint64(0)
	s.beginRecoveryAttempt()
	s.finishRecoveryAttempt(true)
	if s.stats.TCPRecoveryAttempts != ^uint64(0) || s.stats.TCPRecoveryFailures != ^uint64(0) || s.stats.TCPRecoveryInFlight {
		t.Fatal("bounded telemetry counters wrapped")
	}
}

func TestUDPTransportProbeSlotStallDoesNotOvercommit(t *testing.T) {
	s, now, _ := udpOwner(t)
	// These are synthetic committed records. Advance the real cipher number as
	// well so the probe preflight reaches the intended live-slot limit instead
	// of being rejected as an impossible record-number sequence.
	for n := 0; n < 256; n++ {
		if _, _, err := s.current.tx.Seal(nil); err != nil {
			t.Fatal(err)
		}
	}
	for n := uint64(0); n < 256; n++ {
		_, err := s.udpPath.ledger.Commit(udptransport.Packet{Scope: s.udpPath.scope(0), Number: n, Size: 100, AckEliciting: true, Probe: n >= 248})
		if err != nil {
			t.Fatal(err)
		}
	}
	s.udpPath.deadline = *now
	s.maintainUDP(*now)
	t.Logf("before flush active=%v stalled=%d probeRemaining=%d deadline=%v now=%v ack=%v pace=%v", s.active, s.stats.UDPStalled, s.udpPath.probeRemaining, s.udpPath.deadline, *now, s.udpPath.ackTime, s.paceTime)
	s.flushUDP()
	if s.active || s.stats.UDPStalled != 1 || s.stats.UDPProbeSent != 0 || s.udpPath.ledger.Snapshot().Live != 256 {
		t.Fatalf("slot failure hidden or overcommitted active=%v stalled=%d probes=%d live=%d", s.active, s.stats.UDPStalled, s.stats.UDPProbeSent, s.udpPath.ledger.Snapshot().Live)
	}
}

func TestUDPTransportDistinctLossRetryUsesLatestStateAndRecoveryOnce(t *testing.T) {
	s, now, _ := udpOwner(t)
	st := s.streams[1]
	st.receiveNext = 10
	st.consumed = 4
	for n := uint64(0); n < 4; n++ {
		_, err := s.udpPath.ledger.Commit(udptransport.Packet{Scope: s.udpPath.scope(0), Number: n, Size: 100, AckEliciting: true})
		if err != nil {
			t.Fatal(err)
		}
	}
	s.udpPath.refs[security.RecordMeta{}] = makeRef(protocol.Frame{Kind: protocol.StreamAck, Flow: 1, Offset: 1})
	*now = now.Add(time.Millisecond)
	f, _ := udptransport.EncodeACK(udptransport.ACK{Largest: 3, Ranges: []udptransport.Range{{First: 1, Last: 3}}})
	s.receiveUDPACK(f)
	if s.cwnd != 6150 || s.flight != 0 || len(s.udpPath.retries) != 1 {
		t.Fatal("loss recovery", s.cwnd, s.flight, len(s.udpPath.retries))
	}
	for _, r := range s.udpPath.retries {
		resolved, ok := s.resolveRef(r, *now)
		if !ok || resolved.Offset != 10 || s.classForFrame(resolved) != protocol.Interactive {
			t.Fatal("stale state retry", resolved)
		}
	}
	cwnd := s.cwnd
	ownerACK(t, s, 0)
	if s.cwnd != cwnd || s.flight != 0 || s.stats.UDPTransportProgress != 2 {
		t.Fatal("late ACK grew cwnd or did not progress")
	}
	ownerACK(t, s, 0)
	if s.stats.UDPTransportProgress != 2 {
		t.Fatal("duplicate late progress")
	}
}

func TestUDPTransportAttachResetPreservesClassifierAndRetainedState(t *testing.T) {
	s, now, _ := udpOwner(t)
	st := s.streams[1]
	st.sendNext = 4
	st.chunks = []chunk{{offset: 0, data: []byte("data"), sentGeneration: 1}}
	before := st
	s.udpPath.pto.Expire()
	s.udpSuspect = true
	s.paceTokens = -1000
	s.resetTransport(now.Add(time.Second))
	if st != before || st.sendNext != 4 || len(st.chunks) != 1 || s.udpPath.pto.Rounds() != 0 || s.udpPath.rtt.BasePTO() != 625*time.Millisecond || s.paceTokens != 4800 || s.udpSuspect {
		t.Fatal("path reset corrupted logical state")
	}
}

func TestUDPTransportBootRevisionAndNoiseAuthenticationBinding(t *testing.T) {
	server, cred := newSecurityTestServer(t)
	if _, err := server.initialize(boot{Version: 1, Action: "init"}, "udp", nil, &net.UDPAddr{}); !errors.Is(err, security.ErrAuthentication) {
		t.Fatal("old boot accepted", err)
	}
	if _, _, err := server.confirm(boot{Version: 1}, "tcp", ""); !errors.Is(err, security.ErrAuthentication) {
		t.Fatal("old confirm accepted", err)
	}
	for _, mode := range []string{"new", "resume"} {
		t.Run(mode, func(t *testing.T) {
			secret := bytes.Repeat([]byte{4}, 32)
			initiator, err := newHandshake(true, mode, "udp", "attempt", 0, cred, secret)
			if err != nil {
				t.Fatal(err)
			}
			var responder *security.Handshake
			old := []byte("bfp/v1/" + mode + "/udp/attempt/0")
			if mode == "new" {
				responder, err = security.NewIKHandshake(false, keyPair(server.cfg.Credentials), nil, old)
			} else {
				responder, err = security.NewResumeHandshake(false, secret, old)
			}
			if err != nil {
				t.Fatal(err)
			}
			first, _, err := initiator.WriteMessage(encodeJSON(defaultCapabilityOffer()))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = responder.ReadMessage(first); err == nil {
				t.Fatal("mismatched revision authenticated")
			}
		})
	}
	if reflect.DeepEqual(prologue("new", "udp", "a", 0), []byte("bfp/v1/new/udp/a/0")) {
		t.Fatal("revision missing from prologue")
	}
	_ = context.Background()
}
