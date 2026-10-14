package session

import (
	"bfp/protocol"
	"bfp/scheduler"
	"bfp/security"
	"context"
	"errors"
	"math"
	"net"
	"sync"
	"testing"
	"time"
)

// Retain the exact authenticated INIT so its cached-candidate fast path can
// be exercised after revocation or alias expiry. All proofs use real Noise.
func ticketAdversarialCandidate(t *testing.T, s *Server, cred Credentials, port int, previous *sessionInfo) (*pending, boot, boot, sessionInfo) {
	t.Helper()
	mode, expected, locator := "new", uint64(0), ""
	var secret []byte
	if previous != nil {
		mode, expected, locator, secret = "resume", previous.Generation, previous.Ticket, previous.Secret
	}
	attempt := randomID()
	hs, e := newHandshake(true, mode, "udp", attempt, expected, cred, secret)
	if e != nil {
		t.Fatal(e)
	}
	offer, e := clientCapabilityOffer(ClientConfig{}, previous)
	if e != nil {
		t.Fatal(e)
	}
	first, _, e := hs.WriteMessage(encodeJSON(offer))
	if e != nil {
		t.Fatal(e)
	}
	initial := boot{Version: wireVersion, Action: "init", Mode: mode, Attempt: attempt, Expected: expected, Ticket: locator, Message: first}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	p, e := s.initialize(initial, "udp", nil, addr)
	if e != nil {
		t.Fatal(e)
	}
	plain, e := security.OpenBootstrap(cred.Admission, p.reply)
	if e != nil {
		t.Fatal(e)
	}
	var reply boot
	if e = decodeJSON(plain, &reply); e != nil {
		t.Fatal(e)
	}
	plain, keys, e := hs.ReadMessage(reply.Message)
	if e != nil || keys == nil {
		t.Fatal(e)
	}
	var info sessionInfo
	if e = decodeJSON(plain, &info); e != nil {
		t.Fatal(e)
	}
	var handle [16]byte
	copy(handle[:], info.Handle)
	tx, e := security.NewRecordCipher(keys.Send[:], handle, 0)
	if e != nil {
		t.Fatal(e)
	}
	proof, _, e := tx.Seal(encodeJSON(confirm{info.Challenge, hs.ChannelBinding()}))
	if e != nil {
		t.Fatal(e)
	}
	return p, initial, boot{Version: wireVersion, Action: "confirm", Attempt: attempt, Handle: info.Handle, Message: proof}, info
}

func ticketAdversarialCommit(t *testing.T, s *Server, cred Credentials, port int) (*pending, boot, sessionInfo) {
	t.Helper()
	p, _, proof, info := ticketAdversarialCandidate(t, s, cred, port, nil)
	if _, _, e := s.confirm(proof, "udp", p.peer); e != nil {
		t.Fatal(e)
	}
	return p, proof, info
}

func ticketAdversarialNoTickets(t *testing.T, s *Server) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.tickets) != 0 {
		t.Fatalf("revocation left %d usable ticket locators", len(s.tickets))
	}
}

func TestTicketAdversarialRevokeInitialPending(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	p, initial, proof, _ := ticketAdversarialCandidate(t, s, cred, 47101, nil)
	if e := s.RevokeDevice(cred.Public); e != nil {
		t.Fatal(e)
	}
	if _, e := s.initialize(initial, "udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 47101}); e == nil {
		t.Error("revoked initial candidate returned cached INIT reply")
	}
	if _, _, e := s.confirm(proof, "udp", p.peer); e == nil {
		t.Error("revoked initial candidate committed")
	}
	s.mu.Lock()
	count := len(s.sessions)
	s.mu.Unlock()
	if count != 0 {
		t.Fatal("revoked initial proof created a Session")
	}
	ticketAdversarialNoTickets(t, s)
}

func TestTicketAdversarialRevokeCommittedReady(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	p, proof, _ := ticketAdversarialCommit(t, s, cred, 47102)
	if e := s.RevokeDevice(cred.Public); e != nil {
		t.Fatal(e)
	}
	if !p.session.closed() {
		t.Fatal("RevokeDevice returned before owner stopped")
	}
	if _, _, e := s.confirm(proof, "udp", p.peer); e == nil {
		t.Fatal("revoked committed candidate returned cached READY")
	}
	ticketAdversarialNoTickets(t, s)
}

func TestTicketAdversarialClosedSessionCannotReturnReady(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	p, initial, proof, _ := ticketAdversarialCandidate(t, s, cred, 47103, nil)
	if _, _, e := s.confirm(proof, "udp", p.peer); e != nil {
		t.Fatal(e)
	}
	// This synthetic candidate has no receiving peer. Local teardown succeeds,
	// but the bounded close API must honestly retain the missing confirmation.
	if e := p.session.Close(); !errors.Is(e, ErrCloseUnconfirmed) {
		t.Fatal(e)
	}
	if _, e := s.initialize(initial, "udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 47103}); e == nil {
		t.Error("closed Session returned cached initial reply before registry maintenance")
	}
	if _, _, e := s.confirm(proof, "udp", p.peer); e == nil {
		t.Fatal("closed Session returned cached initial READY before registry maintenance")
	}
}

func TestTicketAdversarialExpiryRejectsCommittedResumeReady(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	_, _, original := ticketAdversarialCommit(t, s, cred, 47114)
	p, _, proof, _ := ticketAdversarialCandidate(t, s, cred, 47115, &original)
	if _, _, e := s.confirm(proof, "udp", p.peer); e != nil {
		t.Fatal(e)
	}
	s.mu.Lock()
	s.tickets[original.Ticket].expires = time.Now().Add(-time.Nanosecond)
	s.mu.Unlock()
	if _, _, e := s.confirm(proof, "udp", p.peer); e == nil {
		t.Fatal("strict expiry was bypassed by committed resume READY cache")
	}
}

func TestTicketAdversarialLocatorEqualityAtDeadlineIsExpired(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	p, _, original := ticketAdversarialCommit(t, s, cred, 47116)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tickets[original.Ticket].expires = now
	if s.ticketValidLocked(original.Ticket, p.session, now) {
		t.Fatal("locator remained valid exactly at its expiry")
	}
}

func TestTicketAdversarialAliasExpiryRejectsCachedInitAndConfirm(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	_, _, original := ticketAdversarialCommit(t, s, cred, 47104)
	p, initial, proof, _ := ticketAdversarialCandidate(t, s, cred, 47105, &original)
	s.mu.Lock()
	s.tickets[original.Ticket].expires = time.Now().Add(-time.Nanosecond)
	s.mu.Unlock()
	if _, e := s.initialize(initial, "udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 47105}); e == nil {
		t.Error("expired locator bypassed strict use-time check through cached INIT")
	}
	if _, _, e := s.confirm(proof, "udp", p.peer); e == nil {
		t.Error("expired locator committed a previously initialized candidate")
	}
}

func TestTicketAdversarialRotationShortensExistingCandidateAlias(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	ownerPending, _, original := ticketAdversarialCommit(t, s, cred, 47106)
	owner := ownerPending.session
	p, initial, proof, _ := ticketAdversarialCandidate(t, s, cred, 47107, &original)
	var before, after time.Time
	if e := owner.call(context.Background(), func() {
		owner.opts.TicketOverlap = time.Nanosecond
		s.mu.Lock()
		before = s.tickets[original.Ticket].expires
		s.mu.Unlock()
		if e := s.rotateTicket(owner, time.Now().Add(-time.Second)); e != nil {
			t.Error(e)
		}
		s.mu.Lock()
		after = s.tickets[original.Ticket].expires
		s.mu.Unlock()
	}); e != nil {
		t.Fatal(e)
	}
	if !after.Before(before) || after.After(time.Now()) {
		t.Fatal("rotation did not impose an expired, shortened overlap cutoff")
	}
	if _, e := s.initialize(initial, "udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 47107}); e == nil {
		t.Error("cached INIT ignored the alias cutoff shortened by rotation")
	}
	if _, _, e := s.confirm(proof, "udp", p.peer); e == nil {
		t.Error("pending candidate kept old snapshot validity after rotation")
	}
}

func TestTicketAdversarialQueuedAttachChecksAliasAtExecution(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	initial, _, original := ticketAdversarialCommit(t, s, cred, 47108)
	owner := initial.session
	p, _, proof, _ := ticketAdversarialCandidate(t, s, cred, 47109, &original)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	owner.commands <- func() { close(entered); <-release }
	<-entered
	result := make(chan error, 1)
	go func() { _, _, e := s.confirm(proof, "udp", p.peer); result <- e }()
	// The actor is already inside the barrier, so the queued command can only
	// be this candidate's attach. Expire its alias after admission, before run.
	runtimeWait(t, "confirmed candidate queued for actor attach", func() bool { return len(owner.commands) > 0 })
	s.mu.Lock()
	s.tickets[original.Ticket].expires = time.Now().Add(-time.Nanosecond)
	s.mu.Unlock()
	unblock()
	select {
	case e := <-result:
		if e == nil {
			t.Fatal("queued attach committed after its alias expired")
		}
	case <-time.After(time.Second):
		t.Fatal("queued attach did not terminate")
	}
	if e := owner.call(context.Background(), func() {
		if owner.info.Generation != original.Generation || owner.current != initial.carrier {
			t.Error("failed expired candidate replaced the existing carrier")
		}
	}); e != nil {
		t.Fatal(e)
	}
}

func TestTicketAdversarialRevokeCannotBeUndoneByQueuedRotation(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	p, _, _ := ticketAdversarialCommit(t, s, cred, 47110)
	owner := p.session
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	rotation := make(chan error, 1)
	owner.commands <- func() { close(entered); <-release; rotation <- s.rotateTicket(owner, time.Now()) }
	<-entered
	revocation := make(chan error, 1)
	go func() { revocation <- s.RevokeDevice(cred.Public) }()
	runtimeWait(t, "administrative revocation linearized", func() bool { return owner.authority.revoked.Load() })
	unblock()
	select {
	case e := <-rotation:
		if e == nil {
			t.Error("late actor signing recreated a revoked locator")
		}
	case <-time.After(time.Second):
		t.Fatal("rotation did not return")
	}
	select {
	case e := <-revocation:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("revocation waited indefinitely for actor")
	}
	ticketAdversarialNoTickets(t, s)
}

func ticketAdversarialClientState(now time.Time) *Session {
	return &Session{client: true, info: sessionInfo{ID: randomID(), Ticket: randomID(), Secret: randomBytes(32), Generation: 1, TicketSerial: 2, ticketUntil: now.Add(time.Minute), lifetimeUntil: now.Add(time.Hour)}, queue: scheduler.New[protocol.Frame](1200, 1<<20), cancel: func() {}}
}

func TestTicketAdversarialDuplicateRefreshAndLateMergeCannotExtendOrRollback(t *testing.T) {
	now := time.Now()
	s := ticketAdversarialClientState(now)
	old := s.info
	locator := randomID()
	s.receiveTicket(protocol.Frame{Kind: protocol.TicketRefresh, Value: 3, Offset: 60000, Data: []byte(locator)}, now)
	installed := s.info.ticketUntil
	s.receiveTicket(protocol.Frame{Kind: protocol.TicketRefresh, Value: 3, Offset: 60000, Data: []byte(locator)}, now.Add(20*time.Second))
	if !s.info.ticketUntil.Equal(installed) {
		t.Fatal("duplicate refresh extended client monotonic expiry")
	}
	s.receiveTicket(protocol.Frame{Kind: protocol.TicketRefresh, Value: old.TicketSerial, Offset: 60000, Data: []byte(old.Ticket)}, now.Add(25*time.Second))
	late := old
	late.Generation, late.Handle, late.Challenge = 2, randomBytes(16), randomBytes(32)
	late.ticketUntil, late.lifetimeUntil = now.Add(10*time.Hour), now.Add(20*time.Hour)
	if e := s.mergeInfo(late); e != nil {
		t.Fatal(e)
	}
	if s.info.TicketSerial != 3 || s.info.Ticket != locator || !s.info.ticketUntil.Equal(installed) || !s.info.lifetimeUntil.Equal(old.lifetimeUntil) || s.info.Generation != 2 {
		t.Fatal("late handshake rolled back credentials or extended deadlines")
	}
	conflict := s.info
	conflict.Ticket = randomID()
	if e := s.mergeInfo(conflict); e == nil {
		t.Fatal("same serial accepted a different locator")
	}
	same := s.info
	same.ticketUntil = now.Add(30 * time.Second)
	if e := s.mergeInfo(same); e != nil || !s.info.ticketUntil.Equal(same.ticketUntil) {
		t.Fatal("same serial failed to conservatively tighten expiry")
	}
}

func TestTicketAdversarialRefreshRejectsConflictingLocatorAndInvalidTTL(t *testing.T) {
	for _, variant := range []string{"conflict", "zero", "overflow"} {
		t.Run(variant, func(t *testing.T) {
			now := time.Now()
			s := ticketAdversarialClientState(now)
			canceled := false
			s.cancel = func() { canceled = true }
			f := protocol.Frame{Kind: protocol.TicketRefresh, Value: s.info.TicketSerial, Offset: 60000, Data: []byte(s.info.Ticket)}
			switch variant {
			case "conflict":
				f.Data = []byte(randomID())
			case "zero":
				f.Offset = 0
			case "overflow":
				f.Offset = math.MaxUint64
			}
			s.receiveTicket(f, now)
			if !canceled {
				t.Fatal("invalid credential refresh remained usable")
			}
		})
	}
}

func TestTicketAdversarialLostRefreshAckKeepsFixedIssueAndBoundedAliases(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	p, _, _ := ticketAdversarialCommit(t, s, cred, 47111)
	owner := p.session
	if e := owner.call(context.Background(), func() {
		if e := s.rotateTicket(owner, time.Now()); e != nil {
			t.Error(e)
			return
		}
		issued := owner.info
		for i := 0; i < 4; i++ {
			owner.maintainTicket(time.Now().Add(time.Duration(i) * time.Millisecond))
			owner.handle(protocol.Frame{Kind: protocol.TicketRefreshAck, Value: issued.TicketSerial + 1})
		}
		if owner.info.Ticket != issued.Ticket || owner.info.TicketSerial != issued.TicketSerial || !owner.info.ticketUntil.Equal(issued.ticketUntil) || owner.ticketPending != issued.TicketSerial {
			t.Error("lost ACK or future ACK changed the pending issue")
		}
		owner.handle(protocol.Frame{Kind: protocol.TicketRefreshAck, Value: issued.TicketSerial})
		owner.handle(protocol.Frame{Kind: protocol.TicketRefreshAck, Value: issued.TicketSerial})
		if owner.ticketPending != 0 || !owner.info.ticketUntil.Equal(issued.ticketUntil) {
			t.Error("duplicate matching ACK extended the ticket")
		}
		for i := 0; i < 3; i++ {
			if e := s.rotateTicket(owner, time.Now()); e != nil {
				t.Error(e)
			}
		}
		s.mu.Lock()
		count := len(s.tickets)
		s.mu.Unlock()
		if count > 2 {
			t.Errorf("ticket rotation accumulated %d aliases", count)
		}
	}); e != nil {
		t.Fatal(e)
	}
}

func TestTicketAdversarialRotationAndResumeDoNotExtendMaximumLifetime(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	p, _, original := ticketAdversarialCommit(t, s, cred, 47112)
	owner := p.session
	var fixed time.Time
	if e := owner.call(context.Background(), func() {
		fixed = owner.info.lifetimeUntil
		if e := s.rotateTicket(owner, time.Now()); e != nil {
			t.Error(e)
		}
		if !owner.info.lifetimeUntil.Equal(fixed) || owner.info.ticketUntil.After(fixed) {
			t.Error("refresh extended maximum lifetime")
		}
	}); e != nil {
		t.Fatal(e)
	}
	current, e := sessionSnapshot(owner)
	if e != nil {
		t.Fatal(e)
	}
	current.Generation = original.Generation
	resume, _, proof, _ := ticketAdversarialCandidate(t, s, cred, 47113, &current)
	if _, _, e = s.confirm(proof, "udp", resume.peer); e != nil {
		t.Fatal(e)
	}
	if e = owner.call(context.Background(), func() {
		if !owner.info.lifetimeUntil.Equal(fixed) {
			t.Error("resume changed fixed maximum lifetime")
		}
		owner.maintain(fixed)
	}); e != nil {
		t.Fatal(e)
	}
	select {
	case <-owner.done:
	case <-time.After(time.Second):
		t.Fatal("maximum lifetime did not close an unsynchronized resumed Session")
	}
}

func TestTicketAdversarialExpiryDoesNotCloseHealthyBusiness(t *testing.T) {
	f := newRuntimeFixture(t, "udp")
	flow := runtimeFlow(t, f)
	runtimeExchange(t, flow, []byte("before ticket expiry"))
	var old string
	if e := f.peer.call(context.Background(), func() {
		now := time.Now()
		old = f.peer.info.Ticket
		f.peer.info.ticketUntil = now.Add(-time.Millisecond)
		f.server.mu.Lock()
		f.server.tickets[old].expires = f.peer.info.ticketUntil
		f.server.mu.Unlock()
		f.peer.lastReceive = now
		f.peer.maintain(now)
		if f.peer.ctx.Err() != nil || f.peer.info.Ticket == old {
			t.Error("healthy carrier failed to replace its expired locator")
		}
	}); e != nil {
		t.Fatal(e)
	}
	runtimeExchange(t, flow, []byte("same socket after ticket expiry"))
	if f.backend.dials.Load() != 1 {
		t.Fatal("ticket expiry redialed the existing target")
	}
}

func TestTicketAdversarialClientReconnectsAfterMaximumLifetime(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	serveDone := make(chan error, 1)
	go func() { serveDone <- s.Serve(context.Background()) }()
	t.Cleanup(func() { s.Close(); <-serveDone })
	c, e := NewClient(ClientConfig{Server: s.Addr().String(), TCPServer: s.Addr().String(), Credentials: cred})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	first, e := c.Connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	info, e := sessionSnapshot(first)
	if e != nil {
		t.Fatal(e)
	}
	if e = first.call(ctx, func() { first.maintain(first.info.lifetimeUntil) }); e != nil {
		t.Fatal(e)
	}
	select {
	case <-first.done:
	case <-time.After(time.Second):
		t.Fatal("client maximum lifetime did not close its old Session")
	}
	second, e := c.Connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	newInfo, e := sessionSnapshot(second)
	if e != nil {
		t.Fatal(e)
	}
	if second == first || newInfo.ID == info.ID || newInfo.Ticket == info.Ticket || newInfo.Generation != 1 {
		t.Fatal("Connect reused closed Session rather than a fresh network")
	}
}

func TestTicketAdversarialTerminalAuthorityClosesRegisteredTarget(t *testing.T) {
	for _, reason := range []string{"revocation", "lifetime"} {
		t.Run(reason, func(t *testing.T) {
			f := newRuntimeFixture(t, "udp")
			flow := runtimeFlow(t, f)
			runtimeExchange(t, flow, []byte("registered target before terminal authority"))
			var target net.Conn
			if e := f.peer.call(context.Background(), func() {
				for _, st := range f.peer.streams {
					if st.targetConn != nil {
						target = st.targetConn
					}
				}
			}); e != nil || target == nil {
				t.Fatal("test did not establish a registered target socket")
			}
			if reason == "revocation" {
				if e := f.server.RevokeDevice(f.cfg.Credentials.Public); e != nil {
					t.Fatal(e)
				}
			} else {
				if e := f.peer.call(context.Background(), func() { f.peer.maintain(f.peer.info.lifetimeUntil) }); e != nil {
					t.Fatal(e)
				}
				select {
				case <-f.peer.done:
				case <-time.After(time.Second):
					t.Fatal("maximum lifetime did not finish owner cleanup")
				}
			}
			if !f.peer.closed() {
				t.Fatal("terminal authority returned before owner stopped")
			}
			_ = target.SetWriteDeadline(time.Now().Add(time.Second))
			if _, e := target.Write([]byte("must not reach closed target")); e == nil {
				t.Fatal("registered target survived terminal authority cleanup")
			}
		})
	}
}

func TestTicketAdversarialMaximumCredentialReplyFitsMinimumUDPInit(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	for _, mode := range []string{"new", "resume"} {
		t.Run(mode, func(t *testing.T) {
			attempt, expected, locator := randomID(), uint64(0), ""
			var secret []byte
			if mode == "resume" {
				expected, locator, secret = math.MaxUint64, randomID(), randomBytes(32)
			}
			initiator, e := newHandshake(true, mode, "udp", attempt, expected, cred, secret)
			if e != nil {
				t.Fatal(e)
			}
			responder, e := newHandshake(false, mode, "udp", attempt, expected, s.cfg.Credentials, secret)
			if e != nil {
				t.Fatal(e)
			}
			first, _, e := initiator.WriteMessage(encodeJSON(defaultCapabilityOffer()))
			if e != nil {
				t.Fatal(e)
			}
			if _, _, e = responder.ReadMessage(first); e != nil {
				t.Fatal(e)
			}
			initial := boot{Version: wireVersion, Action: "init", Mode: mode, Attempt: attempt, Expected: expected, Ticket: locator, Message: first}
			wire, e := sealBoot(cred.Admission, initial, 1200, true)
			if e != nil {
				t.Fatal(e)
			}
			initialPlain, e := security.OpenBootstrap(cred.Admission, wire)
			if e != nil {
				t.Fatal(e)
			}
			maximumMS := uint64(maxCredentialDuration / time.Millisecond)
			info := sessionInfo{ID: randomID(), ClientAddress: randomID(), ServerAddress: randomID(), Ticket: randomID(), Secret: randomBytes(32), Generation: math.MaxUint64, Handle: randomBytes(16), Challenge: randomBytes(32), TicketSerial: math.MaxUint64, TicketRemainingMS: maximumMS, LifetimeRemainingMS: maximumMS, Profile: ProfileClassAnnouncementV1, Capabilities: CapabilityClassAnnouncementV1, authority: &deviceAuthority{}, issuer: s, ticketUntil: time.Now().Add(maxCredentialDuration), lifetimeUntil: time.Now().Add(maxCredentialDuration)}
			message, _, e := responder.WriteMessage(encodeJSON(info))
			if e != nil {
				t.Fatal(e)
			}
			replyPlain := encodeJSON(boot{Version: wireVersion, Action: "reply", Attempt: attempt, Message: message})
			maximumReply := min(1200, security.BootstrapOverhead+len(replyPlain)+255)
			minimumInit := security.BootstrapOverhead + len(initialPlain)
			if maximumReply > minimumInit || security.BootstrapOverhead+len(replyPlain) > 1200 {
				t.Fatalf("credential fields exceed UDP response budget: reply max=%d INIT min=%d", maximumReply, minimumInit)
			}
			t.Logf("%s credential maximum: reply max=%d INIT min=%d", mode, maximumReply, minimumInit)
		})
	}
}
