package session

import (
	"bfp/classification"
	"bfp/internal/backend"
	"bfp/security"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	// maxPendingHandshakes bounds all raw TCP sockets that have not completed
	// the authenticated bootstrap. A second per-source budget prevents one
	// scanner/NAT address from consuming the entire global pool while sockets
	// wait for the handshake deadline.
	maxPendingHandshakes       = 64
	maxPendingHandshakesSource = 8
)

// Lock order is pending.mu -> attemptGroup.mu -> Server.mu. Never wait for a
// pending/group lock or a Session actor while holding Server.mu. Device commit
// gates follow group locks; the actor never takes a device gate.
type attemptGroup struct {
	mu             sync.Mutex
	created        time.Time
	info           sessionInfo // immutable operation template
	session        *Session
	baseGeneration uint64
	committed      bool
	offer          capabilityOffer
}
type pending struct {
	mu                                         sync.Mutex
	created                                    time.Time
	registryKey, groupKey, attempt, mode, peer string
	ticketAlias                                string
	expected                                   uint64
	initDigest                                 [32]byte
	confirmDigest                              [32]byte
	info                                       sessionInfo
	hs                                         *security.Handshake
	carrier                                    *carrier
	reply, ready                               []byte
	session                                    *Session
	group                                      *attemptGroup
	committed, closed                          bool
}
type Server struct {
	classifier        *classification.Classifier
	cfg               ServerConfig
	ctx               context.Context
	cancel            context.CancelFunc
	udp               *net.UDPConn
	udpWriter         *sharedUDPWriter
	tcp               net.Listener
	mu                sync.Mutex
	sessions          map[string]*Session
	tickets           map[string]*ticketRecord
	devices           map[string]*deviceAuthority
	pending           map[string]*pending
	handles           map[[16]byte]*pending
	attempts          map[string]*attemptGroup
	replay            map[[32]byte]time.Time
	connections       map[net.Conn]string
	sourceConnections map[string]int
	budgetAt          time.Time
	budgetCount       int
	started           bool
	wg                sync.WaitGroup
	closeOnce         sync.Once
}

func NewServer(cfg ServerConfig) (*Server, error) {
	cfg.Credentials = copyCredentials(cfg.Credentials)
	if e := validateCredentials(cfg.Credentials, false); e != nil {
		return nil, e
	}
	if backend.IsNil(cfg.Backend) {
		return nil, errors.New("session: server requires backend")
	}
	cfg.Options = cfg.Options.defaults()
	if e := validateTicketOptions(cfg.Options); e != nil {
		return nil, e
	}
	negotiation, e := normalizeNegotiation(cfg.Negotiation)
	if e != nil {
		return nil, e
	}
	cfg.Negotiation = negotiation
	classifier, e := compileClassification(cfg.Classification)
	if e != nil {
		return nil, e
	}
	cfg.Classification = nil
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 64
	}
	tcp, udp, e := listenPlatformServer(cfg.Listen)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{cfg: cfg, classifier: classifier, ctx: ctx, cancel: cancel, udp: udp, tcp: tcp, sessions: map[string]*Session{}, tickets: map[string]*ticketRecord{}, devices: map[string]*deviceAuthority{}, pending: map[string]*pending{}, handles: map[[16]byte]*pending{}, attempts: map[string]*attemptGroup{}, replay: map[[32]byte]time.Time{}, connections: map[net.Conn]string{}, sourceConnections: map[string]int{}}
	s.udpWriter = newSharedUDPWriter(udp)
	for _, pub := range cfg.Credentials.AllowedClients {
		s.devices[string(pub)] = &deviceAuthority{}
	}
	return s, nil
}
func (s *Server) Addr() net.Addr { return s.tcp.Addr() }
func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	if s.started || s.ctx.Err() != nil {
		s.mu.Unlock()
		return ErrClosed
	}
	s.started = true
	s.wg.Add(2)
	s.mu.Unlock()
	go func() { defer s.wg.Done(); s.readUDP() }()
	go func() { defer s.wg.Done(); s.maintenance() }()
	go func() {
		select {
		case <-ctx.Done():
			s.Close()
		case <-s.ctx.Done():
		}
	}()
	defer s.Close()
	for {
		conn, e := s.tcp.Accept()
		if e != nil {
			if s.ctx.Err() != nil {
				return nil
			}
			return e
		}
		source := tcpSourceKey(conn.RemoteAddr())
		s.mu.Lock()
		if s.ctx.Err() != nil || len(s.connections) >= maxPendingHandshakes || s.sourceConnections[source] >= maxPendingHandshakesSource {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		// Reserve raw connections before any reads or goroutine creation.
		s.connections[conn] = source
		s.sourceConnections[source]++
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer s.releaseTCPConnection(conn)
			s.acceptTCP(conn)
		}()
	}
}

// tcpSourceKey deliberately uses the peer IP only. A scanner can vary its
// source port, but cannot use that to obtain a fresh handshake budget. The
// fallback preserves an IP/host key for test and non-TCP Addr implementations
// without performing reverse DNS.
func tcpSourceKey(addr net.Addr) string {
	if tcp, ok := addr.(*net.TCPAddr); ok && tcp != nil && tcp.IP != nil {
		return tcp.IP.String()
	}
	if addr == nil {
		return "<nil>"
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}

func (s *Server) releaseTCPConnection(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	source, ok := s.connections[conn]
	if !ok {
		return
	}
	delete(s.connections, conn)
	if n := s.sourceConnections[source]; n <= 1 {
		delete(s.sourceConnections, source)
	} else {
		s.sourceConnections[source] = n - 1
	}
}
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.cancel()
		_ = s.tcp.Close()
		_ = s.udp.Close()
		// Retire the shared write owner before waiting for Sessions. It rejects
		// late publications and forces an active net.UDPConn write to wake via
		// its deadline without ever closing the socket from a Session.
		s.udpWriter.retire()
		list := make([]*Session, 0, len(s.sessions))
		for _, x := range s.sessions {
			list = append(list, x)
		}
		candidates := make([]*pending, 0, len(s.pending))
		for _, p := range s.pending {
			candidates = append(candidates, p)
		}
		connections := make([]net.Conn, 0, len(s.connections))
		for c := range s.connections {
			connections = append(connections, c)
		}
		s.mu.Unlock()
		for _, c := range connections {
			_ = c.Close()
		}
		for _, p := range candidates {
			p.mu.Lock()
			p.closed = true
			p.carrier.close()
			p.mu.Unlock()
		}
		for _, x := range list {
			// Server shutdown revokes the control lifetime as well as business.
			// Do not serialize a fresh close drain for every registered Session.
			x.cancel()
		}
		for _, x := range list {
			<-x.done
		}
		s.wg.Wait()
	})
	return nil
}
func (s *Server) Snapshot() []Stats {
	s.mu.Lock()
	list := make([]*Session, 0, len(s.sessions))
	for _, x := range s.sessions {
		list = append(list, x)
	}
	s.mu.Unlock()
	out := make([]Stats, 0, len(list))
	for _, x := range list {
		out = append(out, x.Stats())
	}
	return out
}

// ClassificationSnapshot is read-only test/diagnostic evidence. The server lock
// is released before any Session actor call. A failed actor query is explicit;
// callers must not interpret a partial snapshot as a complete peer view.
func (s *Server) ClassificationSnapshot(ctx context.Context) (map[string][]FlowClassification, error) {
	s.mu.Lock()
	list := make(map[string]*Session, len(s.sessions))
	for id, x := range s.sessions {
		list[id] = x
	}
	s.mu.Unlock()
	out := make(map[string][]FlowClassification, len(list))
	for id, x := range list {
		flows, err := x.FlowClassifications(ctx)
		if err != nil {
			return nil, err
		}
		out[id] = flows
	}
	return out, nil
}
func (s *Server) maintenance() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-tick.C:
			s.mu.Lock()
			candidates := make([]*pending, 0, len(s.pending))
			for _, p := range s.pending {
				candidates = append(candidates, p)
			}
			groups := make(map[string]*attemptGroup, len(s.attempts))
			for k, g := range s.attempts {
				groups[k] = g
			}
			for k, t := range s.replay {
				if now.Sub(t) > time.Minute {
					delete(s.replay, k)
				}
			}
			for id, x := range s.sessions {
				// closed means the control actor has stopped. A terminating
				// Session still owns its authenticated UDP responder route.
				if x.closed() {
					delete(s.sessions, id)
					for t, owner := range s.tickets {
						if owner.session == x {
							delete(s.tickets, t)
						}
					}
					for h, p := range s.handles {
						if p.info.ID == id {
							delete(s.handles, h)
						}
					}
				}
			}
			for locator, record := range s.tickets {
				if record.session.terminating() || !record.expires.After(now) || record.authority.revoked.Load() {
					delete(s.tickets, locator)
				}
			}
			s.mu.Unlock()
			for _, p := range candidates {
				p.mu.Lock()
				p.group.mu.Lock()
				terminal := p.session != nil && p.session.terminating()
				terminal = terminal || p.group.session != nil && p.group.session.terminating()
				if terminal || now.Sub(p.created) > s.cfg.Options.HandshakeTimeout*2 {
					s.mu.Lock()
					if s.pending[p.registryKey] == p {
						delete(s.pending, p.registryKey)
					}
					if !p.committed {
						p.closed = true
						if s.handles[p.carrier.handle] == p {
							delete(s.handles, p.carrier.handle)
						}
					}
					s.mu.Unlock()
					if !p.committed {
						p.carrier.close()
					}
					p.hs = nil
					p.reply = nil
					if terminal {
						p.ready = nil
						p.info.Secret, p.info.Challenge = nil, nil
					}
				}
				p.group.mu.Unlock()
				p.mu.Unlock()
			}
			for k, g := range groups {
				g.mu.Lock()
				remove := g.session != nil && g.session.terminating() || g.session == nil && now.Sub(g.created) > s.cfg.Options.HandshakeTimeout*2
				// Recovery operation deduplication is retained for a bounded recovery
				// period. Initial-connect groups remain only while their session is live.
				if len(k) > 7 && k[:7] == "resume/" && now.Sub(g.created) > s.cfg.Options.RetainTimeout {
					remove = true
				}
				if remove {
					s.mu.Lock()
					if s.attempts[k] == g {
						delete(s.attempts, k)
					}
					s.mu.Unlock()
					g.info.Secret, g.info.Handle, g.info.Challenge = nil, nil, nil
				}
				g.mu.Unlock()
			}
		}
	}
}
func (s *Server) readUDP() {
	buf := make([]byte, security.MaxUDPRecordSize+1)
	for {
		n, addr, e := s.udp.ReadFromUDP(buf)
		if e != nil {
			return
		}
		if n > security.MaxUDPRecordSize {
			continue
		}
		wire := append([]byte(nil), buf[:n]...)
		if n >= 16 {
			var h [16]byte
			copy(h[:], wire[:16])
			s.mu.Lock()
			p := s.handles[h]
			s.mu.Unlock()
			if p != nil {
				p.mu.Lock()
				owner, c := p.session, p.carrier
				valid := p.committed && !p.closed && owner != nil && !owner.closed() && c.kind == "udp" && p.peer == addr.String()
				p.mu.Unlock()
				if valid {
					owner.deliver(c, wire)
					continue
				}
			}
		}
		plain, e := security.OpenBootstrap(s.cfg.Credentials.Admission, wire)
		if e != nil || !s.allowBootstrap(wire) {
			continue
		}
		var b boot
		if decodeJSON(plain, &b) != nil || b.Version != wireVersion {
			continue
		}
		var answer []byte
		var p *pending
		if b.Action == "init" {
			p, e = s.initialize(b, "udp", nil, addr)
			if e != nil {
				continue
			}
			p.mu.Lock()
			if p.session == nil || !p.session.terminating() {
				answer = append([]byte(nil), p.reply...)
			}
			p.mu.Unlock()
		}
		if b.Action == "confirm" {
			answer, p, e = s.confirm(b, "udp", addr.String())
			if e != nil {
				continue
			}
		}
		if len(answer) > 0 && len(answer) <= n {
			we := errSharedUDPWriterClosed
			if s.udpWriter != nil {
				we = s.udpWriter.write(answer, addr, nil, time.Time{})
			}
			if we == nil && b.Action == "confirm" {
				p.mu.Lock()
				owner := p.session
				valid := p.committed && !p.closed && owner != nil && !owner.terminating()
				p.mu.Unlock()
				if valid {
					owner.activate(p.carrier)
				}
			} else if b.Action == "confirm" {
				suspendUnready(p)
			}
		} else if b.Action == "confirm" && p != nil {
			suspendUnready(p)
		}
	}
}
func (s *Server) allowBootstrap(wire []byte) bool {
	return s.allowBootstrapDigest(digest(wire))
}
func (s *Server) allowBootstrapDigest(h [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, yes := s.replay[h]; yes {
		return false
	}
	if len(s.replay) >= 4096 {
		return false
	}
	s.replay[h] = time.Now()
	return true
}
func (s *Server) allowHandshake() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if now.Sub(s.budgetAt) >= time.Second {
		s.budgetAt = now
		s.budgetCount = 0
	}
	if s.ctx.Err() != nil || s.budgetCount >= 128 {
		return false
	}
	s.budgetCount++
	return true
}
func sessionSnapshot(x *Session) (sessionInfo, error) {
	if x == nil || x.terminating() {
		return sessionInfo{}, ErrClosed
	}
	var info sessionInfo
	var snapshotErr error
	e := x.call(context.Background(), func() {
		x.admissionMu.RLock()
		defer x.admissionMu.RUnlock()
		if x.terminating() {
			snapshotErr = ErrClosed
			return
		}
		info = x.info
		info.Secret = append([]byte(nil), info.Secret...)
		info.Handle = append([]byte(nil), info.Handle...)
		info.Challenge = append([]byte(nil), info.Challenge...)
	})
	if e != nil {
		return sessionInfo{}, e
	}
	if snapshotErr != nil || x.terminating() {
		return sessionInfo{}, ErrClosed
	}
	return info, nil
}
func (s *Server) initialize(b boot, kind string, conn net.Conn, addr *net.UDPAddr) (*pending, error) {
	if b.Version != wireVersion {
		return nil, security.ErrAuthentication
	}
	if len(b.Attempt) != 32 || (b.Mode != "new" && b.Mode != "resume") {
		return nil, security.ErrAuthentication
	}
	if b.Mode == "new" && (b.Expected != 0 || b.Ticket != "") {
		return nil, security.ErrAuthentication
	}
	peer := ""
	if addr != nil {
		peer = addr.String()
	} else {
		peer = conn.RemoteAddr().String()
	}
	pk := kind + "/" + peer + "/" + b.Attempt
	requestDigest := digest(encodeJSON(struct {
		Mode, Ticket string
		Expected     uint64
		Message      []byte
	}{b.Mode, b.Ticket, b.Expected, b.Message}))
	s.mu.Lock()
	old := s.pending[pk]
	busy := s.ctx.Err() != nil || len(s.pending) >= maxPendingHandshakes
	record := s.tickets[b.Ticket]
	var previous *Session
	if record != nil && s.ticketValidLocked(b.Ticket, record.session, time.Now()) {
		previous = record.session
	}
	s.mu.Unlock()
	if old != nil {
		old.mu.Lock()
		old.group.mu.Lock()
		owner := old.session
		if owner == nil {
			owner = old.group.session
		}
		if owner != nil {
			owner.admissionMu.RLock()
		}
		valid := !old.closed && old.initDigest == requestDigest && time.Since(old.created) <= s.cfg.Options.HandshakeTimeout*2 && (kind != "tcp" || old.carrier.conn == conn)
		s.mu.Lock()
		valid = valid && s.candidateValidLocked(old, time.Now())
		s.mu.Unlock()
		if owner != nil {
			owner.admissionMu.RUnlock()
		}
		old.group.mu.Unlock()
		old.mu.Unlock()
		if valid {
			return old, nil
		}
		return nil, ErrState
	}
	if busy || !s.allowHandshake() {
		return nil, ErrLimit
	}
	var prior sessionInfo
	var secret []byte
	if b.Mode == "resume" {
		if previous == nil || previous.closed() || previous.terminating() {
			return nil, ErrClosed
		}
		var e error
		prior, e = sessionSnapshot(previous)
		if e != nil {
			return nil, e
		}
		secret = prior.Secret
	}
	hs, e := newHandshake(false, b.Mode, kind, b.Attempt, b.Expected, s.cfg.Credentials, secret)
	if e != nil {
		return nil, e
	}
	payload, _, e := hs.ReadMessage(b.Message)
	if e != nil {
		return nil, e
	}
	groupKey := ""
	var authority *deviceAuthority
	if b.Mode == "new" {
		s.mu.Lock()
		authority = s.devices[string(hs.PeerStatic())]
		s.mu.Unlock()
		if authority == nil || authority.revoked.Load() {
			return nil, security.ErrAuthentication
		}
		groupKey = "new/" + hex.EncodeToString(hs.PeerStatic()) + "/" + b.Attempt
	} else {
		authority = prior.authority
		groupKey = "resume/" + prior.ID + "/" + b.Attempt
	}
	offer, e := decodeCapabilityOffer(payload)
	if e != nil {
		return nil, e
	}
	var pinned *sessionInfo
	if b.Mode == "resume" {
		pinned = &prior
	}
	profile, capabilities, e := selectCapabilities(offer, s.cfg.Negotiation, pinned)
	if e != nil {
		return nil, e
	}
	s.mu.Lock()
	if authority == nil || authority.revoked.Load() || b.Mode == "resume" && !s.ticketValidLocked(b.Ticket, previous, time.Now()) {
		s.mu.Unlock()
		return nil, security.ErrAuthentication
	}
	group := s.attempts[groupKey]
	if group == nil {
		if len(s.attempts) >= 4096 {
			s.mu.Unlock()
			return nil, ErrLimit
		}
		if b.Mode == "new" {
			now := time.Now()
			until := now.Add(s.cfg.Options.MaxSessionLifetime)
			prior = sessionInfo{ID: randomID(), ClientAddress: randomID(), ServerAddress: randomID(), Ticket: randomID(), Secret: randomBytes(32), Generation: 1, TicketSerial: 1, Profile: profile, Capabilities: capabilities, ticketUntil: earlier(now.Add(s.cfg.Options.TicketTTL), until), lifetimeUntil: until, authority: authority, issuer: s}
		}
		group = &attemptGroup{created: time.Now(), info: prior, session: previous, baseGeneration: b.Expected, offer: offer}
		s.attempts[groupKey] = group
	}
	s.mu.Unlock()
	group.mu.Lock()
	defer group.mu.Unlock()
	if group.offer != offer || group.info.Profile != profile || group.info.Capabilities != capabilities {
		return nil, security.ErrAuthentication
	}
	previous = group.session
	if previous != nil && previous.terminating() {
		return nil, ErrClosed
	}
	prior = group.info
	if previous != nil {
		prior, e = sessionSnapshot(previous)
		if e != nil {
			return nil, e
		}
	}
	if prior.Profile != profile || prior.Capabilities != capabilities {
		return nil, security.ErrAuthentication
	}
	info := prior
	expected := b.Expected
	if b.Mode == "resume" {
		if group.baseGeneration != b.Expected {
			return nil, ErrState
		}
		if prior.Generation == b.Expected {
			info.Generation = b.Expected + 1
			expected = b.Expected
		} else if group.committed && prior.Generation == b.Expected+1 {
			info.Generation = prior.Generation
			expected = prior.Generation
		} else {
			return nil, ErrState
		}
	} else if previous != nil {
		info.Generation = prior.Generation + 1
		expected = prior.Generation
	}
	info.Handle = randomBytes(16)
	info.Challenge = randomBytes(32)
	info = exportDeadlines(info, time.Now())
	if info.TicketRemainingMS == 0 || info.LifetimeRemainingMS == 0 {
		return nil, ErrClosed
	}
	reply, keys, e := hs.WriteMessage(encodeJSON(info))
	if e != nil {
		return nil, e
	}
	c, e := makeCarrier(kind, info.Generation, info.Handle, keys, conn, s.udp, addr)
	if e != nil {
		return nil, e
	}
	c.udpWriter = s.udpWriter
	c.profile, c.capabilities = info.Profile, info.Capabilities
	wire, e := sealBoot(s.cfg.Credentials.Admission, boot{Version: wireVersion, Action: "reply", Attempt: b.Attempt, Message: reply}, 1200, false)
	if e != nil {
		return nil, e
	}
	p := &pending{created: time.Now(), registryKey: pk, groupKey: groupKey, attempt: b.Attempt, mode: b.Mode, ticketAlias: b.Ticket, expected: expected, peer: peer, initDigest: requestDigest, info: info, hs: hs, carrier: c, reply: wire, session: previous, group: group}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.candidateValidLocked(p, time.Now()) || len(s.pending) >= maxPendingHandshakes || s.pending[pk] != nil {
		return nil, ErrLimit
	}
	s.pending[pk] = p
	s.handles[c.handle] = p
	return p, nil
}
func (s *Server) confirm(b boot, kind, peer string) ([]byte, *pending, error) {
	if b.Version != wireVersion {
		return nil, nil, security.ErrAuthentication
	}
	if len(b.Handle) != 16 {
		return nil, nil, security.ErrAuthentication
	}
	var h [16]byte
	copy(h[:], b.Handle)
	s.mu.Lock()
	p := s.handles[h]
	s.mu.Unlock()
	if p == nil || p.carrier.kind != kind || p.peer != peer || p.attempt != b.Attempt {
		return nil, nil, security.ErrAuthentication
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.session != nil && p.session.terminating() || time.Since(p.created) > s.cfg.Options.HandshakeTimeout*2 || s.ctx.Err() != nil {
		return nil, nil, ErrClosed
	}
	a := p.info.authority
	if a == nil {
		return nil, nil, security.ErrAuthentication
	}
	if p.committed {
		// READY retries must carry the exact already-authenticated record.
		// Opening it again would reject a legitimate duplicate as replay, but
		// accepting arbitrary replacement bytes would bypass the device proof.
		if digest(b.Message) != p.confirmDigest {
			return nil, nil, security.ErrAuthentication
		}
		p.group.mu.Lock()
		defer p.group.mu.Unlock()
		a.gate.Lock()
		defer a.gate.Unlock()
		p.session.admissionMu.RLock()
		defer p.session.admissionMu.RUnlock()
		s.mu.Lock()
		valid := s.candidateValidLocked(p, time.Now())
		s.mu.Unlock()
		if !valid {
			return nil, nil, security.ErrAuthentication
		}
		return append([]byte(nil), p.ready...), p, nil
	}
	plain, _, e := p.carrier.rx.Open(b.Message)
	if e != nil {
		return nil, nil, e
	}
	var proof confirm
	if decodeJSON(plain, &proof) != nil || !bytes.Equal(proof.Challenge, p.info.Challenge) || !bytes.Equal(proof.Binding, p.hs.ChannelBinding()) {
		return nil, nil, security.ErrAuthentication
	}
	p.group.mu.Lock()
	defer p.group.mu.Unlock()
	a.gate.Lock()
	defer a.gate.Unlock()
	s.mu.Lock()
	groupValid := s.attempts[p.groupKey] == p.group && s.candidateValidLocked(p, time.Now())
	s.mu.Unlock()
	if !groupValid {
		return nil, nil, ErrState
	}
	if p.group.session != nil {
		p.session = p.group.session
	}
	createdSession := false
	if p.session == nil {
		s.mu.Lock()
		if !s.candidateValidLocked(p, time.Now()) || len(s.sessions) >= s.cfg.MaxSessions {
			s.mu.Unlock()
			return nil, nil, ErrLimit
		}
		p.session = newSession(s.ctx, p.info, s.cfg.Options, false, s.cfg.Backend, s.classifier)
		s.sessions[p.info.ID] = p.session
		s.tickets[p.info.Ticket] = &ticketRecord{p.session, a, p.info.TicketSerial, p.info.ticketUntil}
		s.mu.Unlock()
		p.group.session = p.session
		createdSession = true
	}
	if e = p.session.attachGuarded(p.carrier, p.expected, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.candidateValidLocked(p, time.Now())
	}); e != nil {
		if createdSession {
			p.session.cancel()
		}
		return nil, nil, e
	}
	// Carrier attachment commits this operation's generation even if time runs
	// out just before READY. A retry with another live alias must not increment
	// the same operation twice or get stuck behind an uncommitted group.
	p.group.committed = true
	s.mu.Lock()
	validAfterAttach := s.candidateValidLocked(p, time.Now())
	s.mu.Unlock()
	if !validAfterAttach {
		p.session.post(func() {
			if !p.session.terminating() && p.session.current == p.carrier {
				p.session.suspend()
			}
		})
		return nil, nil, ErrClosed
	}
	// Attachment's actor gate is complete. Do not hold this read gate while
	// waiting for that actor; only the local READY commit uses it.
	p.session.admissionMu.RLock()
	defer p.session.admissionMu.RUnlock()
	if p.session.terminating() {
		return nil, nil, ErrClosed
	}
	ready, _, e := p.carrier.tx.Seal([]byte("ready"))
	if e != nil {
		return nil, nil, e
	}
	p.ready, e = sealBoot(s.cfg.Credentials.Admission, boot{Version: wireVersion, Action: "ready", Attempt: b.Attempt, Message: ready}, 1200, false)
	if e != nil {
		return nil, nil, e
	}
	p.confirmDigest = digest(b.Message)
	p.committed = true
	p.group.committed = true
	p.hs = nil
	s.mu.Lock()
	for handle, other := range s.handles {
		if other != p && other.info.ID == p.info.ID {
			delete(s.handles, handle)
		}
	}
	s.mu.Unlock()
	if p.session.terminating() {
		return nil, nil, ErrClosed
	}
	return append([]byte(nil), p.ready...), p, nil
}
func (s *Server) acceptTCP(conn net.Conn) {
	transferred := false
	defer func() {
		if !transferred {
			conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(s.cfg.Options.HandshakeTimeout))
	readBootstrap := func() ([]byte, error) {
		// Hash the exact authenticated envelope consumed by this read without
		// changing its framing or allocating a second copy of the wire record.
		h := sha256.New()
		plain, err := security.ReadBootstrap(io.TeeReader(conn, h), s.cfg.Credentials.Admission)
		if err != nil {
			return nil, err
		}
		var wireDigest [32]byte
		copy(wireDigest[:], h.Sum(nil))
		if !s.allowBootstrapDigest(wireDigest) {
			return nil, security.ErrAuthentication
		}
		return plain, nil
	}
	plain, e := readBootstrap()
	if e != nil {
		return
	}
	var b boot
	if decodeJSON(plain, &b) != nil || b.Action != "init" || b.Version != wireVersion {
		return
	}
	p, e := s.initialize(b, "tcp", conn, nil)
	if e != nil {
		return
	}
	p.mu.Lock()
	var reply []byte
	if p.session == nil || !p.session.terminating() {
		reply = append([]byte(nil), p.reply...)
	}
	p.mu.Unlock()
	if len(reply) == 0 {
		return
	}
	if e = security.WriteBootstrap(conn, reply); e != nil {
		return
	}
	plain, e = readBootstrap()
	if e != nil {
		return
	}
	if decodeJSON(plain, &b) != nil || b.Action != "confirm" || b.Version != wireVersion {
		return
	}
	ready, committed, e := s.confirm(b, "tcp", conn.RemoteAddr().String())
	if e != nil {
		return
	}
	if e = security.WriteBootstrap(conn, ready); e != nil {
		suspendUnready(committed)
		return
	}
	_ = conn.SetDeadline(time.Time{})
	transferred = true
	committed.mu.Lock()
	owner, c := committed.session, committed.carrier
	committed.mu.Unlock()
	// READY completed and the carrier was already attached. Even if close
	// intent raced this publication, its current authenticated reader is
	// needed by the control drain; activate itself rejects business termination.
	owner.startReader(c)
	owner.activate(c)
}

// A committed candidate whose READY cannot be delivered remains resumable only
// for the ordinary suspended-session retention period, rather than forever.
func suspendUnready(p *pending) {
	p.mu.Lock()
	owner, c, committed := p.session, p.carrier, p.committed
	p.mu.Unlock()
	if !committed || owner == nil || owner.terminating() {
		return
	}
	owner.post(func() {
		if !owner.terminating() && owner.current == c && !owner.active {
			owner.suspend()
		}
	})
}
