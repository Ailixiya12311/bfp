package session

import (
	"bfp/security"
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func newSecurityTestServer(t *testing.T) (*Server, Credentials) {
	t.Helper()
	client, e := security.GenerateKeyPair()
	if e != nil {
		t.Fatal(e)
	}
	server, e := security.GenerateKeyPair()
	if e != nil {
		t.Fatal(e)
	}
	admit := randomBytes(32)
	// The constructor owns both sockets continuously; no preflight socket is
	// released and rebound, and a failed test is never retried by this fixture.
	cfg := ServerConfig{Listen: "127.0.0.1:0", Credentials: Credentials{Admission: admit, Private: server.Private, Public: server.Public, AllowedClients: [][]byte{client.Public}}, Backend: &net.Dialer{}}
	s, e := NewServer(cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, Credentials{Admission: admit, Private: client.Private, Public: client.Public, ServerPublic: server.Public}
}
func prepareCandidate(t *testing.T, s *Server, cred Credentials, kind, attempt string, port int, previous *sessionInfo) (*pending, boot, sessionInfo) {
	t.Helper()
	mode := "new"
	expected := uint64(0)
	ticket := ""
	var secret []byte
	if previous != nil {
		mode = "resume"
		expected = previous.Generation
		ticket = previous.Ticket
		secret = previous.Secret
	}
	hs, e := newHandshake(true, mode, kind, attempt, expected, cred, secret)
	if e != nil {
		t.Fatal(e)
	}
	offer, e := clientCapabilityOffer(ClientConfig{}, previous)
	if e != nil {
		t.Fatal(e)
	}
	message, _, e := hs.WriteMessage(encodeJSON(offer))
	if e != nil {
		t.Fatal(e)
	}
	b := boot{Version: wireVersion, Action: "init", Mode: mode, Attempt: attempt, Expected: expected, Ticket: ticket, Message: message}
	var conn net.Conn
	var addr *net.UDPAddr
	if kind == "udp" {
		addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	} else {
		a, z := net.Pipe()
		conn = a
		t.Cleanup(func() { a.Close(); z.Close() })
	}
	p, e := s.initialize(b, kind, conn, addr)
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
	var h [16]byte
	copy(h[:], info.Handle)
	tx, e := security.NewRecordCipher(keys.Send[:], h, 0)
	if e != nil {
		t.Fatal(e)
	}
	proof, _, e := tx.Seal(encodeJSON(confirm{Challenge: info.Challenge, Binding: hs.ChannelBinding()}))
	if e != nil {
		t.Fatal(e)
	}
	return p, boot{Version: wireVersion, Action: "confirm", Attempt: attempt, Handle: info.Handle, Message: proof}, info
}
func TestServerSourceBoundConfirmAndInitialAttemptDedup(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	attempt := randomID()
	udp, proof, info := prepareCandidate(t, s, cred, "udp", attempt, 44001, nil)
	tcp, tcpProof, tcpInfo := prepareCandidate(t, s, cred, "tcp", attempt, 0, nil)
	if info.ID != tcpInfo.ID || info.Ticket != tcpInfo.Ticket {
		t.Fatal("cross-carrier initial attempt got different sessions")
	}
	if _, _, e := s.confirm(proof, "udp", "127.0.0.1:44002"); !errors.Is(e, security.ErrAuthentication) {
		t.Fatal("confirm accepted from a different source")
	}
	ready, committed, e := s.confirm(proof, "udp", udp.peer)
	if e != nil || committed != udp || len(ready) == 0 {
		t.Fatalf("confirm failed: %v", e)
	}
	duplicate, _, e := s.confirm(proof, "udp", udp.peer)
	if e != nil || string(duplicate) != string(ready) {
		t.Fatal("confirmation retry not idempotent")
	}
	if _, _, e = s.confirm(tcpProof, "tcp", tcp.peer); e == nil {
		t.Fatal("superseded candidate committed")
	}
	if len(s.Snapshot()) != 1 {
		t.Fatal("initial attempt created multiple sessions")
	}
	later, laterProof, laterInfo := prepareCandidate(t, s, cred, "udp", attempt, 44003, nil)
	if laterInfo.ID != info.ID {
		t.Fatal("late fallback created another network")
	}
	if _, _, e = s.confirm(laterProof, "udp", later.peer); e != nil {
		t.Fatal(e)
	}
	s.mu.Lock()
	count := len(s.handles)
	s.mu.Unlock()
	if count != 1 {
		t.Fatalf("obsolete handles retained: %d", count)
	}
	if len(s.Snapshot()) != 1 {
		t.Fatal("late fallback created another Session")
	}
}
func TestServerLostReadyRecoveryRetryKeepsCommittedGeneration(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	p, proof, original := prepareCandidate(t, s, cred, "udp", randomID(), 45001, nil)
	if _, _, e := s.confirm(proof, "udp", p.peer); e != nil {
		t.Fatal(e)
	}
	attempt := randomID()
	first, firstProof, firstInfo := prepareCandidate(t, s, cred, "udp", attempt, 45002, &original)
	if firstInfo.Generation != original.Generation+1 {
		t.Fatal("first recovery did not increment")
	}
	if _, _, e := s.confirm(firstProof, "udp", first.peer); e != nil {
		t.Fatal(e)
	}
	// The READY is treated as lost: retry uses the same attempt and original
	// expected generation, with a fresh Noise exchange and a different source.
	retry, retryProof, retryInfo := prepareCandidate(t, s, cred, "udp", attempt, 45003, &original)
	if retryInfo.Generation != firstInfo.Generation || retryInfo.ID != original.ID {
		t.Fatal("recovery retry changed committed operation")
	}
	if _, _, e := s.confirm(retryProof, "udp", retry.peer); e != nil {
		t.Fatal(e)
	}
	if got := s.Snapshot()[0].Generation; got != firstInfo.Generation {
		t.Fatalf("recovery retry incremented twice: %d", got)
	}
	s.mu.Lock()
	handles := len(s.handles)
	s.mu.Unlock()
	if handles != 1 {
		t.Fatal("old recovery lookup handles accumulated")
	}
}
func TestServerRawTCPHandshakeSlotsAndClose(t *testing.T) {
	s, _ := newSecurityTestServer(t)
	served := make(chan error, 1)
	go func() { served <- s.Serve(context.Background()) }()
	clients := make([]net.Conn, 0, maxPendingHandshakes+8)
	for i := 0; i < maxPendingHandshakes+8; i++ {
		// Spread the fixture over loopback aliases so this test continues to
		// exercise the global cap after the per-source cap is enabled.
		source := byte(2 + i%maxPendingHandshakesSource)
		if i >= maxPendingHandshakes {
			// Overflow attempts use fresh sources, so only the global limit can
			// reject them; none is at its own per-source cap.
			source = byte(10 + i - maxPendingHandshakes)
		}
		d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, source)}}
		c, e := d.Dial("tcp", s.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		clients = append(clients, c)
	}
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		count := len(s.connections)
		s.mu.Unlock()
		if count == maxPendingHandshakes {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("raw handshake slots not observed: %d", count)
		}
		time.Sleep(time.Millisecond)
	}
	s.mu.Lock()
	count := len(s.connections)
	s.mu.Unlock()
	if count > maxPendingHandshakes {
		t.Fatal("unbounded raw TCP connections")
	}
	_ = clients[len(clients)-1].SetReadDeadline(time.Now().Add(time.Second))
	if n, err := clients[len(clients)-1].Read(make([]byte, 1201)); n != 0 || err == nil {
		t.Fatalf("global raw handshake overflow emitted application data: bytes=%d err=%v", n, err)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("global raw handshake overflow did not close")
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt unauthenticated reads")
	}
	select {
	case e := <-served:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not exit")
	}
	s.mu.Lock()
	count = len(s.connections)
	s.mu.Unlock()
	if count != 0 {
		t.Fatal("untransferred TCP connections survived Close")
	}
	s.mu.Lock()
	bySource := len(s.sourceConnections)
	s.mu.Unlock()
	if bySource != 0 {
		t.Fatalf("raw TCP source accounting survived Close: sources=%d", bySource)
	}
}

func TestServerRawTCPHandshakePerSourceBudget(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	served := make(chan error, 1)
	go func() { served <- s.Serve(context.Background()) }()
	clients := make([]net.Conn, 0, maxPendingHandshakesSource+4)
	for i := 0; i < maxPendingHandshakesSource+4; i++ {
		c, e := net.DialTimeout("tcp", s.Addr().String(), time.Second)
		if e != nil {
			t.Fatal(e)
		}
		clients = append(clients, c)
	}
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		count := s.sourceConnections["127.0.0.1"]
		s.mu.Unlock()
		if count == maxPendingHandshakesSource {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("per-source raw handshake budget not observed: %d", count)
		}
		time.Sleep(time.Millisecond)
	}
	s.mu.Lock()
	count := s.sourceConnections["127.0.0.1"]
	global := len(s.connections)
	s.mu.Unlock()
	if count > maxPendingHandshakesSource || global > maxPendingHandshakes {
		t.Fatalf("raw handshake budgets exceeded: source=%d global=%d", count, global)
	}
	// The refused socket must produce no application response. TCP FIN/reset
	// remains observable and is not a protocol-invisibility guarantee.
	_ = clients[len(clients)-1].SetReadDeadline(time.Now().Add(time.Second))
	if n, err := clients[len(clients)-1].Read(make([]byte, 1201)); n != 0 || err == nil {
		t.Fatalf("refused raw handshake emitted application data: bytes=%d err=%v", n, err)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("over-budget raw handshake did not close")
	}
	// A different source remains able to authenticate using the ordinary TCP
	// bootstrap; rejected inputs must not allocate Session/target state.
	s.mu.Lock()
	authenticated := len(s.pending) + len(s.sessions) + len(s.attempts) + len(s.handles)
	s.mu.Unlock()
	if authenticated != 0 {
		t.Fatal("raw handshake saturation allocated authenticated state")
	}
	authenticateTCPFromSource(t, s, cred, net.IPv4(127, 0, 0, 2))
	s.mu.Lock()
	createdSessions, saturatedRaw := len(s.sessions), s.sourceConnections["127.0.0.1"]
	s.mu.Unlock()
	if createdSessions != 1 || saturatedRaw != maxPendingHandshakesSource {
		t.Fatal("another source could not authenticate independently of saturated raw source")
	}
	// Releasing one raw socket must return exactly one source token; otherwise
	// a single burst would permanently deny later authenticated fallback.
	if err := clients[0].Close(); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		count = s.sourceConnections["127.0.0.1"]
		s.mu.Unlock()
		if count == maxPendingHandshakesSource-1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("source token was not released after raw close: %d", count)
		}
		time.Sleep(time.Millisecond)
	}
	replacement, err := net.DialTimeout("tcp", s.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clients = append(clients, replacement)
	deadline = time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		count = s.sourceConnections["127.0.0.1"]
		s.mu.Unlock()
		if count == maxPendingHandshakesSource {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("released source token was not reusable: %d", count)
		}
		time.Sleep(time.Millisecond)
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt per-source unauthenticated reads")
	}
	select {
	case e := <-served:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not exit")
	}
}

func authenticateTCPFromSource(t *testing.T, s *Server, cred Credentials, source net.IP) {
	t.Helper()
	d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: source}}
	conn, err := d.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	attempt := randomID()
	hs, err := newHandshake(true, "new", "tcp", attempt, 0, cred, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := hs.WriteMessage(encodeJSON(defaultCapabilityOffer()))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealBoot(cred.Admission, boot{Version: wireVersion, Action: "init", Mode: "new", Attempt: attempt, Message: first}, 1200, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = security.WriteBootstrap(conn, wire); err != nil {
		t.Fatal(err)
	}
	plain, err := security.ReadBootstrap(conn, cred.Admission)
	if err != nil {
		t.Fatal(err)
	}
	var reply boot
	if err = decodeJSON(plain, &reply); err != nil || reply.Action != "reply" || reply.Attempt != attempt {
		t.Fatal("another-source TCP handshake reply failed", err)
	}
	plain, keys, err := hs.ReadMessage(reply.Message)
	if err != nil || keys == nil {
		t.Fatal("another-source TCP server proof failed", err)
	}
	var info sessionInfo
	if err = decodeJSON(plain, &info); err != nil {
		t.Fatal(err)
	}
	c, err := makeCarrier("tcp", info.Generation, info.Handle, keys, conn, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.close() })
	proof, _, err := c.tx.Seal(encodeJSON(confirm{Challenge: info.Challenge, Binding: hs.ChannelBinding()}))
	if err != nil {
		t.Fatal(err)
	}
	wire, err = sealBoot(cred.Admission, boot{Version: wireVersion, Action: "confirm", Attempt: attempt, Handle: info.Handle, Message: proof}, 1200, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = security.WriteBootstrap(conn, wire); err != nil {
		t.Fatal(err)
	}
	plain, err = security.ReadBootstrap(conn, cred.Admission)
	if err != nil {
		t.Fatal(err)
	}
	var ready boot
	if err = decodeJSON(plain, &ready); err != nil || ready.Action != "ready" || ready.Attempt != attempt {
		t.Fatal("another-source TCP confirmation failed", err)
	}
	plain, _, err = c.rx.Open(ready.Message)
	if err != nil || !bytes.Equal(plain, []byte("ready")) {
		t.Fatal("another-source TCP READY proof failed", err)
	}
}

func TestServerSlowTCPBootstrapExpiresWithoutResponse(t *testing.T) {
	s, _ := newSecurityTestServer(t)
	// This value is installed before Serve starts; production defaults stay
	// unchanged. Partial bytes must not roll the absolute bootstrap deadline.
	s.cfg.Options.HandshakeTimeout = 150 * time.Millisecond
	served := make(chan error, 1)
	go func() { served <- s.Serve(context.Background()) }()
	conn, err := net.DialTimeout("tcp", s.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		count := len(s.connections)
		s.mu.Unlock()
		if count == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slow bootstrap was not registered")
		}
		time.Sleep(time.Millisecond)
	}
	started := time.Now()
	_ = conn.SetDeadline(started.Add(time.Second))
	type rawReadResult struct {
		n   int
		err error
	}
	reads := make(chan rawReadResult, 1)
	go func() {
		n, err := conn.Read(make([]byte, 1201))
		reads <- rawReadResult{n, err}
	}()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	var result rawReadResult
drip:
	for bytesSent := 0; ; {
		select {
		case result = <-reads:
			break drip
		case <-tick.C:
			if _, err = conn.Write([]byte{byte(bytesSent)}); err != nil {
				// A closed server read can precede delivery of its FIN/reset to
				// this concurrent reader. Join the observation within its bound.
				select {
				case result = <-reads:
				case <-time.After(time.Second):
					t.Fatal("partial bootstrap reader did not exit after write failure")
				}
				break drip
			}
			bytesSent++
		}
	}
	if result.n != 0 || result.err == nil {
		t.Fatalf("partial bootstrap emitted application response: bytes=%d err=%v", result.n, result.err)
	} else if ne, ok := result.err.(net.Error); ok && ne.Timeout() {
		t.Fatal("partial bootstrap outlived absolute deadline")
	}
	if elapsed := time.Since(started); elapsed > 3*s.cfg.Options.HandshakeTimeout {
		t.Fatalf("partial bytes extended absolute bootstrap deadline: elapsed=%v budget=%v", elapsed, s.cfg.Options.HandshakeTimeout)
	}
	deadline = time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		count := len(s.connections)
		sources := len(s.sourceConnections)
		authenticated := len(s.pending) + len(s.sessions) + len(s.attempts) + len(s.handles)
		s.mu.Unlock()
		if authenticated != 0 {
			t.Fatal("partial bootstrap allocated authenticated state")
		}
		if count == 0 && sources == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expired raw handshake accounting remained: raw=%d sources=%d", count, sources)
		}
		time.Sleep(time.Millisecond)
	}
	s.Close()
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not exit")
	}
}
