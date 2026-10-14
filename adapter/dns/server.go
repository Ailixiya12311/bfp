// Package dns provides a bounded loopback DNS entry for Session-owned fake A/AAAA
// records. It does not change operating-system DNS, routes or interfaces.
package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"bfp/internal/addressscope"
	"bfp/session"
	"golang.org/x/net/dns/dnsmessage"
)

const maxMessageBytes = 1232

var ErrConfig = errors.New("dns: invalid frontend configuration")

// SessionSelector selects a real owner once for each supported query. There
// is no frontend cache and no implicit retry against a different Session.
// Connect must be thread-safe and honor ctx, including cancellation of any
// application factory callback. The concrete session.Client supplies that owner.
type SessionSelector interface {
	Connect(context.Context) (*session.Session, error)
}

type Config struct {
	Listen               string
	Client               SessionSelector
	MaxConcurrent        int
	MaxTCPConnections    int
	QueryTimeout         time.Duration
	TCPIdleTimeout       time.Duration
	ResponseWriteTimeout time.Duration
}

type Server struct {
	cfg             Config
	udp             *net.UDPConn
	tcp             *net.TCPListener
	ctx             context.Context
	cancel          context.CancelFunc
	queries         chan struct{}
	connections     chan struct{}
	mu              sync.Mutex
	active          map[net.Conn]struct{}
	closed, serving bool
	wg              sync.WaitGroup
	closeOnce       sync.Once
	writeMu         sync.Mutex // only this gate changes the shared UDP write deadline
}

func New(cfg Config) (*Server, error) {
	if addressscope.IsNil(cfg.Client) || cfg.MaxConcurrent < 0 || cfg.MaxTCPConnections < 0 || cfg.QueryTimeout < 0 || cfg.TCPIdleTimeout < 0 || cfg.ResponseWriteTimeout < 0 {
		return nil, ErrConfig
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:0"
	}
	// Require a literal loopback, without a DNS lookup as an entry side effect.
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil || net.ParseIP(host) == nil {
		return nil, ErrConfig
	}
	address, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil || address.IP == nil || !address.IP.IsLoopback() {
		return nil, ErrConfig
	}
	if cfg.MaxConcurrent == 0 {
		cfg.MaxConcurrent = 32
	}
	if cfg.MaxTCPConnections == 0 {
		cfg.MaxTCPConnections = 16
	}
	if cfg.MaxConcurrent > 128 || cfg.MaxTCPConnections > 64 {
		return nil, ErrConfig
	}
	if cfg.QueryTimeout == 0 {
		cfg.QueryTimeout = 3 * time.Second
	}
	if cfg.TCPIdleTimeout == 0 {
		cfg.TCPIdleTimeout = 5 * time.Second
	}
	if cfg.ResponseWriteTimeout == 0 {
		cfg.ResponseWriteTimeout = 100 * time.Millisecond
	}
	if cfg.ResponseWriteTimeout > time.Second || cfg.ResponseWriteTimeout > cfg.QueryTimeout {
		return nil, ErrConfig
	}
	if cfg.QueryTimeout > 30*time.Second || cfg.TCPIdleTimeout > time.Minute {
		return nil, ErrConfig
	}
	udp, tcp, err := listenPair(address, net.ListenTCP, net.ListenUDP)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{cfg: cfg, udp: udp, tcp: tcp, ctx: ctx, cancel: cancel, queries: make(chan struct{}, cfg.MaxConcurrent), connections: make(chan struct{}, cfg.MaxTCPConnections), active: make(map[net.Conn]struct{})}, nil
}

func (s *Server) Addr() net.Addr { return s.udp.LocalAddr() }

func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	if s.serving || s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.serving = true
	s.wg.Add(2)
	s.mu.Unlock()
	errorsOut := make(chan error, 2)
	go func() { defer s.wg.Done(); errorsOut <- s.serveUDP() }()
	go func() { defer s.wg.Done(); errorsOut <- s.serveTCP() }()
	defer s.Close()
	select {
	case <-ctx.Done():
		return nil
	case <-s.ctx.Done():
		return nil
	case err := <-errorsOut:
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

// Close joins all owned handlers. It closes the DNS entry only; the caller's
// Client and its mappings retain their independent Session lifetime.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.cancel()
		for conn := range s.active {
			conn.Close()
		}
		s.mu.Unlock()
		s.udp.Close()
		s.tcp.Close()
		s.wg.Wait()
	})
	return nil
}

func (s *Server) serveUDP() error {
	buffer := make([]byte, maxMessageBytes+1)
	for {
		n, peer, err := s.udp.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		if n > maxMessageBytes || n < 12 || !peer.IP.IsLoopback() {
			continue
		}
		select {
		case s.queries <- struct{}{}:
		default:
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			<-s.queries
			return net.ErrClosed
		}
		data := append([]byte(nil), buffer[:n]...)
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() { <-s.queries }()
			ctx, cancel := context.WithTimeout(s.ctx, s.cfg.QueryTimeout)
			defer cancel()
			response := s.answer(ctx, data)
			s.writeMu.Lock()
			defer s.writeMu.Unlock()
			until := responseDeadline(ctx, s.cfg.ResponseWriteTimeout)
			wire := s.packReply(ctx, response, until)
			if wire != nil && ctx.Err() == nil {
				_ = s.udp.SetWriteDeadline(until)
				_, _ = s.udp.WriteToUDP(wire, peer)
			}
		}()
	}
}

func (s *Server) serveTCP() error {
	for {
		conn, err := s.tcp.AcceptTCP()
		if err != nil {
			return err
		}
		select {
		case s.connections <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			<-s.connections
			conn.Close()
			return net.ErrClosed
		}
		s.active[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() {
				conn.Close()
				s.mu.Lock()
				delete(s.active, conn)
				s.mu.Unlock()
				<-s.connections
			}()
			s.handleTCP(conn)
		}()
	}
}

func (s *Server) handleTCP(conn net.Conn) {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.cfg.TCPIdleTimeout))
		var prefix [2]byte
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(prefix[:]))
		if size < 12 || size > maxMessageBytes {
			return
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(conn, data); err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(s.ctx, s.cfg.QueryTimeout)
		select {
		case s.queries <- struct{}{}:
		case <-ctx.Done():
			cancel()
			return
		}
		response := s.answer(ctx, data)
		<-s.queries
		if response == nil || ctx.Err() != nil {
			cancel()
			return
		}
		until := responseDeadline(ctx, s.cfg.ResponseWriteTimeout)
		wire := s.packReplyLimit(ctx, response, until, maxMessageBytes)
		if wire == nil {
			cancel()
			return
		}
		_ = conn.SetWriteDeadline(until)
		packet := binary.BigEndian.AppendUint16(nil, uint16(len(wire)))
		packet = append(packet, wire...)
		_, err := io.Copy(conn, bytes.NewReader(packet))
		cancel()
		if err != nil {
			return
		}
	}
}

type preparedReply struct {
	message  dnsmessage.Message
	owner    *session.Session
	lease    session.LocalAddressLease
	udpLimit int
}

func (s *Server) answer(ctx context.Context, data []byte) *preparedReply {
	// Preflight only DNS header counts before the maintained parser allocates
	// resource slices. Wire names, compression and resources are never parsed
	// manually. This frontend supports a canonical single-question request.
	if len(data) < 12 || len(data) > maxMessageBytes {
		return nil
	}
	if binary.BigEndian.Uint16(data[2:4])&0x8000 != 0 {
		return nil
	}
	var query dnsmessage.Message
	if binary.BigEndian.Uint16(data[4:6]) != 1 || binary.BigEndian.Uint16(data[6:8]) != 0 || binary.BigEndian.Uint16(data[8:10]) != 0 || binary.BigEndian.Uint16(data[10:12]) > 1 {
		return dnsHeaderError(data, dnsmessage.RCodeFormatError)
	}
	if err := query.Unpack(data); err != nil {
		return dnsHeaderError(data, dnsmessage.RCodeFormatError)
	}
	if query.Response {
		return nil
	} // Never answer DNS response packets.
	canonical, err := query.Pack()
	if err != nil || !bytes.Equal(canonical, data) || query.Truncated || query.Authoritative || query.RecursionAvailable || query.RCode != dnsmessage.RCodeSuccess {
		return dnsQueryError(query, dnsmessage.RCodeFormatError)
	}
	question := query.Questions[0]
	edns, code := parseEDNS(query)
	if code != dnsmessage.RCodeSuccess {
		return edns.queryError(query, code)
	}
	if query.OpCode != 0 || question.Type != dnsmessage.TypeA && question.Type != dnsmessage.TypeAAAA || question.Class != dnsmessage.ClassINET {
		return edns.queryError(query, dnsmessage.RCodeNotImplemented)
	}
	owner, err := s.cfg.Client.Connect(ctx)
	if err != nil || owner == nil {
		return edns.queryError(query, dnsmessage.RCodeServerFailure)
	}
	family := session.LocalAddressIPv4
	if question.Type == dnsmessage.TypeAAAA {
		family = session.LocalAddressIPv6
	}
	lease, err := owner.AllocateLocalAddressLeaseForFamily(ctx, question.Name.String(), family)
	if _, mapped := addressscope.MappingAddress(lease.Address); err != nil || !mapped {
		return edns.queryError(query, dnsmessage.RCodeServerFailure)
	}
	var body dnsmessage.ResourceBody
	if question.Type == dnsmessage.TypeAAAA {
		body = &dnsmessage.AAAAResource{AAAA: lease.Address.As16()}
	} else {
		body = &dnsmessage.AResource{A: lease.Address.As4()}
	}
	// AD in a query is a DNSSEC-related hint, not proof that these locally
	// synthesized records are validated. CD is echoed; AD/AA/RA remain false.
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionDesired: query.RecursionDesired, CheckingDisabled: query.CheckingDisabled}, Questions: query.Questions,
		Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET}, Body: body}}}
	return edns.attach(&preparedReply{message: response, owner: owner, lease: lease}, dnsmessage.RCodeSuccess)
}

func responseDeadline(ctx context.Context, budget time.Duration) time.Time {
	until := time.Now().Add(budget)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(until) {
		until = deadline
	}
	return until
}

// TTL is computed at dispatch from the real map/Session lease, reduced by the
// same bounded write window enforced on the socket. It never uses a fixed DNS
// cache TTL. Validation rejects an owner already known to be terminal and bounds
// the scheduled expiry. A Close racing validation and the subsequent socket
// write may still produce a late positive response; no dispatch gate makes those
// operations atomic. Non-reused addresses and Session's dial-use guard preserve
// fail-closed behavior when such a response reaches the local DNS consumer.
func (s *Server) packReply(ctx context.Context, reply *preparedReply, until time.Time) []byte {
	limit := defaultUDPPayload
	if reply != nil && reply.udpLimit != 0 {
		limit = reply.udpLimit
	}
	return s.packReplyLimit(ctx, reply, until, limit)
}

func (s *Server) packReplyLimit(ctx context.Context, reply *preparedReply, until time.Time, limit int) []byte {
	if reply == nil || ctx.Err() != nil || !until.After(time.Now()) {
		return nil
	}
	if reply.owner != nil {
		started := time.Now()
		remaining, err := reply.owner.ValidateLocalAddressLease(ctx, reply.lease)
		// Validation measures remaining inside the actor. Refer that duration
		// back to the earlier invocation time, so mailbox latency can only
		// shorten the advertised expiry, never extend it.
		cacheBudget := started.Add(remaining).Sub(until)
		if err != nil || cacheBudget < time.Second {
			failure := dnsQueryError(reply.message, dnsmessage.RCodeServerFailure)
			failure.message.Additionals = reply.message.Additionals
			failure.udpLimit = reply.udpLimit
			reply = failure
		} else {
			reply.message.Answers[0].Header.TTL = uint32(cacheBudget / time.Second)
		}
	}
	wire, err := reply.message.Pack()
	if err != nil || limit < defaultUDPPayload || limit > maxMessageBytes || ctx.Err() != nil {
		return nil
	}
	if len(wire) > limit {
		// Retain the question and empty OPT, but never send a partial RR. TCP
		// uses its separate bounded message limit rather than the UDP offer.
		truncated := reply.message
		truncated.Truncated = true
		truncated.Answers = nil
		truncated.Authorities = nil
		wire, err = truncated.Pack()
		if err != nil || len(wire) > limit {
			return nil
		}
	}
	return wire
}

func dnsError(id uint16, code dnsmessage.RCode, questions []dnsmessage.Question) *preparedReply {
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: id, Response: true, RCode: code}, Questions: questions}
	return &preparedReply{message: response}
}

func dnsQueryError(query dnsmessage.Message, code dnsmessage.RCode) *preparedReply {
	reply := dnsError(query.ID, code, query.Questions)
	reply.message.RecursionDesired = query.RecursionDesired
	reply.message.CheckingDisabled = query.CheckingDisabled
	reply.message.OpCode = query.OpCode
	return reply
}

// Parser Start reads only the maintained parser's DNS header. Even malformed
// questions/counts can preserve CD/RD in an error without hand-parsing flags.
func dnsHeaderError(data []byte, code dnsmessage.RCode) *preparedReply {
	var parser dnsmessage.Parser
	header, err := parser.Start(data)
	if err != nil {
		return nil
	}
	return dnsQueryError(dnsmessage.Message{Header: header}, code)
}
