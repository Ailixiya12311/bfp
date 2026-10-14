// Package socks provides a bounded SOCKS5 entry point on the local device.
package socks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"bfp/protocol"
)

type Backend interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// TargetRestorer is an adapter-local reverse mapping boundary.  An upstream
// fake-IP allocator (for example, a selected Mihomo/sing-box integration) can
// implement this interface to turn a session-owned numeric address back into
// its hostname before the backend receives it.  The restorer must not perform
// an OS dial, and a mapping that is absent from the live session must return an
// error.  BFP does not provide the allocator or configure a TUN/DNS service.
type TargetRestorer interface {
	RestoreTarget(protocol.Target) (protocol.Target, error)
}

// SessionTargetRestoringBackend selects the actual Session and restores its
// target within the same dial admission. A separate adapter restorer would
// split that operation across scopes when the backend replaces its Session.
type SessionTargetRestoringBackend interface {
	RestoresSessionTargets() bool
}

type Config struct {
	Listen           string
	Backend          Backend
	TargetRestorer   TargetRestorer
	MaxConnections   int
	HandshakeTimeout time.Duration
	MaxUDPControls   int
	MaxUDPTargets    int
	DomainSource     DomainSource
}

type Server struct {
	cfg       Config
	metadata  MetadataBackend
	listener  net.Listener
	ctx       context.Context
	cancel    context.CancelFunc
	connSlots chan struct{}
	udpSlots  chan struct{}
	mu        sync.Mutex
	resources map[net.Conn]struct{}
	closed    bool
	serving   bool
	wg        sync.WaitGroup
}

func New(cfg Config) (*Server, error) {
	if cfg.Backend == nil {
		return nil, errors.New("socks: backend is required")
	}
	if owner, ok := cfg.Backend.(SessionTargetRestoringBackend); ok && owner.RestoresSessionTargets() && cfg.TargetRestorer != nil {
		return nil, ErrTargetRestorerConflict
	}
	if cfg.MaxConnections < 0 || cfg.MaxUDPControls < 0 || cfg.MaxUDPTargets < 0 || cfg.HandshakeTimeout < 0 {
		return nil, errors.New("socks: negative limit or timeout")
	}
	metadata, err := configureDomainSource(&cfg)
	if err != nil {
		return nil, err
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:0"
	}
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("socks: invalid listen address: %w", err)
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("socks: unauthenticated listener must use a numeric loopback address")
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 128
	}
	if cfg.MaxUDPControls == 0 {
		cfg.MaxUDPControls = 32
	}
	if cfg.MaxUDPTargets == 0 {
		cfg.MaxUDPTargets = 64
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 5 * time.Second
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{cfg: cfg, metadata: metadata, listener: ln, ctx: ctx, cancel: cancel, connSlots: make(chan struct{}, cfg.MaxConnections), udpSlots: make(chan struct{}, cfg.MaxUDPControls), resources: make(map[net.Conn]struct{})}, nil
}

func (s *Server) Addr() net.Addr { return s.listener.Addr() }

func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	if s.serving {
		s.mu.Unlock()
		return errors.New("socks: Serve already called")
	}
	s.serving = true
	s.mu.Unlock()
	watchDone := make(chan struct{})
	defer close(watchDone)
	defer s.wg.Wait()
	defer s.Close()
	go func() {
		select {
		case <-ctx.Done():
			s.Close()
		case <-s.ctx.Done():
		case <-watchDone:
		}
	}()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.ctx.Err() != nil || ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case s.connSlots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		if !s.track(conn) {
			<-s.connSlots
			conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.connSlots }()
			defer s.release(conn)
			s.handle(conn)
		}()
	}
}

// Close cancels pending backend dials and closes controls, relays and targets.
// Serve waits for its handlers to finish after cancellation.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.cancel()
	resources := make([]net.Conn, 0, len(s.resources))
	for conn := range s.resources {
		resources = append(resources, conn)
	}
	s.mu.Unlock()
	err := s.listener.Close()
	for _, conn := range resources {
		conn.Close()
	}
	return err
}

func (s *Server) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.resources[conn] = struct{}{}
	return true
}

func (s *Server) release(conn net.Conn) {
	conn.Close()
	s.mu.Lock()
	delete(s.resources, conn)
	s.mu.Unlock()
}

func (s *Server) handle(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting[0] != 5 || greeting[1] == 0 {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	noAuth := false
	for _, method := range methods {
		noAuth = noAuth || method == 0
	}
	if !noAuth {
		writeAll(conn, []byte{5, 255})
		return
	}
	if err := writeAll(conn, []byte{5, 0}); err != nil {
		return
	}
	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil || request[0] != 5 || request[2] != 0 {
		return
	}
	address, _, err := readAddress(conn, request[3])
	if err != nil {
		s.reply(conn, 8, nil)
		return
	}
	switch request[1] {
	case 1:
		dialCtx, cancel := context.WithTimeout(s.ctx, s.cfg.HandshakeTimeout)
		upstream, err := s.dialTarget(dialCtx, "tcp", address, request[3])
		cancel()
		if err != nil {
			s.reply(conn, 1, nil)
			return
		}
		if !s.track(upstream) {
			upstream.Close()
			return
		}
		defer s.release(upstream)
		if err := s.reply(conn, 0, upstream.LocalAddr()); err != nil {
			return
		}
		conn.SetDeadline(time.Time{})
		relay(conn, upstream)
	case 3:
		select {
		case s.udpSlots <- struct{}{}:
			defer func() { <-s.udpSlots }()
		default:
			s.reply(conn, 2, nil)
			return
		}
		s.serveUDP(conn)
	default:
		s.reply(conn, 7, nil)
	}
}

func (s *Server) reply(conn net.Conn, code byte, bound net.Addr) error {
	address := "127.0.0.1:0"
	if bound != nil {
		if _, _, err := net.SplitHostPort(bound.String()); err == nil {
			address = bound.String()
		}
	}
	encoded, err := encodeAddress(address)
	if err != nil {
		encoded, _ = encodeAddress("127.0.0.1:0")
	}
	return writeAll(conn, append([]byte{5, code, 0}, encoded...))
}

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copyDirection := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err == nil {
			if half, ok := dst.(interface{ CloseWrite() error }); ok {
				if err := half.CloseWrite(); err != nil {
					a.Close()
					b.Close()
				}
			}
		} else {
			a.Close()
			b.Close()
		}
		done <- struct{}{}
	}
	go copyDirection(a, b)
	go copyDirection(b, a)
	<-done
	<-done
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func readAddress(r io.Reader, atyp byte) (string, []byte, error) {
	encoded := []byte{atyp}
	var host string
	switch atyp {
	case 1, 4:
		length := 4
		if atyp == 4 {
			length = 16
		}
		ip := make([]byte, length)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", nil, err
		}
		host = net.IP(ip).String()
		encoded = append(encoded, ip...)
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil || length[0] == 0 {
			return "", nil, errors.New("socks: empty or incomplete domain")
		}
		domain := make([]byte, int(length[0]))
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", nil, err
		}
		host = string(domain)
		encoded = append(append(encoded, length[0]), domain...)
	default:
		return "", nil, errors.New("socks: unsupported address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", nil, err
	}
	encoded = append(encoded, port[:]...)
	return net.JoinHostPort(host, strconv.Itoa(int(port[0])<<8|int(port[1]))), encoded, nil
}

func encodeAddress(address string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return nil, errors.New("socks: invalid port")
	}
	var out []byte
	ip := net.ParseIP(host)
	if v4 := ip.To4(); v4 != nil {
		out = append([]byte{1}, v4...)
	} else if ip != nil {
		out = append([]byte{4}, ip.To16()...)
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("socks: invalid domain length")
		}
		out = append([]byte{3, byte(len(host))}, []byte(host)...)
	}
	return append(out, byte(port>>8), byte(port)), nil
}
