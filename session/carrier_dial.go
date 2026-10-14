package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"time"
)

// TCPPhysicalDialFunc dials the BFP server's stream socket. network is always
// "tcp"; address is TCPServer when supplied, otherwise Server. The result must
// be an exclusively owned stream net.Conn with deadlines and Close that wake
// blocked I/O. Packet sockets and non-TCP remote addresses are rejected.
//
// A successful result transfers socket ownership to BFP. Hooks must not bind
// the returned socket's lifetime to ctx after returning. They should honor ctx;
// a result arriving after cancellation is closed rather than installed.
type TCPPhysicalDialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// UDPPhysicalDialFunc dials the BFP server's datagram socket. network is always
// "udp"; address is Server. It returns an exclusively owned net.PacketConn and
// a concrete peer IP/port. A PacketConn preserves message boundaries; arbitrary
// stream net.Conn values cannot satisfy this hook. Both unconnected sockets
// and connected packet sockets bound to exactly peer are supported.
//
// BFP wraps the socket as a connected datagram net.Conn, filters other senders,
// and copies peer to make its binding immutable. The socket must support
// deadlines and Close that wake blocked I/O. Ownership/cancellation rules are
// the same as TCPPhysicalDialFunc. DNS resolution and routing belong to the
// hook; a hostname must be resolved before choosing the concrete peer.
type UDPPhysicalDialFunc func(ctx context.Context, network, address string) (socket net.PacketConn, peer *net.UDPAddr, err error)

// ErrCarrierDialContract identifies an invalid physical carrier hook result or
// unsupported carrier network. It is a configuration error, so initial Connect
// does not hide it by silently falling back to another carrier.
var ErrCarrierDialContract = errors.New("session: invalid physical carrier dial contract")

// ErrCarrierDialBusy means a previous canceled hook is still running. Each
// Client permits at most one outstanding callback per carrier kind so repeated
// recovery attempts cannot accumulate workers when a hook ignores ctx.
var ErrCarrierDialBusy = errors.New("session: physical carrier dial hook still running")

type carrierDialState struct {
	tcp, udp chan struct{}
}

func newCarrierDialState() *carrierDialState {
	return &carrierDialState{tcp: make(chan struct{}, 1), udp: make(chan struct{}, 1)}
}

type physicalDialResult struct {
	conn net.Conn
	err  error
}

func dialPhysicalCarrier(ctx context.Context, cfg ClientConfig, kind, address string) (net.Conn, error) {
	if kind != "tcp" && kind != "udp" {
		return nil, fmt.Errorf("%w: unsupported network %q", ErrCarrierDialContract, kind)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if kind == "tcp" && cfg.DialTCP == nil || kind == "udp" && cfg.DialUDP == nil {
		return (&net.Dialer{Timeout: cfg.Options.HandshakeTimeout}).DialContext(ctx, kind, address)
	}
	dialCtx, cancel := context.WithTimeout(ctx, cfg.Options.defaults().HandshakeTimeout)
	defer cancel()
	state := cfg.carrierDials
	if state == nil {
		state = newCarrierDialState() // Direct internal establish callers.
	}
	gate := state.tcp
	if kind == "udp" {
		gate = state.udp
	}
	select {
	case gate <- struct{}{}:
	default:
		return nil, ErrCarrierDialBusy
	}
	results := make(chan physicalDialResult)
	dialTCP, dialUDP := cfg.DialTCP, cfg.DialUDP
	go func() {
		defer func() { <-gate }()
		var conn net.Conn
		var err error
		if kind == "tcp" {
			conn, err = dialTCP(dialCtx, kind, address)
			if !nilSocket(conn) && err == nil {
				if _, packet := conn.(net.PacketConn); packet || !tcpRemote(conn.RemoteAddr()) {
					err = fmt.Errorf("%w: TCP hook returned a non-TCP stream socket", ErrCarrierDialContract)
				}
			}
		} else {
			var socket net.PacketConn
			var peer *net.UDPAddr
			socket, peer, err = dialUDP(dialCtx, kind, address)
			if !nilSocket(socket) {
				if err == nil {
					conn, err = wrapDatagramSocket(socket, peer)
				}
				if err != nil {
					_ = socket.Close()
				}
			}
		}
		if nilSocket(conn) {
			conn = nil
			if err == nil {
				err = fmt.Errorf("%w: hook returned no socket", ErrCarrierDialContract)
			}
		}
		if err == nil {
			if deadlineErr := conn.SetDeadline(time.Time{}); deadlineErr != nil {
				err = fmt.Errorf("%w: hook socket cannot set deadlines: %v", ErrCarrierDialContract, deadlineErr)
			}
		}
		if err != nil && conn != nil {
			_ = conn.Close()
			conn = nil
		}
		select {
		case results <- physicalDialResult{conn: conn, err: err}:
		case <-dialCtx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
	select {
	case result := <-results:
		if err := dialCtx.Err(); err != nil {
			if result.conn != nil {
				_ = result.conn.Close()
			}
			return nil, err
		}
		return result.conn, result.err
	case <-dialCtx.Done():
		return nil, dialCtx.Err()
	}
}

func nilSocket(socket any) bool {
	if socket == nil {
		return true
	}
	value := reflect.ValueOf(socket)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func tcpRemote(address net.Addr) bool {
	if nilSocket(address) {
		return false
	}
	switch address.Network() {
	case "tcp", "tcp4", "tcp6":
		return true
	default:
		return false
	}
}

type pinnedDatagramConn struct {
	socket    net.PacketConn
	peer      *net.UDPAddr
	connected net.Conn
}

func wrapDatagramSocket(socket net.PacketConn, peer *net.UDPAddr) (net.Conn, error) {
	if peer == nil || peer.IP.To16() == nil || peer.IP.IsUnspecified() || peer.IP.IsMulticast() || peer.Port <= 0 || peer.Port > 65535 {
		return nil, fmt.Errorf("%w: UDP hook requires a concrete unicast peer", ErrCarrierDialContract)
	}
	copyPeer := &net.UDPAddr{IP: append(net.IP(nil), peer.IP...), Port: peer.Port, Zone: peer.Zone}
	conn := &pinnedDatagramConn{socket: socket, peer: copyPeer}
	if connected, ok := socket.(net.Conn); ok && connected.RemoteAddr() != nil {
		if !sameUDPPeer(connected.RemoteAddr(), copyPeer) {
			return nil, fmt.Errorf("%w: connected UDP socket has a different peer", ErrCarrierDialContract)
		}
		conn.connected = connected
	}
	return conn, nil
}

func sameUDPPeer(address net.Addr, peer *net.UDPAddr) bool {
	actual, ok := address.(*net.UDPAddr)
	return ok && actual != nil && actual.Port == peer.Port && actual.Zone == peer.Zone && actual.IP.Equal(peer.IP)
}

func (c *pinnedDatagramConn) Read(buffer []byte) (int, error) {
	for {
		n, from, err := c.socket.ReadFrom(buffer)
		if err != nil {
			return n, err
		}
		if sameUDPPeer(from, c.peer) {
			return n, nil
		}
	}
}
func (c *pinnedDatagramConn) Write(buffer []byte) (int, error) {
	if c.connected != nil {
		return c.connected.Write(buffer)
	}
	return c.socket.WriteTo(buffer, c.peer)
}
func (c *pinnedDatagramConn) Close() error        { return c.socket.Close() }
func (c *pinnedDatagramConn) LocalAddr() net.Addr { return c.socket.LocalAddr() }
func (c *pinnedDatagramConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: append(net.IP(nil), c.peer.IP...), Port: c.peer.Port, Zone: c.peer.Zone}
}
func (c *pinnedDatagramConn) SetDeadline(t time.Time) error      { return c.socket.SetDeadline(t) }
func (c *pinnedDatagramConn) SetReadDeadline(t time.Time) error  { return c.socket.SetReadDeadline(t) }
func (c *pinnedDatagramConn) SetWriteDeadline(t time.Time) error { return c.socket.SetWriteDeadline(t) }
