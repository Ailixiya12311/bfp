package socks

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type trackingBackend struct {
	active    atomic.Int32
	dials     atomic.Int32
	mu        sync.Mutex
	addresses []string
}
type trackingConn struct {
	net.Conn
	backend *trackingBackend
	once    sync.Once
}

func (b *trackingBackend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	b.dials.Add(1)
	b.active.Add(1)
	b.mu.Lock()
	b.addresses = append(b.addresses, address)
	b.mu.Unlock()
	return &trackingConn{Conn: c, backend: b}, nil
}
func (c *trackingConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.backend.active.Add(-1) })
	return err
}
func (c *trackingConn) CloseWrite() error {
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
}

func startServer(t *testing.T, cfg Config) (*Server, chan error) {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background()) }()
	t.Cleanup(func() {
		s.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("server failed to stop")
		}
	})
	return s, done
}

func connectSOCKS(t *testing.T, s *Server, command byte, address string) (net.Conn, byte, string) {
	t.Helper()
	c, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(c, method[:]); err != nil || method != [2]byte{5, 0} {
		t.Fatalf("greeting %v %v", method, err)
	}
	encoded, err := encodeAddress(address)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(append([]byte{5, command, 0}, encoded...)); err != nil {
		t.Fatal(err)
	}
	var response [4]byte
	if _, err := io.ReadFull(c, response[:]); err != nil {
		t.Fatal(err)
	}
	bound, _, err := readAddress(c, response[3])
	if err != nil {
		t.Fatal(err)
	}
	return c, response[1], bound
}

func TestNewRestrictsListenerAndConfig(t *testing.T) {
	b := &trackingBackend{}
	for _, cfg := range []Config{{Backend: b, Listen: "0.0.0.0:0"}, {Backend: b, Listen: "192.0.2.1:0"}, {Backend: b, MaxConnections: -1}, {Listen: "127.0.0.1:0"}} {
		if s, err := New(cfg); err == nil {
			s.Close()
			t.Fatalf("accepted unsafe config %+v", cfg)
		}
	}
}

func TestConnectPreservesHalfCloseAndDomain(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		data, _ := io.ReadAll(c)
		c.Write(bytes.ToUpper(data))
	}()
	b := &trackingBackend{}
	s, _ := startServer(t, Config{Backend: b})
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	c, code, _ := connectSOCKS(t, s, 1, net.JoinHostPort("localhost", port))
	defer c.Close()
	if code != 0 {
		t.Fatalf("CONNECT failed: %d", code)
	}
	c.Write([]byte("half close response"))
	c.(*net.TCPConn).CloseWrite()
	response, err := io.ReadAll(c)
	if err != nil || string(response) != "HALF CLOSE RESPONSE" {
		t.Fatalf("half-close reply %q: %v", response, err)
	}
	b.mu.Lock()
	requested := b.addresses[0]
	b.mu.Unlock()
	if !strings.HasPrefix(requested, "localhost:") {
		t.Fatalf("domain metadata lost: %s", requested)
	}
	waitFor(t, func() bool { return b.active.Load() == 0 })
}

func udpEcho(t *testing.T) (*net.UDPConn, *atomic.Int32) {
	t.Helper()
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	count := &atomic.Int32{}
	t.Cleanup(func() { u.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, peer, err := u.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			count.Add(1)
			u.WriteToUDP(buffer[:n], peer)
		}
	}()
	return u, count
}

func TestUDPAssociateBoundariesSourceAndCleanup(t *testing.T) {
	upstream, count := udpEcho(t)
	b := &trackingBackend{}
	s, _ := startServer(t, Config{Backend: b})
	control, code, bound := connectSOCKS(t, s, 3, "0.0.0.0:0")
	defer control.Close()
	if code != 0 {
		t.Fatalf("UDP ASSOCIATE failed: %d", code)
	}
	relayAddr, err := net.ResolveUDPAddr("udp", bound)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	target, _ := encodeAddress(upstream.LocalAddr().String())
	for _, payload := range [][]byte{[]byte("one"), {}, bytes.Repeat([]byte("x"), 16000)} {
		packet := append(append([]byte{0, 0, 0}, target...), payload...)
		if _, err := client.WriteToUDP(packet, relayAddr); err != nil {
			t.Fatal(err)
		}
		client.SetReadDeadline(time.Now().Add(time.Second))
		buffer := make([]byte, 65535)
		n, _, err := client.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		r := bytes.NewReader(buffer[4:n])
		address, _, err := readAddress(r, buffer[3])
		if err != nil {
			t.Fatal(err)
		}
		if address != upstream.LocalAddr().String() || !bytes.Equal(buffer[n-r.Len():n], payload) {
			t.Fatalf("datagram boundary failed: %s len=%d", address, r.Len())
		}
	}
	if b.dials.Load() != 1 {
		t.Fatalf("target cache did not reuse association: %d", b.dials.Load())
	}
	// Unsupported SOCKS fragmentation and a different UDP source port cannot use
	// the control after the valid first packet fixed its source endpoint.
	fragment := append(append([]byte{0, 0, 1}, target...), []byte("fragment")...)
	client.WriteToUDP(fragment, relayAddr)
	other, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.WriteToUDP(append(append([]byte{0, 0, 0}, target...), []byte("wrong source")...), relayAddr)
	time.Sleep(80 * time.Millisecond)
	if count.Load() != 3 {
		t.Fatalf("invalid fragment/source reached target: %d", count.Load())
	}
	control.Close()
	waitFor(t, func() bool { return b.active.Load() == 0 })
}

func TestUDPControlAndTargetLimits(t *testing.T) {
	first, _ := udpEcho(t)
	second, _ := udpEcho(t)
	b := &trackingBackend{}
	s, _ := startServer(t, Config{Backend: b, MaxUDPControls: 1, MaxUDPTargets: 1})
	control, code, bound := connectSOCKS(t, s, 3, "0.0.0.0:0")
	defer control.Close()
	if code != 0 {
		t.Fatal(code)
	}
	extra, code, _ := connectSOCKS(t, s, 3, "0.0.0.0:0")
	extra.Close()
	if code == 0 {
		t.Fatal("exceeded UDP control limit")
	}
	address, _ := net.ResolveUDPAddr("udp", bound)
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, target := range []string{first.LocalAddr().String(), second.LocalAddr().String()} {
		encoded, _ := encodeAddress(target)
		client.WriteToUDP(append(append([]byte{0, 0, 0}, encoded...), 1), address)
		time.Sleep(40 * time.Millisecond)
	}
	if b.dials.Load() != 1 || b.active.Load() != 1 {
		t.Fatalf("target limit not enforced: dials=%d active=%d", b.dials.Load(), b.active.Load())
	}
}

func TestHandshakeTimeoutAndServerCancelCleanup(t *testing.T) {
	b := &trackingBackend{}
	s, _ := startServer(t, Config{Backend: b, HandshakeTimeout: 40 * time.Millisecond})
	c, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	c.Write([]byte{5})
	buffer := make([]byte, 1)
	if _, err := c.Read(buffer); err == nil {
		t.Fatal("slow handshake was not closed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	second, err := New(Config{Backend: b})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- second.Serve(ctx) }()
	control, code, _ := connectSOCKS(t, second, 3, "0.0.0.0:0")
	defer control.Close()
	if code != 0 {
		t.Fatal(code)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not close active control")
	}
}

func TestConnectionLimitRejectsExcessBeforeHandshake(t *testing.T) {
	s, _ := startServer(t, Config{Backend: &trackingBackend{}, MaxConnections: 1, HandshakeTimeout: time.Second})
	first, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	first.SetDeadline(time.Now().Add(time.Second))
	first.Write([]byte{5, 1, 0})
	var method [2]byte
	if _, err := io.ReadFull(first, method[:]); err != nil {
		t.Fatal(err)
	}
	second, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := second.Read(method[:]); err == nil {
		t.Fatal("excess connection received a handshake response")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("excess connection was left waiting instead of rejected")
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("cleanup condition not met")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
