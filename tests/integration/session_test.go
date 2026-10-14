package integration_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bfp/gateway"
	"bfp/protocol"
	"bfp/security"
	"bfp/session"
)

type fixture struct {
	server      *session.Server
	credentials session.Credentials
	options     session.Options
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	serverKey, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	admission := make([]byte, 32)
	if _, err := rand.Read(admission); err != nil {
		t.Fatal(err)
	}
	backend, err := gateway.New(gateway.Policy{AllowPrivate: true, AllowedCIDRs: []string{"127.0.0.0/8"}, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	options := session.Options{HandshakeTimeout: 500 * time.Millisecond, ProbeInterval: 100 * time.Millisecond, FailureTimeout: 600 * time.Millisecond, RetainTimeout: 5 * time.Second}
	server, err := session.NewServer(session.ServerConfig{Listen: "127.0.0.1:0", Backend: backend, Options: options, MaxSessions: 4, Credentials: session.Credentials{Admission: admission, Private: serverKey.Private, Public: serverKey.Public, AllowedClients: [][]byte{clientKey.Public}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		server.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("session server did not stop")
		}
	})
	return fixture{server: server, options: options, credentials: session.Credentials{Admission: admission, Private: clientKey.Private, Public: clientKey.Public, ServerPublic: serverKey.Public}}
}

func (f fixture) client(t *testing.T, udpAddress string) (*session.Client, *session.Session) {
	t.Helper()
	if udpAddress == "" {
		udpAddress = f.server.Addr().String()
	}
	client, err := session.NewClient(session.ClientConfig{Server: udpAddress, TCPServer: f.server.Addr().String(), Credentials: f.credentials, Options: f.options})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	connected, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return client, connected
}

func tcpTarget(t *testing.T, afterEOF bool) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	connections := map[net.Conn]struct{}{}
	var wg sync.WaitGroup
	count := &atomic.Int32{}
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		for c := range connections {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			mu.Lock()
			connections[conn] = struct{}{}
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { conn.Close(); mu.Lock(); delete(connections, conn); mu.Unlock() }()
				conn.SetDeadline(time.Now().Add(12 * time.Second))
				if afterEOF {
					data, err := io.ReadAll(conn)
					if err == nil {
						conn.Write(bytes.ToUpper(data))
					}
				} else {
					io.Copy(conn, conn)
				}
			}()
		}
	}()
	return ln.Addr().String(), count
}

func udpTarget(t *testing.T) string {
	t.Helper()
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 65535)
		for {
			n, peer, err := u.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			u.WriteToUDP(buffer[:n], peer)
		}
	}()
	t.Cleanup(func() { u.Close(); <-done })
	return u.LocalAddr().String()
}

func dial(t *testing.T, client *session.Client, network, address string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := client.DialContext(ctx, network, address)
	if err != nil {
		var stats session.Stats
		if current := client.Session(); current != nil {
			stats = current.Stats()
		}
		t.Fatalf("dial %s %s: %v; client stats=%+v", network, address, err, stats)
	}
	c.SetDeadline(time.Now().Add(8 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}

func assertExchange(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(c, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("reliable byte stream changed")
	}
}

func TestSessionMultiplexesTCPUDPAndClasses(t *testing.T) {
	tcpAddress, count := tcpTarget(t, false)
	udpAddress := udpTarget(t)
	f := newFixture(t)
	client, s := f.client(t, "")
	initial := s.Stats()
	if initial.Carrier != "udp" {
		t.Fatalf("default carrier=%q", initial.Carrier)
	}
	first := dial(t, client, "tcp", tcpAddress)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	second, err := s.DialClass(ctx, protocol.Target{Network: "tcp", Address: tcpAddress, Class: protocol.Interactive})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetDeadline(time.Now().Add(4 * time.Second))
	assertExchange(t, first, []byte("first independent stream"))
	assertExchange(t, second, []byte("second interactive stream"))
	udp := dial(t, client, "udp", udpAddress)
	for _, payload := range [][]byte{[]byte("short message"), bytes.Repeat([]byte("fragmented"), 1600)} {
		if _, err := udp.Write(payload); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, 16384)
		n, err := udp.Read(response)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(response[:n], payload) {
			t.Fatalf("UDP message boundary changed: got=%d want=%d", n, len(payload))
		}
	}
	final := s.Stats()
	if final.ID != initial.ID || final.Generation != initial.Generation || final.Opened != 3 || count.Load() != 2 {
		t.Fatalf("multiplexing created new session/exit: %+v exits=%d", final, count.Load())
	}
	if client.Session() != s {
		t.Fatal("Client.Session returned another session")
	}
}

func TestSessionHalfCloseKeepsResponseDirection(t *testing.T) {
	target, _ := tcpTarget(t, true)
	f := newFixture(t)
	client, _ := f.client(t, "")
	c := dial(t, client, "tcp", target)
	if _, err := c.Write([]byte("request after eof")); err != nil {
		t.Fatal(err)
	}
	half, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("session flow lacks CloseWrite")
	}
	if err := half.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "REQUEST AFTER EOF" {
		t.Fatalf("response lost after half-close: %q", response)
	}
}

func TestInitialUDPBlackholeFallsBackToTCP(t *testing.T) {
	target, count := tcpTarget(t, false)
	f := newFixture(t)
	blackhole, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	client, s := f.client(t, blackhole.LocalAddr().String())
	if stats := s.Stats(); stats.Carrier != "tcp" {
		t.Fatalf("UDP failure did not select TCP: %+v", stats)
	}
	assertExchange(t, dial(t, client, "tcp", target), []byte("TCP fallback after UDP timeout"))
	if count.Load() != 1 {
		t.Fatalf("unexpected target dial count=%d", count.Load())
	}
}

type udpRelay struct {
	local    *net.UDPConn
	upstream *net.UDPConn
	drop     atomic.Bool
	mu       sync.Mutex
	peer     *net.UDPAddr
	wg       sync.WaitGroup
}

func newRelay(t *testing.T, server string) *udpRelay {
	t.Helper()
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	destination, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		local.Close()
		t.Fatal(err)
	}
	upstream, err := net.DialUDP("udp", nil, destination)
	if err != nil {
		local.Close()
		t.Fatal(err)
	}
	r := &udpRelay{local: local, upstream: upstream}
	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		b := make([]byte, 65535)
		for {
			n, peer, err := local.ReadFromUDP(b)
			if err != nil {
				return
			}
			r.mu.Lock()
			if r.peer == nil {
				r.peer = peer
			}
			same := r.peer.String() == peer.String()
			r.mu.Unlock()
			if same && !r.drop.Load() {
				upstream.Write(b[:n])
			}
		}
	}()
	go func() {
		defer r.wg.Done()
		b := make([]byte, 65535)
		for {
			n, err := upstream.Read(b)
			if err != nil {
				return
			}
			r.mu.Lock()
			peer := r.peer
			r.mu.Unlock()
			if peer != nil && !r.drop.Load() {
				local.WriteToUDP(b[:n], peer)
			}
		}
	}()
	t.Cleanup(func() { local.Close(); upstream.Close(); r.wg.Wait() })
	return r
}

func TestRunningUDPBlackholeRecoversSameExitAndBytes(t *testing.T) {
	target, count := tcpTarget(t, false)
	f := newFixture(t)
	relay := newRelay(t, f.server.Addr().String())
	client, s := f.client(t, relay.local.LocalAddr().String())
	c := dial(t, client, "tcp", target)
	assertExchange(t, c, []byte("before blackhole"))
	initial := s.Stats()
	payload := make([]byte, 384*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	relay.drop.Store(true)
	result := make(chan error, 1)
	go func() { _, err := io.Copy(c, bytes.NewReader(payload)); result <- err }()
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(c, response); err != nil {
		t.Fatalf("transfer did not resume: %v stats=%+v", err, s.Stats())
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(response) != sha256.Sum256(payload) {
		t.Fatal("resumed reliable stream hash differs")
	}
	final := s.Stats()
	if final.Carrier != "tcp" || final.ID != initial.ID || final.ClientAddress != initial.ClientAddress || final.ServerAddress != initial.ServerAddress || final.Generation <= initial.Generation || final.Switches < 1 {
		t.Fatalf("session identity not preserved on switch: before=%+v after=%+v", initial, final)
	}
	if count.Load() != 1 {
		t.Fatalf("switch recreated target socket: accepted=%d", count.Load())
	}
	assertExchange(t, c, []byte("same stream after switch"))
	var found bool
	for _, stats := range f.server.Snapshot() {
		if stats.ID == final.ID {
			found = true
			if stats.Carrier != "tcp" {
				t.Fatalf("server retained wrong carrier: %+v", stats)
			}
		}
	}
	if !found {
		t.Fatal("server lost resumed session")
	}
}

func TestUnauthenticatedUDPAndTCPProbesAreSilent(t *testing.T) {
	f := newFixture(t)
	address, err := net.ResolveUDPAddr("udp", f.server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	u, err := net.DialUDP("udp", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	probe := make([]byte, 1200)
	rand.Read(probe)
	if _, err := u.Write(probe); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	if n, err := u.Read(buffer); err == nil {
		t.Fatalf("invalid UDP probe received %d-byte response", n)
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("UDP probe did not time out silently: %v", err)
	}
	c, err := net.Dial("tcp", f.server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write(probe); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Read(buffer); n > 0 || err == nil {
		t.Fatalf("invalid TCP probe received application response: bytes=%d err=%v", n, err)
	}
	if snapshot := f.server.Snapshot(); len(snapshot) != 0 {
		t.Fatalf("invalid probe created sessions: %+v", snapshot)
	}
}
