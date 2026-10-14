package session

import (
	"bfp/classification"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type carrierHookPacketSpy struct {
	net.PacketConn
	reads, writes, closes atomic.Int32
}

func (c *carrierHookPacketSpy) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n, from, err := c.PacketConn.ReadFrom(buffer)
	if err == nil {
		c.reads.Add(1)
	}
	return n, from, err
}
func (c *carrierHookPacketSpy) WriteTo(buffer []byte, to net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(buffer, to)
	if err == nil {
		c.writes.Add(1)
	}
	return n, err
}
func (c *carrierHookPacketSpy) Close() error {
	c.closes.Add(1)
	return c.PacketConn.Close()
}

type carrierHookStreamSpy struct {
	net.Conn
	reads, writes, closes atomic.Int32
}

func (c *carrierHookStreamSpy) Read(buffer []byte) (int, error) {
	n, err := c.Conn.Read(buffer)
	if n > 0 {
		c.reads.Add(1)
	}
	return n, err
}
func (c *carrierHookStreamSpy) Write(buffer []byte) (int, error) {
	n, err := c.Conn.Write(buffer)
	if n > 0 {
		c.writes.Add(1)
	}
	return n, err
}
func (c *carrierHookStreamSpy) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

type carrierHookObservation struct {
	mu        sync.Mutex
	udp       []*carrierHookPacketSpy
	tcp       []*carrierHookStreamSpy
	networks  []string
	addresses []string
}

func (o *carrierHookObservation) configure(t *testing.T, cfg *ClientConfig) {
	t.Helper()
	udpAddress, tcpAddress := cfg.Server, cfg.TCPServer
	// These names have no listeners. Successful handshakes therefore prove
	// the configured hooks supplied the actual physical sockets.
	cfg.Server = "udp-hook.invalid:443"
	cfg.TCPServer = "tcp-hook.invalid:443"
	cfg.DialUDP = func(ctx context.Context, network, address string) (net.PacketConn, *net.UDPAddr, error) {
		peer, err := net.ResolveUDPAddr("udp", udpAddress)
		if err != nil {
			return nil, nil, err
		}
		socket, err := (&net.ListenConfig{}).ListenPacket(ctx, network, "127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}
		spy := &carrierHookPacketSpy{PacketConn: socket}
		o.mu.Lock()
		o.udp = append(o.udp, spy)
		o.networks = append(o.networks, network)
		o.addresses = append(o.addresses, address)
		o.mu.Unlock()
		return spy, peer, nil
	}
	cfg.DialTCP = func(ctx context.Context, network, address string) (net.Conn, error) {
		socket, err := (&net.Dialer{}).DialContext(ctx, network, tcpAddress)
		if err != nil {
			return nil, err
		}
		spy := &carrierHookStreamSpy{Conn: socket}
		o.mu.Lock()
		o.tcp = append(o.tcp, spy)
		o.networks = append(o.networks, network)
		o.addresses = append(o.addresses, address)
		o.mu.Unlock()
		return spy, nil
	}
}

func (o *carrierHookObservation) assertCalls(t *testing.T, wantTCP bool) {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	wantCount := 1
	if wantTCP {
		wantCount++
	}
	if len(o.networks) != wantCount || len(o.udp) != 1 || len(o.tcp) != wantCount-1 {
		t.Fatalf("unexpected hook calls: networks=%v addresses=%v udp=%d tcp=%d", o.networks, o.addresses, len(o.udp), len(o.tcp))
	}
	if o.networks[0] != "udp" || o.addresses[0] != "udp-hook.invalid:443" {
		t.Fatalf("initial UDP hook arguments: networks=%v addresses=%v", o.networks, o.addresses)
	}
	if wantTCP && (o.networks[1] != "tcp" || o.addresses[1] != "tcp-hook.invalid:443") {
		t.Fatalf("TCP hook arguments: networks=%v addresses=%v", o.networks, o.addresses)
	}
	if o.udp[0].writes.Load() < 1 {
		t.Fatal("UDP hook socket did not carry actual bootstrap packets")
	}
	if wantTCP && (o.tcp[0].reads.Load() == 0 || o.tcp[0].writes.Load() == 0) {
		t.Fatal("TCP hook socket did not carry physical bootstrap/business I/O")
	}
}

func TestCarrierHooksRealUDPInitialAndBlockedFallback(t *testing.T) {
	for _, initialBlocked := range []bool{false, true} {
		name := "normal-udp"
		if initialBlocked {
			name = "initial-udp-blackhole"
		}
		t.Run(name, func(t *testing.T) {
			observation := &carrierHookObservation{}
			f, _ := newClassRecoveryFixtureWithCarrier(t, initialBlocked, false, func(cfg *ClientConfig) { observation.configure(t, cfg) })
			before := f.local.Stats()
			flow, target := f.dial(t, "plain", classification.Metadata{})
			transferClassBytes(t, flow, target, 3072)
			transferClassBytes(t, target, flow, 4096)
			after := f.local.Stats()
			if after.ID != before.ID || after.Generation != 1 || f.backend.dials.Load() != 1 {
				t.Fatalf("initial hook session/flow identity: before=%+v after=%+v target_dials=%d", before, after, f.backend.dials.Load())
			}
			observation.assertCalls(t, initialBlocked)
			if initialBlocked && observation.udp[0].closes.Load() != 1 {
				t.Fatal("failed initial UDP socket was not closed exactly once")
			}
			if err := f.client.Abort(); err != nil {
				t.Fatal(err)
			}
			for _, socket := range observation.udp {
				if socket.closes.Load() != 1 {
					t.Fatal("Client.Abort did not close its injected UDP socket exactly once")
				}
			}
			for _, socket := range observation.tcp {
				if socket.closes.Load() != 1 {
					t.Fatal("Client.Abort did not close its injected TCP socket exactly once")
				}
			}
		})
	}
}

func TestCarrierHooksRuntimeUDPBlackholeRecoversSameTarget(t *testing.T) {
	observation := &carrierHookObservation{}
	f, relay := newClassRecoveryFixtureWithCarrier(t, false, true, func(cfg *ClientConfig) { observation.configure(t, cfg) })
	flow, target := f.dial(t, "plain", classification.Metadata{})
	transferClassBytes(t, flow, target, 2048)
	transferClassBytes(t, target, flow, 2048)
	before := f.local.Stats()
	relay.blackholeUDP.Store(true)
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(5 * time.Millisecond)
	defer poll.Stop()
	for f.local.Stats().Carrier != "tcp" || !runtimeReady(f.local) || !runtimeReady(f.peer) {
		select {
		case <-deadline.C:
			t.Fatalf("actual Client recovery did not converge: client=%+v peer=%+v", f.local.Stats(), f.peer.Stats())
		case <-poll.C:
		}
	}
	transferClassBytes(t, flow, target, 5000)
	transferClassBytes(t, target, flow, 6000)
	after := f.local.Stats()
	if after.ID != before.ID || after.Generation != before.Generation+1 || after.Switches != 1 || f.backend.dials.Load() != 1 {
		t.Fatalf("recovery replaced Session/target: before=%+v after=%+v target_dials=%d", before, after, f.backend.dials.Load())
	}
	observation.assertCalls(t, true)
	if err := f.client.Close(); err != nil {
		t.Fatal("authenticated close over hooked TCP", err)
	}
	if observation.udp[0].closes.Load() != 1 || observation.tcp[0].closes.Load() != 1 {
		t.Fatal("Client.Close did not release both injected carriers exactly once")
	}
}

func TestCarrierHooksCanceledDialLateSocketAndBoundedWorkers(t *testing.T) {
	for _, kind := range []string{"udp", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			_, credentials := newSecurityTestServer(t)
			entered := make(chan struct{})
			release := make(chan struct{})
			returned := make(chan struct{})
			var calls atomic.Int32
			cfg := ClientConfig{Server: "127.0.0.1:1", Credentials: credentials, Options: Options{HandshakeTimeout: time.Second}}
			var physicalClose func() int32
			if kind == "udp" {
				socket, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { socket.Close() })
				spy := &carrierHookPacketSpy{PacketConn: socket}
				physicalClose = spy.closes.Load
				cfg.DialUDP = func(context.Context, string, string) (net.PacketConn, *net.UDPAddr, error) {
					calls.Add(1)
					close(entered)
					<-release
					defer close(returned)
					return spy, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, nil
				}
			} else {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { listener.Close() })
				conn, err := net.Dial("tcp", listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				peer, err := listener.Accept()
				if err != nil {
					conn.Close()
					t.Fatal(err)
				}
				t.Cleanup(func() { conn.Close(); peer.Close() })
				spy := &carrierHookStreamSpy{Conn: conn}
				physicalClose = spy.closes.Load
				cfg.DialTCP = func(context.Context, string, string) (net.Conn, error) {
					calls.Add(1)
					close(entered)
					<-release
					defer close(returned)
					return spy, nil
				}
			}
			cfg.carrierDials = newCarrierDialState()
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() { _, err := dialPhysicalCarrier(ctx, cfg, kind, cfg.Server); result <- err }()
			<-entered
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled hook returned %v", err)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("cancellation waited for noncooperative hook")
			}
			for n := 0; n < 100; n++ {
				if _, err := dialPhysicalCarrier(context.Background(), cfg, kind, cfg.Server); !errors.Is(err, ErrCarrierDialBusy) {
					t.Fatalf("outstanding canceled callback admitted another worker: %v", err)
				}
			}
			if calls.Load() != 1 {
				t.Fatal("callback worker count was not bounded")
			}
			close(release)
			<-returned
			runtimeWait(t, "late injected socket cleanup", func() bool { return physicalClose() == 1 })
		})
	}
}
