package session

import (
	"bfp/security"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestCarrierHooksRejectUnsupportedNetworkBeforeCallingHook(t *testing.T) {
	var calls atomic.Int32
	cfg := ClientConfig{
		DialTCP: func(context.Context, string, string) (net.Conn, error) { calls.Add(1); return nil, nil },
		DialUDP: func(context.Context, string, string) (net.PacketConn, *net.UDPAddr, error) {
			calls.Add(1)
			return nil, nil, nil
		},
	}
	for _, kind := range []string{"", "unix", "udp4", "tcp4", "quic"} {
		if _, err := dialPhysicalCarrier(context.Background(), cfg, kind, "127.0.0.1:1"); !errors.Is(err, ErrCarrierDialContract) {
			t.Fatalf("unsupported carrier %q returned %v", kind, err)
		}
		if _, _, err := establish(context.Background(), cfg, kind, randomID(), nil); !errors.Is(err, ErrCarrierDialContract) {
			t.Fatalf("establish unsupported carrier %q returned %v", kind, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("unsupported network invoked a hook")
	}
}

func TestCarrierHooksInvalidUDPResultDoesNotFallback(t *testing.T) {
	for _, kind := range []string{"nil-socket", "typed-nil-socket", "nil-peer", "unspecified-peer", "bad-port", "multicast-peer"} {
		t.Run(kind, func(t *testing.T) {
			_, credentials := newSecurityTestServer(t)
			var tcpCalls atomic.Int32
			var spy *carrierHookPacketSpy
			cfg := ClientConfig{Server: "127.0.0.1:1", Credentials: credentials}
			cfg.DialUDP = func(context.Context, string, string) (net.PacketConn, *net.UDPAddr, error) {
				peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
				if kind == "nil-socket" {
					return nil, peer, nil
				}
				if kind == "typed-nil-socket" {
					var socket *net.UDPConn
					return socket, peer, nil
				}
				socket, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					return nil, nil, err
				}
				spy = &carrierHookPacketSpy{PacketConn: socket}
				switch kind {
				case "nil-peer":
					peer = nil
				case "unspecified-peer":
					peer.IP = net.IPv4zero
				case "bad-port":
					peer.Port = 0
				case "multicast-peer":
					peer.IP = net.IPv4(224, 0, 0, 1)
				}
				return spy, peer, nil
			}
			cfg.DialTCP = func(context.Context, string, string) (net.Conn, error) { tcpCalls.Add(1); return nil, nil }
			client, err := NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { client.Abort() })
			if _, err = client.Connect(context.Background()); !errors.Is(err, ErrCarrierDialContract) {
				t.Fatalf("invalid hook result %q was hidden: %v", kind, err)
			}
			if tcpCalls.Load() != 0 {
				t.Fatal("configuration error silently fell back to TCP")
			}
			if spy != nil && spy.closes.Load() != 1 {
				t.Fatal("invalid UDP socket was not closed exactly once")
			}
		})
	}
}

func TestCarrierHooksRejectPacketSocketAsTCP(t *testing.T) {
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	cfg := ClientConfig{DialTCP: func(context.Context, string, string) (net.Conn, error) { return socket, nil }}
	if _, err = dialPhysicalCarrier(context.Background(), cfg, "tcp", "127.0.0.1:1"); !errors.Is(err, ErrCarrierDialContract) {
		t.Fatalf("packet socket was installed as TCP: %v", err)
	}
	if err = socket.SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("rejected socket remained open: %v", err)
	}
}

func TestCarrierHooksConnectionAndErrorAlwaysClosesSocket(t *testing.T) {
	for _, kind := range []string{"udp", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			failure := errors.New("explicit hook dial failure")
			var countClose func() int32
			cfg := ClientConfig{}
			if kind == "udp" {
				socket, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { socket.Close() })
				spy := &carrierHookPacketSpy{PacketConn: socket}
				countClose = spy.closes.Load
				cfg.DialUDP = func(context.Context, string, string) (net.PacketConn, *net.UDPAddr, error) { return spy, nil, failure }
			} else {
				conn, peer := net.Pipe()
				t.Cleanup(func() { conn.Close(); peer.Close() })
				spy := &carrierHookStreamSpy{Conn: conn}
				countClose = spy.closes.Load
				cfg.DialTCP = func(context.Context, string, string) (net.Conn, error) { return spy, failure }
			}
			if conn, err := dialPhysicalCarrier(context.Background(), cfg, kind, "127.0.0.1:1"); conn != nil || !errors.Is(err, failure) {
				t.Fatalf("partial hook result was accepted: conn=%v err=%v", conn, err)
			}
			if countClose() != 1 {
				t.Fatal("partial hook socket not closed exactly once")
			}
		})
	}
}

func TestCarrierHooksUDPWrapperPinsPeerAndPreservesBoundaries(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	foreign, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { foreign.Close() })
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	inputPeer := peer.LocalAddr().(*net.UDPAddr)
	originalPeer := &net.UDPAddr{IP: append(net.IP(nil), inputPeer.IP...), Port: inputPeer.Port}
	conn, err := wrapDatagramSocket(socket, inputPeer)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	inputPeer.IP[0] ^= 1
	inputPeer.Port = foreign.LocalAddr().(*net.UDPAddr).Port
	returnedPeer := conn.RemoteAddr().(*net.UDPAddr)
	returnedPeer.IP[0] ^= 1
	returnedPeer.Port = inputPeer.Port
	if !sameUDPPeer(conn.RemoteAddr(), originalPeer) {
		t.Fatal("external mutation changed pinned peer")
	}
	if err = conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	for _, payload := range [][]byte{[]byte("datagram-one"), []byte("datagram-two-is-separate")} {
		if _, err = conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err = peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		n, from, err := peer.ReadFromUDP(buffer)
		if err != nil || !bytes.Equal(buffer[:n], payload) {
			t.Fatalf("boundary not preserved: n=%d err=%v bytes=%q", n, err, buffer[:n])
		}
		if _, err = foreign.WriteToUDP([]byte("foreign datagram"), from); err != nil {
			t.Fatal(err)
		}
		if _, err = peer.WriteToUDP(payload, from); err != nil {
			t.Fatal(err)
		}
		n, err = conn.Read(buffer)
		if err != nil || !bytes.Equal(buffer[:n], payload) {
			t.Fatalf("wrong sender accepted or boundary lost: n=%d err=%v bytes=%q", n, err, buffer[:n])
		}
	}
	if _, err = foreign.WriteToUDP([]byte("only foreign"), socket.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	if err = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Read(buffer); err == nil {
		t.Fatal("untrusted sender satisfied pinned Read")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("deadline lost while filtering sender: %v", err)
	}
}

func TestCarrierHooksConnectedUDPWorksAndWrongPeerRejected(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	for _, matching := range []bool{true, false} {
		socket, err := net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { socket.Close() })
		remote := peer.LocalAddr().(*net.UDPAddr)
		remote = &net.UDPAddr{IP: append(net.IP(nil), remote.IP...), Port: remote.Port}
		if !matching {
			remote.Port++
		}
		cfg := ClientConfig{DialUDP: func(context.Context, string, string) (net.PacketConn, *net.UDPAddr, error) {
			return socket, remote, nil
		}}
		conn, err := dialPhysicalCarrier(context.Background(), cfg, "udp", "hook.invalid:443")
		if !matching {
			if !errors.Is(err, ErrCarrierDialContract) {
				t.Fatalf("mismatched connected peer accepted: %v", err)
			}
			if err = socket.SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
				t.Fatal("invalid connected socket remained open", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err = conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err = conn.Write([]byte("connected UDP")); err != nil {
			t.Fatal(err)
		}
		if err = peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 128)
		n, from, err := peer.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = peer.WriteToUDP(buffer[:n], from); err != nil {
			t.Fatal(err)
		}
		n, err = conn.Read(buffer)
		if err != nil || string(buffer[:n]) != "connected UDP" {
			t.Fatalf("connected socket round trip failed: n=%d err=%v", n, err)
		}
	}
}

func TestCarrierHooksClientCloseCancelsPendingDialAndClosesLateSocket(t *testing.T) {
	for _, kind := range []string{"udp", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			_, credentials := newSecurityTestServer(t)
			entered := make(chan struct{})
			release := make(chan struct{})
			var countClose func() int32
			cfg := ClientConfig{Server: "127.0.0.1:1", Credentials: credentials}
			if kind == "udp" {
				socket, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { socket.Close() })
				spy := &carrierHookPacketSpy{PacketConn: socket}
				countClose = spy.closes.Load
				cfg.DialUDP = func(context.Context, string, string) (net.PacketConn, *net.UDPAddr, error) {
					close(entered)
					<-release
					return spy, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, nil
				}
			} else {
				conn, peer := net.Pipe()
				t.Cleanup(func() { conn.Close(); peer.Close() })
				spy := &carrierHookStreamSpy{Conn: conn}
				countClose = spy.closes.Load
				cfg.DialUDP = func(context.Context, string, string) (net.PacketConn, *net.UDPAddr, error) {
					return nil, nil, errors.New("UDP unavailable")
				}
				cfg.DialTCP = func(context.Context, string, string) (net.Conn, error) {
					close(entered)
					<-release
					return spy, nil
				}
			}
			client, err := NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { client.Abort() })
			connectResult := make(chan error, 1)
			go func() { _, err := client.Connect(context.Background()); connectResult <- err }()
			<-entered
			closeResult := make(chan error, 1)
			go func() { closeResult <- client.Close() }()
			select {
			case err = <-closeResult:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("Close waited for a hook ignoring its canceled context")
			}
			select {
			case err = <-connectResult:
				if !errors.Is(err, context.Canceled) && !errors.Is(err, ErrClosed) {
					t.Fatal("Connect cancellation lost", err)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("Connect remained locked after Client.Close")
			}
			close(release)
			runtimeWait(t, "Client.Close late socket destruction", func() bool { return countClose() == 1 })
			if client.Session() != nil {
				t.Fatal("late dial resurrected a Session after Close")
			}
		})
	}
}

func TestCarrierHooksBootstrapCancellationAndSuccessfulTransfer(t *testing.T) {
	for _, kind := range []string{"udp", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			server, credentials := newSecurityTestServer(t)
			serveDone := make(chan error, 1)
			go func() { serveDone <- server.Serve(context.Background()) }()
			t.Cleanup(func() { server.Close(); <-serveDone })
			cfg := ClientConfig{Server: server.Addr().String(), TCPServer: server.Addr().String(), Credentials: credentials, Options: Options{HandshakeTimeout: time.Second}}
			observation := &carrierHookObservation{}
			observation.configure(t, &cfg)
			ctx, cancel := context.WithCancel(context.Background())
			car, _, err := establish(ctx, cfg, kind, randomID(), nil)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			defer car.close()
			cancel()
			if err = car.conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal("canceled dial parent closed transferred socket", err)
			}
			if kind == "tcp" {
				if _, err = car.conn.Write(nil); err != nil && !errors.Is(err, io.ErrShortWrite) {
					t.Fatal(err)
				}
			} else if observation.udp[0].closes.Load() != 0 {
				t.Fatal("transferred UDP socket closed with dial context")
			}
		})
	}
}

func TestCarrierHooksBootstrapCancelInterruptsActualSocket(t *testing.T) {
	for _, kind := range []string{"udp", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			_, credentials := newSecurityTestServer(t)
			cfg := ClientConfig{Server: "hook.invalid:443", Credentials: credentials, Options: Options{HandshakeTimeout: time.Second}}
			received := make(chan error, 1)
			var countClose func() int32
			if kind == "udp" {
				listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { listener.Close() })
				socket, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { socket.Close() })
				spy := &carrierHookPacketSpy{PacketConn: socket}
				countClose = spy.closes.Load
				cfg.DialUDP = func(context.Context, string, string) (net.PacketConn, *net.UDPAddr, error) {
					return spy, listener.LocalAddr().(*net.UDPAddr), nil
				}
				go func() {
					listener.SetReadDeadline(time.Now().Add(time.Second))
					buffer := make([]byte, 1201)
					n, _, err := listener.ReadFromUDP(buffer)
					if err == nil {
						_, err = security.OpenBootstrap(credentials.Admission, buffer[:n])
					}
					received <- err
				}()
			} else {
				listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { listener.Close() })
				socket, err := net.Dial("tcp", listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { socket.Close() })
				peer, err := listener.AcceptTCP()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { peer.Close() })
				spy := &carrierHookStreamSpy{Conn: socket}
				countClose = spy.closes.Load
				cfg.DialTCP = func(context.Context, string, string) (net.Conn, error) { return spy, nil }
				go func() {
					peer.SetReadDeadline(time.Now().Add(time.Second))
					_, err := security.ReadBootstrap(peer, credentials.Admission)
					received <- err
				}()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, _, err := establish(ctx, cfg, kind, randomID(), nil); result <- err }()
			select {
			case err := <-received:
				if err != nil {
					t.Fatal("actual bootstrap packet", err)
				}
			case <-time.After(time.Second):
				t.Fatal("injected socket carried no bootstrap packet")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("bootstrap cancellation lost", err)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("cancellation failed to interrupt injected socket bootstrap I/O")
			}
			if countClose() != 1 {
				t.Fatal("bootstrap cancellation did not destroy its injected socket exactly once")
			}
		})
	}
}

type carrierHookUnsupportedDeadline struct{ net.PacketConn }

func (c *carrierHookUnsupportedDeadline) SetDeadline(time.Time) error {
	return errors.New("deadlines unsupported")
}

func TestCarrierHooksUnsupportedDeadlineFailsClosed(t *testing.T) {
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	spy := &carrierHookPacketSpy{PacketConn: socket}
	cfg := ClientConfig{DialUDP: func(context.Context, string, string) (net.PacketConn, *net.UDPAddr, error) {
		return &carrierHookUnsupportedDeadline{PacketConn: spy}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, nil
	}}
	if conn, err := dialPhysicalCarrier(context.Background(), cfg, "udp", "hook.invalid:443"); conn != nil || !errors.Is(err, ErrCarrierDialContract) {
		t.Fatalf("socket without deadlines installed: conn=%v err=%v", conn, err)
	}
	if spy.closes.Load() != 1 || spy.writes.Load() != 0 {
		t.Fatal("unsupported socket was used or not closed")
	}
}

type carrierHookShortPacketWrite struct{ net.PacketConn }

func (c *carrierHookShortPacketWrite) WriteTo(buffer []byte, address net.Addr) (int, error) {
	return len(buffer) - 1, nil
}

func TestCarrierHooksUDPBootstrapShortWriteRejected(t *testing.T) {
	_, credentials := newSecurityTestServer(t)
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	spy := &carrierHookPacketSpy{PacketConn: socket}
	cfg := ClientConfig{Server: "hook.invalid:443", Credentials: credentials, Options: Options{HandshakeTimeout: time.Second},
		DialUDP: func(context.Context, string, string) (net.PacketConn, *net.UDPAddr, error) {
			return &carrierHookShortPacketWrite{PacketConn: spy}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, nil
		},
	}
	if car, _, err := establish(context.Background(), cfg, "udp", randomID(), nil); car != nil || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("partial datagram was accepted: carrier=%v err=%v", car, err)
	}
	if spy.closes.Load() != 1 {
		t.Fatal("short-write bootstrap socket was not closed")
	}
}
