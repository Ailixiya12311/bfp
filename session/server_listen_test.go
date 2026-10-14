package session

import (
	"errors"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
)

type serverListenTestTCP struct {
	addr   net.Addr
	closed int
}

func (l *serverListenTestTCP) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l *serverListenTestTCP) Close() error              { l.closed++; return nil }
func (l *serverListenTestTCP) Addr() net.Addr            { return l.addr }

type serverListenTestAddr string

func (a serverListenTestAddr) Network() string { return "tcp" }
func (a serverListenTestAddr) String() string  { return string(a) }

func serverListenTestCollision() error {
	var errno error = syscall.EADDRINUSE
	if runtime.GOOS == "windows" {
		errno = syscall.Errno(10048)
	}
	return &net.OpError{Op: "listen", Net: "udp", Err: &os.SyscallError{Syscall: "bind", Err: errno}}
}

func serverListenTestUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	return udp
}

func TestServerListenEphemeralCollisionKeepsSuccessfulSockets(t *testing.T) {
	udp := serverListenTestUDP(t)
	port := udp.LocalAddr().(*net.UDPAddr).Port
	listeners := []*serverListenTestTCP{
		{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41001}},
		{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}},
	}
	tcpCalls, udpCalls := 0, 0
	tcp, actualUDP, err := listenServer("127.0.0.1:0", func(network, address string) (net.Listener, error) {
		if network != "tcp" || address != "127.0.0.1:0" || tcpCalls >= len(listeners) {
			t.Fatalf("unexpected TCP candidate %d: %s %s", tcpCalls, network, address)
		}
		if tcpCalls != 0 && listeners[tcpCalls-1].closed != 1 {
			t.Fatal("rejected TCP candidate still open at next selection")
		}
		listener := listeners[tcpCalls]
		tcpCalls++
		return listener, nil
	}, func(network string, address *net.UDPAddr) (*net.UDPConn, error) {
		if network != "udp" || tcpCalls != udpCalls+1 || listeners[udpCalls].closed != 0 ||
			address.Port != listeners[udpCalls].Addr().(*net.TCPAddr).Port || !address.IP.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Fatal("UDP bind did not use the continuously held TCP address")
		}
		udpCalls++
		if udpCalls == 1 {
			return nil, serverListenTestCollision()
		}
		return udp, nil
	})
	if err != nil || tcp != listeners[1] || actualUDP != udp || tcpCalls != 2 || udpCalls != 2 ||
		listeners[0].closed != 1 || listeners[1].closed != 0 {
		t.Fatalf("successful sockets not transferred intact: tcp=%v udp=%v calls=%d/%d err=%v", tcp == listeners[1], actualUDP == udp, tcpCalls, udpCalls, err)
	}
	if err := actualUDP.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("successful UDP socket was closed: %v", err)
	}
	_ = tcp.Close()
	_ = actualUDP.Close()
	if listeners[1].closed != 1 || !errors.Is(actualUDP.SetReadDeadline(time.Time{}), net.ErrClosed) {
		t.Fatal("successful listeners did not remain owned until caller close")
	}
}

func TestServerListenFixedPortDoesNotSearch(t *testing.T) {
	listener := &serverListenTestTCP{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42001}}
	cause := serverListenTestCollision()
	tcpCalls, udpCalls := 0, 0
	tcp, udp, err := listenServer("127.0.0.1:42001", func(network, address string) (net.Listener, error) {
		tcpCalls++
		if address != "127.0.0.1:42001" {
			t.Fatal("fixed listen address changed")
		}
		return listener, nil
	}, func(string, *net.UDPAddr) (*net.UDPConn, error) {
		udpCalls++
		return nil, cause
	})
	if tcp != nil || udp != nil || err != cause || tcpCalls != 1 || udpCalls != 1 || listener.closed != 1 {
		t.Fatalf("fixed-port collision was searched or leaked: calls=%d/%d closed=%d err=%v", tcpCalls, udpCalls, listener.closed, err)
	}
}

func TestServerListenUDPFirstKeepsChosenPortAndClosesRejectedSocket(t *testing.T) {
	var candidates []*net.UDPConn
	tcpCalls := 0
	var accepted *serverListenTestTCP
	tcp, udp, err := listenServerUDPFirst("127.0.0.1:0", func(network, address string) (net.Listener, error) {
		tcpCalls++
		current := candidates[len(candidates)-1]
		if network != "tcp" || address != current.LocalAddr().String() {
			t.Fatal("TCP did not bind the continuously held UDP candidate")
		}
		if err := current.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("candidate was closed before the matching TCP bind: %v", err)
		}
		if tcpCalls == 1 {
			return nil, serverListenTestCollision()
		}
		accepted = &serverListenTestTCP{addr: serverListenTestAddr(address)}
		return accepted, nil
	}, func(network string, address *net.UDPAddr) (*net.UDPConn, error) {
		if network != "udp" || address.Port != 0 {
			t.Fatal("UDP ephemeral selection used a TCP-selected port")
		}
		if len(candidates) > 0 && !errors.Is(candidates[len(candidates)-1].SetReadDeadline(time.Time{}), net.ErrClosed) {
			t.Fatal("rejected UDP socket leaked into the next candidate")
		}
		u := serverListenTestUDP(t)
		candidates = append(candidates, u)
		return u, nil
	})
	if err != nil || tcp != accepted || udp != candidates[1] || tcpCalls != 2 {
		t.Fatalf("UDP-first listener ownership failed: attempts=%d err=%v", tcpCalls, err)
	}
	defer tcp.Close()
	if err := udp.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("successful UDP socket was rebound or closed: %v", err)
	}
}

func TestServerListenUDPFirstNonCollisionClosesSocket(t *testing.T) {
	u := serverListenTestUDP(t)
	cause := &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EMFILE}
	attempts := 0
	tcp, udp, err := listenServerUDPFirst("127.0.0.1:0", func(string, string) (net.Listener, error) {
		attempts++
		return nil, cause
	}, func(string, *net.UDPAddr) (*net.UDPConn, error) {
		return u, nil
	})
	if tcp != nil || udp != nil || err != cause || attempts != 1 || !errors.Is(u.SetReadDeadline(time.Time{}), net.ErrClosed) {
		t.Fatalf("non-collision was retried or leaked a socket: attempts=%d err=%v", attempts, err)
	}
}

func TestServerListenNonCollisionReturnsImmediately(t *testing.T) {
	listener := &serverListenTestTCP{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43001}}
	cause := &net.OpError{Op: "listen", Net: "udp", Err: &os.SyscallError{Syscall: "bind", Err: syscall.EMFILE}}
	tcpCalls, udpCalls := 0, 0
	tcp, udp, err := listenServer("127.0.0.1:0", func(string, string) (net.Listener, error) {
		tcpCalls++
		return listener, nil
	}, func(string, *net.UDPAddr) (*net.UDPConn, error) {
		udpCalls++
		return nil, cause
	})
	if tcp != nil || udp != nil || err != cause || tcpCalls != 1 || udpCalls != 1 || listener.closed != 1 {
		t.Fatalf("non-collision UDP failure was retried or leaked: calls=%d/%d closed=%d err=%v", tcpCalls, udpCalls, listener.closed, err)
	}
}

func TestServerListenTCPFailureReturnsImmediately(t *testing.T) {
	for _, priorCollision := range []bool{false, true} {
		name := "first_candidate"
		if priorCollision {
			name = "after_udp_collision"
		}
		t.Run(name, func(t *testing.T) {
			cause := serverListenTestCollision()
			listener := &serverListenTestTCP{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 44001}}
			tcpCalls, udpCalls := 0, 0
			tcp, udp, err := listenServer("127.0.0.1:0", func(string, string) (net.Listener, error) {
				tcpCalls++
				if priorCollision && tcpCalls == 1 {
					return listener, nil
				}
				return nil, cause
			}, func(string, *net.UDPAddr) (*net.UDPConn, error) {
				udpCalls++
				return nil, serverListenTestCollision()
			})
			wantTCP, wantUDP, wantClose := 1, 0, 0
			if priorCollision {
				wantTCP, wantUDP, wantClose = 2, 1, 1
			}
			if tcp != nil || udp != nil || err != cause || tcpCalls != wantTCP || udpCalls != wantUDP || listener.closed != wantClose {
				t.Fatalf("TCP failure was retried: calls=%d/%d closed=%d err=%v", tcpCalls, udpCalls, listener.closed, err)
			}
		})
	}
}

func TestServerListenEphemeralSearchHasSixteenCandidateLimit(t *testing.T) {
	cause := serverListenTestCollision()
	var listeners []*serverListenTestTCP
	udpCalls := 0
	tcp, udp, err := listenServer("127.0.0.1:0", func(string, string) (net.Listener, error) {
		listener := &serverListenTestTCP{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45001 + len(listeners)}}
		listeners = append(listeners, listener)
		return listener, nil
	}, func(string, *net.UDPAddr) (*net.UDPConn, error) {
		udpCalls++
		return nil, cause
	})
	if tcp != nil || udp != nil || len(listeners) != 16 || udpCalls != 16 || err == cause || !errors.Is(err, cause) {
		t.Fatalf("search limit or preserved cause failed: calls=%d/%d err=%v", len(listeners), udpCalls, err)
	}
	for i, listener := range listeners {
		if listener.closed != 1 {
			t.Fatalf("candidate %d closed %d times", i, listener.closed)
		}
	}
}

func TestServerListenAddressFailureClosesTCPWithoutSearch(t *testing.T) {
	listener := &serverListenTestTCP{addr: serverListenTestAddr("not-an-address")}
	tcpCalls, udpCalls := 0, 0
	tcp, udp, err := listenServer("127.0.0.1:0", func(string, string) (net.Listener, error) {
		tcpCalls++
		return listener, nil
	}, func(string, *net.UDPAddr) (*net.UDPConn, error) {
		udpCalls++
		return nil, errors.New("unexpected UDP listen")
	})
	var addressError *net.AddrError
	if tcp != nil || udp != nil || !errors.As(err, &addressError) || tcpCalls != 1 || udpCalls != 0 || listener.closed != 1 {
		t.Fatalf("address conversion failure was retried or leaked: calls=%d/%d closed=%d err=%v", tcpCalls, udpCalls, listener.closed, err)
	}
}

func TestServerListenPlatformCollisionClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"posix_address_in_use", syscall.EADDRINUSE, runtime.GOOS != "windows"},
		{"winsock_address_in_use", syscall.Errno(10048), runtime.GOOS == "windows"},
		{"winsock_access_denied", syscall.Errno(10013), runtime.GOOS == "windows"},
		{"posix_access_denied", syscall.EACCES, false},
		{"file_limit", syscall.EMFILE, false},
		{"other_error", errors.New("address already in use"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := &net.OpError{Op: "listen", Net: "udp", Err: &os.SyscallError{Syscall: "bind", Err: tc.err}}
			if retryableServerUDPCollision(tc.err) != tc.want || retryableServerUDPCollision(wrapped) != tc.want {
				t.Fatalf("incorrect platform classification for %v", tc.err)
			}
		})
	}
	if retryableServerUDPCollision(nil) {
		t.Fatal("nil error treated as collision")
	}
}

func TestServerListenRecognizesOnlyRequestedEphemeralPort(t *testing.T) {
	for _, tc := range []struct {
		address string
		want    bool
	}{
		{"", true}, {":", true}, {":0", true}, {"127.0.0.1:", true}, {"127.0.0.1:0", true},
		{"127.0.0.1:000", true}, {"127.0.0.1:+0", true}, {"[::1]:0", true}, {"[fe80::1%loop]:0", true},
		{"127.0.0.1:8080", false}, {"127.0.0.1:http", false}, {"127.0.0.1:65536", false},
		{"127.0.0.1:-1", false}, {"127.0.0.1", false}, {"::1", false}, {"not-an-address", false},
	} {
		if got := ephemeralServerAddress(tc.address); got != tc.want {
			t.Errorf("ephemeralServerAddress(%q) = %v, want %v", tc.address, got, tc.want)
		}
	}
}

func TestServerListenRealConstructorOwnsSamePortThroughClose(t *testing.T) {
	server, _ := newSecurityTestServer(t)
	tcp := server.tcp.(*net.TCPListener)
	udp := server.udp
	tcpAddress := tcp.Addr().(*net.TCPAddr)
	udpAddress := udp.LocalAddr().(*net.UDPAddr)
	if tcpAddress.Port == 0 || tcpAddress.Port != udpAddress.Port || !tcpAddress.IP.Equal(udpAddress.IP) {
		t.Fatalf("constructor assigned distinct addresses: TCP=%s UDP=%s", tcpAddress, udpAddress)
	}
	if err := tcp.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("constructor returned a closed TCP listener: %v", err)
	}
	if err := udp.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("constructor returned a closed UDP socket: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := tcp.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Server.Close did not close its TCP listener: %v", err)
	}
	if err := udp.SetReadDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Server.Close did not close its UDP socket: %v", err)
	}
}
