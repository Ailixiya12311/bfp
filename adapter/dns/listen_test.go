package dns

import (
	"errors"
	"net"
	"testing"
)

func TestDNSListenPairEphemeralTCPChoosesPortFirst(t *testing.T) {
	var tcp *net.TCPListener
	udp, paired, err := listenPair(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		func(network string, address *net.TCPAddr) (*net.TCPListener, error) {
			var err error
			tcp, err = net.ListenTCP(network, address)
			return tcp, err
		}, func(network string, address *net.UDPAddr) (*net.UDPConn, error) {
			if tcp == nil || address.Port == 0 || address.Port != tcp.Addr().(*net.TCPAddr).Port {
				t.Fatal("UDP allocation preceded TCP or did not preserve its selected port")
			}
			return net.ListenUDP(network, address)
		})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close(); paired.Close() })
	if udp.LocalAddr().String() != paired.Addr().String() {
		t.Fatal("DNS listeners are not paired on the same address")
	}
}

func TestDNSListenPairEphemeralOccupiedUDPIsRetired(t *testing.T) {
	var retired *net.TCPListener
	var occupied *net.UDPConn
	calls := 0
	udp, tcp, err := listenPair(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		func(network string, address *net.TCPAddr) (*net.TCPListener, error) {
			listener, err := net.ListenTCP(network, address)
			if retired == nil {
				retired = listener
			}
			return listener, err
		}, func(network string, address *net.UDPAddr) (*net.UDPConn, error) {
			calls++
			if calls == 1 {
				var err error
				occupied, err = net.ListenUDP(network, address)
				if err != nil {
					t.Fatal("could not create controlled UDP collision", err)
				}
				t.Cleanup(func() { occupied.Close() })
			}
			return net.ListenUDP(network, address)
		})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close(); tcp.Close() })
	if calls < 2 || calls > 8 || retired == tcp {
		t.Fatal("failed candidate was not replaced within the bounded ephemeral budget")
	}
	if _, err := retired.AcceptTCP(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("failed candidate leaked its owned TCP listener", err)
	}
}

func TestDNSListenPairExplicitPortNeverMoves(t *testing.T) {
	// Choose and keep an actual TCP listener; the helper must not bypass this
	// explicit caller reservation by selecting a different available port.
	occupied, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { occupied.Close() })
	want := occupied.Addr().(*net.TCPAddr).Port
	tcpCalls, udpCalls := 0, 0
	udp, tcp, err := listenPair(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: want},
		func(network string, address *net.TCPAddr) (*net.TCPListener, error) {
			tcpCalls++
			if address.Port != want {
				t.Fatal("explicit port changed")
			}
			return net.ListenTCP(network, address)
		}, func(network string, address *net.UDPAddr) (*net.UDPConn, error) {
			udpCalls++
			return net.ListenUDP(network, address)
		})
	if err == nil || udp != nil || tcp != nil || tcpCalls != 1 || udpCalls != 0 {
		t.Fatalf("explicit conflicting port not rejected: err=%v calls=%d/%d", err, tcpCalls, udpCalls)
	}
}

func TestDNSListenPairExhaustionClosesAllCandidates(t *testing.T) {
	want := errors.New("controlled UDP allocation unavailable")
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "ephemeral", true: "explicit"}[explicit], func(t *testing.T) {
			var listeners []*net.TCPListener
			address := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
			var expected int
			if explicit {
				// Supply an owned available real listener through the test seam;
				// only the UDP bind fails. The explicit port must not be retried.
				address.Port, expected = 1, 1
			} else {
				expected = 8
			}
			udp, tcp, err := listenPair(address,
				func(network string, address *net.TCPAddr) (*net.TCPListener, error) {
					listener, err := net.ListenTCP(network, &net.TCPAddr{IP: address.IP})
					if err == nil {
						listeners = append(listeners, listener)
					}
					return listener, err
				}, func(string, *net.UDPAddr) (*net.UDPConn, error) { return nil, want })
			if !errors.Is(err, want) || udp != nil || tcp != nil || len(listeners) != expected {
				t.Fatalf("allocation budget: err=%v candidates=%d want=%d", err, len(listeners), expected)
			}
			for _, listener := range listeners {
				if _, err := listener.AcceptTCP(); !errors.Is(err, net.ErrClosed) {
					t.Fatal("exhausted candidate listener not retired", err)
				}
			}
		})
	}
}
