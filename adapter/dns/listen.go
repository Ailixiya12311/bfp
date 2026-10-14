package dns

import "net"

// Let TCP choose a TCP-available ephemeral port before pairing UDP. A UDP-only
// allocator may choose a TCP connection's local port or a TCP-excluded port.
// If the independently occupied UDP port prevents pairing, retire this owned
// TCP listener and try a bounded number of new ephemeral candidates. A caller's
// explicit port is never changed or retried; the bind error remains visible.
func listenPair(address *net.UDPAddr,
	listenTCP func(string, *net.TCPAddr) (*net.TCPListener, error),
	listenUDP func(string, *net.UDPAddr) (*net.UDPConn, error),
) (*net.UDPConn, *net.TCPListener, error) {
	attempts := 1
	if address.Port == 0 {
		attempts = 8
	}
	var last error
	for i := 0; i < attempts; i++ {
		tcp, err := listenTCP("tcp", &net.TCPAddr{IP: address.IP, Port: address.Port, Zone: address.Zone})
		if err != nil {
			return nil, nil, err
		}
		bound := tcp.Addr().(*net.TCPAddr)
		udp, err := listenUDP("udp", &net.UDPAddr{IP: bound.IP, Port: bound.Port, Zone: bound.Zone})
		if err == nil {
			return udp, tcp, nil
		}
		tcp.Close()
		last = err
	}
	return nil, nil, last
}
