package session

import (
	"fmt"
	"net"
	"strconv"
)

const maxEphemeralServerCandidates = 16

// listenServer keeps each TCP listener open while binding UDP to its actual
// address. Successful sockets transfer directly to Server without rebinding.
// Only a requested ephemeral port may search for a shared TCP/UDP port. A
// candidate rejected by UDP is closed before selecting the next candidate;
// neither a fixed port nor a failed TCP listen is retried.
// The listen functions are explicit dependencies for deterministic tests,
// rather than mutable package state used by running servers.
func listenServer(address string,
	listenTCP func(string, string) (net.Listener, error),
	listenUDP func(string, *net.UDPAddr) (*net.UDPConn, error),
) (net.Listener, *net.UDPConn, error) {
	limit := 1
	if ephemeralServerAddress(address) {
		limit = maxEphemeralServerCandidates
	}
	for candidate := 1; candidate <= limit; candidate++ {
		tcp, err := listenTCP("tcp", address)
		if err != nil {
			return nil, nil, err
		}
		udpAddress, err := net.ResolveUDPAddr("udp", tcp.Addr().String())
		if err != nil {
			_ = tcp.Close()
			return nil, nil, err
		}
		udp, err := listenUDP("udp", udpAddress)
		if err == nil {
			return tcp, udp, nil
		}
		_ = tcp.Close()
		if limit == 1 || !retryableServerUDPCollision(err) {
			return nil, nil, err
		}
		if candidate == limit {
			return nil, nil, fmt.Errorf("session: no shared TCP/UDP port after %d ephemeral candidates: %w", limit, err)
		}
	}
	panic("session: unreachable listener search")
}

// listenServerUDPFirst lets the operating system select a usable datagram port
// before holding the matching stream listener. Windows can allocate a long
// sequence of TCP ephemeral ports that are excluded for UDP; selecting UDP
// first avoids walking that entire excluded range. No socket is closed and
// rebound on success. Fixed ports retain the ordinary no-search behavior.
func listenServerUDPFirst(address string,
	listenTCP func(string, string) (net.Listener, error),
	listenUDP func(string, *net.UDPAddr) (*net.UDPConn, error),
) (net.Listener, *net.UDPConn, error) {
	if !ephemeralServerAddress(address) {
		return listenServer(address, listenTCP, listenUDP)
	}
	requested, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, nil, err
	}
	for candidate := 1; candidate <= maxEphemeralServerCandidates; candidate++ {
		udp, err := listenUDP("udp", requested)
		if err != nil {
			return nil, nil, err
		}
		tcp, err := listenTCP("tcp", udp.LocalAddr().String())
		if err == nil {
			return tcp, udp, nil
		}
		_ = udp.Close()
		if !retryableServerUDPCollision(err) {
			return nil, nil, err
		}
		if candidate == maxEphemeralServerCandidates {
			return nil, nil, fmt.Errorf("session: no shared UDP/TCP port after %d ephemeral candidates: %w", candidate, err)
		}
	}
	panic("session: unreachable UDP-first listener search")
}

// Empty addresses/ports also request port zero in net.Listen. Numeric signed
// and leading-zero representations preserve the same meaning. Service names
// and malformed addresses are left to net.Listen and never enable a search.
func ephemeralServerAddress(address string) bool {
	if address == "" {
		return true
	}
	_, service, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if service == "" {
		return true
	}
	port, err := strconv.Atoi(service)
	return err == nil && port == 0
}
