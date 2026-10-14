package session

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"syscall"
	"time"
)

const winsockServerAddressInUse syscall.Errno = 10048

func listenPlatformServer(address string) (net.Listener, *net.UDPConn, error) {
	if !ephemeralServerAddress(address) {
		return listenServer(address, net.Listen, net.ListenUDP)
	}
	requested, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, nil, err
	}
	// Windows maintains separate excluded-port ranges for TCP and UDP. Asking
	// the OS for TCP :0 and then trying the same number for UDP can walk a long
	// contiguous excluded range. Select bounded random candidates instead; each
	// candidate is held as TCP while UDP claims the same port, and every failed
	// socket is closed before the next candidate.
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var last error
	for attempt := 0; attempt < 64; attempt++ {
		port := 49152 + rng.Intn(16384)
		candidate := &net.TCPAddr{IP: requested.IP, Port: port, Zone: requested.Zone}
		tcp, err := net.ListenTCP("tcp", candidate)
		if err != nil {
			last = err
			if retryableWindowsBind(err) {
				continue
			}
			return nil, nil, err
		}
		udpAddress := &net.UDPAddr{IP: requested.IP, Port: port, Zone: requested.Zone}
		udp, err := net.ListenUDP("udp", udpAddress)
		if err == nil {
			return tcp, udp, nil
		}
		_ = tcp.Close()
		last = err
		if !retryableWindowsBind(err) {
			return nil, nil, err
		}
	}
	if last == nil {
		last = errors.New("no candidate port")
	}
	return nil, nil, fmt.Errorf("session: no shared TCP/UDP port after 64 random candidates: %w", last)
}

func retryableWindowsBind(err error) bool {
	return errors.Is(err, winsockServerAddressInUse) || errors.Is(err, syscall.WSAEACCES)
}

func retryableServerUDPCollision(err error) bool {
	// Go's syscall.EADDRINUSE is a synthesized POSIX value on Windows; actual
	// socket bind failures carry Winsock errors. WSAEACCES may describe a UDP
	// excluded port, an exclusive socket, or a permission restriction. It is
	// only a bounded candidate rejection, not a diagnosis of its cause.
	return errors.Is(err, winsockServerAddressInUse) || errors.Is(err, syscall.WSAEACCES)
}
