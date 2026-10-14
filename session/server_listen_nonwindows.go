//go:build !windows

package session

import (
	"errors"
	"net"
	"syscall"
)

func listenPlatformServer(address string) (net.Listener, *net.UDPConn, error) {
	return listenServer(address, net.Listen, net.ListenUDP)
}

func retryableServerUDPCollision(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}
