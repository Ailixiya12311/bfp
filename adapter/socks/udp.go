package socks

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"time"
)

type udpControl struct {
	server  *Server
	ctx     context.Context
	cancel  context.CancelFunc
	udp     *net.UDPConn
	peerIP  net.IP
	mu      sync.Mutex
	source  *net.UDPAddr
	targets map[string]*udpTarget
	wg      sync.WaitGroup
}

type udpTarget struct {
	conn    net.Conn
	address []byte
}

func (s *Server) serveUDP(control net.Conn) {
	peer, ok := control.RemoteAddr().(*net.TCPAddr)
	if !ok {
		s.reply(control, 1, nil)
		return
	}
	local, ok := control.LocalAddr().(*net.TCPAddr)
	if !ok {
		s.reply(control, 1, nil)
		return
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP, Port: 0})
	if err != nil {
		s.reply(control, 1, nil)
		return
	}
	if !s.track(udp) {
		udp.Close()
		return
	}
	defer s.release(udp)
	ctx, cancel := context.WithCancel(s.ctx)
	u := &udpControl{server: s, ctx: ctx, cancel: cancel, udp: udp, peerIP: append(net.IP(nil), peer.IP...), targets: make(map[string]*udpTarget)}
	if err := s.reply(control, 0, udp.LocalAddr()); err != nil {
		cancel()
		return
	}
	control.SetDeadline(time.Time{})
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		u.receive()
	}()
	io.Copy(io.Discard, control)
	cancel()
	udp.Close()
	u.mu.Lock()
	for _, target := range u.targets {
		target.conn.Close()
	}
	u.mu.Unlock()
	u.wg.Wait()
}

func (u *udpControl) receive() {
	buffer := make([]byte, 65535)
	for {
		n, source, err := u.udp.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		if !source.IP.Equal(u.peerIP) || n < 4 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 {
			continue
		}
		reader := bytes.NewReader(buffer[4:n])
		address, encoded, err := readAddress(reader, buffer[3])
		if err != nil {
			continue
		}
		u.mu.Lock()
		if u.source == nil {
			clone := *source
			clone.IP = append(net.IP(nil), source.IP...)
			u.source = &clone
		}
		validSource := source.Port == u.source.Port && source.IP.Equal(u.source.IP)
		u.mu.Unlock()
		if !validSource {
			continue
		}
		target := u.target(address, encoded)
		if target == nil {
			continue
		}
		// One Write is one datagram. Never split or retry a short datagram write.
		payload := buffer[n-reader.Len() : n]
		written, err := target.conn.Write(payload)
		if err != nil || written != len(payload) {
			u.remove(address, target)
		}
	}
}

func (u *udpControl) target(address string, encoded []byte) *udpTarget {
	u.mu.Lock()
	if target := u.targets[address]; target != nil {
		u.mu.Unlock()
		return target
	}
	if len(u.targets) >= u.server.cfg.MaxUDPTargets || u.ctx.Err() != nil {
		u.mu.Unlock()
		return nil
	}
	u.mu.Unlock()
	ctx, cancel := context.WithTimeout(u.ctx, u.server.cfg.HandshakeTimeout)
	conn, err := u.server.dialTarget(ctx, "udp", address, encoded[0])
	cancel()
	if err != nil {
		return nil
	}
	if !u.server.track(conn) {
		conn.Close()
		return nil
	}
	target := &udpTarget{conn: conn, address: append([]byte(nil), encoded...)}
	u.mu.Lock()
	if u.ctx.Err() != nil {
		u.mu.Unlock()
		u.server.release(conn)
		return nil
	}
	u.targets[address] = target
	u.wg.Add(1)
	u.mu.Unlock()
	go func() {
		defer u.wg.Done()
		defer u.remove(address, target)
		u.returnDatagrams(target)
	}()
	return target
}

func (u *udpControl) returnDatagrams(target *udpTarget) {
	buffer := make([]byte, 65535)
	for {
		n, err := target.conn.Read(buffer)
		if err != nil {
			return
		}
		u.mu.Lock()
		source := u.source
		u.mu.Unlock()
		if source == nil || u.ctx.Err() != nil {
			return
		}
		message := make([]byte, 3+len(target.address)+n)
		copy(message[3:], target.address)
		copy(message[3+len(target.address):], buffer[:n])
		if _, err := u.udp.WriteToUDP(message, source); err != nil {
			return
		}
	}
}

func (u *udpControl) remove(address string, target *udpTarget) {
	u.mu.Lock()
	if u.targets[address] == target {
		delete(u.targets, address)
	}
	u.mu.Unlock()
	u.server.release(target.conn)
}
