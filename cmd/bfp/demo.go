package main

import (
	"bfp/adapter/socks"
	"bfp/gateway"
	"bfp/security"
	"bfp/session"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// runDemo is the smallest complete product path: it creates ephemeral
// credentials in memory, starts a BFP server and two local exit fixtures, and
// exercises the default UDP carrier, the initial UDP-to-TCP fallback, one
// reliable TCP flow and one message-oriented UDP flow. It is deliberately
// self-contained so a new checkout can prove the product wiring before any
// remote or native-adapter test is attempted.
func runDemo(parent context.Context) error {
	result, err := demoSession(parent)
	if err == nil {
		emit(result)
	}
	return err
}

func demoSession(parent context.Context) (result map[string]any, failure error) {
	ctx, cancelDemo := context.WithTimeout(parent, 15*time.Second)
	defer cancelDemo()
	serverKey, err := security.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	clientKey, err := security.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	admission := make([]byte, 32)
	if _, err = rand.Read(admission); err != nil {
		return nil, err
	}
	backend, err := gateway.New(gateway.Policy{
		AllowPrivate: true,
		AllowedCIDRs: []string{"127.0.0.0/8"},
		Timeout:      2 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	options := session.Options{
		HandshakeTimeout: 2 * time.Second,
		ProbeInterval:    100 * time.Millisecond,
		FailureTimeout:   800 * time.Millisecond,
		RetainTimeout:    5 * time.Second,
	}
	server, err := session.NewServer(session.ServerConfig{
		Listen:      "127.0.0.1:0",
		Backend:     backend,
		Options:     options,
		MaxSessions: 4,
		Credentials: session.Credentials{
			Admission:      admission,
			Private:        serverKey.Private,
			Public:         serverKey.Public,
			AllowedClients: [][]byte{clientKey.Public},
		},
	})
	if err != nil {
		return nil, err
	}
	defer server.Close()

	tcpTarget, stopTCP, err := startDemoTCPEcho()
	if err != nil {
		return nil, err
	}
	defer stopTCP()
	udpTarget, stopUDP, err := startDemoUDPEcho()
	if err != nil {
		return nil, err
	}
	defer stopUDP()

	serveCtx, stopServe := context.WithCancel(ctx)
	defer stopServe()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(serveCtx) }()
	defer func() {
		stopServe()
		_ = server.Close()
		select {
		case serveErr := <-serveDone:
			if failure == nil {
				failure = serveErr
			}
		case <-time.After(2 * time.Second):
			if failure == nil {
				failure = errors.New("demo: server did not stop")
			}
		}
	}()

	client, err := session.NewClient(session.ClientConfig{
		Server:    server.Addr().String(),
		TCPServer: server.Addr().String(),
		Options:   options,
		Credentials: session.Credentials{
			Admission:    admission,
			Private:      clientKey.Private,
			Public:       clientKey.Public,
			ServerPublic: serverKey.Public,
		},
	})
	if err != nil {
		return nil, err
	}
	defer client.Abort()

	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	s, err := client.Connect(connectCtx)
	cancel()
	if err != nil {
		return nil, err
	}
	if s.Stats().Carrier != "udp" {
		return nil, errors.New("demo: default UDP carrier was unavailable")
	}
	entry, err := socks.New(socks.Config{Listen: "127.0.0.1:0", Backend: client})
	if err != nil {
		return nil, err
	}
	entryCtx, stopEntry := context.WithCancel(ctx)
	entryDone := make(chan error, 1)
	go func() { entryDone <- entry.Serve(entryCtx) }()
	defer func() {
		stopEntry()
		_ = entry.Close()
		if entryErr := <-entryDone; failure == nil {
			failure = entryErr
		}
	}()
	dialer, err := proxy.SOCKS5("tcp", entry.Addr().String(), nil, &net.Dialer{})
	if err != nil {
		return nil, err
	}

	tcpConn, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", tcpTarget)
	if err != nil {
		return nil, err
	}
	defer tcpConn.Close()
	deadline, _ := ctx.Deadline()
	_ = tcpConn.SetDeadline(deadline)
	stopTCPOnCancel := context.AfterFunc(ctx, func() { _ = tcpConn.Close() })
	defer stopTCPOnCancel()
	tcpPayload := []byte("bfp demo tcp")
	if _, err = tcpConn.Write(tcpPayload); err != nil {
		return nil, err
	}
	tcpReply := make([]byte, len(tcpPayload))
	if _, err = io.ReadFull(tcpConn, tcpReply); err != nil {
		return nil, err
	}
	if !bytes.Equal(tcpReply, tcpPayload) {
		return nil, errors.New("demo: TCP echo payload changed")
	}

	udpConn, err := client.DialContext(ctx, "udp", udpTarget)
	if err != nil {
		return nil, err
	}
	defer udpConn.Close()
	_ = udpConn.SetDeadline(time.Now().Add(5 * time.Second))
	udpPayload := []byte("bfp demo udp")
	if _, err = udpConn.Write(udpPayload); err != nil {
		return nil, err
	}
	udpReply := make([]byte, len(udpPayload))
	n, err := udpConn.Read(udpReply)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(udpReply[:n], udpPayload) {
		return nil, errors.New("demo: UDP echo payload changed")
	}

	// Exercise the product's initial fallback contract with a second client.
	// The hook is deliberately failed before any UDP socket is created; the
	// Client must then establish the same authenticated Session over TCP.
	fallbackClient, err := session.NewClient(session.ClientConfig{
		Server:    server.Addr().String(),
		TCPServer: server.Addr().String(),
		DialUDP: func(context.Context, string, string) (net.PacketConn, *net.UDPAddr, error) {
			return nil, nil, errors.New("demo: UDP carrier intentionally blocked")
		},
		Options: options,
		Credentials: session.Credentials{
			Admission:    admission,
			Private:      clientKey.Private,
			Public:       clientKey.Public,
			ServerPublic: serverKey.Public,
		},
	})
	if err != nil {
		return nil, err
	}
	defer fallbackClient.Abort()
	fallbackCtx, cancelFallback := context.WithTimeout(ctx, 5*time.Second)
	fallbackSession, err := fallbackClient.Connect(fallbackCtx)
	cancelFallback()
	if err != nil {
		return nil, err
	}
	if fallbackSession.Stats().Carrier != "tcp" {
		return nil, errors.New("demo: initial UDP failure did not select TCP carrier")
	}
	fallbackConn, err := fallbackSession.DialContext(ctx, "tcp", tcpTarget)
	if err != nil {
		return nil, err
	}
	defer fallbackConn.Close()
	_ = fallbackConn.SetDeadline(time.Now().Add(5 * time.Second))
	fallbackPayload := []byte("bfp demo tcp fallback")
	if _, err = fallbackConn.Write(fallbackPayload); err != nil {
		return nil, err
	}
	fallbackReply := make([]byte, len(fallbackPayload))
	if _, err = io.ReadFull(fallbackConn, fallbackReply); err != nil {
		return nil, err
	}
	if !bytes.Equal(fallbackReply, fallbackPayload) {
		return nil, errors.New("demo: TCP fallback echo payload changed")
	}

	stats := s.Stats()
	result = map[string]any{
		"event":               "demo_pass",
		"version":             buildVersion,
		"carrier":             stats.Carrier,
		"session_id":          stats.ID,
		"generation":          stats.Generation,
		"tcp_bytes":           len(tcpReply),
		"udp_bytes":           n,
		"tcp_target_open":     true,
		"udp_target_open":     true,
		"socks_tcp":           true,
		"initial_udp_blocked": true,
		"fallback_carrier":    fallbackSession.Stats().Carrier,
		"fallback_tcp_bytes":  len(fallbackReply),
	}
	return result, nil
}

func startDemoTCPEcho() (string, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	closed := false
	connections := make(map[net.Conn]struct{})
	stop := func() {
		_ = ln.Close()
		mu.Lock()
		closed = true
		for conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		wg.Wait()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = conn.Close()
				return
			}
			connections[conn] = struct{}{}
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer func() {
					_ = conn.Close()
					mu.Lock()
					delete(connections, conn)
					mu.Unlock()
				}()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String(), stop, nil
}

func startDemoUDPEcho() (string, func(), error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return "", nil, err
	}
	var wg sync.WaitGroup
	stop := func() {
		_ = conn.Close()
		wg.Wait()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 64<<10)
		for {
			n, peer, readErr := conn.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], peer)
		}
	}()
	return conn.LocalAddr().String(), stop, nil
}
