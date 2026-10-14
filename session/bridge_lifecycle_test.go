package session

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type bridgeLifecycleConn struct {
	*net.TCPConn
	closes        atomic.Int32
	closed        chan struct{}
	closeOnce     sync.Once
	halfClosed    chan struct{}
	halfCloseOnce sync.Once
}

func (c *bridgeLifecycleConn) Close() error {
	c.closes.Add(1)
	e := c.TCPConn.Close()
	c.closeOnce.Do(func() { close(c.closed) })
	return e
}
func (c *bridgeLifecycleConn) CloseWrite() error {
	e := c.TCPConn.CloseWrite()
	if e == nil {
		c.halfCloseOnce.Do(func() { close(c.halfClosed) })
	}
	return e
}

type bridgeLifecycleBackend struct {
	dialed chan *bridgeLifecycleConn
}

func (b *bridgeLifecycleBackend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, e := (&net.Dialer{}).DialContext(ctx, network, address)
	if e != nil {
		return nil, e
	}
	c := &bridgeLifecycleConn{TCPConn: conn.(*net.TCPConn), closed: make(chan struct{}), halfClosed: make(chan struct{})}
	b.dialed <- c
	return c, nil
}

type bridgeLifecycleFixture struct {
	client *Client
	server *Server
	local  *Session
	peer   *Session
	flow   *Flow
	target *net.TCPConn
	exit   *bridgeLifecycleConn
}

func newBridgeLifecycleFixture(t *testing.T) bridgeLifecycleFixture {
	t.Helper()
	listener, e := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { listener.Close() })
	server, cred := newSecurityTestServer(t)
	backend := &bridgeLifecycleBackend{dialed: make(chan *bridgeLifecycleConn, 1)}
	opts := Options{HandshakeTimeout: time.Second, ProbeInterval: 100 * time.Millisecond, FailureTimeout: 3 * time.Second, RetainTimeout: 5 * time.Second}
	server.cfg.Backend = backend
	server.cfg.Options = opts.defaults()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background()) }()
	t.Cleanup(func() {
		server.Close()
		select {
		case e := <-serveDone:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(time.Second):
			t.Error("bridge lifecycle server did not stop")
		}
	})
	client, e := NewClient(ClientConfig{Server: server.Addr().String(), TCPServer: server.Addr().String(), Credentials: cred, Options: opts})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	local, e := client.Connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	conn, e := client.DialContext(ctx, "tcp", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	// Keep the logical flow open for the entire normal-FIN assertion.
	// Only Session cleanup is allowed to close it after the assertion.
	flow := conn.(*Flow)
	_ = flow.SetDeadline(time.Now().Add(6 * time.Second))
	_ = listener.SetDeadline(time.Now().Add(time.Second))
	target, e := listener.AcceptTCP()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { target.Close() })
	_ = target.SetDeadline(time.Now().Add(6 * time.Second))
	var exit *bridgeLifecycleConn
	select {
	case exit = <-backend.dialed:
	case <-time.After(time.Second):
		t.Fatal("target backend did not return its real TCP connection")
	}
	sessionID := local.Stats().ID
	server.mu.Lock()
	peer := server.sessions[sessionID]
	server.mu.Unlock()
	if peer == nil {
		t.Fatal("real handshake did not commit the server Session")
	}
	return bridgeLifecycleFixture{client: client, server: server, local: local, peer: peer, flow: flow, target: target, exit: exit}
}

func bridgeLifecycleWrite(conn net.Conn, payload []byte, closeWrite func() error) <-chan error {
	done := make(chan error, 1)
	go func() {
		n, e := io.Copy(conn, bytes.NewReader(payload))
		if e == nil && n != int64(len(payload)) {
			e = fmt.Errorf("short write: %d/%d", n, len(payload))
		}
		if e == nil {
			e = closeWrite()
		}
		done <- e
	}()
	return done
}

func bridgeLifecycleWaitWrite(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reverse-direction writer did not finish")
	}
}

func TestBridgeGracefulFINClosesTargetOnceAfterBothDirections(t *testing.T) {
	for _, first := range []string{"client", "target"} {
		t.Run(first+"_FIN_first", func(t *testing.T) {
			f := newBridgeLifecycleFixture(t)
			firstPayload := []byte("the first direction finishes independently")
			// Exceed one receive window so the reverse direction must continue
			// delivering reliable bytes while the first direction is already EOF.
			reversePayload := bytes.Repeat([]byte("reverse direction after half-close\n"), 8192)
			if first == "client" {
				if _, e := f.flow.Write(firstPayload); e != nil {
					t.Fatal(e)
				}
				if e := f.flow.CloseWrite(); e != nil {
					t.Fatal(e)
				}
				got, e := io.ReadAll(f.target)
				if e != nil || !bytes.Equal(got, firstPayload) {
					t.Fatalf("first direction: %d bytes, %v", len(got), e)
				}
				select {
				case <-f.exit.halfClosed:
				case <-time.After(time.Second):
					t.Fatal("client FIN did not half-close the target")
				}
				if n := f.exit.closes.Load(); n != 0 {
					t.Fatalf("single client FIN fully closed target %d times", n)
				}
				done := bridgeLifecycleWrite(f.target, reversePayload, f.target.CloseWrite)
				got, e = io.ReadAll(f.flow)
				if e != nil || !bytes.Equal(got, reversePayload) {
					t.Fatalf("response after client FIN: %d/%d bytes, %v", len(got), len(reversePayload), e)
				}
				bridgeLifecycleWaitWrite(t, done)
			} else {
				if _, e := f.target.Write(firstPayload); e != nil {
					t.Fatal(e)
				}
				if e := f.target.CloseWrite(); e != nil {
					t.Fatal(e)
				}
				got, e := io.ReadAll(f.flow)
				if e != nil || !bytes.Equal(got, firstPayload) {
					t.Fatalf("first direction: %d bytes, %v", len(got), e)
				}
				if n := f.exit.closes.Load(); n != 0 {
					t.Fatalf("single target FIN fully closed target %d times", n)
				}
				done := bridgeLifecycleWrite(f.flow, reversePayload, f.flow.CloseWrite)
				got, e = io.ReadAll(f.target)
				if e != nil || !bytes.Equal(got, reversePayload) {
					t.Fatalf("request after target FIN: %d/%d bytes, %v", len(got), len(reversePayload), e)
				}
				bridgeLifecycleWaitWrite(t, done)
			}
			select {
			case <-f.exit.closed:
			case <-time.After(time.Second):
				t.Fatal("bidirectional FIN retained the target socket while Session stayed alive")
			}
			if n := f.exit.closes.Load(); n != 1 {
				t.Fatalf("target closed %d times, want exactly once", n)
			}
			runtimeWait(t, "normal FIN completion without RESET on either live Session", func() bool {
				ready := true
				for _, s := range []*Session{f.local, f.peer} {
					if e := s.call(context.Background(), func() {
						st := s.streams[f.flow.id]
						ready = ready && s.active && st != nil && !st.reset && st.terminal()
					}); e != nil {
						return false
					}
				}
				return ready
			})
			// Later Session destruction also uses the same close guard.
			f.client.Close()
			f.server.Close()
			if n := f.exit.closes.Load(); n != 1 {
				t.Fatalf("Session cleanup closed an already-finished target again: %d", n)
			}
		})
	}
}
