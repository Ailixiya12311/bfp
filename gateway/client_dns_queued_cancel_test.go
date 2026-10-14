package gateway

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dnsfront "bfp/adapter/dns"
	"bfp/session"
	"golang.org/x/net/dns/dnsmessage"
)

// Observe admission into the real Client.Connect while an unrelated first
// Connect owns the carrier hook. No stub result substitutes for the real lock.
type queuedDNSSelector struct {
	client   *session.Client
	entered  chan struct{}
	finished chan error
}

func (s *queuedDNSSelector) Connect(ctx context.Context) (*session.Session, error) {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	owner, err := s.client.Connect(ctx)
	select {
	case s.finished <- err:
	default:
	}
	return owner, err
}

func TestClientDNSQueuedTimeoutAndCloseDoNotCancelIndependentFirstConnect(t *testing.T) {
	for _, scene := range []string{"query_50ms_timeout", "frontend_close"} {
		t.Run(scene, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			base, err := New(Policy{})
			if err != nil {
				t.Fatal(err)
			}
			opts := session.Options{HandshakeTimeout: 2 * time.Second}
			server, credentials := sessionDNSTerminationServer(t, ctx, &sessionDNSRuntimeFactory{base: base}, opts)
			recorder := newClientAddressScopeRecorder(t)
			hookEntered, hookRelease := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(hookRelease) }) }
			t.Cleanup(release)
			var hookCalls atomic.Int32
			client, err := session.NewClient(session.ClientConfig{Server: "queued-real-dns.invalid:9", TCPServer: server.Addr().String(), Credentials: credentials, Options: opts, AddressScopeFactory: recorder,
				DialUDP: func(ctx context.Context, network, address string) (net.PacketConn, *net.UDPAddr, error) {
					hookCalls.Add(1)
					if network != "udp" || address != "queued-real-dns.invalid:9" {
						return nil, nil, errors.New("queued DNS hook got wrong carrier address")
					}
					close(hookEntered)
					select {
					case <-hookRelease:
					case <-ctx.Done():
						return nil, nil, ctx.Err()
					}
					peer, err := net.ResolveUDPAddr("udp", server.Addr().String())
					if err != nil {
						return nil, nil, err
					}
					socket, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
					return socket, peer, err
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { release(); client.Abort() })
			type connectResult struct {
				owner *session.Session
				err   error
			}
			first := make(chan connectResult, 1)
			go func() { owner, err := client.Connect(ctx); first <- connectResult{owner, err} }()
			select {
			case <-hookEntered:
			case <-ctx.Done():
				t.Fatal("independent first Connect did not enter hook")
			}
			selector := &queuedDNSSelector{client: client, entered: make(chan struct{}, 1), finished: make(chan error, 1)}
			front, err := dnsfront.New(dnsfront.Config{Client: selector, QueryTimeout: 50 * time.Millisecond, ResponseWriteTimeout: 5 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			frontDone := make(chan error, 1)
			go func() { frontDone <- front.Serve(ctx) }()
			t.Cleanup(func() {
				front.Close()
				select {
				case err := <-frontDone:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(time.Second):
					t.Error("queued DNS Serve did not join")
				}
			})
			name, err := dnsmessage.NewName("queued-query-owner.test.")
			if err != nil {
				t.Fatal(err)
			}
			query := dnsmessage.Message{Header: dnsmessage.Header{ID: 8899, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
			wire, err := query.Pack()
			if err != nil {
				t.Fatal(err)
			}
			udp, err := net.Dial("udp", front.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			started := time.Now()
			if _, err := udp.Write(wire); err != nil {
				t.Fatal(err)
			}
			select {
			case <-selector.entered:
			case <-time.After(time.Second):
				t.Fatal("real DNS did not queue behind first Connect")
			}
			if scene == "frontend_close" {
				closed := make(chan error, 1)
				go func() { closed <- front.Close() }()
				select {
				case err := <-closed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(200 * time.Millisecond):
					t.Fatal("DNS Close remained blocked behind unrelated first Connect")
				}
			}
			select {
			case err := <-selector.finished:
				if scene == "query_50ms_timeout" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("queued query lost deadline: %v", err)
				}
				if scene == "frontend_close" && !errors.Is(err, context.Canceled) {
					t.Fatalf("closed query lost cancellation: %v", err)
				}
			case <-time.After(200 * time.Millisecond):
				t.Fatal("DNS timeout/Close did not end queued real Client.Connect")
			}
			if time.Since(started) > 250*time.Millisecond || hookCalls.Load() != 1 || len(recorder.snapshot()) != 0 {
				t.Fatal("queued DNS caller dialed/allocated scope or ignored bounded deadline")
			}
			select {
			case result := <-first:
				if result.owner != nil {
					result.owner.Close()
				}
				t.Fatalf("queued DNS canceled independent first Connect: %v", result.err)
			default:
			}
			release()
			var owner *session.Session
			select {
			case result := <-first:
				if result.err != nil {
					t.Fatal(result.err)
				}
				owner = result.owner
			case <-time.After(time.Second):
				t.Fatal("first Connect did not succeed after DNS cancellation")
			}
			if owner == nil || owner.Stats().Carrier != "udp" || hookCalls.Load() != 1 || len(recorder.snapshot()) != 1 {
				t.Fatal("independent owner scope/carrier was damaged by DNS cancellation")
			}
			if scene == "frontend_close" {
				front = startClientDNSFrontend(t, ctx, client)
			}
			ip, _ := requireClientDNSAddress(t, clientDNSQuery(t, ctx, front, "tcp", "after-queue-release.test"))
			if client.Session() != owner || hookCalls.Load() != 1 || len(recorder.snapshot()) != 1 {
				t.Fatal("successful later DNS query replaced independent Session")
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			requireFakeIPCleared(t, recorder.snapshot()[0], ip)
		})
	}
}
