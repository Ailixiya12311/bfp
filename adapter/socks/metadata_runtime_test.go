package socks

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"bfp/classification"
	"bfp/protocol"
	"bfp/security"
	"bfp/session"
)

// The local target mapping is a fixture DNS seam, not a gateway DNS/policy test.
// Session still carries the unchanged requested address over real encrypted I/O.
type metadataExitBackend struct {
	trackingBackend
	tcpTarget, udpTarget string
	muRequest            sync.Mutex
	requested            []string
}

func (b *metadataExitBackend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	b.muRequest.Lock()
	b.requested = append(b.requested, address)
	b.muRequest.Unlock()
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) == nil {
		if network == "tcp" {
			address = b.tcpTarget
		} else {
			address = b.udpTarget
		}
	}
	return b.trackingBackend.DialContext(ctx, network, address)
}

type metadataRuntimeClient struct {
	client *session.Client
	mu     sync.Mutex
	flows  []*session.Flow
	metas  []classification.Metadata
	legacy int
}

func (b *metadataRuntimeClient) remember(c net.Conn, err error) (net.Conn, error) {
	if err == nil {
		b.mu.Lock()
		b.flows = append(b.flows, c.(*session.Flow))
		b.mu.Unlock()
	}
	return c, err
}
func (b *metadataRuntimeClient) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	b.mu.Lock()
	b.legacy++
	b.mu.Unlock()
	return b.remember(b.client.DialContext(ctx, network, address))
}
func (b *metadataRuntimeClient) DialMetadata(ctx context.Context, meta classification.Metadata) (net.Conn, error) {
	b.mu.Lock()
	b.metas = append(b.metas, meta)
	b.mu.Unlock()
	return b.remember(b.client.DialMetadata(ctx, meta))
}
func (b *metadataRuntimeClient) state() ([]*session.Flow, []classification.Metadata, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*session.Flow(nil), b.flows...), append([]classification.Metadata(nil), b.metas...), b.legacy
}

func newMetadataRuntime(t *testing.T, local classification.Config) (*metadataRuntimeClient, *session.Session, *metadataExitBackend) {
	t.Helper()
	tcp := tcpMetadataEcho(t)
	udp, _ := udpEcho(t)
	backend := &metadataExitBackend{tcpTarget: tcp, udpTarget: udp.LocalAddr().String()}
	sk, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ck, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	admission := make([]byte, 32)
	if _, err := rand.Read(admission); err != nil {
		t.Fatal(err)
	}
	// The peer receives no local DomainTrusted flag and uses its own cap. The
	// session package independently verifies that peer TX snapshot contract.
	peer := classification.DefaultConfig()
	peer.DefaultClass = protocol.Bulk
	peer.HighestAllowed = protocol.Bulk
	peer.Behavior.Enabled = false
	peer.Rules = []classification.Rule{{Name: "peer-domain", DomainSuffix: "example.test", Class: protocol.Interactive}}
	opts := session.Options{HandshakeTimeout: time.Second, ProbeInterval: 100 * time.Millisecond, FailureTimeout: 5 * time.Second, RetainTimeout: time.Second}
	server, err := session.NewServer(session.ServerConfig{Listen: "127.0.0.1:0", Backend: backend, Credentials: session.Credentials{Admission: admission, Private: sk.Private, Public: sk.Public, AllowedClients: [][]byte{ck.Public}}, Options: opts, Classification: &peer})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(context.Background()) }()
	t.Cleanup(func() {
		server.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("BFP server did not stop")
		}
	})
	client, err := session.NewClient(session.ClientConfig{Server: server.Addr().String(), TCPServer: server.Addr().String(), Credentials: session.Credentials{Admission: admission, Private: ck.Private, Public: ck.Public, ServerPublic: sk.Public}, Options: opts, Classification: &local})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return &metadataRuntimeClient{client: client}, s, backend
}

func metadataLocalPolicy() classification.Config {
	cfg := classification.DefaultConfig()
	cfg.Behavior.Enabled = false
	cfg.Rules = []classification.Rule{{Name: "local-domain", DomainSuffix: "example.test", Class: protocol.Interactive}, {Name: "port-network", Network: "tcp", Class: protocol.Bulk}}
	return cfg
}

func TestMetadataRuntimeCONNECTRuleCapAndLegacyDefault(t *testing.T) {
	for _, tc := range []struct {
		name      string
		source    DomainSource
		cap, want protocol.Class
		rule      string
	}{
		{"opt_in", DomainSourceSOCKSAddress, protocol.Interactive, protocol.Interactive, "local-domain"},
		{"local_cap", DomainSourceSOCKSAddress, protocol.Normal, protocol.Normal, "local-domain"},
		{"default_ignore", "", protocol.Interactive, protocol.Bulk, "port-network"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := metadataLocalPolicy()
			cfg.HighestAllowed = tc.cap
			backend, s, exit := newMetadataRuntime(t, cfg)
			proxy, _ := startServer(t, Config{Backend: backend, DomainSource: tc.source})
			_, port, _ := net.SplitHostPort(exit.tcpTarget)
			c, code, _ := connectEncodedSOCKS(t, proxy, 1, domainEncoding(t, "Call.Example.TEST.", port))
			if code != 0 {
				t.Fatal(code)
			}
			flows, metas, legacy := backend.state()
			if len(flows) != 1 {
				t.Fatalf("flows=%d", len(flows))
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			snap, err := flows[0].Classification(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if snap.LocalTX.Class != tc.want || snap.LocalTX.Baseline.Rule != tc.rule || snap.LocalTX.Baseline.Source == classification.SourceHint {
				t.Fatalf("classification=%+v", snap)
			}
			if tc.source == "" {
				if len(metas) != 0 || legacy != 1 {
					t.Fatal("ignore created metadata")
				}
			} else {
				if len(metas) != 1 || legacy != 0 || metas[0].Hint != nil || !metas[0].DomainTrusted {
					t.Fatalf("metadata=%+v legacy=%d", metas, legacy)
				}
			}
			payload := []byte("encrypted BFP SOCKS half-close")
			if _, err := c.Write(payload); err != nil {
				t.Fatal(err)
			}
			c.(*net.TCPConn).CloseWrite()
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, bytes.ToUpper(payload)) {
				t.Fatalf("reply=%q err=%v", got, err)
			}
			if stats := s.Stats(); stats.Opened != 1 || stats.Carrier != "udp" {
				t.Fatalf("session=%+v", stats)
			}
			exit.muRequest.Lock()
			requested := append([]string(nil), exit.requested...)
			exit.muRequest.Unlock()
			if len(requested) != 1 || requested[0] != net.JoinHostPort("Call.Example.TEST.", port) {
				t.Fatalf("encrypted OPEN changed target identity: %v", requested)
			}
			waitFor(t, func() bool { return exit.active.Load() == 0 })
		})
	}
}

func TestMetadataRuntimeInvalidDomainDoesNotAllocateOPEN(t *testing.T) {
	backend, s, exit := newMetadataRuntime(t, metadataLocalPolicy())
	proxy, _ := startServer(t, Config{Backend: backend, DomainSource: DomainSourceSOCKSAddress})
	_, port, _ := net.SplitHostPort(exit.tcpTarget)
	before := s.Stats()
	for _, host := range []string{"bad_name.test", "中文.test", "bad..example.test"} {
		_, code, _ := connectEncodedSOCKS(t, proxy, 1, domainEncoding(t, host, port))
		if code != 1 {
			t.Fatalf("host=%q code=%d", host, code)
		}
	}
	if after := s.Stats(); after.Opened != before.Opened || after.Flows != before.Flows || exit.dials.Load() != 0 {
		t.Fatalf("invalid metadata allocated/opened target: before=%+v after=%+v exit=%d", before, after, exit.dials.Load())
	}
	// The first valid request still receives the first flow identifier.
	c, code, _ := connectEncodedSOCKS(t, proxy, 1, domainEncoding(t, "valid.example.test", port))
	if code != 0 {
		t.Fatal(code)
	}
	defer c.Close()
	flows, _, _ := backend.state()
	snap, err := flows[0].Classification(context.Background())
	if err != nil || snap.ID != 1 {
		t.Fatalf("snapshot=%+v err=%v", snap, err)
	}
}

func TestMetadataRuntimeUDPUsesBusinessDomainAndReusesFlow(t *testing.T) {
	cfg := metadataLocalPolicy()
	cfg.Rules = cfg.Rules[:1]
	backend, s, exit := newMetadataRuntime(t, cfg)
	proxy, _ := startServer(t, Config{Backend: backend, DomainSource: DomainSourceSOCKSAddress})
	control, c, relay := udpMetadataClient(t, proxy, []byte{1, 0, 0, 0, 0, 0, 0})
	_, port, _ := net.SplitHostPort(exit.udpTarget)
	encoded := domainEncoding(t, "UDP.Example.TEST.", port)
	invalid := domainEncoding(t, "bad_name.example.test", port)
	c.WriteToUDP(append(append([]byte{0, 0, 0}, invalid...), 1), relay)
	c.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	var invalidReply [32]byte
	if _, _, err := c.ReadFromUDP(invalidReply[:]); err == nil {
		t.Fatal("invalid trusted UDP domain received a reply")
	}
	if stats := s.Stats(); stats.Opened != 0 || exit.dials.Load() != 0 {
		t.Fatalf("invalid UDP domain allocated OPEN: stats=%+v exit=%d", stats, exit.dials.Load())
	}
	for _, payload := range [][]byte{[]byte("datagram"), {}, bytes.Repeat([]byte("u"), 16000)} {
		if got := udpMetadataExchange(t, c, relay, encoded, payload); !bytes.Equal(got, encoded) {
			t.Fatal("original UDP reply envelope changed")
		}
	}
	flows, metas, legacy := backend.state()
	if len(flows) != 1 || len(metas) != 1 || legacy != 0 || !metas[0].DomainTrusted || metas[0].Target.Domain != "UDP.Example.TEST." || metas[0].Hint != nil {
		t.Fatalf("flow=%d metadata=%+v legacy=%d", len(flows), metas, legacy)
	}
	snap, err := flows[0].Classification(context.Background())
	if err != nil || snap.ID != 1 || snap.LocalTX.Class != protocol.Interactive || snap.LocalTX.TotalBytes != 16008 {
		t.Fatalf("snapshot=%+v err=%v", snap, err)
	}
	if stats := s.Stats(); stats.Opened != 1 || exit.dials.Load() != 1 {
		t.Fatalf("cache redial: stats=%+v exits=%d", stats, exit.dials.Load())
	}
	control.Close()
	waitFor(t, func() bool { return exit.active.Load() == 0 })
}
