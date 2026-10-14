package socks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"bfp/classification"
	"bfp/protocol"
)

type metadataRecordBackend struct {
	trackingBackend
	muMeta    sync.Mutex
	metas     []classification.Metadata
	decisions []classification.Decision
	policy    *classification.Classifier
	target    string
	returned  net.Conn
}

func newMetadataBackend(t *testing.T, target string) *metadataRecordBackend {
	t.Helper()
	cfg := classification.DefaultConfig()
	cfg.Behavior.Enabled = false
	cfg.Rules = []classification.Rule{{Name: "domain", DomainSuffix: "example.test", Class: protocol.Interactive}, {Name: "port", Network: "udp", Class: protocol.Bulk}}
	p, err := classification.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &metadataRecordBackend{policy: p, target: target}
}

func (b *metadataRecordBackend) DialMetadata(ctx context.Context, meta classification.Metadata) (net.Conn, error) {
	b.muMeta.Lock()
	b.metas = append(b.metas, meta)
	b.muMeta.Unlock()
	d, err := b.policy.Decide(meta)
	if err != nil {
		return nil, err
	}
	b.muMeta.Lock()
	b.decisions = append(b.decisions, d)
	b.muMeta.Unlock()
	address := meta.Target.Address
	if b.target != "" {
		address = b.target
	}
	c, err := b.trackingBackend.DialContext(ctx, meta.Target.Network, address)
	b.muMeta.Lock()
	b.returned = c
	b.muMeta.Unlock()
	return c, err
}

func (b *metadataRecordBackend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if b.target != "" {
		address = b.target
	}
	return b.trackingBackend.DialContext(ctx, network, address)
}

func (b *metadataRecordBackend) records() ([]classification.Metadata, []classification.Decision) {
	b.muMeta.Lock()
	defer b.muMeta.Unlock()
	return append([]classification.Metadata(nil), b.metas...), append([]classification.Decision(nil), b.decisions...)
}

func domainEncoding(t *testing.T, host, portText string) []byte {
	t.Helper()
	port, err := strconv.Atoi(portText)
	if err != nil || len(host) == 0 || len(host) > 255 {
		t.Fatal("invalid test address")
	}
	return append(append([]byte{3, byte(len(host))}, []byte(host)...), byte(port>>8), byte(port))
}

func connectEncodedSOCKS(t *testing.T, s *Server, command byte, encoded []byte) (net.Conn, byte, string) {
	t.Helper()
	c, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if err := writeAll(c, []byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(c, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatalf("greeting=%v err=%v", greeting, err)
	}
	if err := writeAll(c, append([]byte{5, command, 0}, encoded...)); err != nil {
		t.Fatal(err)
	}
	var response [4]byte
	if _, err := io.ReadFull(c, response[:]); err != nil {
		t.Fatal(err)
	}
	bound, _, err := readAddress(c, response[3])
	if err != nil {
		t.Fatal(err)
	}
	return c, response[1], bound
}

func tcpMetadataEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				data, err := io.ReadAll(c)
				if err == nil {
					writeAll(c, bytes.ToUpper(data))
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestDomainSourceValidationPrecedesListen(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	for _, tc := range []struct {
		source DomainSource
		want   error
	}{
		{DomainSourceSOCKSAddress, ErrMetadataBackend}, {"sniff", ErrDomainSource},
	} {
		s, err := New(Config{Backend: &trackingBackend{}, Listen: occupied.Addr().String(), DomainSource: tc.source})
		if s != nil || !errors.Is(err, tc.want) {
			t.Fatalf("source=%q got=%v want=%v", tc.source, err, tc.want)
		}
	}
	for _, source := range []DomainSource{"", DomainSourceIgnore} {
		s, err := New(Config{Backend: &trackingBackend{}, DomainSource: source})
		if err != nil {
			t.Fatal(err)
		}
		if s.cfg.DomainSource != DomainSourceIgnore || s.metadata != nil {
			t.Fatal("default required optional capability")
		}
		s.Close()
	}
}

func TestMetadataCONNECTUsesActualATYPWithoutHint(t *testing.T) {
	target := tcpMetadataEcho(t)
	_, port, _ := net.SplitHostPort(target)
	for _, tc := range []struct {
		name, host string
		atyp       byte
		domain     string
		class      protocol.Class
	}{
		{"domain", "Call.Example.TEST.", 3, "Call.Example.TEST.", protocol.Interactive},
		{"text_ipv4", "127.0.0.1", 3, "", protocol.Normal},
		{"text_ipv6", "::1", 3, "", protocol.Normal},
		{"ipv4", "127.0.0.1", 1, "", protocol.Normal},
		{"ipv6", "::1", 4, "", protocol.Normal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newMetadataBackend(t, target)
			s, _ := startServer(t, Config{Backend: b, DomainSource: DomainSourceSOCKSAddress})
			address := net.JoinHostPort(tc.host, port)
			encoded, err := encodeAddress(address)
			if err != nil {
				t.Fatal(err)
			}
			if tc.atyp == 3 {
				encoded = domainEncoding(t, tc.host, port)
			}
			c, code, _ := connectEncodedSOCKS(t, s, 1, encoded)
			if code != 0 {
				t.Fatal(code)
			}
			payload := []byte("half close metadata")
			if _, err := c.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := c.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, bytes.ToUpper(payload)) {
				t.Fatalf("reply=%q err=%v", got, err)
			}
			metas, decisions := b.records()
			if len(metas) != 1 || len(decisions) != 1 {
				t.Fatal(metas, decisions)
			}
			m := metas[0]
			if m.Target.Network != "tcp" || m.Target.Address != address || m.Target.Domain != tc.domain || m.DomainTrusted != (tc.domain != "") || m.Target.RuleTag != "" || m.RuleTagTrusted || m.Hint != nil || m.Target.Class != protocol.Normal || decisions[0].Class != tc.class {
				t.Fatalf("envelope=%+v decision=%+v", m, decisions[0])
			}
			waitFor(t, func() bool { return b.active.Load() == 0 })
		})
	}
}

func TestMetadataCONNECTRejectsInvalidTrustedDomain(t *testing.T) {
	for _, host := range []string{"bad_name.test", "-bad.test", "bad..test", "中文.test", strings.Repeat("a", 64) + ".test"} {
		t.Run(host, func(t *testing.T) {
			b := newMetadataBackend(t, "")
			s, _ := startServer(t, Config{Backend: b, DomainSource: DomainSourceSOCKSAddress})
			_, code, _ := connectEncodedSOCKS(t, s, 1, domainEncoding(t, host, "443"))
			if code != 1 || b.dials.Load() != 0 {
				t.Fatalf("code=%d targetdials=%d", code, b.dials.Load())
			}
			metas, decisions := b.records()
			if len(metas) != 0 || len(decisions) != 0 {
				t.Fatalf("invalid domain reached metadata backend: metas=%v decisions=%v", metas, decisions)
			}
		})
	}
}

func TestIgnoreMetadataBackendKeepsLegacyDial(t *testing.T) {
	target := tcpMetadataEcho(t)
	b := newMetadataBackend(t, "")
	s, _ := startServer(t, Config{Backend: b})
	_, port, _ := net.SplitHostPort(target)
	c, code, _ := connectSOCKS(t, s, 1, net.JoinHostPort("localhost", port))
	if code != 0 {
		t.Fatal(code)
	}
	if _, err := c.Write([]byte("legacy")); err != nil {
		t.Fatal(err)
	}
	c.(*net.TCPConn).CloseWrite()
	if got, err := io.ReadAll(c); err != nil || string(got) != "LEGACY" {
		t.Fatalf("reply=%q err=%v", got, err)
	}
	metas, _ := b.records()
	if len(metas) != 0 || b.dials.Load() != 1 {
		t.Fatalf("metadata=%v dials=%d", metas, b.dials.Load())
	}
}

func TestIgnoreUDPMetadataBackendKeepsLegacyDial(t *testing.T) {
	upstream, _ := udpEcho(t)
	b := newMetadataBackend(t, upstream.LocalAddr().String())
	s, _ := startServer(t, Config{Backend: b, DomainSource: DomainSourceIgnore})
	control, c, relay := udpMetadataClient(t, s, domainEncoding(t, "control.example.test", "0"))
	_, port, _ := net.SplitHostPort(upstream.LocalAddr().String())
	encoded := domainEncoding(t, "localhost", port)
	udpMetadataExchange(t, c, relay, encoded, []byte("legacy UDP"))
	metas, _ := b.records()
	if len(metas) != 0 || b.dials.Load() != 1 {
		t.Fatalf("ignore UDP created metadata=%v dials=%d", metas, b.dials.Load())
	}
	control.Close()
	waitFor(t, func() bool { return b.active.Load() == 0 })
}

type pendingMetadataBackend struct {
	started  chan struct{}
	canceled chan error
}

func (b *pendingMetadataBackend) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected legacy dial")
}

func (b *pendingMetadataBackend) DialMetadata(ctx context.Context, _ classification.Metadata) (net.Conn, error) {
	close(b.started)
	<-ctx.Done()
	b.canceled <- ctx.Err()
	return nil, ctx.Err()
}

func TestMetadataCONNECTDeadlineAndServerCancellation(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		b := &pendingMetadataBackend{started: make(chan struct{}), canceled: make(chan error, 1)}
		s, _ := startServer(t, Config{Backend: b, DomainSource: DomainSourceSOCKSAddress, HandshakeTimeout: 40 * time.Millisecond})
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel()
		if c, err := s.dialTarget(ctx, "tcp", "deadline.example.test:443", 3); c != nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("deadline result c=%v err=%v", c, err)
		}
		if err := <-b.canceled; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("backend did not receive deadline", err)
		}
	})
	t.Run("server_close", func(t *testing.T) {
		b := &pendingMetadataBackend{started: make(chan struct{}), canceled: make(chan error, 1)}
		s, _ := startServer(t, Config{Backend: b, DomainSource: DomainSourceSOCKSAddress, HandshakeTimeout: time.Second})
		c, err := net.Dial("tcp", s.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		writeAll(c, []byte{5, 1, 0})
		var greeting [2]byte
		if _, err := io.ReadFull(c, greeting[:]); err != nil {
			t.Fatal(err)
		}
		writeAll(c, append([]byte{5, 1, 0}, domainEncoding(t, "cancel.example.test", "443")...))
		select {
		case <-b.started:
		case <-time.After(time.Second):
			t.Fatal("metadata dial did not start")
		}
		s.Close()
		select {
		case err := <-b.canceled:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("server close did not cancel metadata dial", err)
			}
		case <-time.After(time.Second):
			t.Fatal("metadata dial survived server close")
		}
		// Cancellation may race with the normal SOCKS failure reply. Either a
		// closed control or that bounded reply is valid; the metadata dial must
		// already have observed context cancellation above.
		if n, err := c.Read(greeting[:]); n > 2 || (n == 0 && err == nil) {
			t.Fatalf("control survived server close n=%d err=%v", n, err)
		}
	})
}

func TestMetadataDialPreservesOriginalConnection(t *testing.T) {
	target := tcpMetadataEcho(t)
	b := newMetadataBackend(t, target)
	s, _ := startServer(t, Config{Backend: b, DomainSource: DomainSourceSOCKSAddress})
	c, err := s.dialTarget(context.Background(), "tcp", "call.example.test:443", 3)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b.muMeta.Lock()
	original := b.returned
	b.muMeta.Unlock()
	if c != original {
		t.Fatal("metadata helper wrapped original connection")
	}
	if _, ok := c.(interface{ CloseWrite() error }); !ok {
		t.Fatal("metadata helper lost CloseWrite")
	}
	if err := c.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}

func udpMetadataClient(t *testing.T, s *Server, controlEncoded []byte) (net.Conn, *net.UDPConn, *net.UDPAddr) {
	t.Helper()
	control, code, bound := connectEncodedSOCKS(t, s, 3, controlEncoded)
	if code != 0 {
		t.Fatal(code)
	}
	address, err := net.ResolveUDPAddr("udp", bound)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); control.Close() })
	return control, c, address
}

func udpMetadataExchange(t *testing.T, c *net.UDPConn, relay *net.UDPAddr, encoded, payload []byte) []byte {
	t.Helper()
	if _, err := c.WriteToUDP(append(append([]byte{0, 0, 0}, encoded...), payload...), relay); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 65535)
	n, _, err := c.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n < 4 {
		t.Fatal("short SOCKS UDP reply")
	}
	r := bytes.NewReader(buffer[4:n])
	_, gotEncoded, err := readAddress(r, buffer[3])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer[n-r.Len():n], payload) {
		t.Fatalf("UDP payload changed got=%d want=%d", r.Len(), len(payload))
	}
	return gotEncoded
}

func TestMetadataUDPBusinessSourceCacheAndFirstEncoding(t *testing.T) {
	upstream, _ := udpEcho(t)
	_, port, _ := net.SplitHostPort(upstream.LocalAddr().String())
	b := newMetadataBackend(t, upstream.LocalAddr().String())
	s, _ := startServer(t, Config{Backend: b, DomainSource: DomainSourceSOCKSAddress, MaxUDPTargets: 3})
	// The control's ATYP=3 must never supply the business flow's domain.
	control, c, relay := udpMetadataClient(t, s, domainEncoding(t, "control.example.test", "0"))
	first := domainEncoding(t, "Call.Example.TEST.", port)
	for _, payload := range [][]byte{[]byte("one"), {}, bytes.Repeat([]byte("x"), 16000)} {
		if got := udpMetadataExchange(t, c, relay, first, payload); !bytes.Equal(got, first) {
			t.Fatal("first domain encoding changed")
		}
	}
	textIP := domainEncoding(t, "127.0.0.1", port)
	if got := udpMetadataExchange(t, c, relay, textIP, []byte("text IP")); !bytes.Equal(got, textIP) {
		t.Fatal("text IP encoding changed")
	}
	ip, _ := encodeAddress(upstream.LocalAddr().String())
	if got := udpMetadataExchange(t, c, relay, ip, []byte("same address alias")); !bytes.Equal(got, textIP) {
		t.Fatal("cache alias replaced first encoded address")
	}
	otherCase := domainEncoding(t, "call.example.test.", port)
	if got := udpMetadataExchange(t, c, relay, otherCase, []byte("separate raw identity")); !bytes.Equal(got, otherCase) {
		t.Fatal("case identity merged")
	}
	metas, decisions := b.records()
	if len(metas) != 3 || len(decisions) != 3 || b.dials.Load() != 3 {
		t.Fatalf("metadata=%v decisions=%v dials=%d", metas, decisions, b.dials.Load())
	}
	if metas[0].Target.Domain != "Call.Example.TEST." || !metas[0].DomainTrusted || metas[1].Target.Domain != "" || metas[1].DomainTrusted || metas[2].Target.Domain != "call.example.test." || decisions[1].Class != protocol.Bulk {
		t.Fatalf("business envelope=%+v decisions=%+v", metas, decisions)
	}
	for _, m := range metas {
		if m.Hint != nil || m.RuleTagTrusted || m.Target.RuleTag != "" || m.Target.Network != "udp" {
			t.Fatalf("fabricated metadata=%+v", m)
		}
	}
	control.Close()
	waitFor(t, func() bool { return b.active.Load() == 0 })
}

func TestMetadataUDPRejectsInvalidNamesAndKeepsLimits(t *testing.T) {
	upstream, count := udpEcho(t)
	_, port, _ := net.SplitHostPort(upstream.LocalAddr().String())
	b := newMetadataBackend(t, upstream.LocalAddr().String())
	s, _ := startServer(t, Config{Backend: b, DomainSource: DomainSourceSOCKSAddress, MaxUDPTargets: 1})
	control, c, relay := udpMetadataClient(t, s, []byte{1, 0, 0, 0, 0, 0, 0})
	invalid := domainEncoding(t, "bad_name.test", port)
	c.WriteToUDP(append(append([]byte{0, 0, 0}, invalid...), 1), relay)
	c.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	var buffer [32]byte
	if _, _, err := c.ReadFromUDP(buffer[:]); err == nil {
		t.Fatal("invalid trusted name received a reply")
	}
	if b.dials.Load() != 0 || count.Load() != 0 {
		t.Fatal("invalid trusted name dialed a target")
	}
	first := domainEncoding(t, "first.example.test", port)
	udpMetadataExchange(t, c, relay, first, []byte("valid"))
	second := domainEncoding(t, "second.example.test", port)
	c.WriteToUDP(append(append([]byte{0, 0, 0}, second...), 1), relay)
	fragment := append(append([]byte{0, 0, 1}, first...), 1)
	c.WriteToUDP(fragment, relay)
	other, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.WriteToUDP(append(append([]byte{0, 0, 0}, first...), 1), relay)
	c.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	if _, _, err := c.ReadFromUDP(buffer[:]); err == nil {
		t.Fatal("limited target or fragment got reply")
	}
	metas, _ := b.records()
	if len(metas) != 1 || b.dials.Load() != 1 || count.Load() != 1 {
		t.Fatalf("metadata=%d dials=%d targetwrites=%d", len(metas), b.dials.Load(), count.Load())
	}
	control.Close()
	waitFor(t, func() bool { return b.active.Load() == 0 })
}
