package socks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"bfp/gateway"
	"bfp/protocol"
)

func TestFakeIPTargetRestorerRunsBeforeMetadataBackend(t *testing.T) {
	echo := tcpMetadataEcho(t)
	_, port, err := net.SplitHostPort(echo)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := gateway.NewFakeIPScope(context.Background(), time.Minute, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer scope.Close()
	fake, err := scope.Allocate("restore.example.test")
	if err != nil {
		t.Fatal(err)
	}

	b := newMetadataBackend(t, echo)
	s, _ := startServer(t, Config{
		Backend:        b,
		DomainSource:   DomainSourceSOCKSAddress,
		TargetRestorer: scope,
	})
	encoded, err := encodeAddress(net.JoinHostPort(fake.String(), port))
	if err != nil {
		t.Fatal(err)
	}
	c, code, _ := connectEncodedSOCKS(t, s, 1, encoded)
	if code != 0 {
		t.Fatalf("SOCKS reply=%d", code)
	}
	payload := []byte("fake-ip metadata")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, bytes.ToUpper(payload)) {
		t.Fatalf("echo=%q err=%v", got, err)
	}
	metas, decisions := b.records()
	if len(metas) != 1 || len(decisions) != 1 {
		t.Fatalf("metadata=%v decisions=%v", metas, decisions)
	}
	meta := metas[0]
	if meta.Target.Address != "restore.example.test:"+port || meta.Target.Domain != "restore.example.test" || !meta.DomainTrusted {
		t.Fatalf("restored metadata=%+v", meta)
	}
	if decisions[0].Class != protocol.Interactive {
		t.Fatalf("restored domain did not reach local rule: %+v", decisions[0])
	}
}

func TestFakeIPTargetRestorerRunsBeforeLegacyBackend(t *testing.T) {
	echo := tcpMetadataEcho(t)
	_, port, err := net.SplitHostPort(echo)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := gateway.NewFakeIPScope(context.Background(), time.Minute, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer scope.Close()
	fake, err := scope.Allocate("legacy-restore.example.test")
	if err != nil {
		t.Fatal(err)
	}
	b := &legacyRestoreBackend{trackingBackend: trackingBackend{}, dialTarget: echo}
	s, _ := startServer(t, Config{Backend: b, TargetRestorer: scope})
	encoded, err := encodeAddress(net.JoinHostPort(fake.String(), port))
	if err != nil {
		t.Fatal(err)
	}
	c, code, _ := connectEncodedSOCKS(t, s, 1, encoded)
	if code != 0 {
		t.Fatalf("SOCKS reply=%d", code)
	}
	payload := []byte("fake-ip legacy")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, bytes.ToUpper(payload)) {
		t.Fatalf("echo=%q err=%v", got, err)
	}
	if len(b.requested) != 1 || b.requested[0] != "legacy-restore.example.test:"+port {
		t.Fatalf("legacy backend address=%v", b.requested)
	}
}

func TestFakeIPTargetRestorerRunsForUDPBusinessFlow(t *testing.T) {
	upstream, _ := udpEcho(t)
	_, port, err := net.SplitHostPort(upstream.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := gateway.NewFakeIPScope(context.Background(), time.Minute, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer scope.Close()
	fake, err := scope.Allocate("udp-restore.example.test")
	if err != nil {
		t.Fatal(err)
	}
	b := newMetadataBackend(t, upstream.LocalAddr().String())
	s, _ := startServer(t, Config{
		Backend:        b,
		DomainSource:   DomainSourceSOCKSAddress,
		TargetRestorer: scope,
	})
	control, client, relay := udpMetadataClient(t, s, domainEncoding(t, "control.example.test", "0"))
	defer control.Close()
	fakeEncoded, err := encodeAddress(net.JoinHostPort(fake.String(), port))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("fake-ip udp")
	if got := udpMetadataExchange(t, client, relay, fakeEncoded, payload); !bytes.Equal(got, fakeEncoded) {
		t.Fatalf("response target encoding=%v want=%v", got, fakeEncoded)
	}
	metas, decisions := b.records()
	if len(metas) != 1 || len(decisions) != 1 {
		t.Fatalf("metadata=%v decisions=%v", metas, decisions)
	}
	if metas[0].Target.Network != "udp" || metas[0].Target.Address != "udp-restore.example.test:"+port || !metas[0].DomainTrusted || metas[0].Target.Domain != "udp-restore.example.test" {
		t.Fatalf("restored UDP metadata=%+v", metas[0])
	}
}

type legacyRestoreBackend struct {
	trackingBackend
	dialTarget string
	requested  []string
}

func (b *legacyRestoreBackend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	b.mu.Lock()
	b.requested = append(b.requested, address)
	b.mu.Unlock()
	return b.trackingBackend.DialContext(ctx, network, b.dialTarget)
}

func TestTargetRestorerCannotChangeNetworkOrAddressShape(t *testing.T) {
	b := newMetadataBackend(t, "")
	bad := targetRestorerFunc(func(target protocol.Target) (protocol.Target, error) {
		target.Network = "udp"
		return target, nil
	})
	s, _ := startServer(t, Config{Backend: b, TargetRestorer: bad})
	if _, err := s.dialTarget(context.Background(), "tcp", "example.test:443", 3); !errors.Is(err, ErrTargetRestorer) {
		t.Fatalf("network-changing restorer err=%v", err)
	}
}

type targetRestorerFunc func(protocol.Target) (protocol.Target, error)

func (f targetRestorerFunc) RestoreTarget(target protocol.Target) (protocol.Target, error) {
	return f(target)
}
