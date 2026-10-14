package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	dnsfront "bfp/adapter/dns"
	"bfp/internal/addressscope"
	"bfp/session"
	"golang.org/x/net/dns/dnsmessage"
)

func startClientDNSFrontend(t *testing.T, ctx context.Context, selector dnsfront.SessionSelector) *dnsfront.Server {
	t.Helper()
	front, err := dnsfront.New(dnsfront.Config{Client: selector, QueryTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- front.Serve(ctx) }()
	t.Cleanup(func() {
		front.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("owned DNS frontend did not join")
		}
	})
	return front
}

func clientDNSQuery(t *testing.T, ctx context.Context, front *dnsfront.Server, network, host string, types ...dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	typ := dnsmessage.TypeA
	if len(types) != 0 {
		typ = types[0]
	}
	return clientDNSQueryMode(t, ctx, front, network, host, typ, false)
}

func clientDNSQueryMode(t *testing.T, ctx context.Context, front *dnsfront.Server, network, host string, typ dnsmessage.Type, edns bool) dnsmessage.Message {
	t.Helper()
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		t.Fatal(err)
	}
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: 6789, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: typ, Class: dnsmessage.ClassINET}}}
	if edns {
		var opt dnsmessage.ResourceHeader
		if err := opt.SetEDNS0(4096, 0, true); err != nil {
			t.Fatal(err)
		}
		query.Additionals = []dnsmessage.Resource{{Header: opt, Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 12, Data: make([]byte, 24)}}}}}
	}
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	if network == "tcp" {
		wire = append(binary.BigEndian.AppendUint16(nil, uint16(len(wire))), wire...)
	}
	if _, err := conn.Write(wire); err != nil {
		t.Fatal(err)
	}
	var response []byte
	if network == "tcp" {
		var prefix [2]byte
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			t.Fatal(err)
		}
		size := int(binary.BigEndian.Uint16(prefix[:]))
		if size < 12 || size > 1232 {
			t.Fatalf("invalid DNS TCP response size=%d", size)
		}
		response = make([]byte, size)
		if _, err := io.ReadFull(conn, response); err != nil {
			t.Fatal(err)
		}
	} else {
		response = make([]byte, 1232)
		n, err := conn.Read(response)
		if err != nil {
			t.Fatal(err)
		}
		response = response[:n]
	}
	var result dnsmessage.Message
	if err := result.Unpack(response); err != nil || !result.Response || result.ID != query.ID || len(result.Questions) != 1 || result.Questions[0] != query.Questions[0] {
		t.Fatalf("DNS reply source/question/ID invalid: %+v err=%v", result, err)
	}
	if edns {
		if len(result.Additionals) != 1 || result.Additionals[0].Header.Type != dnsmessage.TypeOPT || result.Additionals[0].Header.Class != 1232 || !result.Additionals[0].Header.DNSSECAllowed() || result.AuthenticData {
			t.Fatal("DNS did not negotiate EDNS for the real exit path")
		}
		options, ok := result.Additionals[0].Body.(*dnsmessage.OPTResource)
		if !ok || len(options.Options) != 0 {
			t.Fatal("DNS reflected unsupported EDNS options")
		}
	} else if len(result.Additionals) != 0 {
		t.Fatal("DNS added EDNS to a legacy query")
	}
	return result
}

func requireClientDNSAddress(t *testing.T, response dnsmessage.Message) (netip.Addr, uint32) {
	t.Helper()
	if response.RCode != dnsmessage.RCodeSuccess || len(response.Answers) != 1 {
		t.Fatalf("DNS did not return a single address answer: %+v", response)
	}
	answer := response.Answers[0]
	var ip netip.Addr
	switch body := answer.Body.(type) {
	case *dnsmessage.AResource:
		if answer.Header.Type != dnsmessage.TypeA {
			t.Fatal("A body has wrong resource type")
		}
		ip = netip.AddrFrom4(body.A)
	case *dnsmessage.AAAAResource:
		if answer.Header.Type != dnsmessage.TypeAAAA {
			t.Fatal("AAAA body has wrong resource type")
		}
		ip = netip.AddrFrom16(body.AAAA)
	default:
		t.Fatal("DNS reply has no supported address body")
	}
	if answer.Header.Type != response.Questions[0].Type || answer.Header.Class != dnsmessage.ClassINET || answer.Header.TTL == 0 || answer.Header.Name != response.Questions[0].Name {
		t.Fatal("DNS reply is not a positive scoped address lease")
	}
	if _, valid := addressscope.MappingAddress(ip); !valid {
		t.Fatalf("DNS returned non-fake address: %s", ip)
	}
	return ip, answer.Header.TTL
}

func TestClientDNSFrontendRealUDPAndTCPQueriesRestoreTCPAndUDPExit(t *testing.T) {
	testClientDNSFrontendExitMatrix(t, false)
}

func TestClientDNSFrontendEDNSQueriesRestoreTCPAndUDPExit(t *testing.T) {
	testClientDNSFrontendExitMatrix(t, true)
}

func testClientDNSFrontendExitMatrix(t *testing.T, edns bool) {
	t.Helper()
	for _, tc := range []struct {
		queryNetwork string
		typ          dnsmessage.Type
		exitIP       string
	}{
		{"udp", dnsmessage.TypeA, "127.0.0.1"}, {"tcp", dnsmessage.TypeA, "127.0.0.1"},
		{"udp", dnsmessage.TypeAAAA, "127.0.0.1"}, {"tcp", dnsmessage.TypeAAAA, "127.0.0.1"},
		{"udp", dnsmessage.TypeA, "::1"}, {"tcp", dnsmessage.TypeA, "::1"},
		{"udp", dnsmessage.TypeAAAA, "::1"}, {"tcp", dnsmessage.TypeAAAA, "::1"},
	} {
		t.Run(tc.queryNetwork+"/"+tc.typ.String()+"/"+tc.exitIP, func(t *testing.T) {
			queryNetwork := tc.queryNetwork
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			tcpPort, targets := sessionDNSRuntimeEcho(t, deadline, tc.exitIP)
			udpEcho, messages := sessionFakeIPRuntimeUDPEcho(t, tc.exitIP)
			udpPort := udpEcho.LocalAddr().(*net.UDPAddr).Port
			prefix := tc.exitIP + "/32"
			if tc.exitIP == "::1" {
				prefix = tc.exitIP + "/128"
			}
			base, err := New(Policy{AllowPrivate: true, AllowedCIDRs: []string{prefix}, AllowedPorts: []int{tcpPort, udpPort}, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			const host = "actual-dns-client.test"
			var lookups atomic.Int32
			base.lookup = func(_ context.Context, name string) ([]net.IPAddr, error) {
				if name != host {
					return nil, errors.New("DNS answer did not restore to original hostname")
				}
				lookups.Add(1)
				return []net.IPAddr{{IP: net.ParseIP(tc.exitIP)}}, nil
			}
			opts := session.Options{MaxSessionLifetime: 6 * time.Second}
			server, credentials := sessionDNSTerminationServer(t, ctx, &sessionDNSRuntimeFactory{base: base}, opts)
			factory, err := NewFakeIPScopeFactory(10*time.Second, 64)
			if err != nil {
				t.Fatal(err)
			}
			recorder := &clientAddressScopeRecorder{base: factory}
			client, owner, allocator := newClientAddressScoped(t, ctx, server, credentials, opts, recorder, "")
			front := startClientDNSFrontend(t, ctx, client)
			ip, ttl := requireClientDNSAddress(t, clientDNSQueryMode(t, ctx, front, queryNetwork, host, tc.typ, edns))
			if ttl > 5 {
				t.Fatalf("DNS TTL exceeded actual six-second Session bound: %d", ttl)
			}
			mapExpiry, err := recorder.snapshot()[0].SessionAddressLeaseExpiry(ip)
			if err != nil || time.Duration(ttl)*time.Second > time.Until(mapExpiry) {
				t.Fatalf("DNS TTL exceeded actual map deadline: ttl=%d expiry=%s err=%v", ttl, mapExpiry, err)
			}
			otherType := dnsmessage.TypeAAAA
			if tc.typ == dnsmessage.TypeAAAA {
				otherType = dnsmessage.TypeA
			}
			otherIP, otherTTL := requireClientDNSAddress(t, clientDNSQueryMode(t, ctx, front, queryNetwork, host, otherType, edns))
			thisKey, ok1 := addressscope.MappingAddress(ip)
			otherKey, ok2 := addressscope.MappingAddress(otherIP)
			otherExpiry, otherErr := recorder.snapshot()[0].SessionAddressLeaseExpiry(otherIP)
			if !ok1 || !ok2 || thisKey != otherKey || otherErr != nil || !otherExpiry.Equal(mapExpiry) || otherTTL > ttl {
				t.Fatal("A and AAAA did not share the original map and expiry")
			}
			if hosts, ips, _ := fakeIPScopeState(recorder.snapshot()[0]); hosts != 1 || ips != 1 {
				t.Fatal("dual-stack DNS consumed two mapping entries")
			}
			if restored, err := allocator.ResolveSessionAddress(ip); err != nil || restored != host {
				t.Fatalf("actual DNS answer not in selected Session: %q %v", restored, err)
			}
			again, againTTL := requireClientDNSAddress(t, clientDNSQueryMode(t, ctx, front, queryNetwork, host, tc.typ, edns))
			againExpiry, err := recorder.snapshot()[0].SessionAddressLeaseExpiry(ip)
			if err != nil || again != ip || againTTL > ttl || !againExpiry.Equal(mapExpiry) {
				t.Fatal("repeated DNS query refreshed mapping deadline or inherited another scope")
			}
			flow := sessionDNSRuntimeExchange(t, ctx, client, net.JoinHostPort(ip.String(), strconv.Itoa(tcpPort)), []byte("real DNS address to fake IP to TCP exit"))
			_ = flow
			udp, err := client.DialContext(ctx, "udp", net.JoinHostPort(ip.String(), strconv.Itoa(udpPort)))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { udp.Close() })
			udp.SetDeadline(deadline)
			payload := []byte("real DNS address to fake IP to UDP exit")
			if n, err := udp.Write(payload); err != nil || n != len(payload) {
				t.Fatalf("UDP write n=%d err=%v", n, err)
			}
			response := make([]byte, 4096)
			n, err := udp.Read(response)
			if err != nil || !bytes.Equal(response[:n], payload) {
				t.Fatalf("DNS-derived UDP echo n=%d err=%v", n, err)
			}
			if targets.Load() != 1 || messages.Load() != 1 || lookups.Load() != 1 || len(recorder.snapshot()) != 1 {
				t.Fatal("DNS-derived TCP/UDP created extra Session/cache/socket work")
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			requireFakeIPCleared(t, recorder.snapshot()[0], ip)
			if conn, err := client.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(tcpPort))); conn != nil || !errors.Is(err, ErrFakeIPUnmapped) {
				if conn != nil {
					conn.Close()
				}
				t.Fatalf("old DNS address inherited by new Session: %v", err)
			}
			fresh := client.Session()
			if fresh.Stats().Opened != 0 || len(recorder.snapshot()) != 2 {
				t.Fatal("stale DNS address created new OPEN")
			}
			freshIP, _ := requireClientDNSAddress(t, clientDNSQueryMode(t, ctx, front, queryNetwork, host, tc.typ, edns))
			if freshIP == ip {
				t.Fatal("fresh DNS query reused retired owner's numeric address")
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			requireFakeIPCleared(t, recorder.snapshot()[1], freshIP)
		})
	}
}

func TestClientDNSFrontendTTLUsesActualMapExpiryAndNoZeroLease(t *testing.T) {
	for _, lifetime := range []time.Duration{1500 * time.Millisecond, 400 * time.Millisecond} {
		t.Run(lifetime.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			base, err := New(Policy{})
			if err != nil {
				t.Fatal(err)
			}
			server, credentials := sessionDNSTerminationServer(t, ctx, &sessionDNSRuntimeFactory{base: base}, session.Options{})
			factory, err := NewFakeIPScopeFactory(lifetime, 64)
			if err != nil {
				t.Fatal(err)
			}
			recorder := &clientAddressScopeRecorder{base: factory}
			client, _, _ := newClientAddressScoped(t, ctx, server, credentials, session.Options{}, recorder, "")
			front := startClientDNSFrontend(t, ctx, client)
			response := clientDNSQuery(t, ctx, front, "udp", "short-map.test")
			if lifetime < time.Second {
				if response.RCode != dnsmessage.RCodeServerFailure || len(response.Answers) != 0 {
					t.Fatal("sub-second map returned an unsafe positive TTL")
				}
				return
			}
			ip, ttl := requireClientDNSAddress(t, response)
			if ttl != 1 {
				t.Fatalf("DNS used a constant rather than 1.5s real map expiry: ttl=%d", ttl)
			}
			// Wait until the actual map entry deadline, without extending its TTL.
			expires, err := recorder.snapshot()[0].SessionAddressLeaseExpiry(ip)
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(time.Until(expires) + time.Millisecond)
			if _, err := recorder.snapshot()[0].Resolve(ip); !errors.Is(err, ErrFakeIPUnmapped) {
				t.Fatalf("map TTL did not retire old DNS answer: %v", err)
			}
			nextIP, _ := requireClientDNSAddress(t, clientDNSQuery(t, ctx, front, "tcp", "short-map.test"))
			if nextIP == ip || len(recorder.snapshot()) != 1 {
				t.Fatal("expired map entry was cached/reused or recreated the Session")
			}
		})
	}
}

type fixedDNSSelection struct {
	client   *session.Client
	selected chan *session.Session
	release  chan struct{}
	calls    atomic.Int32
}

func (s *fixedDNSSelection) Connect(ctx context.Context) (*session.Session, error) {
	s.calls.Add(1)
	owner, err := s.client.Connect(ctx)
	if err != nil {
		return nil, err
	}
	s.selected <- owner
	select {
	case <-s.release:
		return owner, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestClientDNSFrontendQueryNeverMigratesToNewSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	base, err := New(Policy{})
	if err != nil {
		t.Fatal(err)
	}
	server, credentials := sessionDNSTerminationServer(t, ctx, &sessionDNSRuntimeFactory{base: base}, session.Options{})
	recorder := newClientAddressScopeRecorder(t)
	client, owner, _ := newClientAddressScoped(t, ctx, server, credentials, session.Options{}, recorder, "")
	selection := &fixedDNSSelection{client: client, selected: make(chan *session.Session, 1), release: make(chan struct{})}
	front := startClientDNSFrontend(t, ctx, selection)
	response := make(chan dnsmessage.Message, 1)
	go func() { response <- clientDNSQuery(t, ctx, front, "udp", "inflight-owner.test") }()
	select {
	case chosen := <-selection.selected:
		if chosen != owner {
			t.Fatal("query selected wrong original owner")
		}
	case <-ctx.Done():
		t.Fatal("DNS selection did not start")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, err := client.Connect(ctx)
	if err != nil || fresh == owner {
		t.Fatalf("fresh Session did not replace closed owner: %v", err)
	}
	close(selection.release)
	select {
	case result := <-response:
		if result.RCode != dnsmessage.RCodeServerFailure || len(result.Answers) != 0 {
			t.Fatal("inflight DNS query migrated to a fresh Session")
		}
	case <-ctx.Done():
		t.Fatal("inflight query did not end")
	}
	if selection.calls.Load() != 1 || fresh.Stats().Opened != 0 || len(recorder.snapshot()) != 2 {
		t.Fatal("DNS query retried across owners or created business OPEN")
	}
	if hosts, ips, closed := fakeIPScopeState(recorder.snapshot()[1]); hosts != 0 || ips != 0 || closed {
		t.Fatal("fresh scope inherited old DNS query state")
	}
}

func TestClientDNSFrontendExpiryAndDetectedRevocationNeverServeOldMap(t *testing.T) {
	for _, reason := range []string{"expiry", "detected_tcp_revocation"} {
		t.Run(reason, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			base, err := New(Policy{})
			if err != nil {
				t.Fatal(err)
			}
			opts := session.Options{MaxSessionLifetime: 1500 * time.Millisecond}
			if reason == "detected_tcp_revocation" {
				opts = session.Options{HandshakeTimeout: 150 * time.Millisecond, RetainTimeout: 300 * time.Millisecond}
			}
			server, credentials := sessionDNSTerminationServer(t, ctx, &sessionDNSRuntimeFactory{base: base}, opts)
			udpAddress := ""
			if reason == "detected_tcp_revocation" {
				proxy := newSessionDNSCloseUDPProxy(t, server.Addr())
				proxy.dropClient.Store(true)
				proxy.dropResponder.Store(true)
				udpAddress = proxy.front.LocalAddr().String()
			}
			recorder := newClientAddressScopeRecorder(t)
			client, owner, allocator := newClientAddressScoped(t, ctx, server, credentials, opts, recorder, udpAddress)
			front := startClientDNSFrontend(t, ctx, client)
			ip, _ := requireClientDNSAddress(t, clientDNSQuery(t, ctx, front, "udp", "terminal-dns-owner.test"))
			if reason == "detected_tcp_revocation" {
				if owner.Stats().Carrier != "tcp" {
					t.Fatal("revocation scene has no observable TCP socket closure")
				}
				if err := server.RevokeDevice(credentials.Public); err != nil {
					t.Fatal(err)
				}
			}
			until := time.Now().Add(2 * time.Second)
			for {
				if _, err := allocator.ResolveSessionAddress(ip); errors.Is(err, ErrFakeIPScopeClosed) {
					break
				}
				if time.Now().After(until) {
					t.Fatal("terminal DNS map remained live beyond observed bound")
				}
				time.Sleep(time.Millisecond)
			}
			requireFakeIPCleared(t, recorder.snapshot()[0], ip)
			response := clientDNSQuery(t, ctx, front, "tcp", "terminal-dns-owner.test")
			if reason == "detected_tcp_revocation" {
				if response.RCode != dnsmessage.RCodeServerFailure || len(response.Answers) != 0 || len(recorder.snapshot()) != 1 {
					t.Fatal("revoked identity served old DNS map or created fresh map")
				}
			} else {
				// A client whose local lifetime ended may return bounded SERVFAIL
				// before a replacement handshake is admitted. A fresh positive map is
				// also valid, but an old positive address is never valid.
				if response.RCode == dnsmessage.RCodeSuccess {
					freshIP, _ := requireClientDNSAddress(t, response)
					if freshIP == ip || len(recorder.snapshot()) != 2 || client.Session().Stats().Opened != 0 {
						t.Fatal("post-expiry DNS query reused old address/state")
					}
				} else if response.RCode != dnsmessage.RCodeServerFailure || len(response.Answers) != 0 {
					t.Fatalf("post-expiry DNS returned unsafe non-error answer: %+v", response)
				}
			}
		})
	}
}
