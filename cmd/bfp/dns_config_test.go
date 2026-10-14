package main

import (
	"bfp/internal/addressscope"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"bfp/clientconfig"
	"bfp/session"
	"golang.org/x/net/dns/dnsmessage"
)

func TestClientDNSConfigSelectsOwnedMappingAndPreservesOmittedDefault(t *testing.T) {
	for _, raw := range []string{"", `{"listen":"127.0.0.1:0"}`, `{"listen":"[::1]:15353","mapping_ttl":"3s","mapping_capacity":128}`} {
		cfg := clientConfig{DNS: json.RawMessage(raw)}
		sc, err := cfg.sessionConfig()
		if err != nil {
			t.Fatal(err)
		}
		if (sc.AddressScopeFactory != nil) != (raw != "") {
			t.Fatal("DNS factory presence changed")
		}
		if raw == "" {
			continue
		}
		parsed, err := parseClientDNS(cfg.DNS)
		if err != nil {
			t.Fatal(err)
		}
		if raw == `{"listen":"127.0.0.1:0"}` && (parsed.MappingTTL != 10*time.Minute || parsed.MappingCapacity != 64) {
			t.Fatal("default DNS map bounds changed")
		}
	}
}

func TestClientDNSConfigRejectsMalformedBeforeConnectAndPublicLoaderFailsClosed(t *testing.T) {
	bad := []string{`null`, `{}`, `[]`, `{"listen":"localhost:53"}`, `{"listen":"0.0.0.0:53"}`, `{"listen":"192.0.2.1:53"}`, `{"listen":"[::1%zone]:53"}`, `{"listen":"127.0.0.1:domain"}`, `{"listen":"127.0.0.1:65536"}`, `{"listen":"127.0.0.1:01"}`, `{"listen":"127.0.0.1:53","mapping_ttl":null}`, `{"listen":"127.0.0.1:53","mapping_ttl":"0s"}`, `{"listen":"127.0.0.1:53","mapping_ttl":"721h"}`, `{"listen":"127.0.0.1:53","mapping_capacity":65}`, `{"listen":"127.0.0.1:53","mapping_capacity":0}`, `{"listen":"127.0.0.1:53","mapping_capacity":"64"}`, `{"listen":"127.0.0.1:53","listen":"127.0.0.1:54"}`, `{"listen":"127.0.0.1:53","private_invalid_field":true}`}
	for _, raw := range bad {
		t.Run(raw, func(t *testing.T) {
			path := writePrivateOptionsConfig(t, `{"dns":`+raw+`}`)
			var cfg clientConfig
			if err := readConfig(path, &cfg); err == nil || strings.Contains(err.Error(), "private_invalid_field") {
				t.Fatalf("unsafe DNS validation: %v", err)
			}
			if _, err := (clientConfig{DNS: json.RawMessage(raw)}).sessionConfig(); err == nil {
				t.Fatal("direct constructor config bypassed DNS validation")
			}
		})
	}
	for _, body := range []string{`{"dns":{},"dns":{}}`, `{"DNS":{"listen":"127.0.0.1:0"}}`} {
		var cfg clientConfig
		if err := readConfig(writePrivateOptionsConfig(t, body), &cfg); err == nil {
			t.Fatal("duplicate/folded DNS key accepted")
		}
	}
	path := writePrivateOptionsConfig(t, `{"server":"127.0.0.1:9","dns":{}}`)
	if _, err := clientconfig.Load(path); !errors.Is(err, clientconfig.ErrUnsupported) {
		t.Fatalf("public base loader ignored DNS: %v", err)
	}
}

// Backend sees the restored name and uses real numeric loopback sockets, so
// the test exercises DNS -> SOCKS -> BFP OPEN -> exit without external DNS.
type cliDNSBackend struct {
	address string
	dials   atomic.Int32
}

func TestClientDNSRuntimeRejectsMissingSessionBeforeBinding(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "credentials")
	if err := keygen(dir); err != nil {
		t.Fatal(err)
	}
	var cfg clientConfig
	if err := readConfig(filepath.Join(dir, "client.json"), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.DNS = json.RawMessage(`{"listen":"127.0.0.1:0"}`)
	cc, err := cfg.sessionConfig()
	if err != nil {
		t.Fatal(err)
	}
	client, err := session.NewClient(cc)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Abort()
	if err := serveClientEntries(context.Background(), cfg, client); !errors.Is(err, session.ErrClosed) {
		t.Fatalf("unconnected entry did not fail before listeners/readiness: %v", err)
	}
	if client.Session() != nil {
		t.Fatal("readiness triggered a replacement Connect")
	}
}

func (b *cliDNSBackend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !strings.HasPrefix(address, "cli-echo.test:") {
		return nil, errors.New("wrong restored DNS target")
	}
	b.dials.Add(1)
	return (&net.Dialer{}).DialContext(ctx, network, b.address)
}

func TestClientDNSRuntimeSharesSessionWithSOCKSAndJoinsBothEntries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	dir := filepath.Join(t.TempDir(), "credentials")
	if err := keygen(dir); err != nil {
		t.Fatal(err)
	}
	var serverCfg serverConfig
	if err := readConfig(filepath.Join(dir, "server.json"), &serverCfg); err != nil {
		t.Fatal(err)
	}
	backend := &cliDNSBackend{address: target.Addr().String()}
	serverCfg.Listen = "127.0.0.1:0"
	sc, err := serverCfg.sessionConfig(backend)
	if err != nil {
		t.Fatal(err)
	}
	server, err := session.NewServer(sc)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() { _ = server.Serve(ctx) }()
	var cfg clientConfig
	if err := readConfig(filepath.Join(dir, "client.json"), &cfg); err != nil {
		t.Fatal(err)
	}
	dnsProbe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsAddress := dnsProbe.Addr().String()
	dnsProbe.Close()
	socksProbe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.SOCKS = socksProbe.Addr().String()
	socksProbe.Close()
	cfg.Server = server.Addr().String()
	cfg.TCPServer = cfg.Server
	cfg.DNS = json.RawMessage(`{"listen":"` + dnsAddress + `","mapping_ttl":"30s"}`)
	cc, err := cfg.sessionConfig()
	if err != nil {
		t.Fatal(err)
	}
	client, err := session.NewClient(cc)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Abort()
	owner, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	initial := owner.Stats()
	entryCtx, stopEntries := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- serveClientEntries(entryCtx, cfg, client) }()
	defer stopEntries()
	name, _ := dnsmessage.NewName("cli-echo.test.")
	question := dnsmessage.Message{Header: dnsmessage.Header{ID: 1234, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	var ip, mapping netip.Addr
	for _, q := range []struct {
		network string
		typ     dnsmessage.Type
		edns    bool
	}{
		{"udp", dnsmessage.TypeA, false}, {"tcp", dnsmessage.TypeA, false},
		{"udp", dnsmessage.TypeAAAA, false}, {"tcp", dnsmessage.TypeAAAA, false},
		{"udp", dnsmessage.TypeA, true}, {"tcp", dnsmessage.TypeA, true},
		{"udp", dnsmessage.TypeAAAA, true}, {"tcp", dnsmessage.TypeAAAA, true},
	} {
		network := q.network
		question.Questions[0].Type = q.typ
		question.Additionals = nil
		if q.edns {
			var opt dnsmessage.ResourceHeader
			if err := opt.SetEDNS0(4096, 0, true); err != nil {
				t.Fatal(err)
			}
			question.Additionals = []dnsmessage.Resource{{Header: opt, Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 12, Data: make([]byte, 24)}}}}}
		}
		query, err := question.Pack()
		if err != nil {
			t.Fatal(err)
		}
		var answer dnsmessage.Message
		var success bool
		for attempt := 0; attempt < 40; attempt++ {
			c, e := net.DialTimeout(network, dnsAddress, 100*time.Millisecond)
			if e != nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			_ = c.SetDeadline(time.Now().Add(100 * time.Millisecond))
			wire := query
			if network == "tcp" {
				wire = append(binary.BigEndian.AppendUint16(nil, uint16(len(query))), query...)
			}
			_, e = c.Write(wire)
			buffer := make([]byte, 1232)
			var n int
			if e == nil && network == "tcp" {
				var size [2]byte
				_, e = io.ReadFull(c, size[:])
				if e == nil {
					n = int(binary.BigEndian.Uint16(size[:]))
					if n > len(buffer) {
						e = errors.New("oversize DNS")
					} else {
						_, e = io.ReadFull(c, buffer[:n])
					}
				}
			} else if e == nil {
				n, e = c.Read(buffer)
			}
			c.Close()
			if e == nil && answer.Unpack(buffer[:n]) == nil && len(answer.Answers) == 1 {
				success = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !success || answer.ID != 1234 || answer.RCode != dnsmessage.RCodeSuccess || answer.Answers[0].Header.TTL == 0 {
			t.Fatal("DNS frontend did not return a bounded address lease")
		}
		if q.edns {
			if len(answer.Additionals) != 1 || answer.Additionals[0].Header.Type != dnsmessage.TypeOPT || answer.Additionals[0].Header.Class != 1232 || !answer.Additionals[0].Header.DNSSECAllowed() || answer.AuthenticData {
				t.Fatal("CLI DNS did not negotiate a bounded EDNS reply")
			}
			options, ok := answer.Additionals[0].Body.(*dnsmessage.OPTResource)
			if !ok || len(options.Options) != 0 {
				t.Fatal("CLI DNS reflected unsupported EDNS options")
			}
		} else if len(answer.Additionals) != 0 {
			t.Fatal("CLI DNS added EDNS to a legacy query")
		}
		switch body := answer.Answers[0].Body.(type) {
		case *dnsmessage.AResource:
			ip = netip.AddrFrom4(body.A)
		case *dnsmessage.AAAAResource:
			ip = netip.AddrFrom16(body.AAAA)
		default:
			t.Fatal("expected address resource")
		}
		key, ok := addressscope.MappingAddress(ip)
		if !ok || answer.Answers[0].Header.Type != q.typ || mapping.IsValid() && key != mapping {
			t.Fatal("UDP/TCP A/AAAA DNS did not share owner")
		}
		mapping = key
	}
	_, portText, _ := net.SplitHostPort(target.Addr().String())
	port, _ := strconv.Atoi(portText)
	sock, err := net.DialTimeout("tcp", cfg.SOCKS, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	_ = sock.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = sock.Write([]byte{5, 1, 0})
	var greeting [2]byte
	if _, err := io.ReadFull(sock, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatal("SOCKS greeting")
	}
	request := []byte{5, 1, 0, 4}
	ipBytes := ip.As16()
	request = append(request, ipBytes[:]...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	_, _ = sock.Write(request)
	var response [10]byte
	if _, err := io.ReadFull(sock, response[:]); err != nil || response[1] != 0 {
		t.Fatal("DNS-derived SOCKS CONNECT failed")
	}
	payload := []byte("same CLI Session owns DNS and SOCKS")
	_, _ = sock.Write(payload)
	returned := make([]byte, len(payload))
	if _, err := io.ReadFull(sock, returned); err != nil || !bytes.Equal(returned, payload) {
		t.Fatal("real DNS -> SOCKS -> BFP -> TCP echo failed")
	}
	if client.Session() != owner || owner.Stats().ID != initial.ID || backend.dials.Load() != 1 {
		t.Fatal("entry path recreated Session or target")
	}
	stopEntries()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("client entries did not join")
	}
	allocator, ok := owner.LocalAddressAllocator()
	if !ok {
		t.Fatal("CLI DNS did not install the Session allocator")
	}
	if host, err := allocator.ResolveSessionAddress(ip); err != nil || host != "cli-echo.test" {
		t.Fatal("entry stop retired caller's live Session map")
	}
	if err := client.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err := allocator.ResolveSessionAddress(ip); err == nil {
		t.Fatal("client termination left DNS address usable")
	}
}
