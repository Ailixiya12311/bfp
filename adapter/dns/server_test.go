package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"bfp/gateway"
	"bfp/security"
	"bfp/session"
	"golang.org/x/net/dns/dnsmessage"
)

type selectorFunc func(context.Context) (*session.Session, error)

func (f selectorFunc) Connect(ctx context.Context) (*session.Session, error) { return f(ctx) }

func startDNS(t *testing.T, cfg Config) *Server {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background()) }()
	t.Cleanup(func() {
		s.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("DNS Serve did not join")
		}
	})
	return s
}

func dnsQuestion(t *testing.T, typ dnsmessage.Type) []byte {
	t.Helper()
	name, err := dnsmessage.NewName("strict-local.test.")
	if err != nil {
		t.Fatal(err)
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 123, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: typ, Class: dnsmessage.ClassINET}}}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func udpExchange(t *testing.T, s *Server, data []byte, timeout time.Duration) ([]byte, error) {
	t.Helper()
	conn, err := net.Dial("udp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(data); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	return buf[:n], err
}

func TestDNSFrontendStrictParserUnsupportedAndSizeBoundaries(t *testing.T) {
	var calls atomic.Int32
	selector := selectorFunc(func(context.Context) (*session.Session, error) { calls.Add(1); return nil, errors.New("no owner") })
	s := startDNS(t, Config{Client: selector})
	question := dnsQuestion(t, dnsmessage.TypeA)
	compressionCycle := append([]byte(nil), question...)
	compressionCycle[12], compressionCycle[13] = 0xc0, 0x0c
	for index, malformed := range [][]byte{append(append([]byte(nil), question...), 99), append([]byte(nil), question[:len(question)-1]...), append([]byte(nil), question...), compressionCycle} {
		if index == 2 {
			malformed[4], malformed[5] = 255, 255
		}
		wire, err := udpExchange(t, s, malformed, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		var response dnsmessage.Message
		if err := response.Unpack(wire); err != nil || response.RCode != dnsmessage.RCodeFormatError || len(response.Answers) != 0 {
			t.Fatalf("malformed query response=%+v err=%v", response, err)
		}
	}
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeMX, dnsmessage.TypeTXT, dnsmessage.TypePTR} {
		wire, err := udpExchange(t, s, dnsQuestion(t, typ), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		var response dnsmessage.Message
		if err := response.Unpack(wire); err != nil || response.RCode != dnsmessage.RCodeNotImplemented || !response.RecursionDesired || response.RecursionAvailable || len(response.Answers) != 0 {
			t.Fatalf("unsupported query response=%+v err=%v", response, err)
		}
	}
	responsePacket := append([]byte(nil), question...)
	responsePacket[2] |= 128
	if _, err := udpExchange(t, s, responsePacket, 40*time.Millisecond); err == nil {
		t.Fatal("DNS answered a response packet")
	}
	if _, err := udpExchange(t, s, make([]byte, maxMessageBytes+1), 40*time.Millisecond); err == nil {
		t.Fatal("DNS answered oversized datagram")
	}
	if calls.Load() != 0 {
		t.Fatal("unsupported/malformed DNS request selected Session or created map")
	}

	// Oversized framed TCP input is rejected before allocating the body or
	// selecting a Session. An incomplete body is bounded by the idle deadline.
	conn, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write(binary.BigEndian.AppendUint16(nil, maxMessageBytes+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("oversized DNS TCP frame stayed live")
	}
}

func TestDNSFrontendDeadlineConcurrencyAndCloseJoinsHandlers(t *testing.T) {
	var active, highest, calls atomic.Int32
	started := make(chan struct{}, 1)
	selector := selectorFunc(func(ctx context.Context) (*session.Session, error) {
		calls.Add(1)
		count := active.Add(1)
		defer active.Add(-1)
		for {
			old := highest.Load()
			if count <= old || highest.CompareAndSwap(old, count) {
				break
			}
		}
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	s := startDNS(t, Config{Client: selector, MaxConcurrent: 1, MaxTCPConnections: 1, QueryTimeout: 60 * time.Millisecond, ResponseWriteTimeout: time.Millisecond, TCPIdleTimeout: 80 * time.Millisecond})
	udp, err := net.Dial("udp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	query := dnsQuestion(t, dnsmessage.TypeA)
	udp.Write(query)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("DNS query did not start")
	}
	for i := 0; i < 16; i++ {
		udp.Write(query)
	}
	until := time.Now().Add(time.Second)
	for active.Load() != 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if highest.Load() != 1 || active.Load() != 0 {
		t.Fatal("DNS exceeded shared query budget or deadline")
	}
	conn, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	conn.Write(binary.BigEndian.AppendUint16(nil, uint16(len(query)))) // no body
	if _, err := io.ReadFull(conn, make([]byte, 1)); err == nil {
		t.Fatal("incomplete TCP request ignored idle deadline")
	}

	udp.Write(query)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("second owned query did not start")
	}
	begin := time.Now()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if active.Load() != 0 || time.Since(begin) > time.Second {
		t.Fatal("DNS Close returned before cancel/join of owned handler")
	}
	before := calls.Load()
	udp.SetDeadline(time.Now().Add(30 * time.Millisecond))
	udp.Write(query)
	if _, err := udp.Read(make([]byte, 1232)); err == nil {
		t.Fatal("closed DNS listener answered query")
	}
	if calls.Load() != before {
		t.Fatal("closed DNS listener selected a new Session")
	}
}

func TestDNSFrontendConfigRejectsUnboundedOrNonLoopback(t *testing.T) {
	selector := selectorFunc(func(context.Context) (*session.Session, error) { return nil, errors.New("unused") })
	for _, cfg := range []Config{{Client: selector, Listen: "0.0.0.0:0"}, {Client: selector, Listen: "localhost:0"}, {Client: selector, MaxConcurrent: 129}, {Client: selector, MaxTCPConnections: 65}, {Client: selector, QueryTimeout: 31 * time.Second}, {Client: selector, ResponseWriteTimeout: 2 * time.Second}} {
		if s, err := New(cfg); s != nil || !errors.Is(err, ErrConfig) {
			if s != nil {
				s.Close()
			}
			t.Fatalf("invalid DNS config accepted: %v", err)
		}
	}
}

func dnsFlagsRealOwner(t *testing.T) *session.Client {
	t.Helper()
	clientKey, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	admission := make([]byte, 32)
	for i := range admission {
		admission[i] = byte(i + 1)
	}
	backend, err := gateway.New(gateway.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	server, err := session.NewServer(session.ServerConfig{Listen: "127.0.0.1:0", Backend: backend, Credentials: session.Credentials{Admission: admission, Private: serverKey.Private, Public: serverKey.Public, AllowedClients: [][]byte{clientKey.Public}}})
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
		case <-time.After(time.Second):
			t.Error("flags server did not join")
		}
	})
	factory, err := gateway.NewFakeIPScopeFactory(time.Minute, 64)
	if err != nil {
		t.Fatal(err)
	}
	client, err := session.NewClient(session.ClientConfig{Server: server.Addr().String(), TCPServer: server.Addr().String(), AddressScopeFactory: factory, Credentials: session.Credentials{Admission: admission, Private: clientKey.Private, Public: clientKey.Public, ServerPublic: serverKey.Public}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Abort() })
	return client
}

func dnsFlagsWireExchange(t *testing.T, s *Server, network string, wire []byte) dnsmessage.Message {
	t.Helper()
	conn, err := net.Dial(network, s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if network == "tcp" {
		wire = append(binary.BigEndian.AppendUint16(nil, uint16(len(wire))), wire...)
	}
	if _, err := conn.Write(wire); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1232)
	if network == "tcp" {
		var prefix [2]byte
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			t.Fatal(err)
		}
		size := int(binary.BigEndian.Uint16(prefix[:]))
		if size < 12 || size > len(buf) {
			t.Fatalf("flags TCP reply size=%d", size)
		}
		buf = buf[:size]
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatal(err)
		}
	} else {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		buf = buf[:n]
	}
	var result dnsmessage.Message
	if err := result.Unpack(buf); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestDNSFrontendADHintAndCDFlagsRealWireReplies(t *testing.T) {
	client := dnsFlagsRealOwner(t)
	s := startDNS(t, Config{Client: client})
	for _, network := range []string{"udp", "tcp"} {
		for _, cd := range []bool{false, true} {
			for _, ad := range []bool{false, true} {
				for _, scene := range []string{"positive", "positive_aaaa", "unsupported", "invalid_aa", "malformed_count"} {
					var query dnsmessage.Message
					if err := query.Unpack(dnsQuestion(t, dnsmessage.TypeA)); err != nil {
						t.Fatal(err)
					}
					query.CheckingDisabled, query.AuthenticData = cd, ad
					expected := dnsmessage.RCodeSuccess
					switch scene {
					case "positive_aaaa":
						query.Questions[0].Type = dnsmessage.TypeAAAA
					case "unsupported":
						query.Questions[0].Type = dnsmessage.TypeMX
						expected = dnsmessage.RCodeNotImplemented
					case "invalid_aa":
						query.Authoritative = true
						expected = dnsmessage.RCodeFormatError
					case "malformed_count":
						expected = dnsmessage.RCodeFormatError
					}
					wire, err := query.Pack()
					if err != nil {
						t.Fatal(err)
					}
					if scene == "malformed_count" {
						wire[4], wire[5] = 255, 255
					}
					result := dnsFlagsWireExchange(t, s, network, wire)
					if result.ID != query.ID || !result.Response || result.RCode != expected || result.CheckingDisabled != cd || !result.RecursionDesired || result.AuthenticData || result.Authoritative || result.RecursionAvailable {
						t.Fatalf("%s %s cd=%t ad=%t flags=%+v", network, scene, cd, ad, result.Header)
					}
					positive := scene == "positive" || scene == "positive_aaaa"
					if positive && (len(result.Answers) != 1 || result.Answers[0].Header.Type != query.Questions[0].Type) {
						t.Fatal("AD/CD address query did not return actual owner lease")
					}
					if !positive && len(result.Answers) != 0 {
						t.Fatal("AD/CD error replied with records")
					}
				}
			}
		}
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	// Also exercise an ordinary SERVFAIL with a parseable AD/CD request.
	wire := dnsQuestion(t, dnsmessage.TypeA)
	var query dnsmessage.Message
	if err := query.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	query.CheckingDisabled, query.AuthenticData = true, true
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	result := dnsFlagsWireExchange(t, s, "udp", wire)
	if result.RCode != dnsmessage.RCodeServerFailure || !result.CheckingDisabled || result.AuthenticData || result.Authoritative || result.RecursionAvailable {
		t.Fatalf("SERVFAIL flags=%+v", result.Header)
	}
}
