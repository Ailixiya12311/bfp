package dns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"bfp/session"

	"golang.org/x/net/dns/dnsmessage"
)

func ednsQuestion(t *testing.T, typ dnsmessage.Type, payload int, version uint8, do bool, options []dnsmessage.Option) dnsmessage.Message {
	t.Helper()
	var query dnsmessage.Message
	if err := query.Unpack(dnsQuestion(t, typ)); err != nil {
		t.Fatal(err)
	}
	query.AuthenticData = true
	query.CheckingDisabled = true
	var header dnsmessage.ResourceHeader
	if err := header.SetEDNS0(payload, 0, do); err != nil {
		t.Fatal(err)
	}
	header.TTL |= uint32(version) << 16
	query.Additionals = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.OPTResource{Options: options}}}
	return query
}

func requireEDNSReply(t *testing.T, query, response dnsmessage.Message, code dnsmessage.RCode, do bool) {
	t.Helper()
	if response.ID != query.ID || !response.Response || response.RCode != code&0xf || response.AuthenticData || response.Authoritative || response.RecursionAvailable || response.CheckingDisabled != query.CheckingDisabled || response.RecursionDesired != query.RecursionDesired {
		t.Fatalf("EDNS reply flags invalid: %+v", response.Header)
	}
	if len(response.Additionals) != 1 {
		t.Fatal("EDNS response omitted its OPT")
	}
	opt := response.Additionals[0]
	body, ok := opt.Body.(*dnsmessage.OPTResource)
	if !ok || opt.Header.Name.String() != "." || opt.Header.Type != dnsmessage.TypeOPT || opt.Header.Class != 1232 || opt.Header.ExtendedRCode(response.RCode) != code || opt.Header.DNSSECAllowed() != do || len(body.Options) != 0 {
		t.Fatalf("EDNS response version/code/DO/payload/options invalid: %+v", opt)
	}
}

func TestDNSFrontendEDNS0RealOwnerReplies(t *testing.T) {
	client := dnsFlagsRealOwner(t)
	front := startDNS(t, Config{Client: client})
	for _, network := range []string{"udp", "tcp"} {
		for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
			t.Run(network+"/"+typ.String(), func(t *testing.T) {
				var query dnsmessage.Message
				if err := query.Unpack(dnsQuestion(t, typ)); err != nil {
					t.Fatal(err)
				}
				var header dnsmessage.ResourceHeader
				if err := header.SetEDNS0(1232, 0, true); err != nil {
					t.Fatal(err)
				}
				query.Additionals = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.OPTResource{}}}
				wire, err := query.Pack()
				if err != nil {
					t.Fatal(err)
				}
				response := dnsFlagsWireExchange(t, front, network, wire)
				if response.RCode != dnsmessage.RCodeSuccess || len(response.Answers) != 1 || len(response.Additionals) != 1 {
					t.Fatalf("ordinary EDNS query rejected: rcode=%v answers=%d additional=%d", response.RCode, len(response.Answers), len(response.Additionals))
				}
			})
		}
	}
}

func TestDNSFrontendEDNSOffersFlagsAndUnknownOptions(t *testing.T) {
	client := dnsFlagsRealOwner(t)
	front := startDNS(t, Config{Client: client})
	options := []dnsmessage.Option{{Code: 65001, Data: []byte("private-option-marker")}, {Code: 12, Data: make([]byte, 32)}, {Code: 10, Data: []byte("12345678")}}
	for _, network := range []string{"udp", "tcp"} {
		for _, size := range []int{0, 128, 512, 1200, 1232, 4096, 65535} {
			for _, do := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/%t", network, size, do), func(t *testing.T) {
					query := ednsQuestion(t, dnsmessage.TypeAAAA, size, 0, do, options)
					// Unknown Z flags must be ignored, not reflected.
					query.Additionals[0].Header.TTL |= 0x21
					wire, err := query.Pack()
					if err != nil {
						t.Fatal(err)
					}
					response := dnsFlagsWireExchange(t, front, network, wire)
					requireEDNSReply(t, query, response, 0, do)
					if len(response.Answers) != 1 || response.Answers[0].Header.Type != dnsmessage.TypeAAAA || response.Answers[0].Header.TTL == 0 {
						t.Fatal("EDNS failed to return a real AAAA lease")
					}
					packed, err := response.Pack()
					if err != nil {
						t.Fatal(err)
					}
					limit := 1232
					if network == "udp" {
						limit = min(max(size, 512), 1232)
					}
					if len(packed) > limit || bytes.Contains(packed, []byte("private-option-marker")) || response.Additionals[0].Header.TTL & ^uint32(0x8000) != 0 {
						t.Fatal("EDNS reflected option metadata/flags or exceeded negotiated size")
					}
				})
			}
		}
	}
}

func TestDNSFrontendEDNSInvalidAndUnsupportedNeverSelectOwner(t *testing.T) {
	var calls atomic.Int32
	selector := selectorFunc(func(context.Context) (*session.Session, error) {
		calls.Add(1)
		return nil, errors.New("unexpected selection")
	})
	front := startDNS(t, Config{Client: selector})
	for _, network := range []string{"udp", "tcp"} {
		for _, scene := range []string{"version", "duplicate", "non_root", "non_opt", "extended_query_code", "malformed_option", "trailing_data", "unsupported_question"} {
			t.Run(network+"/"+scene, func(t *testing.T) {
				query := ednsQuestion(t, dnsmessage.TypeA, 4096, 0, true, nil)
				code := dnsmessage.RCodeFormatError
				expectOPT := false
				switch scene {
				case "version":
					query.Additionals[0].Header.TTL |= 1 << 16
					code = rCodeBadVersion
					expectOPT = true
				case "duplicate":
					query.Additionals = append(query.Additionals, query.Additionals[0])
				case "non_root":
					query.Additionals[0].Header.Name, _ = dnsmessage.NewName("wrong.test.")
				case "non_opt":
					query.Additionals[0].Body = &dnsmessage.AResource{}
				case "extended_query_code":
					query.Additionals[0].Header.TTL |= 1 << 24
					expectOPT = true
				case "malformed_option":
					query.Additionals[0].Body = &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 65000, Data: []byte{1}}}}
				case "unsupported_question":
					query.Questions[0].Type = dnsmessage.TypeMX
					code = dnsmessage.RCodeNotImplemented
					expectOPT = true
				}
				wire, err := query.Pack()
				if err != nil {
					t.Fatal(err)
				}
				if scene == "malformed_option" {
					wire[len(wire)-3], wire[len(wire)-2] = 255, 255
				}
				if scene == "trailing_data" {
					wire = append(wire, 99)
				}
				response := dnsFlagsWireExchange(t, front, network, wire)
				if len(response.Answers) != 0 {
					t.Fatal("invalid EDNS returned an address")
				}
				if expectOPT {
					requireEDNSReply(t, query, response, code, true)
				} else if response.RCode != code || len(response.Additionals) != 0 {
					t.Fatalf("malformed EDNS reply: %+v", response)
				}
			})
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid/unsupported EDNS allocated a Session or mapping")
	}
}

func TestDNSFrontendEDNSExpiredOwnerPreservesOPTOnFailure(t *testing.T) {
	client := dnsFlagsRealOwner(t)
	front := startDNS(t, Config{Client: client})
	query := ednsQuestion(t, dnsmessage.TypeAAAA, 512, 0, true, nil)
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	reply := front.answer(context.Background(), wire)
	if reply == nil || reply.owner == nil {
		t.Fatal("did not prepare a real EDNS owner lease")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	wire = front.packReply(context.Background(), reply, time.Now().Add(100*time.Millisecond))
	var response dnsmessage.Message
	if err := response.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	requireEDNSReply(t, query, response, dnsmessage.RCodeServerFailure, true)
	if len(response.Answers) != 0 || len(wire) > 512 {
		t.Fatal("terminal EDNS owner emitted a positive lease")
	}
}

func TestDNSFrontendUDPTruncationRetainsWholeQuestionAndOPT(t *testing.T) {
	query := ednsQuestion(t, dnsmessage.TypeAAAA, 512, 0, false, nil)
	reply := ednsParameters{enabled: true, payload: 512}.queryError(query, 0)
	for i := 0; i < 24; i++ {
		reply.message.Answers = append(reply.message.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AAAAResource{}})
	}
	front := &Server{}
	udp := front.packReply(context.Background(), reply, time.Now().Add(time.Second))
	var truncated dnsmessage.Message
	if err := truncated.Unpack(udp); err != nil {
		t.Fatal(err)
	}
	if len(udp) > 512 || !truncated.Truncated || len(truncated.Answers) != 0 || len(truncated.Questions) != 1 || truncated.Questions[0] != query.Questions[0] {
		t.Fatal("UDP did not truncate complete records within the offered size")
	}
	requireEDNSReply(t, query, truncated, 0, false)
	tcp := front.packReplyLimit(context.Background(), reply, time.Now().Add(time.Second), 1232)
	var complete dnsmessage.Message
	if err := complete.Unpack(tcp); err != nil || complete.Truncated || len(complete.Answers) != 24 {
		t.Fatal("TCP incorrectly inherited the UDP payload limit")
	}
}
