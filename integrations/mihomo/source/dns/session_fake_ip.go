package dns

import (
	"strings"
	"time"

	C "github.com/metacubex/mihomo/constant"
	icontext "github.com/metacubex/mihomo/context"
	D "github.com/miekg/dns"
)

func withSessionFakeIP(mapper *ResolverEnhancer) middleware {
	return func(next handler) handler {
		return func(ctx *icontext.DNSContext, request *D.Msg) (*D.Msg, error) {
			question := request.Question[0]
			host := strings.TrimRight(question.Name, ".")
			if mapper.fakeIPSkipper != nil && mapper.fakeIPSkipper.ShouldSkipped(host) {
				return next(ctx, request)
			}
			if question.Qtype == D.TypeHTTPS || question.Qtype == D.TypeSVCB || question.Qtype == D.TypeAAAA && !mapper.ipv6 {
				return handleMsgWithEmptyAnswer(request), nil
			}
			if question.Qtype != D.TypeA && question.Qtype != D.TypeAAAA {
				return next(ctx, request)
			}
			lease, err := mapper.sessionOwner.AllocateSessionFakeIP(ctx, host, question.Qtype == D.TypeAAAA)
			if err != nil {
				return sessionFakeIPFailure(request), nil
			}
			remaining, err := lease.Remaining(ctx)
			if err != nil || remaining <= 0 {
				return sessionFakeIPFailure(request), nil
			}
			ttl := uint32(remaining / time.Second)
			if limit := uint32(mapper.fakeIPTTL); ttl > limit {
				ttl = limit
			}
			header := D.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: D.ClassINET, Ttl: ttl}
			var answer D.RR
			if question.Qtype == D.TypeA {
				answer = &D.A{Hdr: header, A: lease.Address().AsSlice()}
			} else {
				answer = &D.AAAA{Hdr: header, AAAA: lease.Address().AsSlice()}
			}
			response := new(D.Msg)
			response.SetReply(request)
			response.Answer = []D.RR{answer}
			// Validate at dispatch as well as allocation. No global fake pool or
			// resolver answer cache can extend the actual session lease.
			if _, err := lease.Remaining(ctx); err != nil {
				return sessionFakeIPFailure(request), nil
			}
			ctx.SetType(icontext.DNSTypeFakeIP)
			return response, nil
		}
	}
}

func sessionFakeIPFailure(request *D.Msg) *D.Msg {
	response := new(D.Msg)
	response.SetRcode(request, D.RcodeServerFailure)
	return response
}

var _ C.SessionFakeIPMapper = (*ResolverEnhancer)(nil)
