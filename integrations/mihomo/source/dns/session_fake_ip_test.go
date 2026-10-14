package dns

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	icontext "github.com/metacubex/mihomo/context"
	D "github.com/miekg/dns"
)

type sessionFakeIPTestLease struct {
	ip     netip.Addr
	host   string
	proxy  string
	valid  bool
	remain time.Duration
}

func (l *sessionFakeIPTestLease) Address() netip.Addr { return l.ip }
func (l *sessionFakeIPTestLease) Host() string        { return l.host }
func (l *sessionFakeIPTestLease) ProxyName() string   { return l.proxy }
func (l *sessionFakeIPTestLease) Remaining(context.Context) (time.Duration, error) {
	if !l.valid {
		return 0, C.ErrSessionFakeIP
	}
	return l.remain, nil
}

type sessionFakeIPTestOwner struct {
	lease       *sessionFakeIPTestLease
	allocations int
	lookups     int
}

func (o *sessionFakeIPTestOwner) AllocateSessionFakeIP(context.Context, string, bool) (C.SessionFakeIPLease, error) {
	o.allocations++
	if !o.lease.valid {
		next := netip.MustParseAddr("198.18.0.5")
		if o.lease != nil && o.lease.ip == next {
			next = netip.MustParseAddr("198.18.0.6")
		}
		o.lease = &sessionFakeIPTestLease{ip: next, host: "example.test", proxy: "BFP", valid: true, remain: time.Minute}
	}
	return o.lease, nil
}
func (o *sessionFakeIPTestOwner) LookupSessionFakeIP(context.Context, netip.Addr) (C.SessionFakeIPLease, error) {
	o.lookups++
	if o.lease == nil || !o.lease.valid {
		return nil, C.ErrSessionFakeIP
	}
	return o.lease, nil
}
func (o *sessionFakeIPTestOwner) SessionFakeIPPrefixes() (netip.Prefix, netip.Prefix) {
	return netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("fd42:6266:7000::/96")
}
func (o *sessionFakeIPTestOwner) OwnsSessionFakeIP(value C.SessionFakeIPLease) bool {
	return value == o.lease
}
func (o *sessionFakeIPTestOwner) FlushSessionFakeIP() error {
	if o.lease != nil {
		o.lease.valid = false
	}
	return nil
}

func TestSessionFakeIPDNSDoesNotResurrectRetiredLease(t *testing.T) {
	owner := &sessionFakeIPTestOwner{lease: &sessionFakeIPTestLease{ip: netip.MustParseAddr("198.18.0.4"), host: "example.test", proxy: "BFP", valid: true, remain: time.Minute}}
	mapper := NewEnhancer(EnhancerConfig{
		IPv6: true, EnhancedMode: C.DNSFakeIP, FakeIPTTL: 30,
		SessionFakeIPOwner: owner,
	})
	h := withSessionFakeIP(mapper)(func(_ *icontext.DNSContext, _ *D.Msg) (*D.Msg, error) {
		return nil, errors.New("raw resolver must not be reached")
	})
	request := new(D.Msg)
	request.SetQuestion("example.test.", D.TypeA)
	response, err := h(icontext.NewDNSContext(context.Background()), request)
	if err != nil || response == nil || len(response.Answer) != 1 {
		t.Fatalf("first session answer: response=%v err=%v", response, err)
	}
	answer, ok := response.Answer[0].(*D.A)
	if !ok || !answer.A.Equal(owner.lease.ip.AsSlice()) {
		t.Fatalf("unexpected first address: %#v", response.Answer)
	}
	if owner.allocations != 1 {
		t.Fatalf("expected one session allocation, got %d", owner.allocations)
	}

	if err := owner.FlushSessionFakeIP(); err != nil {
		t.Fatal(err)
	}
	lease, reserved, err := mapper.SessionFakeIPDestination(context.Background(), owner.lease.ip)
	if !reserved || lease != nil || err == nil {
		t.Fatalf("retired address lookup was accepted: lease=%v reserved=%v err=%v", lease, reserved, err)
	}
	response, err = h(icontext.NewDNSContext(context.Background()), request)
	if err != nil || response == nil || response.Rcode != D.RcodeSuccess || len(response.Answer) != 1 {
		t.Fatalf("new query should be allowed to create a fresh session: response=%v err=%v", response, err)
	}
	answer, ok = response.Answer[0].(*D.A)
	if !ok || answer.A.Equal(netip.MustParseAddr("198.18.0.4").AsSlice()) {
		t.Fatalf("new session reused retired address: %#v", response.Answer)
	}
	if owner.allocations != 2 {
		t.Fatalf("expected one fresh allocation after retirement, got %d", owner.allocations)
	}
}
