package classification

import (
	"errors"
	"testing"

	"bfp/protocol"
)

func meta(network, domain, tag string) Metadata {
	return Metadata{Target: protocol.Target{Network: network, Address: "203.0.113.1:443", Domain: domain, RuleTag: tag, Class: protocol.Interactive}}
}

func newClassifier(t *testing.T, cfg Config) *Classifier {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRulePriorityAndTrustedPrecedence(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rules = []Rule{
		{Name: "target", Priority: 1000, Network: "tcp", Class: protocol.Normal},
		{Name: "domain-first", Priority: 5, DomainSuffix: "Example.COM.", Class: protocol.Bulk},
		{Name: "tag-second", Priority: 5, RuleTag: "calls", Class: protocol.Interactive, Locked: true},
		{Name: "domain-lower", Priority: 4, Domain: "chat.example.com", Class: protocol.Normal},
	}
	c := newClassifier(t, cfg)
	m := meta("tcp", "CHAT.Example.Com.", "calls")
	m.DomainTrusted, m.RuleTagTrusted = true, true
	d, err := c.Decide(m)
	if err != nil || d.Class != protocol.Bulk || d.Rule != "domain-first" || d.Source != SourceMetadata {
		t.Fatalf("stable metadata priority: %+v, %v", d, err)
	}
	m.Hint = &ClassHint{Class: protocol.Interactive, Trusted: true, Locked: true}
	d, err = c.Decide(m)
	if err != nil || d.Class != protocol.Interactive || !d.Locked || d.Source != SourceHint {
		t.Fatalf("trusted hint: %+v, %v", d, err)
	}
	// A larger priority within the metadata group beats configuration order.
	cfg.Rules[2].Priority = 6
	c = newClassifier(t, cfg)
	m.Hint = nil
	d, err = c.Decide(m)
	if err != nil || d.Rule != "tag-second" || !d.Locked {
		t.Fatalf("explicit priority: %+v, %v", d, err)
	}
}

func TestUntrustedFieldsCannotSetPolicy(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rules = []Rule{{DomainSuffix: "example.com", Class: protocol.Interactive}, {RuleTag: "fast", Class: protocol.Interactive}}
	c := newClassifier(t, cfg)
	m := meta("tcp", "not a valid domain", "fast")
	m.Hint = &ClassHint{Class: protocol.Class(255), Locked: true}
	d, err := c.Decide(m)
	if err != nil || d.Class != protocol.Normal || d.Locked || d.Source != SourceDefault {
		t.Fatalf("untrusted inputs influenced decision: %+v, %v", d, err)
	}
	// Domain in target address is not independently marked trusted either.
	m.Target.Address = "chat.example.com:443"
	m.Target.Domain = "chat.example.com"
	d, err = c.Decide(m)
	if err != nil || d.Source != SourceDefault {
		t.Fatalf("target domain inferred trust: %+v, %v", d, err)
	}
	m.DomainTrusted = true
	d, err = c.Decide(m)
	if err != nil || d.Class != protocol.Interactive {
		t.Fatalf("trusted domain not matched: %+v, %v", d, err)
	}
	// Trusted domain alone must not make an untrusted RuleTag usable.
	m.Target.Domain = "unrelated.test"
	d, err = c.Decide(m)
	if err != nil || d.Source != SourceDefault {
		t.Fatalf("tag inherited domain trust: %+v, %v", d, err)
	}
	m.RuleTagTrusted = true
	d, err = c.Decide(m)
	if err != nil || d.Class != protocol.Interactive {
		t.Fatalf("trusted tag not matched: %+v, %v", d, err)
	}
}

func TestDomainSuffixAndConjunction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rules = []Rule{{Name: "dns", Network: "udp", DomainSuffix: "example.com", Ports: []PortRange{{First: 53, Last: 53}, {First: 5353, Last: 5355}}, RuleTag: "dns", Class: protocol.Interactive}}
	c := newClassifier(t, cfg)
	for _, tc := range []struct {
		domain, network, address, tag string
		match                         bool
	}{
		{"EXAMPLE.COM.", "udp", "[2001:db8::1]:53", "dns", true},
		{"www.example.com", "udp", "203.0.113.1:5354", "dns", true},
		{"badexample.com", "udp", "203.0.113.1:53", "dns", false},
		{"example.com.evil.test", "udp", "203.0.113.1:53", "dns", false},
		{"example.com", "tcp", "203.0.113.1:53", "dns", false},
		{"example.com", "udp", "203.0.113.1:54", "dns", false},
		{"example.com", "udp", "203.0.113.1:53", "other", false},
	} {
		t.Run(tc.domain+tc.network+tc.address+tc.tag, func(t *testing.T) {
			m := meta(tc.network, tc.domain, tc.tag)
			m.Target.Address = tc.address
			m.DomainTrusted, m.RuleTagTrusted = true, true
			d, err := c.Decide(m)
			if err != nil || (d.Source == SourceMetadata) != tc.match {
				t.Fatalf("match=%v: %+v, %v", tc.match, d, err)
			}
		})
	}
}

func TestPriorityCapAndImmutableConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HighestAllowed = protocol.Normal
	cfg.Rules = []Rule{{Name: "tls", Ports: []PortRange{{First: 443, Last: 443}}, Class: protocol.Interactive}}
	c := newClassifier(t, cfg)
	// Mutating caller-owned selectors/config after New must not alter policy.
	cfg.Rules[0].Ports[0].First = 80
	cfg.Rules[0].Class = protocol.Bulk
	m := meta("tcp", "", "")
	d, err := c.Decide(m)
	if err != nil || d.Class != protocol.Normal || d.Rule != "tls" {
		t.Fatalf("rule cap/copy: %+v, %v", d, err)
	}
	m.Hint = &ClassHint{Class: protocol.Interactive, Trusted: true, Locked: true}
	d, err = c.Decide(m)
	if err != nil || d.Class != protocol.Normal || !d.Locked {
		t.Fatalf("hint bypassed cap: %+v, %v", d, err)
	}
	if m.Target.Class != protocol.Interactive {
		t.Fatal("immutable OPEN metadata was changed")
	}
}

func TestInvalidRulesAndMetadata(t *testing.T) {
	for _, r := range []Rule{
		{Network: "quic", Class: protocol.Normal},
		{Network: "tcp", Class: protocol.Class(3)},
		{Class: protocol.Normal},
		{Domain: "example.com", DomainSuffix: "example.com", Class: protocol.Normal},
		{Domain: "example..com", Class: protocol.Normal},
		{Domain: "-example.com", Class: protocol.Normal},
		{Domain: "例子.com", Class: protocol.Normal},
		{Domain: "203.0.113.1", Class: protocol.Normal},
		{RuleTag: "a\nb", Class: protocol.Normal},
		{Ports: []PortRange{{0, 80}}, Class: protocol.Normal},
		{Ports: []PortRange{{81, 80}}, Class: protocol.Normal},
	} {
		cfg := DefaultConfig()
		cfg.Rules = []Rule{r}
		if _, err := New(cfg); !errors.Is(err, ErrConfig) {
			t.Fatalf("invalid rule accepted: %+v, %v", r, err)
		}
	}
	cfg := DefaultConfig()
	cfg.HighestAllowed = protocol.Class(3)
	if _, err := New(cfg); !errors.Is(err, ErrConfig) {
		t.Fatal("invalid priority cap accepted")
	}
	c := newClassifier(t, DefaultConfig())
	for _, m := range []Metadata{
		{Target: protocol.Target{Network: "ip", Address: "203.0.113.1:53"}},
		{Target: protocol.Target{Network: "tcp", Address: "203.0.113.1"}},
		{Target: protocol.Target{Network: "tcp", Address: ":443"}},
		{Target: protocol.Target{Network: "tcp", Address: "203.0.113.1:0"}},
		{Target: protocol.Target{Network: "tcp", Address: "203.0.113.1:65536"}},
		{Target: protocol.Target{Network: "tcp", Address: "203.0.113.1:443", Domain: "bad name"}, DomainTrusted: true},
		{Target: protocol.Target{Network: "tcp", Address: "203.0.113.1:443", RuleTag: "\x00"}, RuleTagTrusted: true},
		{Target: protocol.Target{Network: "tcp", Address: "203.0.113.1:443"}, Hint: &ClassHint{Class: protocol.Class(3), Trusted: true}},
	} {
		if _, err := c.Decide(m); !errors.Is(err, ErrMetadata) {
			t.Fatalf("invalid metadata accepted: %+v, %v", m, err)
		}
	}
}
