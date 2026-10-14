package classification

import (
	"errors"
	"testing"

	"bfp/protocol"
)

func TestLocalMetadataBridgeDiscardsWirePolicyFields(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rules = []Rule{{Name: "wire-domain", DomainSuffix: "example.test", Class: protocol.Interactive}, {Name: "wire-tag", RuleTag: "calls", Class: protocol.Bulk}}
	c := newClassifier(t, cfg)
	wire := protocol.Target{Network: "tcp", Address: "203.0.113.7:443", Domain: "chat.example.test", RuleTag: "calls", Class: protocol.Interactive}
	meta := NewLocalMetadataBridge(wire).Metadata()
	if meta.Target.Domain != "" || meta.Target.RuleTag != "" || meta.Target.Class != protocol.Normal || meta.DomainTrusted || meta.RuleTagTrusted {
		t.Fatalf("wire policy fields crossed bridge: %+v", meta)
	}
	decision, err := c.Decide(meta)
	if err != nil || decision.Source != SourceDefault || decision.Class != protocol.Normal {
		t.Fatalf("wire fields influenced local policy: %+v, %v", decision, err)
	}
	// The bridge owns optional contracts and does not alias caller pointers.
	wire.Delivery = &protocol.DeliveryContract{Version: 1, Mode: protocol.DeliveryStreamReliable}
	b := NewLocalMetadataBridge(wire)
	wire.Delivery.Mode = protocol.DeliveryDatagramBestEffort
	got := b.Metadata()
	if got.Target.Delivery == nil || got.Target.Delivery.Mode != protocol.DeliveryStreamReliable {
		t.Fatalf("target contract was aliased: %+v", got.Target.Delivery)
	}
	first := b.Metadata()
	second := b.Metadata()
	if first.Target.Delivery == second.Target.Delivery {
		t.Fatal("Metadata returned aliased delivery pointers")
	}
	first.Target.Delivery.Mode = protocol.DeliveryDatagramBestEffort
	if b.Metadata().Target.Delivery.Mode != protocol.DeliveryStreamReliable {
		t.Fatal("Metadata exposed bridge-owned delivery contract")
	}
	wire.FEC = &protocol.FECProfile{Version: 1, Algorithm: protocol.FECXOR1, MaxDataShards: 1, ParityShards: 1, ShardSize: 1, MaxBlockSize: 1}
	fecBridge := NewLocalMetadataBridge(wire)
	one, two := fecBridge.Metadata(), fecBridge.Metadata()
	if one.Target.FEC == nil || one.Target.FEC == two.Target.FEC {
		t.Fatal("Metadata returned aliased FEC pointers")
	}
	one.Target.FEC.MaxDataShards = 9
	if fecBridge.Metadata().Target.FEC.MaxDataShards != 1 {
		t.Fatal("Metadata exposed bridge-owned FEC profile")
	}
}

func TestLocalMetadataBridgeExplicitTrustedFields(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rules = []Rule{
		{Name: "domain", DomainSuffix: "example.test", Class: protocol.Interactive},
		{Name: "tag", RuleTag: "calls", Class: protocol.Bulk},
		{Name: "app", Application: "terminal", Class: protocol.Interactive, Locked: true},
	}
	c := newClassifier(t, cfg)
	b := NewLocalMetadataBridge(protocol.Target{Network: "udp", Address: "203.0.113.7:443", Domain: "wire.example.test", RuleTag: "calls", Class: protocol.Bulk})
	if decision, err := c.Decide(b.Metadata()); err != nil || decision.Source != SourceDefault {
		t.Fatalf("untrusted baseline: %+v, %v", decision, err)
	}
	trustedDomain, err := b.WithTrustedDomain("Chat.Example.TEST.")
	if err != nil {
		t.Fatal(err)
	}
	decision, err := c.Decide(trustedDomain.Metadata())
	if err != nil || decision.Rule != "domain" || decision.Class != protocol.Interactive || !trustedDomain.Metadata().DomainTrusted {
		t.Fatalf("trusted domain: %+v, %v", decision, err)
	}
	trustedTag, err := b.WithTrustedRuleTag("calls")
	if err != nil {
		t.Fatal(err)
	}
	decision, err = c.Decide(trustedTag.Metadata())
	if err != nil || decision.Rule != "tag" || !trustedTag.Metadata().RuleTagTrusted {
		t.Fatalf("trusted tag: %+v, %v", decision, err)
	}
	trustedApp, err := b.WithTrustedApplication("terminal")
	if err != nil {
		t.Fatal(err)
	}
	decision, err = c.Decide(trustedApp.Metadata())
	if err != nil || decision.Rule != "app" || !decision.Locked || trustedApp.Metadata().Target.RuleTag != "" || trustedApp.Metadata().Application != "terminal" || !trustedApp.Metadata().ApplicationTrusted {
		t.Fatalf("trusted app: %+v, %v metadata=%+v", decision, err, trustedApp.Metadata())
	}
	// Builder operations return independent values; adding a tag does not add
	// trust to the original bridge or to a previously built domain value.
	if b.Metadata().DomainTrusted || b.Metadata().RuleTagTrusted || trustedDomain.Metadata().RuleTagTrusted {
		t.Fatal("bridge values unexpectedly share trust state")
	}
}

func TestLocalMetadataBridgeRejectsInvalidTrustedInput(t *testing.T) {
	b := NewLocalMetadataBridge(protocol.Target{Network: "tcp", Address: "203.0.113.7:443"})
	for _, tc := range []struct {
		name string
		call func(LocalMetadataBridge) (LocalMetadataBridge, error)
	}{
		{"domain", func(v LocalMetadataBridge) (LocalMetadataBridge, error) { return v.WithTrustedDomain("bad..example") }},
		{"tag", func(v LocalMetadataBridge) (LocalMetadataBridge, error) { return v.WithTrustedRuleTag("bad\x00tag") }},
		{"application", func(v LocalMetadataBridge) (LocalMetadataBridge, error) { return v.WithTrustedApplication("") }},
		{"application_unicode", func(v LocalMetadataBridge) (LocalMetadataBridge, error) { return v.WithTrustedApplication("终端") }},
		{"application_path", func(v LocalMetadataBridge) (LocalMetadataBridge, error) {
			return v.WithTrustedApplication("terminal/app")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.call(b)
			if !errors.Is(err, ErrMetadata) || out.Metadata().DomainTrusted || out.Metadata().RuleTagTrusted || out.Metadata().ApplicationTrusted {
				t.Fatalf("input=%q output=%+v err=%v", tc.name, out.Metadata(), err)
			}
		})
	}
}
