package session

import (
	"bfp/classification"
	"bfp/internal/classcontrol"
	"bfp/protocol"
	"bfp/security"
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func next16PolicyCredentials(t *testing.T) Credentials {
	t.Helper()
	client, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	server, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return Credentials{Admission: randomBytes(32), Private: client.Private, Public: client.Public, ServerPublic: server.Public}
}

func next16PolicyProfile(size uint16) protocol.FECProfile {
	p := next15FECProfile()
	p.ShardSize, p.MaxBlockSize = size, uint32(size)*uint32(p.MaxDataShards)
	return p
}

func TestDatagramFECPolicyNext16ConstructorRejectsInvalidAndUnadvertised(t *testing.T) {
	credentials := next16PolicyCredentials(t)
	for _, tc := range []struct {
		name        string
		class       protocol.Class
		profile     protocol.FECProfile
		negotiation *NegotiationConfig
		wireError   bool
	}{
		{"invalid-class", protocol.Class(255), next15FECProfile(), next15FECNegotiation(false), false},
		{"zero-profile", protocol.Normal, protocol.FECProfile{}, next15FECNegotiation(false), true},
		{"disabled-limits", protocol.Normal, protocol.FECProfile{Version: 1, ShardSize: 1}, next15FECNegotiation(false), true},
		{"unknown-algorithm", protocol.Normal, protocol.FECProfile{Version: 1, Algorithm: 2}, next15FECNegotiation(false), true},
		{"shard-exceeds-selected-contract", protocol.Normal, next16PolicyProfile(901), next15FECNegotiation(false), false},
		{"block-exceeds-selected-contract", protocol.Normal, protocol.FECProfile{Version: 1, Algorithm: protocol.FECXOR1, MaxDataShards: 32, ParityShards: 1, ShardSize: 900, MaxBlockSize: 28801}, next15FECNegotiation(false), false},
		{"default-offer", protocol.Normal, next15FECProfile(), nil, false},
		{"explicit-offer-without-fec", protocol.Normal, next15FECProfile(), &NegotiationConfig{ProfileClassAnnouncementV1, CapabilityClassAnnouncementV1, CapabilityClassAnnouncementV1}, false},
		{"reserved-optional-bit-is-not-fec", protocol.Normal, next15FECProfile(), &NegotiationConfig{ProfileClassAnnouncementV1, CapabilityClassAnnouncementV1 | 2, CapabilityClassAnnouncementV1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Construction cannot perform a handshake or destination dial. An
			// invalid server address is intentionally irrelevant to this gate.
			client, err := NewClient(ClientConfig{Server: "invalid-server-address", Credentials: credentials, Negotiation: tc.negotiation,
				DatagramFEC: &DatagramFECPolicyConfig{ByClass: map[protocol.Class]protocol.FECProfile{tc.class: tc.profile}}})
			if client != nil {
				client.Abort()
			}
			if client != nil || !errors.Is(err, ErrDatagramFECPolicy) || tc.wireError && !errors.Is(err, protocol.ErrFECWire) {
				t.Fatalf("invalid policy constructor client=%v err=%v", client != nil, err)
			}
		})
	}
}

func TestDatagramFECPolicyNext16ConstructorOwnsMapProfilesAndNegotiation(t *testing.T) {
	profile := next15FECProfile()
	byClass := map[protocol.Class]protocol.FECProfile{protocol.Normal: profile, protocol.Bulk: protocol.DisabledFECProfile()}
	policy := &DatagramFECPolicyConfig{ByClass: byClass}
	negotiation := next15FECNegotiation(false)
	client, err := NewClient(ClientConfig{Credentials: next16PolicyCredentials(t), DatagramFEC: policy, Negotiation: negotiation})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Abort() })
	byClass[protocol.Normal] = protocol.DisabledFECProfile()
	byClass[protocol.Interactive] = next16PolicyProfile(700)
	delete(byClass, protocol.Bulk)
	policy.ByClass = map[protocol.Class]protocol.FECProfile{protocol.Normal: next16PolicyProfile(800)}
	profile.ShardSize = 1
	negotiation.OfferedCapabilities = CapabilityClassAnnouncementV1
	if client.cfg.DatagramFEC != nil || client.datagramFEC.byClass[protocol.Normal] != next15FECProfile() || client.datagramFEC.byClass[protocol.Interactive].Enabled() || client.datagramFEC.byClass[protocol.Bulk] != protocol.DisabledFECProfile() || client.cfg.Negotiation.OfferedCapabilities&CapabilityDatagramXORV1 == 0 {
		t.Fatal("constructor retained mutable caller policy/profile/negotiation state")
	}
	// The production constructor publishes the complete policy before starting
	// its actor. Changes to the Client value afterwards cannot alter this copy.
	s := newSessionWithFECPolicy(context.Background(), sessionInfo{Profile: ProfileClassAnnouncementV1, Capabilities: CapabilityClassAnnouncementV1 | CapabilityDatagramXORV1}, Options{}, true, nil, client.datagramFEC, client.classifier)
	t.Cleanup(func() { s.cancel(); <-s.done })
	client.datagramFEC = datagramFECPolicy{}
	if err := s.call(context.Background(), func() {
		selected := s.selectDatagramFEC(protocol.Target{Network: "udp", Class: protocol.Normal})
		if selected.FEC == nil || *selected.FEC != next15FECProfile() {
			t.Error("actor did not receive the immutable construction-time policy")
		}
	}); err != nil {
		t.Fatal(err)
	}
}

// This fixture uses the existing admission-only command owner: no socket writes
// or timer maintenance can hide allocation or alter the queued OPEN image.
func next16PolicyActor(t *testing.T, cfg classification.Config, policy *DatagramFECPolicyConfig, selected Capabilities) *Session {
	t.Helper()
	s, _, _ := next15FECActor(t)
	classifier, err := classification.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := compileDatagramFECPolicy(policy, next15FECNegotiation(false))
	if err != nil {
		t.Fatal(err)
	}
	table, err := classcontrol.New(classcontrol.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.call(context.Background(), func() {
		s.classifier, s.datagramFEC, s.classTable = classifier, compiled, table
		s.info.Profile, s.info.Capabilities, s.info.Generation = ProfileClassAnnouncementV1, selected, 7
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func next16PolicyOpen(t *testing.T, s *Session, meta classification.Metadata) (*Flow, protocol.Target, protocol.Frame) {
	t.Helper()
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	s.post(func() { close(started); <-release })
	<-started
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		conn, err := s.DialMetadata(ctx, meta)
		done <- result{conn, err}
	}()
	// This queued command synchronizes with argument copying, and is never run
	// outside the owner. The next owner command deterministically sees its OPEN.
	var command func()
	select {
	case command = <-s.commands:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	s.commands <- command
	unblock()
	var target protocol.Target
	var frame protocol.Frame
	var found bool
	if err := s.call(ctx, func() {
		st := s.streams[s.nextFlow-1]
		if st == nil || !st.opening {
			t.Error("policy OPEN did not allocate its expected stream")
			return
		}
		target = cloneTarget(st.target)
		frame, found = s.queue.Pop()
		s.result(st, "ok")
	}); err != nil {
		t.Fatal(err)
	}
	var out result
	select {
	case out = <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if out.err != nil || out.conn == nil {
		t.Fatalf("valid policy OPEN failed: %v", out.err)
	}
	flow := out.conn.(*Flow)
	t.Cleanup(func() { flow.Close() })
	if !found || frame.Kind != protocol.Open || frame.Flow != flow.id {
		t.Fatal("policy OPEN missing from ordinary encrypted-frame queue")
	}
	return flow, target, frame
}

func TestDatagramFECPolicyNext16NilMissingAndDisabledClassesRemainDefaultOff(t *testing.T) {
	credentials := next16PolicyCredentials(t)
	for _, tc := range []struct {
		name   string
		policy *DatagramFECPolicyConfig
	}{
		{"nil", nil},
		{"empty", &DatagramFECPolicyConfig{}},
		{"disabled", &DatagramFECPolicyConfig{ByClass: map[protocol.Class]protocol.FECProfile{protocol.Normal: protocol.DisabledFECProfile()}}},
		{"missing-final-class", &DatagramFECPolicyConfig{ByClass: map[protocol.Class]protocol.FECProfile{protocol.Bulk: next15FECProfile()}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			negotiation := (*NegotiationConfig)(nil)
			if tc.name == "missing-final-class" {
				negotiation = next15FECNegotiation(false)
			}
			client, err := NewClient(ClientConfig{Credentials: credentials, DatagramFEC: tc.policy, Negotiation: negotiation})
			if err != nil {
				t.Fatal(err)
			}
			client.Abort()
			cfg := classification.DefaultConfig()
			cfg.Behavior.Enabled = false
			s := next16PolicyActor(t, cfg, tc.policy, CapabilityClassAnnouncementV1|CapabilityDatagramXORV1)
			flow, target, frame := next16PolicyOpen(t, s, classification.Metadata{Target: protocol.Target{Network: "udp", Address: "example.test:443", Class: protocol.Normal}})
			if target.FEC != nil || !bytes.Equal(frame.Data, encodeJSON(target)) {
				t.Fatal("disabled/missing automatic policy changed the legacy OPEN image")
			}
			if n, err := flow.Write(make([]byte, 1813)); n != 1813 || err != nil {
				t.Fatalf("ordinary Datagram admission n=%d err=%v", n, err)
			}
			if err := s.call(context.Background(), func() {
				st := s.streams[flow.id]
				if st.delivery != protocol.DefaultDelivery("udp") || st.fecProfile != protocol.DisabledFECProfile() || s.queue.Len() != 3 {
					t.Error("default-off policy changed Datagram reliability or shard count")
				}
				for s.queue.Len() > 0 {
					f, _ := s.queue.Pop()
					if f.Kind != protocol.Datagram {
						t.Error("default-off policy enqueued repair traffic")
					}
				}
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDatagramFECPolicyNext16UsesFinalInitialClassificationAfterRulesAndCap(t *testing.T) {
	profiles := map[protocol.Class]protocol.FECProfile{protocol.Interactive: next16PolicyProfile(700), protocol.Normal: next16PolicyProfile(800), protocol.Bulk: next15FECProfile()}
	for _, tc := range []struct {
		name string
		cfg  classification.Config
		meta classification.Metadata
		want protocol.Class
	}{
		{"target-class-is-not-trust", classification.DefaultConfig(), classification.Metadata{Target: protocol.Target{Network: "udp", Address: "example.test:443", Class: protocol.Bulk}}, protocol.Normal},
		{"port-rule", classification.Config{DefaultClass: protocol.Normal, Rules: []classification.Rule{{Network: "udp", Ports: []classification.PortRange{{First: 443, Last: 443}}, Class: protocol.Interactive}}}, classification.Metadata{Target: protocol.Target{Network: "udp", Address: "example.test:443", Class: protocol.Normal}}, protocol.Interactive},
		{"trusted-domain-rule", classification.Config{DefaultClass: protocol.Normal, Rules: []classification.Rule{{DomainSuffix: "example.test", Class: protocol.Bulk}}}, classification.Metadata{Target: protocol.Target{Network: "udp", Address: "127.0.0.1:443", Domain: "api.example.test", Class: protocol.Normal}, DomainTrusted: true}, protocol.Bulk},
		{"trusted-hint-capped", classification.Config{DefaultClass: protocol.Bulk, HighestAllowed: protocol.Normal}, classification.Metadata{Target: protocol.Target{Network: "udp", Address: "example.test:443", Class: protocol.Interactive}, Hint: &classification.ClassHint{Class: protocol.Interactive, Trusted: true}}, protocol.Normal},
		{"rule-capped-to-bulk", classification.Config{DefaultClass: protocol.Normal, HighestAllowed: protocol.Bulk, Rules: []classification.Rule{{Network: "udp", Class: protocol.Interactive}}}, classification.Metadata{Target: protocol.Target{Network: "udp", Address: "example.test:443", Class: protocol.Interactive}}, protocol.Bulk},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.Behavior.Enabled = false
			s := next16PolicyActor(t, tc.cfg, &DatagramFECPolicyConfig{ByClass: profiles}, CapabilityClassAnnouncementV1|CapabilityDatagramXORV1)
			flow, target, frame := next16PolicyOpen(t, s, tc.meta)
			var wire protocol.Target
			if target.Class != tc.want || target.FEC == nil || *target.FEC != profiles[tc.want] || decodeJSON(frame.Data, &wire) != nil || wire.Class != tc.want || wire.FEC == nil || *wire.FEC != profiles[tc.want] {
				t.Fatal("FEC policy selected before the final initial local class/cap")
			}
			if err := s.call(context.Background(), func() {
				st := s.streams[flow.id]
				if st.fecProfile != profiles[tc.want] || st.delivery != protocol.DefaultDelivery("udp") || st.txClassifier.Snapshot().Class != tc.want {
					t.Error("frozen contract disagrees with selected initial OPEN")
				}
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDatagramFECPolicyNext16OptionalSelectionFallsBackWithoutRepair(t *testing.T) {
	// Exercise the same authenticated selection as a default server that does
	// not offer XOR. The owner must honor selected capabilities, not the offer.
	profile, selected, err := selectCapabilities(capabilityOffer{ProfileClassAnnouncementV1, CapabilityClassAnnouncementV1 | CapabilityDatagramXORV1, CapabilityClassAnnouncementV1}, nil, nil)
	if err != nil || profile != ProfileClassAnnouncementV1 || selected != CapabilityClassAnnouncementV1 {
		t.Fatalf("optional selection=%d err=%v", selected, err)
	}
	cfg := classification.DefaultConfig()
	cfg.Behavior.Enabled = false
	s := next16PolicyActor(t, cfg, &DatagramFECPolicyConfig{ByClass: map[protocol.Class]protocol.FECProfile{protocol.Normal: next15FECProfile()}}, selected)
	flow, target, _ := next16PolicyOpen(t, s, classification.Metadata{Target: protocol.Target{Network: "udp", Address: "example.test:443", Class: protocol.Normal}})
	if target.FEC != nil {
		t.Fatal("optional fallback encoded an unselected FEC contract")
	}
	if n, err := flow.Write(make([]byte, 901)); n != 901 || err != nil {
		t.Fatalf("optional ordinary Datagram admission n=%d err=%v", n, err)
	}
	if err := s.call(context.Background(), func() {
		if st := s.streams[flow.id]; st.fecProfile != protocol.DisabledFECProfile() || st.delivery != protocol.DefaultDelivery("udp") || s.queue.Len() != 2 {
			t.Error("optional fallback changed the default reliability or added parity")
		}
		for s.queue.Len() > 0 {
			f, _ := s.queue.Pop()
			if f.Kind != protocol.Datagram {
				t.Error("unselected optional capability produced repair")
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDatagramFECPolicyNext16ManualOverrideRemainsStrictAndOwned(t *testing.T) {
	cfg := classification.DefaultConfig()
	cfg.Behavior.Enabled = false
	policy := &DatagramFECPolicyConfig{ByClass: map[protocol.Class]protocol.FECProfile{protocol.Normal: next15FECProfile()}}
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit-disabled", true: "explicit-narrower-profile"}[enabled], func(t *testing.T) {
			s := next16PolicyActor(t, cfg, policy, CapabilityClassAnnouncementV1|CapabilityDatagramXORV1)
			manual := protocol.DisabledFECProfile()
			if enabled {
				manual = next16PolicyProfile(700)
			}
			want := manual
			delivery := protocol.DefaultDelivery("udp")
			flow, target, frame := next16PolicyOpen(t, s, classification.Metadata{Target: protocol.Target{Network: "udp", Address: "example.test:443", Class: protocol.Normal, FEC: &manual, Delivery: &delivery}})
			manual.Version, delivery.Version = 255, 255
			if target.FEC == &manual || target.FEC == nil || *target.FEC != want || target.Delivery == &delivery || target.Delivery == nil || *target.Delivery != protocol.DefaultDelivery("udp") || !bytes.Equal(frame.Data, encodeJSON(target)) {
				t.Fatal("automatic policy overrode or aliased an explicit contract")
			}
			if err := s.call(context.Background(), func() {
				st := s.streams[flow.id]
				if st.fecProfile != want || st.target.FEC == nil || *st.target.FEC != want || !bytes.Equal(frame.Data, encodeJSON(st.target)) {
					t.Error("manual contract/retry image changed after caller mutation")
				}
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDatagramFECPolicyNext16RejectionBeforeAnyOpenSideEffects(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selected Capabilities
		target   protocol.Target
		meta     func(*classification.Metadata)
		want     error
	}{
		{"manual-unselected-is-not-auto-fallback", CapabilityClassAnnouncementV1, protocol.Target{Network: "udp", Address: "example.test:443", Class: protocol.Normal, FEC: ptrNext16Profile(next15FECProfile())}, nil, ErrFECNotNegotiated},
		{"manual-unsupported-is-not-replaced", CapabilityClassAnnouncementV1 | CapabilityDatagramXORV1, protocol.Target{Network: "udp", Address: "example.test:443", Class: protocol.Normal, FEC: ptrNext16Profile(next16PolicyProfile(901))}, nil, ErrFECNotNegotiated},
		{"tcp-manual-repair-still-invalid", CapabilityClassAnnouncementV1 | CapabilityDatagramXORV1, protocol.Target{Network: "tcp", Address: "example.test:443", Class: protocol.Normal, FEC: ptrNext16Profile(next15FECProfile())}, nil, protocol.ErrFECWire},
		{"udp-explicit-stream-mode", CapabilityClassAnnouncementV1 | CapabilityDatagramXORV1, protocol.Target{Network: "udp", Address: "example.test:443", Class: protocol.Normal, Delivery: &protocol.DeliveryContract{Version: 1, Mode: protocol.DeliveryStreamReliable}}, nil, protocol.ErrFECWire},
		{"tcp-explicit-datagram-mode", CapabilityClassAnnouncementV1 | CapabilityDatagramXORV1, protocol.Target{Network: "tcp", Address: "example.test:443", Class: protocol.Normal, Delivery: &protocol.DeliveryContract{Version: 1, Mode: protocol.DeliveryDatagramBestEffort}}, nil, protocol.ErrFECWire},
		{"invalid-local-domain-before-selection", CapabilityClassAnnouncementV1 | CapabilityDatagramXORV1, protocol.Target{Network: "udp", Address: "example.test:443", Class: protocol.Normal, Domain: "bad..test"}, func(meta *classification.Metadata) { meta.DomainTrusted = true }, classification.ErrMetadata},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := classification.DefaultConfig()
			cfg.Behavior.Enabled = false
			s := next16PolicyActor(t, cfg, &DatagramFECPolicyConfig{ByClass: map[protocol.Class]protocol.FECProfile{protocol.Normal: next15FECProfile()}}, tc.selected)
			backend := &next15FECNoDialBackend{}
			if err := s.call(context.Background(), func() { s.backend = backend }); err != nil {
				t.Fatal(err)
			}
			meta := classification.Metadata{Target: tc.target}
			if tc.meta != nil {
				tc.meta(&meta)
			}
			conn, err := s.DialMetadata(context.Background(), meta)
			if conn != nil || !errors.Is(err, tc.want) {
				t.Fatalf("invalid policy OPEN conn=%v err=%v want=%v", conn != nil, err, tc.want)
			}
			if err := s.call(context.Background(), func() {
				if s.nextFlow != 2 || len(s.streams) != 1 || s.stats.Opened != 0 || s.queue.Len() != 0 || s.dialing != 0 || backend.dials.Load() != 0 || s.ctx.Err() != nil {
					t.Error("rejected policy OPEN allocated ID/Flow/queue/dial or terminated Session")
				}
				if _, err := s.classTable.Snapshot(2); err == nil {
					t.Error("rejected contract allocated classification control state")
				}
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func ptrNext16Profile(profile protocol.FECProfile) *protocol.FECProfile { return &profile }

func TestDatagramFECPolicyNext16TCPKeepsReliableDeliveryWithoutAutomaticFEC(t *testing.T) {
	for _, class := range []protocol.Class{protocol.Interactive, protocol.Normal, protocol.Bulk} {
		t.Run(map[protocol.Class]string{protocol.Interactive: "interactive", protocol.Normal: "normal", protocol.Bulk: "bulk"}[class], func(t *testing.T) {
			cfg := classification.Config{DefaultClass: class}
			s := next16PolicyActor(t, cfg, &DatagramFECPolicyConfig{ByClass: map[protocol.Class]protocol.FECProfile{class: next15FECProfile()}}, CapabilityClassAnnouncementV1|CapabilityDatagramXORV1)
			delivery := protocol.DefaultDelivery("tcp")
			flow, target, _ := next16PolicyOpen(t, s, classification.Metadata{Target: protocol.Target{Network: "tcp", Address: "example.test:443", Class: class, Delivery: &delivery}})
			if target.Class != class || target.FEC != nil || target.Delivery == nil || *target.Delivery != delivery {
				t.Fatal("class policy changed TCP OPEN delivery/FEC")
			}
			if err := s.call(context.Background(), func() {
				st := s.streams[flow.id]
				if st.delivery != protocol.DefaultDelivery("tcp") || st.fecProfile != protocol.DisabledFECProfile() {
					t.Error("class policy changed reliable TCP contract")
				}
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDatagramFECPolicyNext16BehaviorPeerAndRecoveryDoNotReselectContract(t *testing.T) {
	for _, repairInitially := range []bool{false, true} {
		t.Run(map[bool]string{false: "off-stays-off", true: "xor-stays-xor"}[repairInitially], func(t *testing.T) {
			initial, afterBulk := protocol.DisabledFECProfile(), next16PolicyProfile(700)
			if repairInitially {
				initial, afterBulk = next15FECProfile(), protocol.DisabledFECProfile()
			}
			s := next16PolicyActor(t, classPolicy(), &DatagramFECPolicyConfig{ByClass: map[protocol.Class]protocol.FECProfile{protocol.Normal: initial, protocol.Bulk: afterBulk}}, CapabilityClassAnnouncementV1|CapabilityDatagramXORV1)
			var elapsed time.Duration
			if err := s.call(context.Background(), func() { s.classNow = func() time.Time { return s.classOrigin.Add(elapsed) } }); err != nil {
				t.Fatal(err)
			}
			flow, target, wire := next16PolicyOpen(t, s, classification.Metadata{Target: protocol.Target{Network: "udp", Address: "example.test:443", Class: protocol.Normal}})
			if err := s.call(context.Background(), func() {
				st := s.streams[flow.id]
				for i := 0; i < 10; i++ {
					elapsed = time.Duration(i) * 100 * time.Millisecond
					s.observeTX(st, 200)
				}
				if st.effectiveClass != protocol.Bulk || st.txClassifier.Snapshot().Class != protocol.Bulk {
					t.Error("fixture did not exercise actual behavior downgrade")
				}
				s.handleClassControl(protocol.Frame{Kind: protocol.ClassUpdate, Flow: flow.id, Offset: 1, Value: uint64(protocol.Bulk)})
				snap := s.classificationSnapshot(st)
				if !snap.PeerTX.Known || snap.PeerTX.Class != protocol.Bulk || st.delivery != protocol.DefaultDelivery("udp") || st.fecProfile != initial || !bytes.Equal(wire.Data, encodeJSON(st.target)) {
					t.Error("behavior/peer class announcement changed immutable delivery/FEC/OPEN")
				}
			}); err != nil {
				t.Fatal(err)
			}
			// Drive the production attach transaction. The command-only fixture has
			// no physical sockets, but all recovery state changes are real.
			resumed := &carrier{kind: "tcp", generation: 8, profile: ProfileClassAnnouncementV1, capabilities: CapabilityClassAnnouncementV1 | CapabilityDatagramXORV1}
			if err := s.attach(resumed, 7); err != nil {
				t.Fatal(err)
			}
			if err := s.call(context.Background(), func() {
				st := s.streams[flow.id]
				if st.fecProfile != initial || st.delivery != protocol.DefaultDelivery("udp") || st.effectiveClass != protocol.Bulk || !bytes.Equal(wire.Data, encodeJSON(st.target)) || !bytes.Equal(wire.Data, encodeJSON(target)) {
					t.Error("carrier recovery reselected initial FEC or changed OPEN/reliability/class")
				}
				s.active, s.peerDone, s.localDoneAck = true, true, true
			}); err != nil {
				t.Fatal(err)
			}
			if n, err := flow.Write(make([]byte, 901)); n != 901 || err != nil {
				t.Fatalf("Datagram after TCP attach n=%d err=%v", n, err)
			}
			if err := s.call(context.Background(), func() {
				if s.queue.Len() != 2 {
					t.Error("TCP recovery added unnecessary parity")
				}
				for s.queue.Len() > 0 {
					frame, _ := s.queue.Pop()
					if frame.Kind != protocol.Datagram {
						t.Error("UDP repair was used on the TCP carrier")
					}
				}
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
