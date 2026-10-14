package session

import (
	"bfp/classification"
	"bfp/protocol"
	"bfp/scheduler"
	"bfp/security"
	"bytes"
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func next15FECProfile() protocol.FECProfile {
	return protocol.FECProfile{Version: protocol.FECWireVersion, Algorithm: protocol.FECXOR1,
		MaxDataShards: 32, ParityShards: 1, ShardSize: 900, MaxBlockSize: 32 * 900}
}

func next15FECNegotiation(required bool) *NegotiationConfig {
	selected := CapabilityClassAnnouncementV1 | CapabilityDatagramXORV1
	require := CapabilityClassAnnouncementV1
	if required {
		require = selected
	}
	return &NegotiationConfig{ProfileClassAnnouncementV1, selected, require}
}

func TestFECAdmissionNext15CapabilitySelectionOptionalAndPinned(t *testing.T) {
	if CapabilityDatagramXORV1 != 4 || knownCapabilities&2 != 0 {
		t.Fatal("datagram XOR reused the reserved unknown optional bit")
	}
	wantDefault := []byte(`{"p":"class-announcement-v1","o":1,"r":1}`)
	if got := encodeJSON(defaultCapabilityOffer()); !bytes.Equal(got, wantDefault) {
		t.Fatal("optional FEC changed the default authenticated offer")
	}
	class := CapabilityClassAnnouncementV1
	both := class | CapabilityDatagramXORV1
	for _, tc := range []struct {
		name     string
		offer    capabilityOffer
		server   *NegotiationConfig
		previous *sessionInfo
		want     Capabilities
		wantErr  bool
	}{
		{"defaults", defaultCapabilityOffer(), nil, nil, class, false},
		{"client-only-optional", capabilityOffer{ProfileClassAnnouncementV1, both, class}, nil, nil, class, false},
		{"server-only-optional", defaultCapabilityOffer(), next15FECNegotiation(false), nil, class, false},
		{"both-optional", capabilityOffer{ProfileClassAnnouncementV1, both, class}, next15FECNegotiation(false), nil, both, false},
		{"reserved-bit-stays-unknown", capabilityOffer{ProfileClassAnnouncementV1, both | 2, class}, &NegotiationConfig{ProfileClassAnnouncementV1, both | 2, class}, nil, both, false},
		{"client-required-server-unsupported", capabilityOffer{ProfileClassAnnouncementV1, both, both}, nil, nil, 0, true},
		{"server-required-client-unsupported", defaultCapabilityOffer(), next15FECNegotiation(true), nil, 0, true},
		{"reserved-bit-required", capabilityOffer{ProfileClassAnnouncementV1, both | 2, both | 2}, next15FECNegotiation(false), nil, 0, true},
		{"resume-pinned", capabilityOffer{ProfileClassAnnouncementV1, both, both}, next15FECNegotiation(false), &sessionInfo{Profile: ProfileClassAnnouncementV1, Capabilities: both}, both, false},
		{"resume-added-offer", capabilityOffer{ProfileClassAnnouncementV1, both | 2, both}, next15FECNegotiation(false), &sessionInfo{Profile: ProfileClassAnnouncementV1, Capabilities: both}, 0, true},
		{"resume-dropped-fec", defaultCapabilityOffer(), next15FECNegotiation(false), &sessionInfo{Profile: ProfileClassAnnouncementV1, Capabilities: both}, 0, true},
		{"resume-server-downgrade", capabilityOffer{ProfileClassAnnouncementV1, both, both}, nil, &sessionInfo{Profile: ProfileClassAnnouncementV1, Capabilities: both}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile, selected, err := selectCapabilities(tc.offer, tc.server, tc.previous)
			if tc.wantErr {
				if !errors.Is(err, security.ErrAuthentication) {
					t.Fatalf("invalid negotiation err=%v", err)
				}
				return
			}
			if err != nil || profile != ProfileClassAnnouncementV1 || selected != tc.want {
				t.Fatalf("selection profile=%q selected=%d err=%v want=%d", profile, selected, err, tc.want)
			}
		})
	}
}

func TestFECAdmissionNext15RealHandshakeAndResumePinSelection(t *testing.T) {
	for _, tc := range []struct {
		name      string
		serverFEC bool
		clientFEC bool
		want      Capabilities
	}{
		{"default", false, false, CapabilityClassAnnouncementV1},
		{"client-optional-server-default", false, true, CapabilityClassAnnouncementV1},
		{"server-optional-client-default", true, false, CapabilityClassAnnouncementV1},
		{"both-explicit", true, true, CapabilityClassAnnouncementV1 | CapabilityDatagramXORV1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, cred := newSecurityTestServer(t)
			if tc.serverFEC {
				s.cfg.Negotiation = next15FECNegotiation(false)
			}
			go s.Serve(context.Background())
			cfg := ClientConfig{Server: s.Addr().String(), TCPServer: s.Addr().String(), Credentials: cred,
				Options: Options{HandshakeTimeout: time.Second}}
			if tc.clientFEC {
				cfg.Negotiation = next15FECNegotiation(false)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			initial, previous, err := establish(ctx, cfg, "udp", randomID(), nil)
			if err != nil {
				t.Fatal("initial UDP handshake", err)
			}
			defer initial.close()
			if previous.Profile != ProfileClassAnnouncementV1 || previous.Capabilities != tc.want || initial.capabilities != tc.want {
				t.Fatalf("authenticated initial selection=%d carrier=%d want=%d", previous.Capabilities, initial.capabilities, tc.want)
			}
			// Caller configuration is no longer negotiation authority on recovery.
			cfg.Negotiation = &NegotiationConfig{Profile: "changed-after-initial-handshake"}
			resumed, info, err := establish(ctx, cfg, "tcp", randomID(), &previous)
			if err != nil {
				t.Fatal("TCP recovery handshake", err)
			}
			defer resumed.close()
			if info.ID != previous.ID || info.Generation != previous.Generation+1 || info.Profile != previous.Profile || info.Capabilities != tc.want || resumed.capabilities != tc.want {
				t.Fatal("carrier recovery changed the authenticated Session selection")
			}
			s.mu.Lock()
			owner := s.sessions[info.ID]
			s.mu.Unlock()
			if owner == nil {
				t.Fatal("real handshake did not retain the Session owner")
			}
			snapshot, err := sessionSnapshot(owner)
			if err != nil || snapshot.Profile != previous.Profile || snapshot.Capabilities != tc.want || snapshot.Generation != info.Generation {
				t.Fatalf("retained Session selection differs from recovery: err=%v", err)
			}
		})
	}
}

// This fixture drives production command admission, not flush/maintenance or
// fake socket I/O. Every mutable field is installed by its owner command.
func next15FECActor(t *testing.T) (*Session, *Flow, *streamState) {
	t.Helper()
	s, flow, st := transportUDPActor(t, 32<<10)
	cfg := classification.DefaultConfig()
	cfg.Behavior.Enabled = false
	policy, err := classification.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var policyErr error
	if err := s.call(context.Background(), func() {
		s.info.Profile, s.info.Capabilities = ProfileClassAnnouncementV1, CapabilityClassAnnouncementV1|CapabilityDatagramXORV1
		s.client = true
		s.nextFlow = 2
		s.current = &carrier{kind: "udp", generation: 7}
		s.active, s.peerDone, s.localDoneAck = true, true, true
		s.classifier, s.classOrigin, s.classNow = policy, time.Now(), time.Now
		st.delivery, st.fecProfile = protocol.DefaultDelivery("udp"), next15FECProfile()
		st.txClassifier, policyErr = policy.NewFlow(classification.Metadata{Target: st.target}, 0)
	}); err != nil {
		t.Fatal(err)
	}
	if policyErr != nil {
		t.Fatal(policyErr)
	}
	return s, flow, st
}

type next15FECNoDialBackend struct{ dials atomic.Int32 }

func (b *next15FECNoDialBackend) DialContext(context.Context, string, string) (net.Conn, error) {
	b.dials.Add(1)
	return nil, errors.New("unexpected destination dial")
}

func TestFECAdmissionNext15InvalidOpenAllocatesNothing(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selected Capabilities
		network  string
		mutate   func(*protocol.FECProfile)
		wantErr  error
	}{
		{"not-negotiated", CapabilityClassAnnouncementV1, "udp", func(*protocol.FECProfile) {}, ErrFECNotNegotiated},
		{"shard-over-900", CapabilityClassAnnouncementV1 | CapabilityDatagramXORV1, "udp", func(p *protocol.FECProfile) { p.MaxDataShards, p.ShardSize, p.MaxBlockSize = 1, 901, 901 }, ErrFECNotNegotiated},
		{"count-over-32", CapabilityClassAnnouncementV1 | CapabilityDatagramXORV1, "udp", func(p *protocol.FECProfile) { p.MaxDataShards, p.ShardSize, p.MaxBlockSize = 33, 1, 33 }, protocol.ErrFECWire},
		{"block-over-28800", CapabilityClassAnnouncementV1 | CapabilityDatagramXORV1, "udp", func(p *protocol.FECProfile) { p.MaxBlockSize = 32*900 + 1 }, ErrFECNotNegotiated},
		{"reliable-tcp", CapabilityClassAnnouncementV1 | CapabilityDatagramXORV1, "tcp", func(*protocol.FECProfile) {}, protocol.ErrFECWire},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := next15FECProfile()
			tc.mutate(&profile)
			target := protocol.Target{Network: tc.network, Address: "127.0.0.1:1", Class: protocol.Normal, FEC: &profile}
			s, _, _ := next15FECActor(t)
			if err := s.call(context.Background(), func() { s.info.Capabilities = tc.selected }); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := s.DialMetadata(ctx, classification.Metadata{Target: target})
			if conn != nil || !errors.Is(err, tc.wantErr) {
				t.Fatalf("invalid local OPEN conn=%v err=%v want=%v", conn, err, tc.wantErr)
			}
			if err := s.call(context.Background(), func() {
				if s.nextFlow != 2 || len(s.streams) != 1 || s.stats.Opened != 0 || s.queue.Len() != 0 || s.ctx.Err() != nil {
					t.Error("invalid local OPEN changed flow/id/queue/Session state")
				}
			}); err != nil {
				t.Fatal(err)
			}
			peer, _ := stateSession(t, "udp")
			backend := &next15FECNoDialBackend{}
			peer.info.Profile, peer.info.Capabilities = ProfileClassAnnouncementV1, tc.selected
			peer.backend = backend
			peer.handleOpen(protocol.Frame{Kind: protocol.Open, Flow: 2, Data: encodeJSON(target)})
			if peer.ctx.Err() == nil || len(peer.streams) != 1 || peer.dialing != 0 || peer.stats.Opened != 0 || peer.queue.Len() != 0 || backend.dials.Load() != 0 {
				t.Fatal("invalid authenticated OPEN allocated a Flow/response/target dial")
			}
		})
	}
}

func TestFECAdmissionNext15ContractPointersCopiedBeforeQueuedOpen(t *testing.T) {
	s, _, _ := next15FECActor(t)
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	s.post(func() { close(started); <-release })
	<-started
	delivery, profile := protocol.DefaultDelivery("udp"), next15FECProfile()
	wantDelivery, wantProfile := delivery, profile
	target := protocol.Target{Network: "udp", Address: "example.test:443", Class: protocol.Normal, Delivery: &delivery, FEC: &profile}
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		conn, err := s.DialMetadata(ctx, classification.Metadata{Target: target})
		done <- result{conn, err}
	}()
	// Receiving this command establishes a happens-before edge after the API
	// copied its arguments; channel length would not provide that guarantee.
	var command func()
	select {
	case command = <-s.commands:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	delivery.Version, delivery.Mode = 255, protocol.DeliveryStreamReliable
	profile.Version, profile.ShardSize = 255, 901
	s.commands <- command
	unblock()
	var retained protocol.Target
	var contract protocol.DeliveryContract
	var repairProfile protocol.FECProfile
	var queued protocol.Frame
	var found bool
	if err := s.call(ctx, func() {
		st := s.streams[2]
		if st == nil {
			return
		}
		retained, contract, repairProfile = st.target, st.delivery, st.fecProfile
		queued, found = s.queue.Pop()
		s.result(st, "ok")
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case out := <-done:
		if out.err != nil || out.conn == nil {
			t.Fatalf("caller mutation changed queued OPEN admission: %v", out.err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if retained.Delivery == &delivery || retained.FEC == &profile || retained.Delivery == nil || retained.FEC == nil || *retained.Delivery != wantDelivery || *retained.FEC != wantProfile || contract != wantDelivery || repairProfile != wantProfile {
		t.Fatal("OPEN retained caller-owned or mutated delivery/FEC contract")
	}
	var wireTarget protocol.Target
	if !found || queued.Kind != protocol.Open || queued.Flow != 2 || decodeJSON(queued.Data, &wireTarget) != nil || wireTarget.Delivery == nil || wireTarget.FEC == nil || *wireTarget.Delivery != wantDelivery || *wireTarget.FEC != wantProfile {
		t.Fatal("OPEN wire image did not preserve the copied admission contract")
	}
	// Later retry serialization must stay frozen too, after the first OPEN was
	// admitted and the caller mutates the same pointers a second time.
	delivery.Mode, profile.ShardSize = protocol.DeliveryDatagramBestEffort, 1
	if !bytes.Equal(queued.Data, encodeJSON(retained)) {
		t.Fatal("caller mutation changed the retained OPEN retry image")
	}
}

func TestFECAdmissionNext15DatagramBatchIncludesBoundParity(t *testing.T) {
	for _, size := range []int{0, 901, 16 << 10} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			s, flow, st := next15FECActor(t)
			payload := bytes.Repeat([]byte{0x71}, size)
			flow.SetWriteDeadline(time.Now().Add(time.Second))
			if n, err := flow.Write(payload); n != size || err != nil {
				t.Fatalf("datagram admission n=%d err=%v", n, err)
			}
			var frames []protocol.Frame
			var next, observed uint64
			if err := s.call(context.Background(), func() {
				next, observed = st.messageNext, st.txClassifier.Snapshot().TotalBytes
				for s.queue.Len() > 0 {
					frame, ok := s.queue.Pop()
					if !ok {
						break
					}
					frames = append(frames, frame)
				}
			}); err != nil {
				t.Fatal(err)
			}
			count := max(1, (size+899)/900)
			if next != 2 || observed != uint64(size) || len(frames) != count+1 {
				t.Fatalf("message admission count/id/class bytes: items=%d next=%d observed=%d", len(frames), next, observed)
			}
			for i, frame := range frames[:count] {
				at, end := i*900, min(size, (i+1)*900)
				if frame.Kind != protocol.Datagram || frame.Flow != flow.id || frame.Offset != 1 || frame.Value != uint64(size)<<32|uint64(at) || !bytes.Equal(frame.Data, payload[at:end]) {
					t.Fatalf("data fragment %d does not preserve message boundary", i)
				}
			}
			parity := frames[count]
			r, err := protocol.DecodeDatagramRepair(parity.Data)
			if err != nil || parity.Kind != protocol.DatagramRepairFrame || parity.Flow != flow.id || parity.Offset != 1 || parity.Value != 7 {
				t.Fatalf("batch repair frame scope err=%v", err)
			}
			if r.Meta.Flow != flow.id || r.Meta.BlockID != 1 || r.Meta.Generation != 7 || r.Meta.Direction != protocol.RepairDirectionOutbound || int(r.Meta.DataShards) != count || len(r.Meta.Lengths) != count || r.Meta.DataShards > st.fecProfile.MaxDataShards || r.Meta.ShardSize != 900 || r.Meta.ParityShards != 1 {
				t.Fatal("repair metadata is not bound to the admitted message/profile")
			}
			for i, length := range r.Meta.Lengths {
				if int(length) != min(900, size-i*900) {
					t.Fatal("repair lengths did not retain the original shard lengths")
				}
			}
		})
	}
}

func TestFECAdmissionNext15DatagramRejectedBatchHasNoPartialCommit(t *testing.T) {
	for _, mode := range []string{"queue-bytes", "session-bytes", "queue-items", "flow-items", "class-items", "profile-count", "expired", "not-negotiated"} {
		t.Run(mode, func(t *testing.T) {
			s, flow, st := next15FECActor(t)
			marker := protocol.Frame{Kind: protocol.Ping, Flow: 99, Value: 123, Data: []byte("pre-existing")}
			limits := scheduler.Limits{MaxBytes: 1 << 16}
			switch mode {
			case "queue-bytes":
				limits.MaxBytes = 2500 // marker + both data records fit; parity does not.
			case "queue-items":
				limits.MaxItems = 3
			case "flow-items":
				limits.MaxFlowItems = 2
			case "class-items":
				limits.MaxClassItems = 3
			}
			var setupErr error
			if err := s.call(context.Background(), func() {
				st.messageNext = 31
				s.queue = scheduler.NewWithLimits[protocol.Frame](1200, limits)
				setupErr = s.queue.Push(marker.Flow, protocol.Normal, 100, marker)
				if mode == "session-bytes" {
					// The queue can admit all records, but the Session's independent
					// byte budget admits only the marker and the data records.
					s.opts.MaxSessionBuffer = 2500
				}
				if mode == "profile-count" {
					st.fecProfile.MaxDataShards, st.fecProfile.ShardSize, st.fecProfile.MaxBlockSize = 2, 100, 200
				}
				if mode == "not-negotiated" {
					s.info.Capabilities = CapabilityClassAnnouncementV1
				}
			}); err != nil || setupErr != nil {
				t.Fatalf("queue fixture err=%v setup=%v", err, setupErr)
			}
			payload := make([]byte, 1800)
			want := error(ErrLimit)
			flow.SetWriteDeadline(time.Now().Add(time.Second))
			if mode == "profile-count" {
				payload = make([]byte, 201)
			}
			if mode == "expired" {
				flow.SetWriteDeadline(time.Now().Add(-time.Second))
				want = context.DeadlineExceeded
			}
			if mode == "not-negotiated" {
				want = ErrFECNotNegotiated
			}
			if n, err := flow.Write(payload); n != 0 || !errors.Is(err, want) {
				t.Fatalf("rejected FEC datagram n=%d err=%v want=%v", n, err, want)
			}
			if err := s.call(context.Background(), func() {
				if st.messageNext != 31 || st.txClassifier.Snapshot().TotalBytes != 0 || s.queue.Len() != 1 || s.queue.Bytes() != 100 {
					t.Error("failed whole-message admission consumed ID/class bytes or a partial batch")
				}
				got, ok := s.queue.Pop()
				if !ok || !reflect.DeepEqual(got, marker) || s.queue.Len() != 0 {
					t.Error("failed admission changed earlier queued data")
				}
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFECAdmissionNext15TCPFallbackRetainsDatagramContractWithoutParity(t *testing.T) {
	s, flow, st := next15FECActor(t)
	profile := next15FECProfile()
	if err := s.call(context.Background(), func() { s.current = &carrier{kind: "tcp", generation: 8} }); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 901)
	if n, err := flow.Write(payload); n != len(payload) || err != nil {
		t.Fatalf("datagram on TCP fallback n=%d err=%v", n, err)
	}
	if err := s.call(context.Background(), func() {
		if st.fecProfile != profile || st.delivery.Mode != protocol.DeliveryDatagramBestEffort || st.messageNext != 2 || s.queue.Len() != 2 || st.txClassifier.Snapshot().TotalBytes != uint64(len(payload)) {
			t.Error("TCP carrier changed the frozen Datagram contract or message accounting")
		}
		for s.queue.Len() > 0 {
			frame, _ := s.queue.Pop()
			if frame.Kind != protocol.Datagram {
				t.Error("TCP fallback spent bandwidth on UDP repair")
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFECAdmissionNext15RepairSchedulingAndNoLogicalRetry(t *testing.T) {
	s, st := stateSession(t, "udp")
	s.current = &carrier{kind: "udp", generation: 7}
	s.udpPath = &udpPath{retries: map[refKey]logicalRef{}}
	frame := protocol.Frame{Kind: protocol.DatagramRepairFrame, Flow: st.flow.id, Offset: 3, Value: 7, Data: []byte("bounded repair")}
	for _, class := range []protocol.Class{protocol.Interactive, protocol.Normal, protocol.Bulk} {
		st.effectiveClass = class
		if got := s.classForFrame(frame); got != class {
			t.Fatalf("repair scheduling class=%d want=%d", got, class)
		}
	}
	ref := makeRef(frame)
	if _, ok := s.resolveRef(ref, time.Now()); ok {
		t.Fatal("lost repair record retained a logical retransmission")
	}
	s.queueRetry(ref)
	if len(s.udpPath.retries) != 0 || s.retryLineage(frame) {
		t.Fatal("best-effort repair entered the retry path")
	}
	if _, tracked := requestOperationKey(frame); tracked {
		t.Fatal("Datagram repair became an acknowledged reliable operation")
	}
}

func TestFECAdmissionNext15PreOpenDataAndRepairCannotReserveOrDeliver(t *testing.T) {
	for _, repairFirst := range []bool{false, true} {
		t.Run(strconv.FormatBool(repairFirst), func(t *testing.T) {
			s, st := fecOwnerNext15(t, "udp", false)
			st.opening = true
			delivery, profile := st.delivery, st.fecProfile
			payload := fecPayloadNext15(1813)
			frames, repair := fecFramesNext15(t, s, st, 1, payload)
			if repairFirst {
				s.handle(repair)
			}
			for _, frame := range frames {
				s.handle(frame)
			}
			s.handle(repair)
			if len(st.datagrams) != 0 || len(st.flow.messages) != 0 || len(st.completed) != 0 || st.messageHigh != 0 || s.stats.RXBuffered != 0 || s.stats.FECRecoveredDatagrams != 0 {
				t.Fatal("pre-OPEN input reserved, delivered, or retired Datagram state")
			}
			if st.delivery != delivery || st.fecProfile != profile || s.ctx.Err() != nil {
				t.Fatal("pre-OPEN input changed the frozen contract or terminated the Session")
			}
			// Rejected early data must not poison the ID after OPEN completion.
			st.opening = false
			s.handle(frames[0])
			s.handle(frames[2])
			s.handle(repair)
			fecExpectOnceNext15(t, s, st, 1, payload, 1)
		})
	}
}

func TestFECAdmissionNext15TCPCarrierRejectsRepairAllowsOrdinaryDatagram(t *testing.T) {
	s, st := fecOwnerNext15(t, "udp", false)
	s.current.kind, s.current.generation = "tcp", 8
	s.info.Generation = 8
	delivery, profile := st.delivery, st.fecProfile
	payload := fecPayloadNext15(1813)
	frames, repair := fecFramesNext15(t, s, st, 1, payload)
	// All metadata matches the new carrier generation. The rejection must be
	// due to the TCP carrier, rather than an old-generation or TCP-flow check.
	s.handle(repair)
	if len(st.datagrams) != 0 || len(st.flow.messages) != 0 || len(st.completed) != 0 || st.messageHigh != 0 || s.stats.RXBuffered != 0 || s.stats.FECRecoveredDatagrams != 0 || s.stats.FECRejected == 0 {
		t.Fatal("current-generation TCP-carrier repair installed Datagram state")
	}
	for _, frame := range frames {
		s.handle(frame)
	}
	fecExpectOnceNext15(t, s, st, 1, payload, 0)
	if st.delivery != delivery || st.fecProfile != profile || st.target.Network != "udp" || st.flow.network != "udp" {
		t.Fatal("TCP fallback mutated the Datagram delivery/FEC admission contract")
	}
}
