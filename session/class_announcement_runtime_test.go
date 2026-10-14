package session

import (
	"bfp/classification"
	"bfp/internal/classcontrol"
	"bfp/internal/udptransport"
	"bfp/obfuscation"
	"bfp/protocol"
	"bfp/security"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// This filter decrypts a separate copy only to choose loss events. The actual
// Session still authenticates, parses and applies every delivered record.
// Class ACK loss must not also discard PacketAck or the opposite TX direction.
type classRuntimeFilter struct {
	holdACK    atomic.Bool
	ackVersion atomic.Uint64 // zero selects every ClassUpdate ACK
	dropped    atomic.Uint32
	done       chan struct{}
}

func newClassAnnouncementFixture(t *testing.T, kind string) (*runtimeFixture, *classRuntimeFilter) {
	t.Helper()
	filter := &classRuntimeFilter{done: make(chan struct{})}
	opts := Options{HandshakeTimeout: time.Second, ProbeInterval: 100 * time.Millisecond,
		FailureTimeout: 5 * time.Second, RetainTimeout: 5 * time.Second,
		KeyUpdateBytes: 1 << 30, KeyUpdateInterval: time.Hour}
	f := newRuntimeFixtureWith(t, kind, opts, func(s *Session, c *carrier) {
		shadow, err := security.NewRecordCipher(c.keys.Receive[:], c.handle, 0)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			defer close(filter.done)
			for {
				wire, err := c.read()
				if err != nil {
					s.deliverPacket(packet{c: c, err: err})
					return
				}
				payload, _, err := shadow.Open(wire)
				if err == nil {
					payload, err = obfuscation.Unpad(payload)
					if err == nil {
						frames, decodeErr := protocol.Decode(payload)
						if decodeErr == nil && len(frames) == 1 {
							frame := frames[0]
							version := filter.ackVersion.Load()
							if frame.Kind == protocol.ClassUpdate && frame.Flags == 1 &&
								filter.holdACK.Load() && (version == 0 || version == frame.Offset) {
								filter.dropped.Add(1)
								continue
							}
						}
					}
				}
				if !s.deliver(c, wire) && c.kind == "tcp" {
					return
				}
			}
		}()
	})
	t.Cleanup(func() {
		f.client.Close()
		select {
		case <-filter.done:
		case <-time.After(time.Second):
			t.Error("class loss reader did not stop")
		}
	})
	return f, filter
}

// Inject intentionally bypasses class semantics on the sending side so that
// malformed authenticated input reaches the real receiver. UDP still records
// the sent packet number: subsequent real PacketAck must not mistake this test
// record for an unsent hole. No fake class publication proof is created.
func classRuntimeInject(t *testing.T, sender *Session, frames ...protocol.Frame) {
	t.Helper()
	var sendErr error
	err := sender.call(context.Background(), func() {
		plain, err := protocol.Encode(frames)
		if err != nil {
			sendErr = err
			return
		}
		maximum := security.MaxRecordSize - security.RecordOverhead
		if sender.current.kind == "udp" {
			maximum = security.MaxUDPRecordSize - security.RecordOverhead
		}
		plain, err = obfuscation.Pad(plain, maximum)
		if err != nil {
			sendErr = err
			return
		}
		meta := sender.current.tx.NextMeta()
		var packet udptransport.Packet
		if sender.current.kind == "udp" {
			packet = udptransport.Packet{Scope: sender.udpPath.scope(meta.Epoch), Number: meta.Number,
				Size:   uint32(len(plain) + security.RecordOverhead),
				SentAt: sender.transportTime().Sub(sender.udpPath.origin), AckEliciting: true}
			if err = sender.udpPath.ledger.CheckCommit(packet); err != nil {
				sendErr = err
				return
			}
		}
		wire, actual, err := sender.current.tx.Seal(plain)
		if err == nil && actual != meta {
			err = ErrState
		}
		if err == nil {
			err = sender.current.write(wire)
		}
		if err != nil {
			sendErr = err
			return
		}
		if sender.current.kind == "udp" {
			packet.SentAt = sender.transportTime().Sub(sender.udpPath.origin)
			if _, err = sender.udpPath.ledger.Commit(packet); err != nil {
				sendErr = err
				return
			}
			sender.flight = int(sender.udpPath.ledger.Snapshot().Flight)
			sender.paceTokens -= float64(len(wire))
		}
		sender.stats.WireSent += uint64(len(wire))
		sender.bytesSinceKey += uint64(len(wire))
	})
	if err != nil || sendErr != nil {
		t.Fatalf("encrypted class injection: command=%v send=%v", err, sendErr)
	}
}

func classRuntimeConverged(s *Session, id uint64, version uint64) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	v, err := s.FlowClassification(ctx, id)
	return err == nil && v.TXVersion == version && v.TXPublishedVersion == version &&
		v.TXAckedVersion == version && !v.TXPending && v.PeerTX.Known
}

func classRuntimeInitial(t *testing.T, f *runtimeFixture, flow *Flow) {
	t.Helper()
	runtimeWait(t, "both initial class announcements are precisely acknowledged", func() bool {
		return classRuntimeConverged(f.client, flow.id, 1) && classRuntimeConverged(f.peer, flow.id, 1)
	})
	for _, endpoint := range []*Session{f.client, f.peer} {
		v := classSnapshot(t, endpoint, flow.id)
		if v.PeerTX.Version != 1 || v.PeerTX.Class != protocol.Normal || v.LocalTX.Class != protocol.Normal {
			t.Fatalf("initial peer/local classes differ: %+v", v)
		}
	}
}

func classRuntimeClosed(t *testing.T, endpoint *Session) {
	t.Helper()
	select {
	case <-endpoint.done:
	case <-time.After(2 * time.Second):
		t.Fatal("authenticated class protocol error did not close the Session")
	}
}

func classRuntimeTableSnapshot(t *testing.T, s *Session, id uint64) classcontrol.Snapshot {
	t.Helper()
	var state classcontrol.Snapshot
	var stateErr error
	if err := s.call(context.Background(), func() { state, stateErr = s.classTable.Snapshot(id) }); err != nil || stateErr != nil {
		t.Fatalf("class table query: command=%v state=%v", err, stateErr)
	}
	return state
}

type classRuntimeGuard struct {
	policy                             classification.Snapshot
	classifier                         *classification.Flow
	effectiveClass                     protocol.Class
	target                             protocol.Target
	targetConn                         net.Conn
	maxRemote, sessionCredit           uint64
	totalSent, totalReceived, consumed uint64
	flowCount, classCount              int
}

type classRuntimeBlockedBackend struct {
	underlying Backend
	entered    chan struct{}
	release    chan struct{}
}

func (b *classRuntimeBlockedBackend) DialContext(ctx context.Context, kind, address string) (net.Conn, error) {
	close(b.entered)
	select {
	case <-b.release:
		return b.underlying.DialContext(ctx, kind, address)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func classRuntimeGuardState(t *testing.T, s *Session, id uint64) classRuntimeGuard {
	t.Helper()
	var out classRuntimeGuard
	if err := s.call(context.Background(), func() {
		st := s.streams[id]
		out = classRuntimeGuard{policy: st.txClassifier.Snapshot(), classifier: st.txClassifier,
			effectiveClass: st.effectiveClass, target: st.target, targetConn: st.targetConn, maxRemote: st.maxRemote,
			sessionCredit: s.peerSessionMax, totalSent: s.totalSent,
			totalReceived: s.totalReceived, consumed: s.totalConsumed,
			flowCount: len(s.streams), classCount: s.classTable.Usage()}
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestClassAnnouncementRuntimeInitialBidirectional(t *testing.T) {
	for _, kind := range []string{"tcp", "udp"} {
		t.Run(kind, func(t *testing.T) {
			f, _ := newClassAnnouncementFixture(t, kind)
			flow := runtimeFlow(t, f).(*Flow)
			classRuntimeInitial(t, f, flow)
			runtimeExchange(t, flow, []byte("class announcements are encrypted controls"))
			for _, endpoint := range []*Session{f.client, f.peer} {
				v := classSnapshot(t, endpoint, flow.id)
				if v.TXVersion != 1 || v.TXPublishedVersion != 1 || v.TXAckedVersion != 1 || v.TXPending {
					t.Fatalf("ordinary traffic advanced a stable class version: %+v", v)
				}
			}
			if f.backend.dials.Load() != 1 {
				t.Fatal("announcement redialed target")
			}
		})
	}
}

func TestClassAnnouncementRuntimePreOPENInputCannotInstallPeerState(t *testing.T) {
	for _, kind := range []string{"tcp", "udp"} {
		t.Run(kind, func(t *testing.T) {
			f, _ := newClassAnnouncementFixture(t, kind)
			blocked := &classRuntimeBlockedBackend{underlying: f.backend, entered: make(chan struct{}), release: make(chan struct{})}
			var id uint64
			if err := f.peer.call(context.Background(), func() { f.peer.backend = blocked }); err != nil {
				t.Fatal(err)
			}
			if err := f.client.call(context.Background(), func() { id = f.client.nextFlow }); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			type dialResult struct {
				conn net.Conn
				err  error
			}
			done := make(chan dialResult, 1)
			go func() {
				conn, err := f.client.DialContext(ctx, "tcp", f.target)
				done <- dialResult{conn, err}
			}()
			select {
			case <-blocked.entered:
			case <-ctx.Done():
				t.Fatal("target backend did not enter blocked OPEN")
			}
			// Both endpoints have allocated this flow, but neither has received
			// proof of successful OPEN installation. Valid-looking frames must
			// not create peer state, publications or ACK obligations yet.
			for _, direction := range []struct{ sender, receiver *Session }{{f.client, f.peer}, {f.peer, f.client}} {
				before := classRuntimeGuardState(t, direction.receiver, id)
				classRuntimeInject(t, direction.sender,
					protocol.Frame{Kind: protocol.ClassUpdate, Flow: id, Offset: 9, Value: uint64(protocol.Bulk)},
					protocol.Frame{Kind: protocol.ClassUpdate, Flags: 1, Flow: id, Offset: 9, Value: uint64(protocol.Bulk)},
					protocol.Frame{Kind: protocol.MaxSessionData, Value: before.sessionCredit + 1})
				runtimeWait(t, "pre-OPEN class input processed without installation", func() bool {
					return classRuntimeGuardState(t, direction.receiver, id).sessionCredit == before.sessionCredit+1
				})
				state := classRuntimeTableSnapshot(t, direction.receiver, id)
				if state.Peer.Known || state.Enabled || state.AckPending || state.Published.Version != 0 || state.Acked.Version != 0 || state.Local.Version != 1 || !state.Pending {
					t.Fatalf("pre-OPEN input changed class lifecycle: %+v", state)
				}
			}
			close(blocked.release)
			var result dialResult
			select {
			case result = <-done:
			case <-ctx.Done():
				t.Fatal("OPEN failed to complete after backend release")
			}
			if result.err != nil {
				t.Fatal(result.err)
			}
			flow := result.conn.(*Flow)
			t.Cleanup(func() { flow.Close() })
			classRuntimeInitial(t, f, flow)
			if f.backend.dials.Load() != 1 {
				t.Fatal("pre-OPEN class input opened another target")
			}
		})
	}
}

func TestClassAnnouncementRuntimePeerViewIsReadOnlyAndMonotonic(t *testing.T) {
	for _, kind := range []string{"tcp", "udp"} {
		t.Run(kind, func(t *testing.T) {
			f, filter := newClassAnnouncementFixture(t, kind)
			flow := runtimeFlow(t, f).(*Flow)
			classRuntimeInitial(t, f, flow)
			runtimeExchange(t, flow, []byte("unique application bytes"))
			runtimeWait(t, "application credit updates settle before peer-view comparison", func() bool {
				guard := classRuntimeGuardState(t, f.peer, flow.id)
				return guard.maxRemote == uint64(f.client.opts.MaxFlowBuffer)+24 &&
					guard.sessionCredit == uint64(f.client.opts.MaxSessionBuffer)+24
			})
			setClassClock(t, f.peer) // Freeze behavior windows for exact local-state comparison.
			if err := f.peer.call(context.Background(), func() { f.peer.tickClassification() }); err != nil {
				t.Fatal(err)
			}
			before := classRuntimeGuardState(t, f.peer, flow.id)
			// This endpoint models a malicious authenticated peer. Returned ACKs
			// are dropped because it has intentionally published no local proof.
			filter.holdACK.Store(true)
			for _, version := range []uint64{5, 2, 5} {
				dropped := filter.dropped.Load()
				frame := protocol.Frame{Kind: protocol.ClassUpdate, Flow: flow.id, Offset: version, Value: uint64(protocol.Interactive)}
				classRuntimeInject(t, f.client, frame)
				runtimeWait(t, "new peer class remains installed", func() bool {
					v := classSnapshot(t, f.peer, flow.id)
					return v.PeerTX.Known && v.PeerTX.Version == 5 && v.PeerTX.Class == protocol.Interactive && filter.dropped.Load() > dropped
				})
			}
			if after := classRuntimeGuardState(t, f.peer, flow.id); after != before {
				t.Fatalf("peer view changed local classification/credit/target: before=%+v after=%+v", before, after)
			}
			if f.backend.dials.Load() != 1 {
				t.Fatal("peer view created another target")
			}
			classRuntimeInject(t, f.client, protocol.Frame{Kind: protocol.ClassUpdate, Flow: flow.id, Offset: 5, Value: uint64(protocol.Bulk)})
			classRuntimeClosed(t, f.peer)
			if f.backend.dials.Load() != 1 {
				t.Fatal("conflicting class announcement redialed target")
			}
		})
	}
}

func TestClassAnnouncementRuntimeRejectsMalformedAuthenticatedInput(t *testing.T) {
	for _, kind := range []string{"tcp", "udp"} {
		for _, tc := range []struct {
			name  string
			frame protocol.Frame
		}{
			{"flags", protocol.Frame{Flags: 2, Offset: 1, Value: 1}},
			{"zero-version", protocol.Frame{Value: 1}},
			{"ack-zero-version", protocol.Frame{Flags: 1, Value: 1}},
			{"data", protocol.Frame{Offset: 1, Value: 1, Data: []byte("unexpected")}},
			{"ack-data", protocol.Frame{Flags: 1, Offset: 1, Value: 1, Data: []byte("unexpected")}},
			{"u64-class-truncation", protocol.Frame{Offset: 1, Value: 256}},
			{"ack-u64-class-truncation", protocol.Frame{Flags: 1, Offset: 1, Value: 256}},
			{"max-u64-class", protocol.Frame{Offset: 1, Value: math.MaxUint64}},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				f, _ := newClassAnnouncementFixture(t, kind)
				flow := runtimeFlow(t, f).(*Flow)
				classRuntimeInitial(t, f, flow)
				frame := tc.frame
				frame.Kind, frame.Flow = protocol.ClassUpdate, flow.id
				classRuntimeInject(t, f.client, frame)
				classRuntimeClosed(t, f.peer)
				if f.backend.dials.Load() != 1 {
					t.Fatal("malformed class input allocated a target")
				}
			})
		}
	}
}

func TestClassAnnouncementRuntimeUnknownAndTerminalDoNotAllocate(t *testing.T) {
	for _, kind := range []string{"tcp", "udp"} {
		t.Run(kind, func(t *testing.T) {
			f, _ := newClassAnnouncementFixture(t, kind)
			flow := runtimeFlow(t, f).(*Flow)
			classRuntimeInitial(t, f, flow)
			before := classRuntimeGuardState(t, f.peer, flow.id)
			unknown := flow.id + 10000
			// An ordered, ordinary credit update proves the preceding unknown
			// class frame was processed; a timer alone would prove nothing.
			marker := before.maxRemote + 1
			classRuntimeInject(t, f.client,
				protocol.Frame{Kind: protocol.ClassUpdate, Flow: unknown, Offset: 1, Value: uint64(protocol.Bulk)},
				protocol.Frame{Kind: protocol.ClassUpdate, Flags: 1, Flow: unknown, Offset: 1, Value: uint64(protocol.Bulk)},
				protocol.Frame{Kind: protocol.MaxFlowData, Flow: flow.id, Value: marker})
			runtimeWait(t, "unknown class input processed without allocation", func() bool {
				return classRuntimeGuardState(t, f.peer, flow.id).maxRemote == marker
			})
			if err := f.peer.call(context.Background(), func() {
				if len(f.peer.streams) != before.flowCount || f.peer.classTable.Usage() != before.classCount {
					t.Error("unknown class input allocated state")
				}
				if _, err := f.peer.classTable.Snapshot(unknown); !errors.Is(err, classcontrol.ErrUnknown) {
					t.Errorf("unknown class entry exists: %v", err)
				}
			}); err != nil {
				t.Fatal(err)
			}
			flow.Close()
			runtimeWait(t, "reset flow class metadata is forgotten", func() bool {
				forgotten := false
				_ = f.peer.call(context.Background(), func() {
					_, err := f.peer.classTable.Snapshot(flow.id)
					forgotten = f.peer.streams[flow.id].terminal() && errors.Is(err, classcontrol.ErrUnknown)
				})
				return forgotten
			})
			var count int
			if err := f.peer.call(context.Background(), func() { count = f.peer.classTable.Usage() }); err != nil {
				t.Fatal(err)
			}
			classRuntimeInject(t, f.client, protocol.Frame{Kind: protocol.ClassUpdate, Flow: flow.id, Offset: 99, Value: uint64(protocol.Interactive)},
				protocol.Frame{Kind: protocol.ClassUpdate, Flags: 1, Flow: flow.id, Offset: 99, Value: uint64(protocol.Interactive)},
				protocol.Frame{Kind: protocol.MaxSessionData, Value: before.sessionCredit + 1})
			runtimeWait(t, "terminal class input processed without revival", func() bool {
				processed := false
				_ = f.peer.call(context.Background(), func() {
					processed = f.peer.peerSessionMax == before.sessionCredit+1
				})
				return processed
			})
			if err := f.peer.call(context.Background(), func() {
				if f.peer.classTable.Usage() != count || !f.peer.streams[flow.id].terminal() {
					t.Error("terminal class input recreated pending/peer state")
				}
			}); err != nil {
				t.Fatal(err)
			}
			if f.backend.dials.Load() != 1 {
				t.Fatal("unknown/terminal class input redialed target")
			}
		})
	}
}

func TestClassAnnouncementRuntimeFINTerminalDoesNotAllocate(t *testing.T) {
	for _, kind := range []string{"tcp", "udp"} {
		t.Run(kind, func(t *testing.T) {
			f, _ := newClassAnnouncementFixture(t, kind)
			flow := runtimeFlow(t, f).(*Flow)
			classRuntimeInitial(t, f, flow)
			payload := []byte("finish both byte-stream directions")
			runtimeExchange(t, flow, payload)
			runtimeWait(t, "FIN test application credit settles", func() bool {
				guard := classRuntimeGuardState(t, f.peer, flow.id)
				return guard.sessionCredit == uint64(f.client.opts.MaxSessionBuffer)+uint64(len(payload))
			})
			if err := flow.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if unexpected, err := io.ReadAll(flow); err != nil || len(unexpected) != 0 {
				t.Fatalf("FIN completion changed bytes: data=%q err=%v", unexpected, err)
			}
			runtimeWait(t, "both FIN-terminal class states are forgotten", func() bool {
				for _, endpoint := range []*Session{f.client, f.peer} {
					forgotten := false
					_ = endpoint.call(context.Background(), func() {
						_, err := endpoint.classTable.Snapshot(flow.id)
						forgotten = endpoint.streams[flow.id].terminal() && errors.Is(err, classcontrol.ErrUnknown)
					})
					if !forgotten {
						return false
					}
				}
				return true
			})
			before := classRuntimeGuardState(t, f.peer, flow.id)
			classRuntimeInject(t, f.client,
				protocol.Frame{Kind: protocol.ClassUpdate, Flow: flow.id, Offset: 9, Value: uint64(protocol.Bulk)},
				protocol.Frame{Kind: protocol.ClassUpdate, Flags: 1, Flow: flow.id, Offset: 9, Value: uint64(protocol.Bulk)},
				protocol.Frame{Kind: protocol.MaxSessionData, Value: before.sessionCredit + 1})
			runtimeWait(t, "FIN-terminal class input is processed without revival", func() bool {
				return classRuntimeGuardState(t, f.peer, flow.id).sessionCredit == before.sessionCredit+1
			})
			if after := classRuntimeGuardState(t, f.peer, flow.id); after.classCount != before.classCount || after.flowCount != before.flowCount || after.targetConn != before.targetConn {
				t.Fatalf("FIN-terminal input allocated class/flow/target state: before=%+v after=%+v", before, after)
			}
			if f.backend.dials.Load() != 1 {
				t.Fatal("FIN-terminal class input redialed target")
			}
		})
	}
}

func TestClassAnnouncementRuntimeLostACKReemitsExactReceipt(t *testing.T) {
	for _, kind := range []string{"tcp", "udp"} {
		t.Run(kind, func(t *testing.T) {
			f, filter := newClassAnnouncementFixture(t, kind)
			filter.holdACK.Store(true)
			flow := runtimeFlow(t, f).(*Flow)
			runtimeWait(t, "initial class ACK was lost on encrypted carrier", func() bool { return filter.dropped.Load() > 0 })
			v := classSnapshot(t, f.client, flow.id)
			if v.TXVersion != 1 || v.TXPublishedVersion != 1 || v.TXAckedVersion != 0 || !v.TXPending {
				t.Fatalf("dropped ACK completed announcement: %+v", v)
			}
			filter.holdACK.Store(false)
			classRuntimeInitial(t, f, flow)
			if state := classRuntimeTableSnapshot(t, f.client, flow.id); state.Attempts < 2 {
				t.Fatalf("no actual announcement retry after lost ACK: %+v", state)
			}
			if f.backend.dials.Load() != 1 {
				t.Fatal("lost class ACK redialed target")
			}
		})
	}
}

func TestClassAnnouncementRuntimeOldACKCannotCompleteNewVersion(t *testing.T) {
	for _, kind := range []string{"tcp", "udp"} {
		t.Run(kind, func(t *testing.T) {
			f, filter := newClassAnnouncementFixture(t, kind)
			flow := runtimeFlow(t, f).(*Flow)
			classRuntimeInitial(t, f, flow)
			filter.ackVersion.Store(2)
			filter.holdACK.Store(true)
			if err := f.client.call(context.Background(), func() {
				state, _, err := f.client.classTable.Update(flow.id, protocol.Bulk, f.client.controlStamp(f.client.transportTime()))
				if err != nil {
					t.Error(err)
				} else {
					f.client.streams[flow.id].classTX = state
				}
			}); err != nil {
				t.Fatal(err)
			}
			runtimeWait(t, "new version actually published but ACK withheld", func() bool {
				v := classSnapshot(t, f.client, flow.id)
				return v.TXVersion == 2 && v.TXPublishedVersion == 2 && v.TXAckedVersion == 1 && v.TXPending && filter.dropped.Load() > 0
			})
			before := classRuntimeTableSnapshot(t, f.client, flow.id)
			marker := classRuntimeGuardState(t, f.client, flow.id).maxRemote + 1
			classRuntimeInject(t, f.peer,
				protocol.Frame{Kind: protocol.ClassUpdate, Flags: 1, Flow: flow.id, Offset: 1, Value: uint64(protocol.Normal)},
				protocol.Frame{Kind: protocol.MaxFlowData, Flow: flow.id, Value: marker})
			runtimeWait(t, "old ACK processed before credit marker", func() bool {
				return classRuntimeGuardState(t, f.client, flow.id).maxRemote == marker
			})
			after := classRuntimeTableSnapshot(t, f.client, flow.id)
			if !after.Pending || after.Acked.Version != 1 || after.Local.Version != 2 || after.Started != before.Started || after.Retries < before.Retries {
				t.Fatalf("old ACK completed or renewed newer episode: before=%+v after=%+v", before, after)
			}
			filter.holdACK.Store(false)
			runtimeWait(t, "exact latest ACK converges", func() bool { return classRuntimeConverged(f.client, flow.id, 2) })
			if f.backend.dials.Load() != 1 {
				t.Fatal("old/latest ACK redialed target")
			}
		})
	}
}

func TestClassAnnouncementRuntimeACKRequiresPublishedExactState(t *testing.T) {
	for _, kind := range []string{"tcp", "udp"} {
		for _, scenario := range []string{"future", "same-version-wrong-class", "current-but-unpublished"} {
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				f, _ := newClassAnnouncementFixture(t, kind)
				flow := runtimeFlow(t, f).(*Flow)
				classRuntimeInitial(t, f, flow)
				ack := protocol.Frame{Kind: protocol.ClassUpdate, Flags: 1, Flow: flow.id, Offset: 2, Value: uint64(protocol.Bulk)}
				if scenario == "same-version-wrong-class" {
					ack.Offset = 1
				}
				if scenario == "current-but-unpublished" {
					if err := f.client.call(context.Background(), func() {
						// Recovery gating keeps the new state off the carrier while
						// preserving a live authenticated receive path.
						f.client.peerDone, f.client.localDoneAck = false, false
						state, _, err := f.client.classTable.Update(flow.id, protocol.Bulk, f.client.controlStamp(f.client.transportTime()))
						if err != nil {
							t.Error(err)
						} else {
							f.client.streams[flow.id].classTX = state
						}
					}); err != nil {
						t.Fatal(err)
					}
					state := classRuntimeTableSnapshot(t, f.client, flow.id)
					if state.Local.Version != 2 || state.Published.Version != 1 || !state.Pending {
						t.Fatalf("test failed to isolate unpublished current state: %+v", state)
					}
				}
				classRuntimeInject(t, f.peer, ack)
				classRuntimeClosed(t, f.client)
				if f.backend.dials.Load() != 1 {
					t.Fatal("unproven ACK allocated a target")
				}
			})
		}
	}
}
