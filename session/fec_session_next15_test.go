package session

import (
	"bfp/protocol"
	"bfp/security"
	"bytes"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"
)

// These fixtures have no Session actor and no network I/O. The test goroutine
// is the sole state owner, as in stateSession; attach's single command is
// explicitly driven and joined under a fixed one-second observation budget.
func fecOwnerNext15(t *testing.T, network string, client bool) (*Session, *streamState) {
	t.Helper()
	s, st := stateSession(t, network)
	s.opts.MaxFlowBuffer, s.opts.MaxSessionBuffer = 64<<10, 128<<10
	s.peerSessionMax = uint64(s.opts.MaxSessionBuffer)
	s.client = client
	s.info.Profile = ProfileClassAnnouncementV1
	s.info.Capabilities = CapabilityClassAnnouncementV1 | CapabilityDatagramXORV1
	s.info.Generation = 7
	s.current = &carrier{kind: "udp", generation: 7, profile: s.info.Profile, capabilities: s.info.Capabilities, closed: make(chan struct{})}
	st.delivery = protocol.DefaultDelivery(network)
	st.fecProfile = protocol.FECProfile{Version: 1, Algorithm: protocol.FECXOR1, MaxDataShards: 32, ParityShards: 1, ShardSize: 900, MaxBlockSize: 28800}
	if network == "tcp" {
		st.fecProfile = protocol.DisabledFECProfile()
	}
	return s, st
}

func fecPayloadNext15(n int) []byte {
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i*29 + i/31 + 7)
	}
	return payload
}

// The fixture computes the parity from original message bytes directly. It
// does not call the production encoder or recovery implementation, so payload
// assertions independently check the owner path's shard slicing and trimming.
func fecFramesNext15(t *testing.T, s *Session, st *streamState, message uint64, payload []byte) ([]protocol.Frame, protocol.Frame) {
	t.Helper()
	size := int(st.fecProfile.ShardSize)
	if size == 0 {
		size = 900
	}
	count := max(1, (len(payload)+size-1)/size)
	lengths := make([]uint16, count)
	parity := make([]byte, size)
	frames := make([]protocol.Frame, 0, count)
	for i := 0; i < count; i++ {
		at, end := i*size, min(len(payload), (i+1)*size)
		part := payload[at:end]
		lengths[i] = uint16(len(part))
		for j, b := range part {
			parity[j] ^= b
		}
		frames = append(frames, protocol.Frame{Kind: protocol.Datagram, Flow: st.flow.id, Offset: message, Value: uint64(len(payload))<<32 | uint64(at), Data: append([]byte(nil), part...)})
	}
	direction := protocol.RepairDirectionOutbound
	if s.client {
		direction = protocol.RepairDirectionInbound
	}
	encoded, err := protocol.EncodeDatagramRepair(protocol.DatagramRepair{Meta: protocol.DatagramRepairMeta{
		Version: 1, Flags: protocol.RepairParity, Direction: direction, Flow: st.flow.id,
		Generation: s.current.generation, BlockID: message, DataShards: uint8(count), ParityShards: 1,
		ShardSize: uint16(size), PayloadLength: uint16(size), Lengths: lengths,
	}, Payload: parity})
	if err != nil {
		t.Fatal(err)
	}
	return frames, protocol.Frame{Kind: protocol.DatagramRepairFrame, Flow: st.flow.id, Offset: message, Value: s.current.generation, Data: encoded}
}

func fecExpectOnceNext15(t *testing.T, s *Session, st *streamState, message uint64, payload []byte, recovered uint64) {
	t.Helper()
	if len(st.flow.messages) != 1 || !bytes.Equal(st.flow.messages[0], payload) {
		t.Fatalf("Datagram payload/boundary: queued=%d want length=%d", len(st.flow.messages), len(payload))
	}
	if len(st.datagrams) != 0 || !st.completed[message] || s.stats.RXBuffered != len(payload) {
		t.Fatalf("completed Datagram retained/duplicated state: assemblies=%d tombstone=%t buffered=%d want=%d", len(st.datagrams), st.completed[message], s.stats.RXBuffered, len(payload))
	}
	if s.stats.FECRecoveredDatagrams != recovered {
		t.Fatalf("recovered Datagram count=%d want=%d", s.stats.FECRecoveredDatagrams, recovered)
	}
	if s.ctx.Err() != nil {
		t.Fatalf("Datagram owner unexpectedly terminated: %v", s.ctx.Err())
	}
}

func TestFECSessionOwnerRecoversOneMissingCanonicalShardNext15(t *testing.T) {
	for _, client := range []bool{false, true} {
		for _, n := range []int{0, 1, 900, 901, 1813, 16 << 10} {
			count := max(1, (n+899)/900)
			for missing := 0; missing < count; missing++ {
				t.Run(fmt.Sprintf("client=%t/bytes=%d/missing=%d", client, n, missing), func(t *testing.T) {
					s, st := fecOwnerNext15(t, "udp", client)
					payload := fecPayloadNext15(n)
					frames, repair := fecFramesNext15(t, s, st, 1, payload)
					for i, frame := range frames {
						if i != missing {
							s.handle(frame)
						}
					}
					if len(st.flow.messages) != 0 {
						t.Fatal("message with a missing data shard delivered before repair")
					}
					s.handle(repair)
					fecExpectOnceNext15(t, s, st, 1, payload, 1)
				})
			}
		}
	}
}

func TestFECSessionOwnerTwoMissingShardsWaitWithoutFalseRecoveryNext15(t *testing.T) {
	s, st := fecOwnerNext15(t, "udp", false)
	payload := fecPayloadNext15(1813)
	frames, repair := fecFramesNext15(t, s, st, 1, payload)
	s.handle(frames[0])
	s.handle(repair)
	s.handle(repair)
	if len(st.flow.messages) != 0 || s.stats.RXBuffered != 0 || s.stats.FECRecoveredDatagrams != 0 || st.completed[1] {
		t.Fatal("one parity shard falsely recovered two absent data shards")
	}
	s.handle(frames[2])
	fecExpectOnceNext15(t, s, st, 1, payload, 1)
}

func TestFECSessionOwnerParityFirstReorderAndDuplicateNext15(t *testing.T) {
	s, st := fecOwnerNext15(t, "udp", false)
	payload := fecPayloadNext15(1813)
	frames, repair := fecFramesNext15(t, s, st, 1, payload)
	s.handle(repair)
	s.handle(frames[2])
	s.handle(frames[2])
	if len(st.flow.messages) != 0 || s.stats.FECRecoveredDatagrams != 0 {
		t.Fatal("parity plus one of three data shards delivered an incomplete message")
	}
	s.handle(frames[0])
	fecExpectOnceNext15(t, s, st, 1, payload, 1)
	for _, frame := range append(frames, repair, repair) {
		s.handle(frame)
	}
	fecExpectOnceNext15(t, s, st, 1, payload, 1)
}

func TestFECSessionOwnerLateRepairCannotRedeliverOrdinaryDatagramNext15(t *testing.T) {
	s, st := fecOwnerNext15(t, "udp", false)
	payload := fecPayloadNext15(1813)
	frames, repair := fecFramesNext15(t, s, st, 1, payload)
	for i := len(frames) - 1; i >= 0; i-- {
		s.handle(frames[i])
	}
	fecExpectOnceNext15(t, s, st, 1, payload, 0)
	s.handle(repair)
	s.handle(repair)
	s.handle(frames[0])
	fecExpectOnceNext15(t, s, st, 1, payload, 0)
}

func TestFECSessionOwnerExpiredAssemblyCannotReviveNext15(t *testing.T) {
	for _, parityFirst := range []bool{false, true} {
		for _, maintainFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("parity_first=%t/maintain_first=%t", parityFirst, maintainFirst), func(t *testing.T) {
				s, st := fecOwnerNext15(t, "udp", false)
				payload := fecPayloadNext15(1813)
				frames, repair := fecFramesNext15(t, s, st, 1, payload)
				if parityFirst {
					s.handle(repair)
				}
				s.handle(frames[0])
				if st.datagrams[1] == nil {
					t.Fatal("fixture did not retain its incomplete message")
				}
				st.datagrams[1].created = time.Now().Add(-2 * time.Second)
				if maintainFirst {
					s.maintain(time.Now())
				}
				// The arrival path must check expiry itself: a late valid repair
				// cannot win merely because periodic maintenance has not run yet.
				s.handle(repair)
				for _, frame := range frames {
					s.handle(frame)
				}
				if len(st.flow.messages) != 0 || len(st.datagrams) != 0 || !st.completed[1] || s.stats.RXBuffered != 0 || s.stats.FECRecoveredDatagrams != 0 {
					t.Fatalf("late input revived expired Datagram: messages=%d assemblies=%d retired=%t buffered=%d recovered=%d", len(st.flow.messages), len(st.datagrams), st.completed[1], s.stats.RXBuffered, s.stats.FECRecoveredDatagrams)
				}
			})
		}
	}
}

func TestFECSessionOwnerWrongScopePreservesOrdinaryAssemblyNext15(t *testing.T) {
	for _, bad := range []string{"outer-flow", "meta-flow", "outer-generation", "meta-generation", "direction", "outer-message", "meta-message"} {
		t.Run(bad, func(t *testing.T) {
			s, st := fecOwnerNext15(t, "udp", false)
			payload := fecPayloadNext15(1813)
			frames, good := fecFramesNext15(t, s, st, 1, payload)
			s.handle(frames[0])
			a := st.datagrams[1]
			data, seen, count, created := append([]byte(nil), a.data...), append([]bool(nil), a.seen...), a.count, a.created
			wrong := good
			repair, err := protocol.DecodeDatagramRepair(good.Data)
			if err != nil {
				t.Fatal(err)
			}
			switch bad {
			case "outer-flow":
				wrong.Flow = 9
			case "meta-flow":
				repair.Meta.Flow = 9
			case "outer-generation":
				wrong.Value--
			case "meta-generation":
				repair.Meta.Generation--
			case "direction":
				repair.Meta.Direction = protocol.RepairDirectionInbound
			case "outer-message":
				wrong.Offset++
			case "meta-message":
				repair.Meta.BlockID++
			}
			wrong.Data, err = protocol.EncodeDatagramRepair(repair)
			if err != nil {
				t.Fatal(err)
			}
			s.handle(wrong)
			if st.datagrams[1] != a || !bytes.Equal(a.data, data) || !reflect.DeepEqual(a.seen, seen) || a.count != count || a.created != created || len(st.datagrams) != 1 || len(st.flow.messages) != 0 || s.ctx.Err() != nil {
				t.Fatal("wrong repair scope changed or terminated the ordinary assembly")
			}
			s.handle(frames[2])
			s.handle(good)
			fecExpectOnceNext15(t, s, st, 1, payload, 1)
		})
	}
}

func TestFECSessionOwnerRejectsRepairOnTCPAndWithoutSelectionNext15(t *testing.T) {
	for _, mode := range []string{"tcp-flow", "missing-capability", "disabled-flow", "resume-not-ready"} {
		t.Run(mode, func(t *testing.T) {
			network := "udp"
			if mode == "tcp-flow" {
				network = "tcp"
			}
			s, st := fecOwnerNext15(t, network, false)
			_, repair := fecFramesNext15(t, s, st, 1, []byte("ordinary"))
			switch mode {
			case "missing-capability":
				s.info.Capabilities = CapabilityClassAnnouncementV1
			case "disabled-flow":
				st.fecProfile = protocol.DisabledFECProfile()
			case "resume-not-ready":
				s.peerDone = false
			}
			s.handle(repair)
			if len(st.datagrams) != 0 || len(st.flow.messages) != 0 || st.flow.buffer.Len() != 0 || s.stats.RXBuffered != 0 || s.stats.FECRecoveredDatagrams != 0 || s.ctx.Err() != nil {
				t.Fatal("unselected/TCP repair allocated message state, delivered data, or closed Session")
			}
			if network == "tcp" {
				s.handle(protocol.Frame{Kind: protocol.StreamData, Flow: 1, Data: []byte("safe")})
				if st.flow.buffer.String() != "safe" || st.receiveNext != 4 {
					t.Fatal("rejected repair changed the reliable StreamData contract")
				}
			}
		})
	}
}

func TestFECSessionOwnerParityOnlyAssembliesRemainBoundedNext15(t *testing.T) {
	s, st := fecOwnerNext15(t, "udp", false)
	for id := uint64(1); id <= 9; id++ {
		_, repair := fecFramesNext15(t, s, st, id, fecPayloadNext15(1813))
		s.handle(repair)
	}
	if len(st.datagrams) != 8 || len(st.flow.messages) != 0 || s.stats.RXBuffered != 0 || s.stats.FECRecoveredDatagrams != 0 {
		t.Fatalf("parity-only state escaped per-flow assembly bound: assemblies=%d queued=%d buffered=%d recovered=%d", len(st.datagrams), len(st.flow.messages), s.stats.RXBuffered, s.stats.FECRecoveredDatagrams)
	}
	if s.stats.FECRejected == 0 {
		t.Fatal("over-budget parity did not record rejection")
	}
}

func TestFECSessionOwnerResetAndCloseCannotRevivePartialBlockNext15(t *testing.T) {
	for _, terminal := range []string{"reset", "close"} {
		t.Run(terminal, func(t *testing.T) {
			s, st := fecOwnerNext15(t, "udp", false)
			frames, repair := fecFramesNext15(t, s, st, 1, fecPayloadNext15(1813))
			s.handle(frames[0])
			if terminal == "reset" {
				s.reset(st, ErrClosed, false)
			} else {
				s.requestClose(true, time.Now())
				s.cleanupBusiness(time.Now())
			}
			s.handle(repair)
			for _, frame := range frames {
				s.handle(frame)
			}
			if !st.reset || len(st.datagrams) != 0 || len(st.flow.messages) != 0 || s.stats.RXBuffered != 0 || s.stats.FECRecoveredDatagrams != 0 {
				t.Fatal("late repair revived a terminated Flow/Session block")
			}
		})
	}
}

func TestFECSessionOwnerAttachPreservesPartialAndRejectsOldGenerationNext15(t *testing.T) {
	s, st := fecOwnerNext15(t, "udp", false)
	frames, oldRepair := fecFramesNext15(t, s, st, 1, fecPayloadNext15(1813))
	s.handle(frames[0])
	conn, peer := net.Pipe()
	t.Cleanup(func() { conn.Close(); peer.Close() })
	keys := security.TransportKeys{Send: [32]byte{1}, Receive: [32]byte{2}}
	c, err := makeCarrier("tcp", 8, bytes.Repeat([]byte{3}, 16), &keys, conn, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.profile, c.capabilities = s.info.Profile, s.info.Capabilities
	done := make(chan error, 1)
	go func() { done <- s.attach(c, 7) }()
	defer func() {
		select {
		case <-s.done:
		default:
			close(s.done)
		}
	}()
	select {
	case command := <-s.commands:
		command()
	case <-time.After(time.Second):
		t.Fatal("single attach owner command did not arrive within 1s")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("single attach owner command did not return within 1s")
	}
	if len(st.datagrams) != 1 || st.datagrams[1].count == 0 || s.current != c || s.info.Generation != 8 {
		t.Fatal("carrier attachment did not retain the partial Datagram block for handover")
	}
	s.peerDone = true // exercise the post-Resume owner admission boundary
	s.handle(oldRepair)
	if len(st.datagrams) != 1 || len(st.flow.messages) != 0 || s.stats.FECRecoveredDatagrams != 0 || s.ctx.Err() != nil {
		t.Fatal("late old-generation repair recreated the retired carrier block")
	}
}
