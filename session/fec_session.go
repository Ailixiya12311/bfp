package session

import (
	"bfp/internal/fec"
	"bfp/protocol"
	"bfp/scheduler"
	"bytes"
	"errors"
	"time"
)

var ErrFECNotNegotiated = errors.New("session: datagram FEC not negotiated or profile exceeds selected bounds")

// CapabilityDatagramXORV1 fixes these resource bounds in the authenticated
// Noise offer/selection. Recovery must retain exactly that selection. Keeping
// one versioned bounded contract avoids a second unacknowledged negotiation
// that could accept OPEN before both peers know the repair semantics.
func datagramFECCapability() protocol.FECCapability {
	return protocol.FECCapability{Version: protocol.FECWireVersion, Algorithms: protocol.FECAlgorithmXOR1,
		MaxDataShards: 32, MaxParityShards: 1, MaxShardSize: 900, MaxBlockSize: 32 * 900, MaxBlocks: 64}
}

func (s *Session) fecPermitted(p protocol.FECProfile) bool {
	return validCapabilitySelection(s.info.Profile, s.info.Capabilities) &&
		s.info.Capabilities&CapabilityDatagramXORV1 != 0 && datagramFECCapability().Supports(p)
}

func cloneTarget(t protocol.Target) protocol.Target {
	if t.Delivery != nil {
		copy := *t.Delivery
		t.Delivery = &copy
	}
	if t.FEC != nil {
		copy := *t.FEC
		t.FEC = &copy
	}
	return t
}

func (s *Session) txRepairDirection() protocol.RepairDirection {
	if s.client {
		return protocol.RepairDirectionOutbound
	}
	return protocol.RepairDirectionInbound
}

// datagramBatch computes the entire bounded transaction before queue/number
// publication. A block protects fragments of one message; it never batches
// multiple application messages, changes their boundaries or waits for fill.
func (s *Session) datagramBatch(st *streamState, id uint64, data []byte) ([]scheduler.Item[protocol.Frame], error) {
	size := 900
	enabled := st.fecProfile.Enabled()
	if enabled {
		if !s.fecPermitted(st.fecProfile) {
			return nil, ErrFECNotNegotiated
		}
		size = int(st.fecProfile.ShardSize)
	}
	count := max(1, (len(data)+size-1)/size)
	if enabled && count > int(st.fecProfile.MaxDataShards) {
		return nil, ErrLimit
	}
	items := make([]scheduler.Item[protocol.Frame], 0, count+1)
	payloads := make([][]byte, count)
	for i := 0; i < count; i++ {
		at, end := i*size, min(len(data), (i+1)*size)
		payloads[i] = data[at:end]
		frame := protocol.Frame{Kind: protocol.Datagram, Flow: st.flow.id, Offset: id,
			Value: uint64(len(data))<<32 | uint64(at), Data: payloads[i]}
		items = append(items, scheduler.Item[protocol.Frame]{Value: frame, Cost: frameCost(frame)})
	}
	// TCP already reliably transports complete records. Retain the immutable
	// datagram contract on recovery without spending bandwidth on TCP parity.
	if !enabled || s.current == nil || s.current.kind != "udp" {
		return items, nil
	}
	block, err := fec.Encode(fec.Profile{DataShards: count, ParityShards: 1, ShardSize: size,
		MaxBlockSize: int(st.fecProfile.MaxBlockSize)}, id, payloads)
	if err != nil {
		return nil, err
	}
	encoded, err := protocol.EncodeDatagramRepair(protocol.DatagramRepair{Meta: protocol.DatagramRepairMeta{
		Version: protocol.FECWireVersion, Flags: protocol.RepairParity, Direction: s.txRepairDirection(),
		Flow: st.flow.id, Generation: s.current.generation, BlockID: id,
		DataShards: uint8(count), ParityShards: 1, ShardSize: uint16(size), PayloadLength: uint16(size), Lengths: block.Lengths}, Payload: block.Parity[0]})
	if err != nil {
		return nil, err
	}
	frame := protocol.Frame{Kind: protocol.DatagramRepairFrame, Flow: st.flow.id, Offset: id,
		Value: s.current.generation, Data: encoded}
	items = append(items, scheduler.Item[protocol.Frame]{Value: frame, Cost: frameCost(frame)})
	return items, nil
}

func (s *Session) datagramID(st *streamState, id uint64) bool {
	if id == 0 || id < st.messageHigh && st.messageHigh-id > 4096 || st.completed[id] {
		return false
	}
	if id > st.messageHigh {
		st.messageHigh = id
		for old := range st.completed {
			if old < id && id-old > 4096 {
				delete(st.completed, old)
			}
		}
	}
	return true
}

func datagramAssemblyBytes(st *streamState, a *assembly) int {
	// Reserve parity even before it arrives, so parity-first and data-first
	// have identical admission costs and cannot overrun the Session cap.
	n := 2 * len(a.data)
	if st.fecProfile.Enabled() {
		size := int(st.fecProfile.ShardSize)
		count := max(1, (len(a.data)+size-1)/size)
		// Reserve parity, duplicate decoder payload and the maximum temporary
		// Recover shards/output before accepting any block. Slice metadata is
		// covered conservatively too; Go allocator/map overhead is measured
		// separately and is not equated with this logical byte budget.
		n += (count+3)*size + count*64
	}
	return n
}

func (s *Session) datagramAssembly(st *streamState, id uint64, total int) *assembly {
	if !s.datagramID(st, id) {
		return nil
	}
	if a := st.datagrams[id]; a != nil {
		now := time.Now()
		expired := !a.handoverUntil.IsZero() && !now.Before(a.handoverUntil)
		if a.handoverUntil.IsZero() {
			expired = now.Sub(a.created) >= time.Second
		}
		if expired || len(a.data) != total {
			s.discardDatagram(st, id)
			return nil
		}
		return a
	}
	count, used := 0, 0
	for _, flow := range s.streams {
		for _, a := range flow.datagrams {
			count++
			used += datagramAssemblyBytes(flow, a)
		}
	}
	// No payload allocation is made until the complete admission test passes.
	reserved := 2 * total
	if st.fecProfile.Enabled() {
		size := int(st.fecProfile.ShardSize)
		count := max(1, (total+size-1)/size)
		reserved += (count+3)*size + count*64
	}
	if len(st.datagrams) >= 8 || count >= 64 || used+reserved+s.stats.RXBuffered > s.opts.MaxSessionBuffer {
		s.stats.Dropped++
		return nil
	}
	a := &assembly{data: make([]byte, total), seen: make([]bool, total), created: time.Now()}
	st.datagrams[id] = a
	return a
}

func (s *Session) discardDatagram(st *streamState, id uint64) {
	delete(st.datagrams, id)
	st.completed[id] = true
}

func (s *Session) finishDatagram(st *streamState, id uint64, a *assembly) {
	if a.count != len(a.data) {
		return
	}
	s.discardDatagram(st, id)
	if s.stats.RXBuffered+len(a.data) > s.opts.MaxSessionBuffer || !st.flow.pushDatagram(a.data) {
		s.stats.Dropped++
	} else {
		s.stats.RXBuffered += len(a.data)
	}
}

func (s *Session) recoverDatagram(st *streamState, id uint64, a *assembly) {
	if len(a.parity) == 0 || a.count == len(a.data) {
		return
	}
	size, total := int(st.fecProfile.ShardSize), len(a.data)
	count := max(1, (total+size-1)/size)
	missing := -1
	shards := make([][]byte, count)
	lengths := make([]uint16, count)
	for i := 0; i < count; i++ {
		at, end := i*size, min(total, (i+1)*size)
		lengths[i] = uint16(end - at)
		complete := true
		for _, seen := range a.seen[at:end] {
			if !seen {
				complete = false
				break
			}
		}
		if !complete {
			if missing != -1 {
				return // XOR cannot recover two absent fragments.
			}
			missing = i
			continue
		}
		shards[i] = make([]byte, size)
		copy(shards[i], a.data[at:end])
	}
	if missing == -1 {
		return
	}
	block := fec.Block{ID: id, Profile: fec.Profile{DataShards: count, ParityShards: 1, ShardSize: size,
		MaxBlockSize: int(st.fecProfile.MaxBlockSize)}, Lengths: lengths, Data: make([][]byte, count), Parity: [][]byte{a.parity}}
	recovered, err := block.Recover(missing, shards)
	if err != nil {
		s.discardDatagram(st, id)
		s.stats.FECRejected++
		return
	}
	at := missing * size
	for i, b := range recovered {
		if a.seen[at+i] && a.data[at+i] != b {
			s.discardDatagram(st, id)
			s.stats.FECRejected++
			return
		}
	}
	for i, b := range recovered {
		if !a.seen[at+i] {
			a.seen[at+i], a.data[at+i] = true, b
			a.count++
		}
	}
	if a.count == total {
		s.stats.FECRecoveredDatagrams++
	}
}

func (s *Session) datagramRepair(frame protocol.Frame) {
	reject := func() { s.stats.FECRejected++; s.stats.Dropped++ }
	st := s.streams[frame.Flow]
	if st == nil || st.reset || st.opening || st.target.Network != "udp" || !st.fecProfile.Enabled() ||
		!s.fecPermitted(st.fecProfile) || s.current == nil || s.current.kind != "udp" || frame.Flags != 0 ||
		frame.Value != s.current.generation {
		reject()
		return
	}
	r, err := protocol.DecodeDatagramRepair(frame.Data)
	if err != nil {
		reject()
		return
	}
	m := r.Meta
	wantDirection := protocol.RepairDirectionOutbound
	if s.client {
		wantDirection = protocol.RepairDirectionInbound
	}
	if m.Direction != wantDirection || m.Flow != frame.Flow || m.BlockID != frame.Offset ||
		m.Generation != s.current.generation || m.ShardSize != st.fecProfile.ShardSize ||
		m.DataShards > st.fecProfile.MaxDataShards || m.ParityShards != st.fecProfile.ParityShards {
		reject()
		return
	}
	total := 0
	for _, n := range m.Lengths {
		total += int(n)
	}
	size := int(st.fecProfile.ShardSize)
	if total > 16<<10 || total > int(st.fecProfile.MaxBlockSize) || max(1, (total+size-1)/size) != int(m.DataShards) {
		reject()
		return
	}
	for i, n := range m.Lengths {
		if int(n) != min(size, total-i*size) {
			reject()
			return
		}
	}
	dropped := s.stats.Dropped
	a := s.datagramAssembly(st, m.BlockID, total)
	if a == nil {
		if s.stats.Dropped != dropped {
			s.stats.FECRejected++
		}
		return
	}
	if a.parity != nil {
		if !bytes.Equal(a.parity, r.Payload) {
			s.discardDatagram(st, m.BlockID)
			reject()
		}
		return
	}
	a.parity = r.Payload // decoder owns the bounded payload copy
	s.stats.FECRepairReceived++
	if total == 0 {
		// The authenticated length table can recover the missing empty message
		// even though it has no data bytes to reconstruct.
		s.stats.FECRecoveredDatagrams++
	}
	s.recoverDatagram(st, m.BlockID, a)
	s.finishDatagram(st, m.BlockID, a)
}
