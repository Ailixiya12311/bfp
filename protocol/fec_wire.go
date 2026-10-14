package protocol

// This file defines the version-1 FEC wire vocabulary. The values are carried
// as Data of authenticated inner frames; they are never visible before the
// record AEAD has been opened. FEC is intentionally limited to optional UDP
// Datagram repair. Reliable StreamData keeps its existing ordered, lossless
// contract and has no FEC interpretation.

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	FECWireVersion uint8 = 1

	FECDisabled FECAlgorithm = 0
	FECXOR1     FECAlgorithm = 1

	FECAlgorithmXOR1 uint8 = 1 << FECXOR1

	DeliveryWireVersion uint8 = 1

	DeliveryStreamReliable     DeliveryMode = 1
	DeliveryDatagramBestEffort DeliveryMode = 2

	RepairParity uint8 = 1 << 0

	RepairDirectionOutbound RepairDirection = 1
	RepairDirectionInbound  RepairDirection = 2

	// The fixed metadata prefix is followed by DataShards uint16 lengths and
	// then one full-size parity shard. Keeping a fixed prefix makes malformed
	// length/count combinations reject before any allocation of payload bytes.
	DatagramRepairHeaderSize = 40
	MaxFECDataShards         = 32
	MaxFECShardSize          = 16 << 10
	MaxFECBlockSize          = 1 << 20
	MaxFECBlocks             = 4096
)

type FECAlgorithm uint8

func (a FECAlgorithm) Valid() bool { return a == FECDisabled || a == FECXOR1 }

type DeliveryMode uint8

func (m DeliveryMode) Valid() bool {
	return m == DeliveryStreamReliable || m == DeliveryDatagramBestEffort
}

// DeliveryContract is frozen at OPEN admission. ClassUpdate changes only the
// scheduler budget/class observation and cannot mutate Mode or FEC semantics.
type DeliveryContract struct {
	Version uint8        `json:"version"`
	Mode    DeliveryMode `json:"mode"`
}

func (c DeliveryContract) Validate() error {
	if c.Version != DeliveryWireVersion || !c.Mode.Valid() {
		return fmt.Errorf("%w: delivery contract", ErrFECWire)
	}
	return nil
}

// FECProfile is the negotiated per-flow datagram repair profile. Version 1
// repairs each Datagram independently with one XOR parity shard. MaxDataShards
// is an upper bound; the message owner derives the actual count from that
// message's total length and ShardSize. It never pools multiple messages into
// one block. A disabled profile has Algorithm=FECDisabled and zero limits.
type FECProfile struct {
	Version       uint8        `json:"version"`
	Algorithm     FECAlgorithm `json:"algorithm"`
	MaxDataShards uint8        `json:"max_data_shards,omitempty"`
	ParityShards  uint8        `json:"parity_shards,omitempty"`
	ShardSize     uint16       `json:"shard_size,omitempty"`
	MaxBlockSize  uint32       `json:"max_block_size,omitempty"`
}

func DisabledFECProfile() FECProfile {
	return FECProfile{Version: FECWireVersion, Algorithm: FECDisabled}
}

func DefaultDelivery(network string) DeliveryContract {
	mode := DeliveryDatagramBestEffort
	if network == "tcp" {
		mode = DeliveryStreamReliable
	}
	return DeliveryContract{Version: DeliveryWireVersion, Mode: mode}
}

func (p FECProfile) Enabled() bool { return p.Algorithm != FECDisabled }

func (p FECProfile) Validate() error {
	if p.Version != FECWireVersion || !p.Algorithm.Valid() {
		return fmt.Errorf("%w: fec version/algorithm", ErrFECWire)
	}
	if p.Algorithm == FECDisabled {
		if p.MaxDataShards != 0 || p.ParityShards != 0 || p.ShardSize != 0 || p.MaxBlockSize != 0 {
			return fmt.Errorf("%w: disabled profile has limits", ErrFECWire)
		}
		return nil
	}
	if p.Algorithm != FECXOR1 || p.MaxDataShards < 1 || p.MaxDataShards > MaxFECDataShards || p.ParityShards != 1 || p.ShardSize < 1 || int(p.ShardSize) > MaxFECShardSize || p.MaxBlockSize == 0 || p.MaxBlockSize > MaxFECBlockSize || uint64(p.MaxDataShards)*uint64(p.ShardSize) > uint64(p.MaxBlockSize) {
		return fmt.Errorf("%w: fec profile bounds", ErrFECWire)
	}
	if DatagramRepairHeaderSize+2*int(p.MaxDataShards)+int(p.ShardSize) > MaxPlaintext-HeaderSize {
		return fmt.Errorf("%w: fec profile repair frame size", ErrFECWire)
	}
	return nil
}

func (p FECProfile) Equal(other FECProfile) bool { return p == other }

// ResolveDelivery applies the network-specific defaults for legacy OPENs and
// validates the resulting immutable contract. FEC is permitted only for UDP
// datagrams. Returned values are copies owned by the caller.
func ResolveDelivery(network string, delivery *DeliveryContract, fec *FECProfile) (DeliveryContract, FECProfile, error) {
	if network != "tcp" && network != "udp" {
		return DeliveryContract{}, FECProfile{}, fmt.Errorf("%w: network", ErrFECWire)
	}
	c := DefaultDelivery(network)
	if delivery != nil {
		c = *delivery
	}
	if err := c.Validate(); err != nil {
		return DeliveryContract{}, FECProfile{}, err
	}
	if network == "tcp" && c.Mode != DeliveryStreamReliable || network == "udp" && c.Mode != DeliveryDatagramBestEffort {
		return DeliveryContract{}, FECProfile{}, fmt.Errorf("%w: mode/network mismatch", ErrFECWire)
	}
	p := DisabledFECProfile()
	if fec != nil {
		p = *fec
	}
	if err := p.Validate(); err != nil {
		return DeliveryContract{}, FECProfile{}, err
	}
	if network == "tcp" && p.Enabled() {
		return DeliveryContract{}, FECProfile{}, fmt.Errorf("%w: fec on reliable stream", ErrFECWire)
	}
	return c, p, nil
}

// FECCapability is a bounded versioned offer. Algorithms is a bit mask using
// FECAlgorithm values. Zero algorithms is a valid explicit "disabled" offer.
type FECCapability struct {
	Version         uint8
	Algorithms      uint8
	MaxDataShards   uint8
	MaxParityShards uint8
	MaxShardSize    uint16
	MaxBlockSize    uint32
	MaxBlocks       uint16
}

func (c FECCapability) Validate() error {
	if c.Version != FECWireVersion || c.Algorithms&^FECAlgorithmXOR1 != 0 || c.MaxBlocks > MaxFECBlocks {
		return fmt.Errorf("%w: capability version/mask", ErrFECWire)
	}
	if c.Algorithms == 0 {
		if c.MaxDataShards != 0 || c.MaxParityShards != 0 || c.MaxShardSize != 0 || c.MaxBlockSize != 0 || c.MaxBlocks != 0 {
			return fmt.Errorf("%w: disabled capability has limits", ErrFECWire)
		}
		return nil
	}
	if c.MaxDataShards < 1 || c.MaxDataShards > MaxFECDataShards || c.MaxParityShards != 1 || c.MaxShardSize < 1 || int(c.MaxShardSize) > MaxFECShardSize || c.MaxBlockSize == 0 || c.MaxBlockSize > MaxFECBlockSize || uint64(c.MaxDataShards)*uint64(c.MaxShardSize) > uint64(c.MaxBlockSize) || c.MaxBlocks == 0 {
		return fmt.Errorf("%w: capability bounds", ErrFECWire)
	}
	if DatagramRepairHeaderSize+2*int(c.MaxDataShards)+int(c.MaxShardSize) > MaxPlaintext-HeaderSize {
		return fmt.Errorf("%w: capability repair frame size", ErrFECWire)
	}
	return nil
}

func (c FECCapability) Supports(p FECProfile) bool {
	if c.Validate() != nil || p.Validate() != nil || !p.Enabled() || c.Algorithms&uint8(1<<p.Algorithm) == 0 {
		return false
	}
	return p.MaxDataShards <= c.MaxDataShards && p.ParityShards <= c.MaxParityShards && p.ShardSize <= c.MaxShardSize && p.MaxBlockSize <= c.MaxBlockSize
}

const fecCapabilityWireSize = 14

func EncodeFECCapability(c FECCapability) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	b := make([]byte, fecCapabilityWireSize)
	b[0], b[1], b[2], b[3] = c.Version, c.Algorithms, c.MaxDataShards, c.MaxParityShards
	binary.BigEndian.PutUint16(b[4:6], c.MaxShardSize)
	binary.BigEndian.PutUint32(b[6:10], c.MaxBlockSize)
	binary.BigEndian.PutUint16(b[10:12], c.MaxBlocks)
	// [12:14] is reserved and must remain zero in version 1.
	return b, nil
}

func DecodeFECCapability(b []byte) (FECCapability, error) {
	if len(b) != fecCapabilityWireSize || b[12] != 0 || b[13] != 0 {
		return FECCapability{}, fmt.Errorf("%w: capability size/reserved", ErrFECWire)
	}
	c := FECCapability{Version: b[0], Algorithms: b[1], MaxDataShards: b[2], MaxParityShards: b[3], MaxShardSize: binary.BigEndian.Uint16(b[4:6]), MaxBlockSize: binary.BigEndian.Uint32(b[6:10]), MaxBlocks: binary.BigEndian.Uint16(b[10:12])}
	if err := c.Validate(); err != nil {
		return FECCapability{}, err
	}
	return c, nil
}

type RepairDirection uint8

func (d RepairDirection) Valid() bool {
	return d == RepairDirectionOutbound || d == RepairDirectionInbound
}

// DatagramRepairMeta is bound to one authenticated Session/carrier/flow
// generation by the Session owner. Lengths is the original length table for
// all data shards, required to trim a recovered shard deterministically.
type DatagramRepairMeta struct {
	Version       uint8
	Flags         uint8
	Direction     RepairDirection
	Flow          uint64
	Generation    uint64
	BlockID       uint64
	ShardIndex    uint8
	DataShards    uint8
	ParityShards  uint8
	ShardSize     uint16
	PayloadLength uint16
	Lengths       []uint16
}

func (m DatagramRepairMeta) Validate(payloadLen int) error {
	if m.Version != FECWireVersion || m.Flags != RepairParity || !m.Direction.Valid() || m.Flow == 0 || m.Generation == 0 || m.BlockID == 0 || m.DataShards < 1 || m.DataShards > MaxFECDataShards || m.ParityShards != 1 || m.ShardIndex >= m.ParityShards || m.ShardSize < 1 || int(m.ShardSize) > MaxFECShardSize || int(m.PayloadLength) != payloadLen || payloadLen != int(m.ShardSize) || len(m.Lengths) != int(m.DataShards) {
		return fmt.Errorf("%w: repair metadata", ErrFECWire)
	}
	for _, n := range m.Lengths {
		if n > m.ShardSize {
			return fmt.Errorf("%w: repair length", ErrFECWire)
		}
	}
	if uint64(m.DataShards)*uint64(m.ShardSize) > MaxFECBlockSize {
		return fmt.Errorf("%w: repair block bound", ErrFECWire)
	}
	return nil
}

type DatagramRepair struct {
	Meta    DatagramRepairMeta
	Payload []byte
}

func EncodeDatagramRepair(r DatagramRepair) ([]byte, error) {
	if err := r.Meta.Validate(len(r.Payload)); err != nil {
		return nil, err
	}
	// This output is a Frame.Data payload. Reserve the frame header here so a
	// helper success always fits a complete single-frame encrypted plaintext.
	if len(r.Payload)+DatagramRepairHeaderSize+2*len(r.Meta.Lengths) > MaxPlaintext-HeaderSize {
		return nil, ErrLimit
	}
	b := make([]byte, DatagramRepairHeaderSize+2*len(r.Meta.Lengths)+len(r.Payload))
	h := b[:DatagramRepairHeaderSize]
	h[0], h[1], h[2], h[3] = r.Meta.Version, r.Meta.Flags, byte(r.Meta.Direction), 0
	binary.BigEndian.PutUint64(h[4:12], r.Meta.Flow)
	binary.BigEndian.PutUint64(h[12:20], r.Meta.Generation)
	binary.BigEndian.PutUint64(h[20:28], r.Meta.BlockID)
	h[28], h[29], h[30], h[31] = r.Meta.ShardIndex, r.Meta.DataShards, r.Meta.ParityShards, uint8(len(r.Meta.Lengths))
	binary.BigEndian.PutUint16(h[32:34], r.Meta.ShardSize)
	binary.BigEndian.PutUint16(h[34:36], r.Meta.PayloadLength)
	// [36:40] reserved for future versioned metadata.
	at := DatagramRepairHeaderSize
	for _, n := range r.Meta.Lengths {
		binary.BigEndian.PutUint16(b[at:at+2], n)
		at += 2
	}
	copy(b[at:], r.Payload)
	return b, nil
}

func DecodeDatagramRepair(b []byte) (DatagramRepair, error) {
	if len(b) > MaxPlaintext-HeaderSize {
		return DatagramRepair{}, ErrLimit
	}
	if len(b) < DatagramRepairHeaderSize {
		return DatagramRepair{}, fmt.Errorf("%w: repair truncated header", ErrMalformed)
	}
	h := b[:DatagramRepairHeaderSize]
	if h[3] != 0 || binary.BigEndian.Uint32(h[36:40]) != 0 {
		return DatagramRepair{}, fmt.Errorf("%w: repair reserved", ErrFECWire)
	}
	count := int(h[31])
	if count == 0 || count > MaxFECDataShards || count != int(h[29]) {
		return DatagramRepair{}, fmt.Errorf("%w: repair count", ErrFECWire)
	}
	at := DatagramRepairHeaderSize + 2*count
	if at > len(b) {
		return DatagramRepair{}, fmt.Errorf("%w: repair lengths", ErrMalformed)
	}
	lengths := make([]uint16, count)
	for i := range lengths {
		lengths[i] = binary.BigEndian.Uint16(b[DatagramRepairHeaderSize+2*i : DatagramRepairHeaderSize+2*i+2])
	}
	m := DatagramRepairMeta{Version: h[0], Flags: h[1], Direction: RepairDirection(h[2]), Flow: binary.BigEndian.Uint64(h[4:12]), Generation: binary.BigEndian.Uint64(h[12:20]), BlockID: binary.BigEndian.Uint64(h[20:28]), ShardIndex: h[28], DataShards: h[29], ParityShards: h[30], ShardSize: binary.BigEndian.Uint16(h[32:34]), PayloadLength: binary.BigEndian.Uint16(h[34:36]), Lengths: lengths}
	if err := m.Validate(len(b) - at); err != nil {
		return DatagramRepair{}, err
	}
	return DatagramRepair{Meta: m, Payload: append([]byte(nil), b[at:]...)}, nil
}

var ErrFECWire = errors.New("protocol: invalid fec wire value")
