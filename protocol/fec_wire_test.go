package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func testFECProfile() FECProfile {
	return FECProfile{Version: FECWireVersion, Algorithm: FECXOR1, MaxDataShards: 3, ParityShards: 1, ShardSize: 32, MaxBlockSize: 128}
}

func TestFECWireKindsAppendWithoutChangingLegacyNumbers(t *testing.T) {
	if ControlReceipt != 24 || FECCapabilityFrame != 25 || DatagramRepairFrame != 26 {
		t.Fatalf("unexpected kind assignment: receipt=%d capability=%d repair=%d", ControlReceipt, FECCapabilityFrame, DatagramRepairFrame)
	}
	if StreamData.Valid() == false || DatagramRepairFrame.Valid() == false {
		t.Fatal("valid kind rejected")
	}
}

func TestFECCapabilityRoundTripAndBounds(t *testing.T) {
	c := FECCapability{Version: FECWireVersion, Algorithms: FECAlgorithmXOR1, MaxDataShards: 8, MaxParityShards: 1, MaxShardSize: 1200, MaxBlockSize: 10000, MaxBlocks: 32}
	b, err := EncodeFECCapability(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeFECCapability(b)
	if err != nil || got != c {
		t.Fatalf("capability=%+v err=%v", got, err)
	}
	b[12] = 1
	if _, err := DecodeFECCapability(b); !errors.Is(err, ErrFECWire) {
		t.Fatalf("reserved capability accepted: %v", err)
	}
	if c.Supports(testFECProfile()) == false {
		t.Fatal("valid profile not supported")
	}
	if c.Supports(FECProfile{Version: FECWireVersion, Algorithm: FECXOR1, MaxDataShards: 9, ParityShards: 1, ShardSize: 32, MaxBlockSize: 512}) {
		t.Fatal("profile over capability accepted")
	}
}

func TestDeliveryResolutionFreezesNetworkContract(t *testing.T) {
	c, p, err := ResolveDelivery("tcp", nil, nil)
	if err != nil || c.Mode != DeliveryStreamReliable || p.Enabled() {
		t.Fatalf("tcp default=%+v/%+v err=%v", c, p, err)
	}
	udp := testFECProfile()
	c, p, err = ResolveDelivery("udp", &DeliveryContract{Version: DeliveryWireVersion, Mode: DeliveryDatagramBestEffort}, &udp)
	if err != nil || c.Mode != DeliveryDatagramBestEffort || !p.Equal(udp) {
		t.Fatalf("udp profile=%+v/%+v err=%v", c, p, err)
	}
	if _, _, err = ResolveDelivery("tcp", &DeliveryContract{Version: DeliveryWireVersion, Mode: DeliveryDatagramBestEffort}, nil); !errors.Is(err, ErrFECWire) {
		t.Fatalf("tcp/datagram contract accepted: %v", err)
	}
	if _, _, err = ResolveDelivery("tcp", nil, &udp); !errors.Is(err, ErrFECWire) {
		t.Fatalf("tcp fec profile accepted: %v", err)
	}
}

func TestDatagramRepairMetadataRoundTripAndOwnership(t *testing.T) {
	payload := bytes.Repeat([]byte{0xa5}, 32)
	r := DatagramRepair{Meta: DatagramRepairMeta{Version: FECWireVersion, Flags: RepairParity, Direction: RepairDirectionOutbound, Flow: 7, Generation: 9, BlockID: 11, ShardIndex: 0, DataShards: 3, ParityShards: 1, ShardSize: 32, PayloadLength: 32, Lengths: []uint16{4, 32, 17}}, Payload: payload}
	b, err := EncodeDatagramRepair(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeDatagramRepair(b)
	if err != nil || !reflect.DeepEqual(got, r) {
		t.Fatalf("repair=%+v err=%v", got, err)
	}
	b[len(b)-1] ^= 0xff
	if got.Payload[len(got.Payload)-1] != 0xa5 {
		t.Fatal("decoded repair payload aliases input")
	}
	binary.BigEndian.PutUint16(b[DatagramRepairHeaderSize:DatagramRepairHeaderSize+2], 0)
	if got.Meta.Lengths[0] != 4 {
		t.Fatal("decoded repair length table aliases input")
	}
	r.Meta.Lengths[1] = 0
	r.Payload[0] = 0
	if binary.BigEndian.Uint16(b[DatagramRepairHeaderSize+2:DatagramRepairHeaderSize+4]) != 32 || b[DatagramRepairHeaderSize+6] != 0xa5 {
		t.Fatal("encoded repair aliases caller data")
	}
	for _, bad := range []DatagramRepair{
		{Meta: r.Meta, Payload: payload[:31]},
		{Meta: func() DatagramRepairMeta { m := r.Meta; m.Generation = 0; return m }(), Payload: payload},
		{Meta: func() DatagramRepairMeta { m := r.Meta; m.Lengths = []uint16{4}; return m }(), Payload: payload},
	} {
		if _, err := EncodeDatagramRepair(bad); !errors.Is(err, ErrFECWire) {
			t.Fatalf("bad repair accepted: %+v err=%v", bad.Meta, err)
		}
	}
}

func TestRepairExactFramePlaintextBoundary(t *testing.T) {
	const count = MaxFECDataShards
	exactShard := MaxPlaintext - HeaderSize - DatagramRepairHeaderSize - 2*count
	makeRepair := func(shard int) DatagramRepair {
		m := DatagramRepairMeta{Version: FECWireVersion, Flags: RepairParity, Direction: RepairDirectionOutbound, Flow: 1, Generation: 1, BlockID: 1, DataShards: count, ParityShards: 1, ShardSize: uint16(shard), PayloadLength: uint16(shard), Lengths: make([]uint16, count)}
		for i := range m.Lengths {
			m.Lengths[i] = uint16(shard)
		}
		return DatagramRepair{Meta: m, Payload: bytes.Repeat([]byte{0xa5}, shard)}
	}
	r := makeRepair(exactShard)
	profile := FECProfile{Version: FECWireVersion, Algorithm: FECXOR1, MaxDataShards: count, ParityShards: 1, ShardSize: uint16(exactShard), MaxBlockSize: uint32(count * exactShard)}
	capability := FECCapability{Version: FECWireVersion, Algorithms: FECAlgorithmXOR1, MaxDataShards: count, MaxParityShards: 1, MaxShardSize: uint16(exactShard), MaxBlockSize: uint32(count * exactShard), MaxBlocks: 1}
	if err := profile.Validate(); err != nil || !capability.Supports(profile) {
		t.Fatalf("exact-sized repair profile/capability rejected: %v", err)
	}
	oversizeProfile := profile
	oversizeProfile.ShardSize++
	oversizeProfile.MaxBlockSize += count
	if err := oversizeProfile.Validate(); !errors.Is(err, ErrFECWire) {
		t.Fatalf("unencodable repair profile accepted: %v", err)
	}
	data, err := EncodeDatagramRepair(r)
	if err != nil || len(data) != MaxPlaintext-HeaderSize {
		t.Fatalf("exact repair boundary len=%d err=%v", len(data), err)
	}
	wire, err := Encode([]Frame{{Kind: DatagramRepairFrame, Flow: r.Meta.Flow, Data: data}})
	if err != nil || len(wire) != MaxPlaintext {
		t.Fatalf("exact full frame len=%d err=%v", len(wire), err)
	}
	decoded, err := DecodeDatagramRepair(data)
	if err != nil || !reflect.DeepEqual(decoded, r) {
		t.Fatalf("exact decoded repair err=%v", err)
	}
	if data, err := EncodeDatagramRepair(makeRepair(exactShard + 1)); !errors.Is(err, ErrLimit) || data != nil {
		t.Fatalf("over boundary encode len=%d err=%v", len(data), err)
	}
	tooLarge := append(append([]byte(nil), data...), 0)
	binary.BigEndian.PutUint16(tooLarge[32:34], uint16(exactShard+1))
	binary.BigEndian.PutUint16(tooLarge[34:36], uint16(exactShard+1))
	if got, err := DecodeDatagramRepair(tooLarge); !errors.Is(err, ErrLimit) || !reflect.DeepEqual(got, DatagramRepair{}) {
		t.Fatalf("over boundary decode returned payload/error: %v", err)
	}
}

func TestRepairMalformedEncodingReturnsNoPartialValue(t *testing.T) {
	r := DatagramRepair{Meta: DatagramRepairMeta{Version: FECWireVersion, Flags: RepairParity, Direction: RepairDirectionOutbound, Flow: 1, Generation: 1, BlockID: 1, DataShards: 3, ParityShards: 1, ShardSize: 32, PayloadLength: 32, Lengths: []uint16{32, 32, 7}}, Payload: bytes.Repeat([]byte{0xa5}, 32)}
	good, err := EncodeDatagramRepair(r)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		edit func([]byte) []byte
		want error
	}{
		{"header truncated", func(b []byte) []byte { return b[:DatagramRepairHeaderSize-1] }, ErrMalformed},
		{"length table truncated", func(b []byte) []byte { return b[:DatagramRepairHeaderSize+5] }, ErrMalformed},
		{"parity truncated", func(b []byte) []byte { return b[:len(b)-1] }, ErrFECWire},
		{"extra parity byte", func(b []byte) []byte { return append(b, 0) }, ErrFECWire},
		{"version zero", func(b []byte) []byte { b[0] = 0; return b }, ErrFECWire},
		{"version future", func(b []byte) []byte { b[0] = 2; return b }, ErrFECWire},
		{"flags missing parity", func(b []byte) []byte { b[1] = 0; return b }, ErrFECWire},
		{"flags unknown", func(b []byte) []byte { b[1] |= 2; return b }, ErrFECWire},
		{"direction missing", func(b []byte) []byte { b[2] = 0; return b }, ErrFECWire},
		{"direction unknown", func(b []byte) []byte { b[2] = 3; return b }, ErrFECWire},
		{"flow zero", func(b []byte) []byte { clear(b[4:12]); return b }, ErrFECWire},
		{"generation zero", func(b []byte) []byte { clear(b[12:20]); return b }, ErrFECWire},
		{"block zero", func(b []byte) []byte { clear(b[20:28]); return b }, ErrFECWire},
		{"parity index outside profile", func(b []byte) []byte { b[28] = 1; return b }, ErrFECWire},
		{"data count missing", func(b []byte) []byte { b[29] = 0; return b }, ErrFECWire},
		{"data count excessive", func(b []byte) []byte { b[29] = 33; return b }, ErrFECWire},
		{"parity count zero", func(b []byte) []byte { b[30] = 0; return b }, ErrFECWire},
		{"parity count excessive", func(b []byte) []byte { b[30] = 2; return b }, ErrFECWire},
		{"length count zero", func(b []byte) []byte { b[31] = 0; return b }, ErrFECWire},
		{"length count excessive", func(b []byte) []byte { b[31] = 33; return b }, ErrFECWire},
		{"length/data count disagree", func(b []byte) []byte { b[31] = 2; return b }, ErrFECWire},
		{"shard size zero", func(b []byte) []byte { clear(b[32:34]); return b }, ErrFECWire},
		{"shard size excessive", func(b []byte) []byte { binary.BigEndian.PutUint16(b[32:34], MaxFECShardSize+1); return b }, ErrFECWire},
		{"declared payload disagrees", func(b []byte) []byte { binary.BigEndian.PutUint16(b[34:36], 31); return b }, ErrFECWire},
		{"original length exceeds shard", func(b []byte) []byte { binary.BigEndian.PutUint16(b[40:42], 33); return b }, ErrFECWire},
	}
	for _, offset := range []int{3, 36, 37, 38, 39} {
		at := offset
		cases = append(cases, struct {
			name string
			edit func([]byte) []byte
			want error
		}{
			name: fmt.Sprintf("reserved byte %d", at), edit: func(b []byte) []byte { b[at] = 1; return b }, want: ErrFECWire,
		})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeDatagramRepair(tc.edit(append([]byte(nil), good...)))
			if !errors.Is(err, tc.want) || !reflect.DeepEqual(got, DatagramRepair{}) {
				t.Fatalf("malformed input returned value=%+v err=%v want=%v", got.Meta, err, tc.want)
			}
		})
	}
}

func TestFECProfileMaximumAndDisabledContracts(t *testing.T) {
	good := testFECProfile()
	encoded, err := json.Marshal(good)
	if err != nil || !bytes.Contains(encoded, []byte(`"max_data_shards":3`)) || bytes.Contains(encoded, []byte(`"data_shards":`)) {
		t.Fatalf("OPEN profile maximum not explicit: %s err=%v", encoded, err)
	}
	mutations := []struct {
		name string
		edit func(*FECProfile)
	}{
		{"version", func(p *FECProfile) { p.Version = 2 }},
		{"algorithm", func(p *FECProfile) { p.Algorithm = 2 }},
		{"zero count", func(p *FECProfile) { p.MaxDataShards = 0 }},
		{"excessive count", func(p *FECProfile) { p.MaxDataShards = 33 }},
		{"unsupported parity", func(p *FECProfile) { p.ParityShards = 2 }},
		{"zero shard", func(p *FECProfile) { p.ShardSize = 0 }},
		{"excessive shard", func(p *FECProfile) { p.ShardSize = MaxFECShardSize + 1 }},
		{"zero block budget", func(p *FECProfile) { p.MaxBlockSize = 0 }},
		{"excessive block budget", func(p *FECProfile) { p.MaxBlockSize = MaxFECBlockSize + 1 }},
		{"insufficient block budget", func(p *FECProfile) { p.MaxBlockSize = 95 }},
		{"repair cannot fit frame", func(p *FECProfile) { p.ShardSize = MaxFECShardSize; p.MaxBlockSize = MaxFECBlockSize }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			p := good
			tc.edit(&p)
			if err := p.Validate(); !errors.Is(err, ErrFECWire) {
				t.Fatalf("invalid profile=%+v err=%v", p, err)
			}
		})
	}
	if err := DisabledFECProfile().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*FECProfile){func(p *FECProfile) { p.MaxDataShards = 1 }, func(p *FECProfile) { p.ParityShards = 1 }, func(p *FECProfile) { p.ShardSize = 1 }, func(p *FECProfile) { p.MaxBlockSize = 1 }} {
		p := DisabledFECProfile()
		edit(&p)
		if err := p.Validate(); !errors.Is(err, ErrFECWire) {
			t.Fatalf("disabled profile retained limits=%+v err=%v", p, err)
		}
	}
}

func TestFECCapabilityMalformedAndDisabledEncoding(t *testing.T) {
	c := FECCapability{Version: FECWireVersion, Algorithms: FECAlgorithmXOR1, MaxDataShards: 3, MaxParityShards: 1, MaxShardSize: 32, MaxBlockSize: 128, MaxBlocks: 2}
	good, err := EncodeFECCapability(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func([]byte) []byte{
		func(b []byte) []byte { return b[:13] },
		func(b []byte) []byte { return append(b, 0) },
		func(b []byte) []byte { b[0] = 2; return b },
		func(b []byte) []byte { b[1] |= 1; return b },
		func(b []byte) []byte { b[2] = 33; return b },
		func(b []byte) []byte { b[3] = 2; return b },
		func(b []byte) []byte { clear(b[4:6]); return b },
		func(b []byte) []byte {
			binary.BigEndian.PutUint16(b[4:6], MaxFECShardSize)
			binary.BigEndian.PutUint32(b[6:10], MaxFECBlockSize)
			return b
		},
		func(b []byte) []byte { binary.BigEndian.PutUint32(b[6:10], 95); return b },
		func(b []byte) []byte { clear(b[10:12]); return b },
		func(b []byte) []byte { binary.BigEndian.PutUint16(b[10:12], MaxFECBlocks+1); return b },
		func(b []byte) []byte { b[12] = 1; return b },
		func(b []byte) []byte { b[13] = 1; return b },
	} {
		got, err := DecodeFECCapability(edit(append([]byte(nil), good...)))
		if !errors.Is(err, ErrFECWire) || got != (FECCapability{}) {
			t.Fatalf("malformed capability returned value=%+v err=%v", got, err)
		}
	}
	disabled := FECCapability{Version: FECWireVersion}
	b, err := EncodeFECCapability(disabled)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeFECCapability(b); err != nil || got != disabled {
		t.Fatalf("disabled capability=%+v err=%v", got, err)
	}
	b[2] = 1
	if _, err := DecodeFECCapability(b); !errors.Is(err, ErrFECWire) {
		t.Fatalf("disabled capability with limits accepted: %v", err)
	}
}

func FuzzDatagramRepairDecodeCanonical(f *testing.F) {
	r := DatagramRepair{Meta: DatagramRepairMeta{Version: FECWireVersion, Flags: RepairParity, Direction: RepairDirectionOutbound, Flow: 1, Generation: 1, BlockID: 1, DataShards: 2, ParityShards: 1, ShardSize: 8, PayloadLength: 8, Lengths: []uint16{8, 3}}, Payload: bytes.Repeat([]byte{1}, 8)}
	good, err := EncodeDatagramRepair(r)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte{})
	f.Add(make([]byte, DatagramRepairHeaderSize))
	f.Fuzz(func(t *testing.T, input []byte) {
		r, err := DecodeDatagramRepair(input)
		if err != nil {
			return
		}
		encoded, err := EncodeDatagramRepair(r)
		if err != nil || !bytes.Equal(encoded, input) {
			t.Fatalf("accepted repair is not canonical: %v", err)
		}
	})
}

func TestRepairCannotExceedEncryptedFramePlaintextLimit(t *testing.T) {
	m := DatagramRepairMeta{Version: FECWireVersion, Flags: RepairParity, Direction: RepairDirectionOutbound, Flow: 1, Generation: 1, BlockID: 1, ShardIndex: 0, DataShards: 32, ParityShards: 1, ShardSize: MaxFECShardSize, PayloadLength: MaxFECShardSize, Lengths: make([]uint16, 32)}
	for i := range m.Lengths {
		m.Lengths[i] = m.ShardSize
	}
	if _, err := EncodeDatagramRepair(DatagramRepair{Meta: m, Payload: bytes.Repeat([]byte{1}, int(m.ShardSize))}); !errors.Is(err, ErrLimit) {
		t.Fatalf("oversize repair err=%v", err)
	}
}
