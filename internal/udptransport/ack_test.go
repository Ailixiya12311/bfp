package udptransport

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"reflect"
	"testing"
	"time"

	"bfp/protocol"
)

func TestACKCodecVectorAndRoundTrip(t *testing.T) {
	a := ACK{Epoch: 2, Largest: 7, Delay: 25 * time.Millisecond, Ranges: []Range{{5, 7}, {0, 2}}}
	f, err := EncodeACK(a)
	if err != nil {
		t.Fatal(err)
	}
	want := "000061a8020000000000000000000005000000000000000700000000000000000000000000000002"
	if hex.EncodeToString(f.Data) != want {
		t.Fatalf("vector %x", f.Data)
	}
	wire, err := protocol.Encode([]protocol.Frame{f})
	if err != nil {
		t.Fatal(err)
	}
	frames, err := protocol.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeACK(frames[0])
	if err != nil || !reflect.DeepEqual(got, a) {
		t.Fatalf("got %+v err %v", got, err)
	}
	// Neither decoded ranges nor output Data alias the caller's storage.
	f.Data[8] = 255
	if got.Ranges[0].First != 5 {
		t.Fatal("range aliases data")
	}
	a.Ranges[0].First = 4
	if frames[0].Data[15] != 5 {
		t.Fatal("encoded data aliases range")
	}
}

func TestACKRejectsMalformedBeforeAnyResult(t *testing.T) {
	base, _ := EncodeACK(ACK{Epoch: 0, Largest: 4, Ranges: []Range{{4, 4}, {0, 1}}})
	cases := map[string]func(*protocol.Frame){
		"kind": func(f *protocol.Frame) { f.Kind = protocol.Ping }, "flags": func(f *protocol.Frame) { f.Flags = 0 }, "flow": func(f *protocol.Frame) { f.Flow = 1 },
		"epoch high bits": func(f *protocol.Frame) { f.Value = uint64(1) << 32 }, "largest overflow": func(f *protocol.Frame) { f.Offset = MaxRecordNumber + 1 },
		"largest mismatch": func(f *protocol.Frame) { f.Offset = 3 }, "delay too high": func(f *protocol.Frame) { binary.BigEndian.PutUint32(f.Data, 25001) },
		"zero count": func(f *protocol.Frame) { f.Data[4] = 0 }, "too many": func(f *protocol.Frame) { f.Data[4] = 33 }, "reserved": func(f *protocol.Frame) { f.Data[7] = 1 },
		"truncated": func(f *protocol.Frame) { f.Data = f.Data[:len(f.Data)-1] }, "trailing": func(f *protocol.Frame) { f.Data = append(f.Data, 0) },
		"inverted": func(f *protocol.Frame) { binary.BigEndian.PutUint64(f.Data[8:16], 5) },
		"adjacent": func(f *protocol.Frame) { binary.BigEndian.PutUint64(f.Data[32:40], 3) },
		"overlap":  func(f *protocol.Frame) { binary.BigEndian.PutUint64(f.Data[32:40], 4) },
		"descending": func(f *protocol.Frame) {
			binary.BigEndian.PutUint64(f.Data[24:32], 5)
			binary.BigEndian.PutUint64(f.Data[32:40], 6)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := base
			f.Data = append([]byte(nil), base.Data...)
			mutate(&f)
			got, err := DecodeACK(f)
			if err == nil || !reflect.DeepEqual(got, ACK{}) {
				t.Fatalf("accepted %+v %v", got, err)
			}
		})
	}
}

func TestACKMaxRangesAndIntegerBoundaries(t *testing.T) {
	ranges := make([]Range, MaxRanges)
	for i := range ranges {
		n := MaxRecordNumber - uint64(2*i)
		ranges[i] = Range{n, n}
	}
	a := ACK{Epoch: math.MaxUint32, Largest: MaxRecordNumber, Delay: MaxACKDelay, Ranges: ranges}
	f, err := EncodeACK(a)
	if err != nil || len(f.Data) != 520 {
		t.Fatalf("max frame %d %v", len(f.Data), err)
	}
	if _, err = DecodeACK(f); err != nil {
		t.Fatal(err)
	}
	for _, a := range []ACK{{Largest: 0, Ranges: []Range{{0, math.MaxUint64}}}, {Largest: 0, Delay: -time.Microsecond, Ranges: []Range{{0, 0}}}, {Largest: 0, Delay: 1, Ranges: []Range{{0, 0}}}, {Largest: 0, Ranges: append(ranges, Range{0, 0})}} {
		if _, err := EncodeACK(a); err == nil {
			t.Fatalf("accepted %+v", a)
		}
	}
}

func FuzzACKDecode(f *testing.F) {
	valid, _ := EncodeACK(ACK{Epoch: 1, Largest: 3, Ranges: []Range{{3, 3}, {0, 0}}})
	f.Add(uint64(3), uint64(1), uint8(1), valid.Data)
	f.Add(uint64(math.MaxUint64), uint64(math.MaxUint64), uint8(255), []byte{})
	f.Fuzz(func(t *testing.T, largest, value uint64, flags uint8, data []byte) {
		a, err := DecodeACK(protocol.Frame{Kind: protocol.PacketAck, Flags: flags, Offset: largest, Value: value, Data: data})
		if err != nil {
			return
		}
		encoded, err := EncodeACK(a)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeACK(encoded)
		if err != nil || !reflect.DeepEqual(a, again) {
			t.Fatalf("unstable %+v %v", again, err)
		}
	})
}
