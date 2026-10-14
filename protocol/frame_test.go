package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestFrameRoundTripAndOwnership(t *testing.T) {
	var frames []Frame
	for k := PacketAck; k <= ControlReceipt; k++ {
		frames = append(frames, Frame{Kind: k, Flags: 7, Flow: ^uint64(0), Offset: 1234, Value: 5678, Data: []byte{byte(k), 0, 255}})
	}
	wire, err := Encode(frames)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(frames, got) {
		t.Fatalf("round trip mismatch: %#v", got)
	}
	wire[HeaderSize] ^= 255
	if got[0].Data[0] != byte(PacketAck) {
		t.Fatal("decoded Data aliases input")
	}
	frames[0].Data[0] = 99
	if wire[HeaderSize] == 99 {
		t.Fatal("encoded buffer aliases frame Data")
	}
}

func TestControlReceiptKeepsExistingTicketFrameNumbers(t *testing.T) {
	if TicketRefreshAck != 23 || ControlReceipt != 24 {
		t.Fatalf("wire kind assignment changed: ticket_ack=%d control_receipt=%d", TicketRefreshAck, ControlReceipt)
	}
}

func TestFrameWireFixture(t *testing.T) {
	wire, err := Encode([]Frame{{Kind: StreamData, Flags: 2, Flow: 1, Offset: 2, Value: 3, Data: []byte("a")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != 29 || wire[0] != byte(StreamData) || wire[1] != 2 || !bytes.Equal(wire[2:4], []byte{0, 1}) {
		t.Fatalf("unexpected header: %x", wire)
	}
	if binary.BigEndian.Uint64(wire[4:12]) != 1 || binary.BigEndian.Uint64(wire[12:20]) != 2 || binary.BigEndian.Uint64(wire[20:28]) != 3 || wire[28] != 'a' {
		t.Fatalf("unexpected encoding: %x", wire)
	}
}

func TestFrameBoundaries(t *testing.T) {
	max := Frame{Kind: StreamData, Data: make([]byte, MaxPlaintext-HeaderSize)}
	wire, err := Encode([]Frame{max})
	if err != nil || len(wire) != MaxPlaintext {
		t.Fatalf("exact limit: len=%d err=%v", len(wire), err)
	}
	if _, err = Decode(wire); err != nil {
		t.Fatal(err)
	}
	max.Data = append(max.Data, 0)
	if _, err = Encode([]Frame{max}); !errors.Is(err, ErrLimit) {
		t.Fatalf("oversize: %v", err)
	}
	frames := make([]Frame, MaxFrames)
	for i := range frames {
		frames[i].Kind = Ping
	}
	wire, err = Encode(frames)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(wire); err != nil {
		t.Fatal(err)
	}
	frames = append(frames, Frame{Kind: Ping})
	if _, err = Encode(frames); !errors.Is(err, ErrLimit) {
		t.Fatalf("frame count: %v", err)
	}
	extra, _ := Encode([]Frame{{Kind: Ping}})
	if _, err = Decode(append(wire, extra...)); !errors.Is(err, ErrLimit) {
		t.Fatalf("decode frame count: %v", err)
	}
	if _, err = Decode(make([]byte, MaxPlaintext+1)); !errors.Is(err, ErrLimit) {
		t.Fatalf("decode size: %v", err)
	}
}

func TestMalformedFramesHaveNoPartialResult(t *testing.T) {
	good, _ := Encode([]Frame{{Kind: Open, Data: []byte("meta")}})
	for _, in := range [][]byte{good[:3], good[:HeaderSize-1], good[:len(good)-1], append(append([]byte(nil), good...), 1)} {
		got, err := Decode(in)
		if !errors.Is(err, ErrMalformed) || got != nil {
			t.Fatalf("accepted malformed input: %x, %v", in, err)
		}
	}
	bad := append([]byte(nil), good...)
	bad[0] = 255
	if _, err := Decode(bad); !errors.Is(err, ErrKind) {
		t.Fatalf("unknown kind: %v", err)
	}
	if _, err := Encode([]Frame{{Kind: 0}}); !errors.Is(err, ErrKind) {
		t.Fatalf("zero kind: %v", err)
	}
}

func TestTargetOptionalMetadata(t *testing.T) {
	input := Target{Network: "tcp", Address: "example.org:443", Class: Interactive}
	b, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("domain")) || bytes.Contains(b, []byte("rule_tag")) {
		t.Fatalf("unexpected optional fields: %s", b)
	}
	var got Target
	if err = json.Unmarshal(b, &got); err != nil || got != input {
		t.Fatalf("target: %#v %v", got, err)
	}
	if Class(255).Valid() || !Bulk.Valid() {
		t.Fatal("invalid class validity")
	}
}

func FuzzDecode(f *testing.F) {
	seed, _ := Encode([]Frame{{Kind: StreamData, Flow: 42, Data: []byte("seed")}})
	f.Add(seed)
	f.Add([]byte{})
	f.Add([]byte{255})
	f.Fuzz(func(t *testing.T, input []byte) {
		frames, err := Decode(input)
		if err != nil {
			return
		}
		encoded, err := Encode(frames)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, input) {
			t.Fatal("accepted input is not canonical")
		}
	})
}
