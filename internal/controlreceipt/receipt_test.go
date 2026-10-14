package controlreceipt

import (
	"errors"
	"testing"

	"bfp/protocol"
)

func TestRoundTripAndScopes(t *testing.T) {
	for _, tc := range []struct {
		kind protocol.Kind
		flow uint64
	}{
		{protocol.StreamAck, 9}, {protocol.MaxFlowData, 9},
		{protocol.MaxSessionData, 0}, {protocol.OpenResult, 9},
	} {
		f, err := New(tc.kind, tc.flow, 7)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(f)
		if err != nil || got.Kind != tc.kind || got.Flow != tc.flow || got.Revision != 7 {
			t.Fatalf("got=%+v err=%v", got, err)
		}
	}
}

func TestRejectsMalformedAndFutureKinds(t *testing.T) {
	for _, f := range []protocol.Frame{
		{Kind: protocol.ControlReceipt, Offset: 1, Value: uint64(protocol.StreamAck)},
		{Kind: protocol.ControlReceipt, Flow: 1, Offset: 0, Value: uint64(protocol.StreamAck)},
		{Kind: protocol.ControlReceipt, Flow: 1, Offset: 1, Value: uint64(protocol.PacketAck)},
		{Kind: protocol.ControlReceipt, Flow: 1, Offset: 1, Value: uint64(protocol.StreamAck), Data: []byte{1}},
	} {
		if _, err := Decode(f); err == nil {
			t.Fatalf("accepted %+v", f)
		}
	}
	if _, err := New(protocol.PacketAck, 1, 1); !errors.Is(err, ErrKind) {
		t.Fatal(err)
	}
	if _, err := New(protocol.StreamAck, 0, 1); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
}
