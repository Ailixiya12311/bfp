// Package controlreceipt validates the small logical receipt carried inside
// the authenticated BFP frame stream. A receipt acknowledges application of
// one published semantic state; it is deliberately separate from PacketAck.
package controlreceipt

import (
	"errors"

	"bfp/protocol"
)

var (
	ErrKind  = errors.New("controlreceipt: unsupported state kind")
	ErrScope = errors.New("controlreceipt: invalid flow scope")
	ErrFrame = errors.New("controlreceipt: malformed frame")
)

// Receipt identifies the state kind and local flow whose revision was
// applied. MaxSessionData uses flow zero; all other supported states use a
// non-zero flow.
type Receipt struct {
	Kind     protocol.Kind
	Flow     uint64
	Revision uint64
}

func supported(k protocol.Kind) bool {
	return k == protocol.StreamAck || k == protocol.MaxFlowData ||
		k == protocol.MaxSessionData || k == protocol.OpenResult
}

func New(kind protocol.Kind, flow, revision uint64) (protocol.Frame, error) {
	if !supported(kind) {
		return protocol.Frame{}, ErrKind
	}
	if revision == 0 || (kind == protocol.MaxSessionData && flow != 0) ||
		(kind != protocol.MaxSessionData && flow == 0) {
		return protocol.Frame{}, ErrScope
	}
	return protocol.Frame{Kind: protocol.ControlReceipt, Flow: flow,
		Offset: revision, Value: uint64(kind)}, nil
}

func Decode(f protocol.Frame) (Receipt, error) {
	if f.Kind != protocol.ControlReceipt || f.Flags != 0 || f.Data != nil && len(f.Data) != 0 || f.Offset == 0 {
		return Receipt{}, ErrFrame
	}
	k := protocol.Kind(f.Value)
	if !supported(k) {
		return Receipt{}, ErrKind
	}
	if (k == protocol.MaxSessionData && f.Flow != 0) ||
		(k != protocol.MaxSessionData && f.Flow == 0) {
		return Receipt{}, ErrScope
	}
	return Receipt{Kind: k, Flow: f.Flow, Revision: f.Offset}, nil
}
