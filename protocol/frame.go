// Package protocol defines the encrypted internal frame representation.
// Encode output is plaintext and must only be transmitted inside an authenticated
// encryption record. It contains no carrier header or authentication tag.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	MaxPlaintext = 16 * 1024
	MaxFrames    = 64
	HeaderSize   = 28
)

type Class uint8

const (
	Interactive Class = iota
	Normal
	Bulk
)

func (c Class) Valid() bool { return c <= Bulk }

type Kind uint8

const (
	PacketAck Kind = iota + 1
	Ping
	Pong
	Open
	OpenResult
	StreamData
	StreamAck
	MaxFlowData
	Fin
	FinAck
	Reset
	ResetAck
	Datagram
	ClassUpdate
	ResumeState
	ResumeDone
	KeyUpdate
	KeyUpdateAck
	SessionClose
	SessionCloseAck
	MaxSessionData
	TicketRefresh
	TicketRefreshAck
	// ControlReceipt is the v2 logical installation receipt. It is kept after
	// the ticket kinds so the v1 numeric assignments remain unambiguous.
	ControlReceipt
	// FECCapability and DatagramRepair are authenticated inner-frame kinds.
	// They are appended to preserve every pre-existing wire number. Reliable
	// StreamData has no FEC interpretation and remains unchanged.
	FECCapabilityFrame
	DatagramRepairFrame
)

func (k Kind) Valid() bool { return k >= PacketAck && k <= DatagramRepairFrame }

type Frame struct {
	Kind   Kind
	Flags  uint8
	Flow   uint64
	Offset uint64
	Value  uint64
	Data   []byte
}

// Target is the JSON metadata carried inside an OPEN frame's encrypted Data.
// Domain and RuleTag are optional adapter hints, not independently authenticated
// identity or authorization evidence.
type Target struct {
	Network string `json:"network"`
	Address string `json:"address"`
	Domain  string `json:"domain,omitempty"`
	RuleTag string `json:"rule_tag,omitempty"`
	Class   Class  `json:"class"`
	// Delivery and FEC are optional for backwards-compatible OPENs. A nil
	// value resolves to the version-1 default for Network; once admitted, the
	// resolved values are retained by the flow and cannot be changed by a
	// ClassUpdate.
	Delivery *DeliveryContract `json:"delivery,omitempty"`
	FEC      *FECProfile       `json:"fec,omitempty"`
}

var (
	ErrLimit     = errors.New("protocol: frame or plaintext limit exceeded")
	ErrMalformed = errors.New("protocol: malformed frame encoding")
	ErrKind      = errors.New("protocol: unsupported frame kind")
)

// Encode serializes a bounded sequence of frames. Each frame has a 28-byte
// header: kind:u8, flags:u8, data_length:u16, flow:u64, offset:u64, value:u64.
// Integers use network byte order. Semantic validation belongs to the session.
func Encode(frames []Frame) ([]byte, error) {
	if len(frames) > MaxFrames {
		return nil, ErrLimit
	}
	size := 0
	for _, f := range frames {
		if !f.Kind.Valid() {
			return nil, ErrKind
		}
		if len(f.Data) > MaxPlaintext-HeaderSize || size > MaxPlaintext-HeaderSize-len(f.Data) {
			return nil, ErrLimit
		}
		size += HeaderSize + len(f.Data)
	}
	out := make([]byte, size)
	at := 0
	for _, f := range frames {
		h := out[at : at+HeaderSize]
		h[0], h[1] = byte(f.Kind), f.Flags
		binary.BigEndian.PutUint16(h[2:4], uint16(len(f.Data)))
		binary.BigEndian.PutUint64(h[4:12], f.Flow)
		binary.BigEndian.PutUint64(h[12:20], f.Offset)
		binary.BigEndian.PutUint64(h[20:28], f.Value)
		copy(out[at+HeaderSize:], f.Data)
		at += HeaderSize + len(f.Data)
	}
	return out, nil
}

// Decode parses complete frames and copies Data so decoded payloads do not
// alias a reusable carrier/decryption buffer. No partial result is returned on
// malformed input. The caller must authenticate the record before decoding it.
func Decode(in []byte) ([]Frame, error) {
	if len(in) > MaxPlaintext {
		return nil, ErrLimit
	}
	frames := make([]Frame, 0, min(len(in)/HeaderSize, MaxFrames))
	for at := 0; at < len(in); {
		if len(frames) == MaxFrames {
			return nil, ErrLimit
		}
		if len(in)-at < HeaderSize {
			return nil, fmt.Errorf("%w: truncated header", ErrMalformed)
		}
		h := in[at : at+HeaderSize]
		kind := Kind(h[0])
		if !kind.Valid() {
			return nil, ErrKind
		}
		n := int(binary.BigEndian.Uint16(h[2:4]))
		at += HeaderSize
		if n > len(in)-at {
			return nil, fmt.Errorf("%w: truncated payload", ErrMalformed)
		}
		frames = append(frames, Frame{
			Kind: kind, Flags: h[1],
			Flow:   binary.BigEndian.Uint64(h[4:12]),
			Offset: binary.BigEndian.Uint64(h[12:20]),
			Value:  binary.BigEndian.Uint64(h[20:28]),
			Data:   append([]byte(nil), in[at:at+n]...),
		})
		at += n
	}
	return frames, nil
}
