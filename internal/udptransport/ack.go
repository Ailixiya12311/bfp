// Package udptransport contains owner-confined UDP reliability primitives.
// It performs no I/O, starts no goroutines, and never reads a real clock.
// Callers must authenticate and fully decode a record before observing it.
// The ranges format here is a candidate revision and is not wired to Session.
package udptransport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"bfp/protocol"
)

const (
	MaxRanges           = 32
	HistoryBits         = 4096
	MaxLivePackets      = 256
	OrdinaryPacketLimit = 248
	MaxProbePackets     = MaxLivePackets - OrdinaryPacketLimit
	MaxLostPackets      = 256
	MaxWireBytes        = 1200
	MaxRecordNumber     = uint64(1<<32 - 1)
	MaxACKDelay         = 25 * time.Millisecond
)

var (
	ErrACK          = errors.New("udptransport: malformed ACK")
	ErrUnsent       = errors.New("udptransport: ACK for unsubmitted record")
	ErrNonEliciting = errors.New("udptransport: ACK for non-eliciting record")
	ErrScope        = errors.New("udptransport: invalid generation or epoch")
	ErrLimit        = errors.New("udptransport: bounded capacity exhausted")
	ErrTime         = errors.New("udptransport: invalid monotonic time")
	ErrSequence     = errors.New("udptransport: invalid send sequence")
	ErrEpochBusy    = errors.New("udptransport: previous epoch still retained")
)

// Scope is local context, not an additional plaintext/wire field. Separate
// instances are required for RX history and TX ledger (opposite directions).
type Scope struct {
	Generation uint64
	Epoch      uint32
}
type Range struct{ First, Last uint64 }
type ACK struct {
	Epoch   uint32
	Largest uint64
	Delay   time.Duration
	Ranges  []Range
}

func (a ACK) Validate() error {
	if a.Delay < 0 || a.Delay > MaxACKDelay || a.Delay%time.Microsecond != 0 || len(a.Ranges) < 1 || len(a.Ranges) > MaxRanges || a.Largest > MaxRecordNumber {
		return ErrACK
	}
	for i, r := range a.Ranges {
		if r.First > r.Last || r.Last > MaxRecordNumber || i == 0 && r.Last != a.Largest {
			return ErrACK
		}
		// Subtraction is safe after ordering validation; no Last+1 overflow.
		if i > 0 && (r.Last >= a.Ranges[i-1].First || a.Ranges[i-1].First-r.Last <= 1) {
			return ErrACK
		}
	}
	return nil
}

// EncodeACK uses the existing Frame type but must only be used after a future
// authenticated revision negotiation. It does not change protocol/frame.go.
func EncodeACK(a ACK) (protocol.Frame, error) {
	if err := a.Validate(); err != nil {
		return protocol.Frame{}, err
	}
	b := make([]byte, 8+16*len(a.Ranges))
	binary.BigEndian.PutUint32(b[:4], uint32(a.Delay/time.Microsecond))
	b[4] = byte(len(a.Ranges))
	for i, r := range a.Ranges {
		binary.BigEndian.PutUint64(b[8+16*i:], r.First)
		binary.BigEndian.PutUint64(b[16+16*i:], r.Last)
	}
	return protocol.Frame{Kind: protocol.PacketAck, Flags: 1, Offset: a.Largest, Value: uint64(a.Epoch), Data: b}, nil
}

func DecodeACK(f protocol.Frame) (ACK, error) {
	if f.Kind != protocol.PacketAck || f.Flags != 1 || f.Flow != 0 || f.Value>>32 != 0 || len(f.Data) < 8 || len(f.Data) > 8+16*MaxRanges {
		return ACK{}, ErrACK
	}
	n := int(f.Data[4])
	if n < 1 || n > MaxRanges || len(f.Data) != 8+16*n || f.Data[5] != 0 || f.Data[6] != 0 || f.Data[7] != 0 {
		return ACK{}, ErrACK
	}
	a := ACK{Epoch: uint32(f.Value), Largest: f.Offset, Delay: time.Duration(binary.BigEndian.Uint32(f.Data[:4])) * time.Microsecond, Ranges: make([]Range, n)}
	for i := range a.Ranges {
		a.Ranges[i] = Range{binary.BigEndian.Uint64(f.Data[8+16*i:]), binary.BigEndian.Uint64(f.Data[16+16*i:])}
	}
	if err := a.Validate(); err != nil {
		return ACK{}, fmt.Errorf("%w: ranges or delay", err)
	}
	return a, nil
}

func includes(ranges []Range, number uint64) bool {
	for _, r := range ranges {
		if number >= r.First && number <= r.Last {
			return true
		}
	}
	return false
}
