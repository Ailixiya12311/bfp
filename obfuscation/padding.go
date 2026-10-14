// Package obfuscation implements bounded LIGHT padding envelopes. Padding is
// not encryption: the entire returned envelope, including its true length,
// must be protected by the carrier's authenticated encryption before sending.
package obfuscation

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
)

const (
	LengthSize  = 2
	MaxOverhead = 256
	BucketSize  = 64
)

var (
	ErrSize      = errors.New("obfuscation: envelope does not fit")
	ErrMalformed = errors.New("obfuscation: malformed padding envelope")
)

// Pad writes a u16 true length followed by the payload and cryptographically
// random padding. It rounds to a 64-byte bucket when possible, randomly chooses
// from additional fitting buckets, then adds a bounded random bucket tail. The
// tail avoids a fixed length residue without introducing another wire field.
// Total overhead, including length, never exceeds 256 bytes or the caller's
// record plaintext budget.
func Pad(payload []byte, max int) ([]byte, error) {
	return PadBounded(payload, max, MaxOverhead)
}

// PadBounded preserves LIGHT framing while limiting optional padding cost for
// bounded feedback. overhead includes the two-byte encrypted true length.
func PadBounded(payload []byte, max, overhead int) ([]byte, error) {
	return padBounded(payload, max, overhead, rand.Reader)
}

// The reader stays private so production callers cannot replace the
// cryptographic randomness; tests can exercise exact tail and budget edges.
func padBounded(payload []byte, max, overhead int, random io.Reader) ([]byte, error) {
	if overhead < LengthSize || overhead > MaxOverhead {
		return nil, ErrSize
	}
	if len(payload) > 65535 || max < LengthSize || len(payload) > max-LengthSize {
		return nil, ErrSize
	}
	base := LengthSize + len(payload)
	available := min(overhead-LengthSize, max-base)
	first := (BucketSize - base%BucketSize) % BucketSize
	if first > available {
		first = 0
	}
	choices := (available-first)/BucketSize + 1
	extra := first
	if choices > 1 {
		n, err := rand.Int(random, big.NewInt(int64(choices)))
		if err != nil {
			return nil, err
		}
		extra += int(n.Int64()) * BucketSize
	}
	// Keep both bounds authoritative even when the highest bucket leaves less
	// than one full tail. With no space, retain the existing minimal envelope.
	if tailRoom := min(BucketSize-1, available-extra); tailRoom > 0 {
		n, err := rand.Int(random, big.NewInt(int64(tailRoom+1)))
		if err != nil {
			return nil, err
		}
		extra += int(n.Int64())
	}
	out := make([]byte, base+extra)
	if _, err := io.ReadFull(random, out[base:]); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(out[:LengthSize], uint16(len(payload)))
	copy(out[LengthSize:], payload)
	return out, nil
}

// Unpad verifies the length before allocation and returns an owned copy of the
// payload. Trailing padding bytes have no semantic effect. Authenticate the
// enclosing record before calling this function.
func Unpad(envelope []byte) ([]byte, error) {
	if len(envelope) < LengthSize {
		return nil, ErrMalformed
	}
	n := int(binary.BigEndian.Uint16(envelope[:LengthSize]))
	if n > len(envelope)-LengthSize {
		return nil, ErrMalformed
	}
	return append([]byte(nil), envelope[LengthSize:LengthSize+n]...), nil
}
