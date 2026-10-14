package security

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"math"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const RecordOverhead = 16 + 12 + 16 + 4
const MaxRecordsPerEpoch = uint64(1) << 32

// OldEpochGraceRecords is retained as a protocol budget reference. Epoch
// retirement itself is owned by Session's key lifecycle; RecordCipher must
// not silently delete the previous key merely because this many new records
// were observed.
const OldEpochGraceRecords = 4096

type RecordMeta struct {
	Epoch  uint32
	Number uint64
}
type recordEpoch struct {
	epoch  uint32
	aead   cipher.AEAD
	header [32]byte
	replay ReplayWindow
}

// RecordCipher is single-direction. Create distinct send and receive objects,
// and never create a new object with an already-used key/handle/epoch tuple.
type RecordCipher struct {
	mu                sync.Mutex
	master            [32]byte
	handle            [16]byte
	current, previous *recordEpoch
	number            uint64
}

func NewRecordCipher(key []byte, handle [16]byte, epoch uint32) (*RecordCipher, error) {
	if len(key) != 32 {
		return nil, ErrKey
	}
	c := &RecordCipher{handle: handle}
	copy(c.master[:], key)
	e, err := c.makeEpoch(epoch)
	if err != nil {
		return nil, err
	}
	c.current = e
	return c, nil
}
func (c *RecordCipher) makeEpoch(epoch uint32) (*recordEpoch, error) {
	var context [20]byte
	copy(context[:16], c.handle[:])
	binary.BigEndian.PutUint32(context[16:], epoch)
	body, err := deriveKey(c.master[:], context[:], "record/body")
	if err != nil {
		return nil, err
	}
	header, err := deriveKey(c.master[:], context[:], "record/header")
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(body[:])
	if err != nil {
		return nil, err
	}
	return &recordEpoch{epoch: epoch, aead: aead, header: header}, nil
}
func (c *RecordCipher) Seal(payload []byte) ([]byte, RecordMeta, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(payload) > MaxRecordSize-RecordOverhead {
		return nil, RecordMeta{}, ErrSize
	}
	if c.number >= MaxRecordsPerEpoch {
		return nil, RecordMeta{}, ErrExhausted
	}
	meta := RecordMeta{Epoch: c.current.epoch, Number: c.number}
	c.number++
	var header [12]byte
	binary.BigEndian.PutUint32(header[:4], meta.Epoch)
	binary.BigEndian.PutUint64(header[4:], meta.Number)
	plain := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(plain[:4], uint32(len(payload)))
	copy(plain[4:], payload)
	var aad [28]byte
	copy(aad[:16], c.handle[:])
	copy(aad[16:], header[:])
	sealed := c.current.aead.Seal(nil, header[:], plain, aad[:])
	mask := mac(c.current.header[:], sealed[:16])
	out := make([]byte, 28, len(sealed)+28)
	copy(out[:16], c.handle[:])
	for i := range header {
		out[16+i] = header[i] ^ mask[i]
	}
	out = append(out, sealed...)
	return out, meta, nil
}
func (c *RecordCipher) Open(record []byte) ([]byte, RecordMeta, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(record) < RecordOverhead || len(record) > MaxRecordSize {
		return nil, RecordMeta{}, ErrSize
	}
	if subtle.ConstantTimeCompare(record[:16], c.handle[:]) != 1 {
		return nil, RecordMeta{}, ErrAuthentication
	}
	for _, candidate := range []*recordEpoch{c.current, c.previous} {
		if candidate == nil {
			continue
		}
		mask := mac(candidate.header[:], record[28:44])
		var header [12]byte
		for i := range header {
			header[i] = record[16+i] ^ mask[i]
		}
		meta := RecordMeta{Epoch: binary.BigEndian.Uint32(header[:4]), Number: binary.BigEndian.Uint64(header[4:])}
		if meta.Epoch != candidate.epoch || meta.Number >= MaxRecordsPerEpoch {
			continue
		}
		var aad [28]byte
		copy(aad[:16], c.handle[:])
		copy(aad[16:], header[:])
		plain, err := candidate.aead.Open(nil, header[:], record[28:], aad[:])
		if err != nil {
			continue
		}
		n := uint64(binary.BigEndian.Uint32(plain[:4]))
		if n > uint64(len(plain)-4) {
			return nil, RecordMeta{}, ErrSize
		}
		if !candidate.replay.Accept(meta.Number) {
			return nil, meta, ErrReplay
		}
		return plain[4 : 4+int(n)], meta, nil
	}
	return nil, RecordMeta{}, ErrAuthentication
}

// UpdateKey accepts exactly +1. Open never derives a next epoch automatically:
// the session layer must authenticate KEY_UPDATE using an accepted old epoch.
func (c *RecordCipher) UpdateKey(nextEpoch uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current.epoch == math.MaxUint32 || nextEpoch != c.current.epoch+1 {
		return ErrEpoch
	}
	e, err := c.makeEpoch(nextEpoch)
	if err != nil {
		return err
	}
	c.previous, c.current = c.current, e
	c.number = 0
	return nil
}
func (c *RecordCipher) RetirePrevious() { c.mu.Lock(); defer c.mu.Unlock(); c.previous = nil }
func (c *RecordCipher) Epoch() uint32   { c.mu.Lock(); defer c.mu.Unlock(); return c.current.epoch }

// NextMeta lets the owner preflight bounded transport admission before Seal.
// Seal and carrier commit must occur serially without another send in between.
func (c *RecordCipher) NextMeta() RecordMeta {
	c.mu.Lock()
	defer c.mu.Unlock()
	return RecordMeta{Epoch: c.current.epoch, Number: c.number}
}
