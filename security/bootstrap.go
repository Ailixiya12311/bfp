package security

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

const bootstrapPrefixSize = 32 + 20

func sealEnvelope(secret, payload []byte, max, paddingLimit int, purpose string) ([]byte, error) {
	if len(secret) != 32 {
		return nil, ErrKey
	}
	if max < BootstrapOverhead || max > MaxRecordSize+BootstrapOverhead || len(payload) > max-BootstrapOverhead {
		return nil, ErrSize
	}
	var salt [32]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return nil, err
	}
	lengthKey, err := deriveKey(secret, salt[:], purpose+"/length")
	if err != nil {
		return nil, err
	}
	bodyKey, err := deriveKey(secret, salt[:], purpose+"/body")
	if err != nil {
		return nil, err
	}
	lengthAEAD, err := chacha20poly1305.New(lengthKey[:])
	if err != nil {
		return nil, err
	}
	bodyAEAD, err := chacha20poly1305.New(bodyKey[:])
	if err != nil {
		return nil, err
	}
	room := max - BootstrapOverhead - len(payload)
	if room > paddingLimit {
		room = paddingLimit
	}
	pad := 0
	if room > 0 {
		var draw [4]byte
		if _, err = io.ReadFull(rand.Reader, draw[:]); err != nil {
			return nil, err
		}
		pad = int(binary.BigEndian.Uint32(draw[:]) % uint32(room+1))
	}
	plain := make([]byte, 4+len(payload)+pad)
	binary.BigEndian.PutUint32(plain[:4], uint32(len(payload)))
	copy(plain[4:], payload)
	if _, err = io.ReadFull(rand.Reader, plain[4+len(payload):]); err != nil {
		return nil, err
	}
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(len(plain)+bodyAEAD.Overhead()))
	var nonce [12]byte
	out := append([]byte(nil), salt[:]...)
	out = lengthAEAD.Seal(out, nonce[:], encoded[:], salt[:])
	return bodyAEAD.Seal(out, nonce[:], plain, out), nil
}

func envelopeLength(secret, prefix []byte, max int, purpose string) (int, error) {
	if len(secret) != 32 {
		return 0, ErrKey
	}
	if len(prefix) != bootstrapPrefixSize {
		return 0, ErrSize
	}
	key, err := deriveKey(secret, prefix[:32], purpose+"/length")
	if err != nil {
		return 0, err
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return 0, err
	}
	var nonce [12]byte
	var scratch [4]byte
	plain, err := aead.Open(scratch[:0], nonce[:], prefix[32:], prefix[:32])
	if err != nil {
		return 0, ErrAuthentication
	}
	n := uint64(binary.BigEndian.Uint32(plain))
	if n < 20 || n > uint64(max-bootstrapPrefixSize) {
		return 0, ErrSize
	}
	return int(n), nil
}

func openEnvelope(secret, record []byte, max int, purpose string) ([]byte, error) {
	if len(record) < BootstrapOverhead || len(record) > max {
		return nil, ErrSize
	}
	n, err := envelopeLength(secret, record[:bootstrapPrefixSize], max, purpose)
	if err != nil {
		return nil, err
	}
	if n != len(record)-bootstrapPrefixSize {
		return nil, ErrSize
	}
	key, err := deriveKey(secret, record[:32], purpose+"/body")
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	plain, err := aead.Open(nil, nonce[:], record[bootstrapPrefixSize:], record[:bootstrapPrefixSize])
	if err != nil {
		return nil, ErrAuthentication
	}
	payloadLength := uint64(binary.BigEndian.Uint32(plain[:4]))
	if payloadLength > uint64(len(plain)-4) {
		return nil, ErrSize
	}
	return plain[4 : 4+int(payloadLength)], nil
}

func readEnvelope(r io.Reader, secret []byte, max int, purpose string) ([]byte, error) {
	if len(secret) != 32 {
		return nil, ErrKey
	}
	var prefix [bootstrapPrefixSize]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	n, err := envelopeLength(secret, prefix[:], max, purpose)
	if err != nil {
		return nil, err
	}
	record := make([]byte, bootstrapPrefixSize+n)
	copy(record, prefix[:])
	if _, err = io.ReadFull(r, record[bootstrapPrefixSize:]); err != nil {
		return nil, err
	}
	return openEnvelope(secret, record, max, purpose)
}

// SealBootstrap uses fresh 256-bit salt and independent length/body keys. Nonce
// zero is used once per purpose-derived key. max includes all envelope overhead.
func SealBootstrap(admit, payload []byte, max int) ([]byte, error) {
	if max > MaxBootstrapSize {
		return nil, ErrSize
	}
	return sealEnvelope(admit, payload, max, 255, "bootstrap")
}
func OpenBootstrap(admit, record []byte) ([]byte, error) {
	return openEnvelope(admit, record, MaxBootstrapSize, "bootstrap")
}
func ReadBootstrap(r io.Reader, admit []byte) ([]byte, error) {
	return readEnvelope(r, admit, MaxBootstrapSize, "bootstrap")
}
func WriteBootstrap(w io.Writer, record []byte) error {
	if len(record) < BootstrapOverhead || len(record) > MaxBootstrapSize {
		return ErrSize
	}
	return writeAll(w, record)
}

// Framer serializes records on TCP with a separate, fresh-salt authenticated
// envelope. A raw record is at most MaxRecordSize; envelope overhead is 72 bytes.
// Failed reads/writes are terminal for the carrier, which must not be reused.
type Framer struct {
	conn            io.ReadWriter
	send, receive   [32]byte
	readMu, writeMu sync.Mutex
	failed          atomic.Bool
}

func NewFramer(conn io.ReadWriter, sendKey, receiveKey []byte) (*Framer, error) {
	if conn == nil {
		return nil, io.ErrClosedPipe
	}
	if len(sendKey) != 32 || len(receiveKey) != 32 {
		return nil, ErrKey
	}
	f := &Framer{conn: conn}
	copy(f.send[:], sendKey)
	copy(f.receive[:], receiveKey)
	return f, nil
}
func (f *Framer) Write(record []byte) error {
	if len(record) == 0 || len(record) > MaxRecordSize {
		return ErrSize
	}
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	if f.failed.Load() {
		return ErrCarrierClosed
	}
	envelope, err := sealEnvelope(f.send[:], record, MaxRecordSize+BootstrapOverhead, 0, "tcp-frame")
	if err != nil {
		f.failed.Store(true)
		return err
	}
	err = writeAll(f.conn, envelope)
	if err != nil {
		f.failed.Store(true)
	}
	return err
}
func (f *Framer) Read() ([]byte, error) {
	f.readMu.Lock()
	defer f.readMu.Unlock()
	if f.failed.Load() {
		return nil, ErrCarrierClosed
	}
	data, err := readEnvelope(f.conn, f.receive[:], MaxRecordSize+BootstrapOverhead, "tcp-frame")
	if err != nil {
		f.failed.Store(true)
		return nil, err
	}
	if len(data) == 0 || len(data) > MaxRecordSize {
		f.failed.Store(true)
		return nil, ErrSize
	}
	return data, nil
}
