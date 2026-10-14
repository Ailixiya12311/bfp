// Package security implements the experimental BFP v0.1 cryptographic profile.
// It does not implement authorization, session ownership, or destination I/O.
package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	KeySize           = 32
	MaxUDPRecordSize  = 1200
	MaxRecordSize     = 16384
	MaxBootstrapSize  = 16384
	BootstrapOverhead = 32 + 20 + 16 + 4
)

var (
	ErrAuthentication    = errors.New("security: authentication failed")
	ErrSize              = errors.New("security: invalid bounded message size")
	ErrKey               = errors.New("security: expected a 32-byte key")
	ErrReplay            = errors.New("security: duplicate or retired record")
	ErrEpoch             = errors.New("security: invalid key epoch")
	ErrExhausted         = errors.New("security: nonce budget exhausted")
	ErrHandshakeComplete = errors.New("security: handshake already complete")
	ErrCarrierClosed     = errors.New("security: framing carrier failed")
)

func deriveKey(secret, salt []byte, purpose string) ([32]byte, error) {
	var key [32]byte
	_, err := io.ReadFull(hkdf.New(sha256.New, secret, salt, []byte("bfp-experimental-v0.1/"+purpose)), key[:])
	return key, err
}

func mac(key, input []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(input)
	return h.Sum(nil)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
