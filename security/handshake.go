package security

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

type KeyPair struct{ Private, Public []byte }
type TransportKeys struct{ Send, Receive [32]byte }

// IK's first message adds at most 96 bytes to its payload in this profile.
const MaxHandshakePayloadSize = MaxRecordSize - 96

func GenerateKeyPair() (KeyPair, error) {
	k, err := noise.DH25519.GenerateKeypair(rand.Reader)
	return KeyPair{Private: k.Private, Public: k.Public}, err
}

// Handshake must be used serially. Payloads are protocol messages, never 0-RTT
// business data. The network/session layer must check authorization and finish
// its freshness confirmation before accepting OPEN or destination side effects.
type Handshake struct {
	state        *noise.HandshakeState
	initiator    bool
	complete     bool
	failed       bool
	expectedPeer []byte
}

func NewIKHandshake(initiator bool, local KeyPair, peerStatic, prologue []byte) (*Handshake, error) {
	if len(local.Private) != 32 || len(local.Public) != 32 {
		return nil, ErrKey
	}
	pub, err := curve25519.X25519(local.Private, curve25519.Basepoint)
	if err != nil || subtle.ConstantTimeCompare(pub, local.Public) != 1 {
		return nil, errors.New("security: inconsistent static keypair")
	}
	if initiator && len(peerStatic) != 32 {
		return nil, ErrKey
	}
	if !initiator && len(peerStatic) != 0 && len(peerStatic) != 32 {
		return nil, ErrKey
	}
	config := noise.Config{CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256), Pattern: noise.HandshakeIK, Initiator: initiator, Prologue: append([]byte(nil), prologue...), StaticKeypair: noise.DHKey{Private: append([]byte(nil), local.Private...), Public: append([]byte(nil), local.Public...)}}
	if initiator {
		config.PeerStatic = append([]byte(nil), peerStatic...)
	}
	state, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, err
	}
	return &Handshake{state: state, initiator: initiator, expectedPeer: append([]byte(nil), peerStatic...)}, nil
}

// NewResumeHandshake selects Noise_NNpsk0_25519_ChaChaPoly_SHA256. Its PSK must
// be an independent secret from a previously authenticated, still-live Session,
// never the deployment admission key or a public handshake transcript hash.
func NewResumeHandshake(initiator bool, psk, prologue []byte) (*Handshake, error) {
	if len(psk) != 32 {
		return nil, ErrKey
	}
	state, err := noise.NewHandshakeState(noise.Config{CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256), Pattern: noise.HandshakeNN, Initiator: initiator, Prologue: append([]byte(nil), prologue...), PresharedKey: append([]byte(nil), psk...), PresharedKeyPlacement: 0})
	if err != nil {
		return nil, err
	}
	return &Handshake{state: state, initiator: initiator}, nil
}

func (h *Handshake) result(data []byte, c1, c2 *noise.CipherState, err error) ([]byte, *TransportKeys, error) {
	if err != nil {
		h.failed = true
		return nil, nil, err
	}
	if len(h.expectedPeer) != 0 && len(h.state.PeerStatic()) != 0 && subtle.ConstantTimeCompare(h.expectedPeer, h.state.PeerStatic()) != 1 {
		h.failed = true
		return nil, nil, ErrAuthentication
	}
	if c1 == nil || c2 == nil {
		return data, nil, nil
	}
	h.complete = true
	// Deliberate use of the library's explicit UnsafeKey export. These cipher
	// states are never used for packet encryption/decryption afterward.
	k1, k2 := c1.UnsafeKey(), c2.UnsafeKey()
	keys := &TransportKeys{Send: k1, Receive: k2}
	if !h.initiator {
		keys.Send, keys.Receive = k2, k1
	}
	return data, keys, nil
}

func (h *Handshake) WriteMessage(payload []byte) ([]byte, *TransportKeys, error) {
	if h.complete || h.failed {
		return nil, nil, ErrHandshakeComplete
	}
	if len(payload) > MaxHandshakePayloadSize {
		return nil, nil, ErrSize
	}
	data, c1, c2, err := h.state.WriteMessage(nil, payload)
	return h.result(data, c1, c2, err)
}

func (h *Handshake) ReadMessage(message []byte) ([]byte, *TransportKeys, error) {
	if h.complete || h.failed {
		return nil, nil, ErrHandshakeComplete
	}
	if len(message) > MaxRecordSize {
		return nil, nil, ErrSize
	}
	data, c1, c2, err := h.state.ReadMessage(nil, message)
	return h.result(data, c1, c2, err)
}

func (h *Handshake) PeerStatic() []byte { return append([]byte(nil), h.state.PeerStatic()...) }
func (h *Handshake) ChannelBinding() []byte {
	if !h.complete || h.failed {
		return nil
	}
	return append([]byte(nil), h.state.ChannelBinding()...)
}
