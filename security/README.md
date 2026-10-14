# Experimental security profile

This package is an executable **experimental v0.1 profile**, not an externally
audited or production-ready cryptographic protocol. It defines choices that the
architecture draft originally left open; deployment requires reviewing these
choices, the complete network state machine, and interoperability vectors.

- First connection: `Noise_IK_25519_ChaChaPoly_SHA256` using `github.com/flynn/noise`.
  An initiator pins the server static public key. A responder may supply the
  expected device public key, or its caller must authorize `PeerStatic()` after
  the first read and before replying. Successful Noise processing is not permission
  to create target sockets: the session layer must complete its fresh challenge.
- Recovery: `Noise_NNpsk0_25519_ChaChaPoly_SHA256`, with fresh ephemeral keys and a
  32-byte recovery secret belonging to an authenticated live session. This PSK
  is independent of admission keys. The caller validates tickets, instance/expiry,
  transcript-bound attachment, single owner and source-path freshness. No 0-RTT
  business operation is permitted. The first PSK message is replayable and has
  no permission to execute `OPEN` or target writes.
- On Noise completion, the wrapper deliberately copies the directional values
  returned by `CipherState.UnsafeKey()`. This is an explicit library API named
  `UnsafeKey`; it is not a general audited exporter. CipherStates are never used
  afterward for transport encryption. Initiator send is split key 1; responder
  send is split key 2. Keys, payloads and handshake state must never be logged.
- Records: `16-byte opaque handle || 12-byte protected (epoch32,PN64) || encrypted
  payload || 16-byte tag`. Integers are big-endian. HKDF-SHA256 with distinct
  `bfp-experimental-v0.1/record/body` and `/record/header` labels derives epoch keys
  using the handle and epoch as context. ChaCha20-Poly1305 nonce is epoch32 followed
  by PN64. AAD is the handle plus unmasked header. The header mask is the first
  12 bytes of HMAC-SHA256 over the first 16 ciphertext bytes. This custom header
  protection is a review candidate, not a claim of a standardized protocol.
- A fresh carrier must have fresh Noise keys. Each direction has a separate
  RecordCipher. Never recreate a sender under an already-used key/handle/epoch.
  Each epoch has a 2^32-record limit and a fixed 4096-record anti-replay window.
  `Open` never derives a new epoch. Authenticated `KEY_UPDATE` handling invokes
  `UpdateKey(epoch+1)` explicitly. At most one previous receive epoch survives;
  it retires after 4096 accepted current-epoch records or `RetirePrevious()`, which
  the caller must invoke on its bounded wall-clock retirement deadline. Epoch
  rollover is rejected. Cross-carrier flow deduplication belongs to Session.
- Bootstrap: fresh random 32-byte salt, authenticated 20-byte length field and
  AEAD body containing payload length and random padding. HKDF separates length
  and body purpose labels; nonce zero is used once per salt-derived purpose key.
  Salt uniqueness relies on a cryptographic 256-bit random draw. `max` includes
  the 72-byte minimum overhead. Random padding is bounded by 255 bytes and the
  caller's maximum. UDP uses at most 1200 bytes; bootstrap reading is at most
  16384 bytes. Authenticate the fixed 52-byte prefix before body allocation.
- TCP Framer uses the same fresh-salt envelope with **different** `tcp-frame`
  purpose labels, no extra padding, and directional keys. The raw record limit is
  16384 bytes, plus 72 bytes of outer overhead. All partial read/write failures
  end the carrier; callers must not reuse it. The inner RecordCipher provides
  replay protection. Socket deadlines and connection/global admission budgets
  are the network caller's responsibility.
- The admission secret only grants a bounded attempt at a cryptographic entry
  point. It must not substitute for device authorization or a recovery secret.
  The caller supplies bounded admission replay tracking, response limits and
  address-bound return-routability proof. No invalid-input response is sent here.
- Go does not guarantee complete secret erasure from memory. The package makes
  no zeroization, indistinguishability, hidden-port, or traffic-analysis claims.

The implementation uses fixed upper bounds before reading attacker-controlled
lengths and only advances replay state after AEAD and structural validation.
Tests cover identity pins, recovery PSKs, transcript/key direction, tampering,
replay and epoch retirement, purpose separation, malformed TCP lengths, and
bounded duplex framing. Session ownership and destination exactly-once delivery
must be tested by the session implementation.
