package security

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func testKey(value byte) []byte { return bytes.Repeat([]byte{value}, 32) }
func testPair(t *testing.T) KeyPair {
	t.Helper()
	k, e := GenerateKeyPair()
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func completeHandshake(t *testing.T, initiator, responder *Handshake) (*TransportKeys, *TransportKeys) {
	t.Helper()
	m1, k, e := initiator.WriteMessage([]byte("client metadata"))
	if e != nil || k != nil {
		t.Fatalf("init: %v %v", k, e)
	}
	p, k, e := responder.ReadMessage(m1)
	if e != nil || k != nil || string(p) != "client metadata" {
		t.Fatalf("receive init: %q %v", p, e)
	}
	m2, rk, e := responder.WriteMessage([]byte("fresh server challenge"))
	if e != nil || rk == nil {
		t.Fatalf("response: %v", e)
	}
	p, ik, e := initiator.ReadMessage(m2)
	if e != nil || ik == nil || string(p) != "fresh server challenge" {
		t.Fatalf("receive response: %q %v", p, e)
	}
	if ik.Send != rk.Receive || ik.Receive != rk.Send || ik.Send == ik.Receive {
		t.Fatal("directional key mismatch")
	}
	if !bytes.Equal(initiator.ChannelBinding(), responder.ChannelBinding()) || len(initiator.ChannelBinding()) != 32 {
		t.Fatal("transcript mismatch")
	}
	return ik, rk
}

func TestIKAuthenticationAndFreshCarrierKeys(t *testing.T) {
	client, server := testPair(t), testPair(t)
	var previous [32]byte
	for i := 0; i < 2; i++ {
		c, e := NewIKHandshake(true, client, server.Public, []byte("initial carrier"))
		if e != nil {
			t.Fatal(e)
		}
		s, e := NewIKHandshake(false, server, client.Public, []byte("initial carrier"))
		if e != nil {
			t.Fatal(e)
		}
		ik, _ := completeHandshake(t, c, s)
		if !bytes.Equal(s.PeerStatic(), client.Public) {
			t.Fatal("authorized client identity not recovered")
		}
		if i > 0 && previous == ik.Send {
			t.Fatal("fresh handshake reused traffic key")
		}
		previous = ik.Send
		if _, _, e = c.WriteMessage(nil); !errors.Is(e, ErrHandshakeComplete) {
			t.Fatal("completed handshake was reused")
		}
	}
	wrong := testPair(t)
	c, _ := NewIKHandshake(true, client, wrong.Public, nil)
	s, _ := NewIKHandshake(false, server, client.Public, nil)
	message, _, e := c.WriteMessage(nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.ReadMessage(message); e == nil {
		t.Fatal("wrong server pin accepted")
	}
	c, _ = NewIKHandshake(true, client, server.Public, nil)
	s, _ = NewIKHandshake(false, server, wrong.Public, nil)
	message, _, _ = c.WriteMessage(nil)
	if _, _, e = s.ReadMessage(message); !errors.Is(e, ErrAuthentication) {
		t.Fatalf("unauthorized client accepted: %v", e)
	}
}

func TestResumePSKAndTamperedHandshake(t *testing.T) {
	c, _ := NewResumeHandshake(true, testKey(9), []byte("session identity"))
	s, _ := NewResumeHandshake(false, testKey(9), []byte("session identity"))
	completeHandshake(t, c, s)
	c, _ = NewResumeHandshake(true, testKey(9), nil)
	s, _ = NewResumeHandshake(false, testKey(10), nil)
	message, _, e := c.WriteMessage(nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.ReadMessage(message); e == nil {
		t.Fatal("wrong recovery PSK accepted")
	}
	c, _ = NewResumeHandshake(true, testKey(9), nil)
	s, _ = NewResumeHandshake(false, testKey(9), nil)
	message, _, _ = c.WriteMessage([]byte("metadata"))
	message[len(message)-1] ^= 1
	if _, _, e = s.ReadMessage(message); e == nil {
		t.Fatal("tampered handshake accepted")
	}
	if _, _, e = s.WriteMessage(nil); !errors.Is(e, ErrHandshakeComplete) {
		t.Fatal("failed handshake could produce response")
	}
}

func TestBootstrapBoundsTamperAndPurposeSeparation(t *testing.T) {
	key := testKey(7)
	payload := []byte("opaque initial request")
	record, e := SealBootstrap(key, payload, MaxUDPRecordSize)
	if e != nil {
		t.Fatal(e)
	}
	if len(record) > MaxUDPRecordSize {
		t.Fatal("UDP bound exceeded")
	}
	plain, e := OpenBootstrap(key, record)
	if e != nil || !bytes.Equal(plain, payload) {
		t.Fatalf("roundtrip: %v", e)
	}
	plain, e = ReadBootstrap(bytes.NewReader(record), key)
	if e != nil || !bytes.Equal(plain, payload) {
		t.Fatalf("TCP bootstrap roundtrip: %v", e)
	}
	if _, e = OpenBootstrap(testKey(8), record); e == nil {
		t.Fatal("wrong admission key accepted")
	}
	for _, index := range []int{0, 31, 32, 51, 52, len(record) - 1} {
		damaged := append([]byte(nil), record...)
		damaged[index] ^= 1
		if _, e = OpenBootstrap(key, damaged); e == nil {
			t.Fatalf("tamper accepted at %d", index)
		}
	}
	if _, e = openEnvelope(key, record, MaxBootstrapSize, "tcp-frame"); e == nil {
		t.Fatal("bootstrap accepted as frame")
	}
	if _, e = SealBootstrap(key, make([]byte, MaxUDPRecordSize), MaxUDPRecordSize); !errors.Is(e, ErrSize) {
		t.Fatal("oversized payload accepted")
	}
	second, e := SealBootstrap(key, payload, MaxUDPRecordSize)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Equal(record[:32], second[:32]) {
		t.Fatal("fresh admission salt reused")
	}
}

type prefixOnlyReader struct {
	data []byte
	read int
}

func (r *prefixOnlyReader) Read(p []byte) (int, error) {
	if len(p) > bootstrapPrefixSize {
		panic("unauthenticated length caused a large read buffer")
	}
	if r.read == len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.read:])
	r.read += n
	return n, nil
}
func TestInvalidTCPPrefixNeverReadsOrAllocatesClaimedBody(t *testing.T) {
	key := testKey(3)
	for _, authenticate := range []bool{false, true} {
		prefix := make([]byte, bootstrapPrefixSize)
		if authenticate {
			lengthKey, e := deriveKey(key, prefix[:32], "bootstrap/length")
			if e != nil {
				t.Fatal(e)
			}
			aead, _ := chacha20poly1305.New(lengthKey[:])
			var claimed [4]byte
			binary.BigEndian.PutUint32(claimed[:], math.MaxUint32)
			var nonce [12]byte
			prefix = append(prefix[:32], aead.Seal(nil, nonce[:], claimed[:], prefix[:32])...)
		}
		reader := &prefixOnlyReader{data: prefix}
		if _, e := ReadBootstrap(reader, key); e == nil {
			t.Fatal("invalid TCP prefix accepted")
		}
		if reader.read != bootstrapPrefixSize {
			t.Fatalf("read %d beyond fixed prefix", reader.read)
		}
	}
}

func TestRecordReplayTamperAndEpochRetirement(t *testing.T) {
	var handle [16]byte
	handle[0] = 17
	send, _ := NewRecordCipher(testKey(1), handle, 0)
	receive, _ := NewRecordCipher(testKey(1), handle, 0)
	r0, m, e := send.Seal([]byte("first"))
	if e != nil || m.Number != 0 {
		t.Fatal(e)
	}
	r1, _, _ := send.Seal([]byte("second"))
	bad := append([]byte(nil), r1...)
	bad[len(bad)-1] ^= 1
	if _, _, e = receive.Open(bad); e == nil {
		t.Fatal("tamper accepted")
	}
	if _, _, e = receive.Open(r1); e != nil {
		t.Fatalf("unauthenticated input poisoned replay state: %v", e)
	}
	if _, _, e = receive.Open(r0); e != nil {
		t.Fatalf("out of order record failed: %v", e)
	}
	if _, _, e = receive.Open(r0); !errors.Is(e, ErrReplay) {
		t.Fatalf("replay accepted: %v", e)
	}
	late, _, _ := send.Seal([]byte("old epoch delayed"))
	if e = send.UpdateKey(2); !errors.Is(e, ErrEpoch) {
		t.Fatal("nonconsecutive epoch accepted")
	}
	if e = send.UpdateKey(1); e != nil {
		t.Fatal(e)
	}
	newRecord, newMeta, _ := send.Seal([]byte("new epoch"))
	if newMeta.Number != 0 || newMeta.Epoch != 1 {
		t.Fatal("epoch numbering failed")
	}
	if _, _, e = receive.Open(newRecord); e == nil {
		t.Fatal("next epoch derived without authorization")
	}
	if e = receive.UpdateKey(1); e != nil {
		t.Fatal(e)
	}
	if _, _, e = receive.Open(newRecord); e != nil {
		t.Fatal(e)
	}
	if _, _, e = receive.Open(late); e != nil {
		t.Fatal("bounded old epoch rejected")
	}
	if _, _, e = receive.Open(r0); !errors.Is(e, ErrReplay) {
		t.Fatal("old replay state lost at update")
	}
	receive.RetirePrevious()
	if _, _, e = receive.Open(late); e == nil {
		t.Fatal("retired epoch accepted")
	}
	if bytes.Equal(r0, newRecord) {
		t.Fatal("updated key reused ciphertext")
	}
}

func TestRecordLimitsRequireExplicitOldEpochRetirement(t *testing.T) {
	var handle [16]byte
	send, _ := NewRecordCipher(testKey(1), handle, math.MaxUint32)
	if e := send.UpdateKey(0); !errors.Is(e, ErrEpoch) {
		t.Fatal("epoch wrap accepted")
	}
	send.number = MaxRecordsPerEpoch
	if _, _, e := send.Seal(nil); !errors.Is(e, ErrExhausted) {
		t.Fatal("nonce budget ignored")
	}
	send, _ = NewRecordCipher(testKey(1), handle, 0)
	receive, _ := NewRecordCipher(testKey(1), handle, 0)
	old, _, _ := send.Seal([]byte("delayed"))
	_ = send.UpdateKey(1)
	_ = receive.UpdateKey(1)
	for i := 0; i < OldEpochGraceRecords; i++ {
		record, _, e := send.Seal(nil)
		if e != nil {
			t.Fatal(e)
		}
		if _, _, e = receive.Open(record); e != nil {
			t.Fatal(e)
		}
	}
	if receive.previous == nil {
		t.Fatal("old key was retired by record-count heuristic")
	}
	if _, _, e := receive.Open(old); e != nil {
		t.Fatal("old key was rejected before explicit lifecycle retirement")
	}
	receive.RetirePrevious()
	if _, _, e := receive.Open(old); e == nil {
		t.Fatal("explicitly retired old epoch accepted")
	}
	if _, _, e := send.Seal(make([]byte, MaxRecordSize)); !errors.Is(e, ErrSize) {
		t.Fatal("unbounded record accepted")
	}
}

func TestReplayWindowBoundaries(t *testing.T) {
	var w ReplayWindow
	for _, n := range []uint64{0, 63, 64, 65, 128, 129, 4096, 4100} {
		if !w.Accept(n) {
			t.Fatalf("fresh %d rejected", n)
		}
		if w.Accept(n) {
			t.Fatalf("duplicate %d accepted", n)
		}
	}
	if w.Accept(0) || w.Accept(4) {
		t.Fatal("expired window accepted")
	}
	if !w.Accept(4099) || w.Accept(4099) {
		t.Fatal("out of order window failed")
	}
	if !w.Accept(math.MaxUint64) || w.Accept(math.MaxUint64-4096) {
		t.Fatal("large jump overflow")
	}
}

func TestTCPFramerBoundedDuplexAndWrongKey(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	sender, _ := NewFramer(left, testKey(1), testKey(2))
	receiver, _ := NewFramer(right, testKey(2), testKey(1))
	done := make(chan error, 1)
	go func() { done <- sender.Write(bytes.Repeat([]byte{9}, MaxRecordSize)) }()
	plain, e := receiver.Read()
	if e != nil || len(plain) != MaxRecordSize {
		t.Fatalf("framer: %d %v", len(plain), e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	go func() { done <- receiver.Write([]byte("response")) }()
	plain, e = sender.Read()
	if e != nil || string(plain) != "response" {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if e = sender.Write(make([]byte, MaxRecordSize+1)); !errors.Is(e, ErrSize) {
		t.Fatal("unbounded frame accepted")
	}
	envelope, e := sealEnvelope(testKey(1), []byte("record"), MaxRecordSize+BootstrapOverhead, 0, "tcp-frame")
	if e != nil {
		t.Fatal(e)
	}
	f, _ := NewFramer(bytes.NewBuffer(envelope), testKey(3), testKey(4))
	if _, e = f.Read(); e == nil {
		t.Fatal("wrong frame key accepted")
	}
	if _, e = f.Read(); !errors.Is(e, ErrCarrierClosed) {
		t.Fatal("failed frame reader was reused")
	}
	if e = f.Write([]byte("invalid continued carrier")); !errors.Is(e, ErrCarrierClosed) {
		t.Fatal("failed framing carrier still wrote")
	}
}

func FuzzOpenRecord(f *testing.F) {
	var handle [16]byte
	sender, _ := NewRecordCipher(testKey(1), handle, 0)
	valid, _, _ := sender.Seal([]byte("seed"))
	f.Add(valid)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		receiver, _ := NewRecordCipher(testKey(1), handle, 0)
		_, _, _ = receiver.Open(data)
	})
}
func FuzzOpenBootstrap(f *testing.F) {
	key := testKey(1)
	valid, _ := SealBootstrap(key, []byte("seed"), MaxUDPRecordSize)
	f.Add(valid)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = OpenBootstrap(key, data) })
}
