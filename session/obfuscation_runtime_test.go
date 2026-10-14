package session

import (
	"reflect"
	"testing"
	"time"

	"bfp/internal/udptransport"
	"bfp/obfuscation"
	"bfp/protocol"
	"bfp/security"
)

// Exercise the production feedback sender, its encrypted UDP carrier, and the
// actual local socket. A one-range ACK used to have exactly one fitting LIGHT
// bucket and therefore always emitted a 112-byte record.
func TestUDPFeedbackPaddingHasRandomTailWithinExistingBudget(t *testing.T) {
	s, now, receiver := udpOwner(t)
	ack, err := udptransport.EncodeACK(udptransport.ACK{
		Epoch:   0,
		Largest: 0,
		Ranges:  []udptransport.Range{{First: 0, Last: 0}},
	})
	if err != nil {
		t.Fatal(err)
	}
	frameBytes, err := protocol.Encode([]protocol.Frame{ack})
	if err != nil {
		t.Fatal(err)
	}
	rx, err := security.NewRecordCipher(s.current.keys.Send[:], s.current.handle, 0)
	if err != nil {
		t.Fatal(err)
	}
	lengths, residues := map[int]bool{}, map[int]bool{}
	buf := make([]byte, security.MaxUDPRecordSize+1)
	const samples = 64
	for i := 0; i < samples; i++ {
		// Empty-queue flush advances the existing virtual clock and replenishes
		// the ordinary feedback reserve; the test never bypasses admission.
		*now = now.Add(25 * time.Millisecond)
		s.flushUDP()
		before := s.udpPath.ackTokens
		sent, err := s.udpSend(ack, false, false, true)
		if err != nil || !sent {
			t.Fatalf("feedback send %d: sent=%v err=%v", i, sent, err)
		}
		if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		n, _, err := receiver.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n > security.MaxUDPRecordSize || n > len(frameBytes)+security.RecordOverhead+66 || n < len(frameBytes)+security.RecordOverhead+obfuscation.LengthSize {
			t.Fatalf("feedback escaped existing budgets: record=%d frame=%d", n, len(frameBytes))
		}
		if before-s.udpPath.ackTokens != float64(n) {
			t.Fatal("feedback reserve did not account for actual padded wire bytes")
		}
		padded, meta, err := rx.Open(buf[:n])
		if err != nil || meta.Number != uint64(i) {
			t.Fatal("encrypted carrier rejected feedback", meta, err)
		}
		plain, err := obfuscation.Unpad(padded)
		if err != nil {
			t.Fatal(err)
		}
		frames, err := protocol.Decode(plain)
		if err != nil || len(frames) != 1 || !reflect.DeepEqual(frames[0], ack) {
			t.Fatal("padding changed ACK semantics", frames, err)
		}
		lengths[n], residues[n%obfuscation.BucketSize] = true, true
	}
	// For this frame all 55 lengths are equiprobable. Accidental equality over
	// 64 records has probability 55^-63 (< 1e-100); exact draws and every budget
	// edge are separately deterministic in the obfuscation package tests.
	if len(lengths) < 2 || len(residues) < 2 {
		t.Fatalf("feedback retained fixed record length/residue: lengths=%v residues=%v", lengths, residues)
	}
	if s.udpPath.ledger.Snapshot().Live != 0 || s.stats.UDPACKSent != samples {
		t.Fatal("random tails changed feedback accounting or ACK elicitation")
	}
	t.Logf("%d actual encrypted UDP ACKs, %d lengths, %d residues, unchanged 66-byte feedback overhead", samples, len(lengths), len(residues))
}
