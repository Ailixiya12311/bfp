package obfuscation

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestPaddingCarrierBudgets(t *testing.T) {
	for _, max := range []int{2, 63, 64, 65, 1152, 1156, 16384} {
		for _, n := range []int{0, 1, max / 2, max - LengthSize} {
			if n < 0 || n > max-LengthSize {
				continue
			}
			payload := bytes.Repeat([]byte{0xa7}, n)
			for attempt := 0; attempt < 8; attempt++ {
				padded, err := Pad(payload, max)
				if err != nil {
					t.Fatalf("max=%d n=%d: %v", max, n, err)
				}
				if len(padded) > max || len(padded)-n > MaxOverhead || len(padded)-n < LengthSize {
					t.Fatalf("padding budget: max=%d n=%d got=%d", max, n, len(padded))
				}
				got, err := Unpad(padded)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("roundtrip max=%d n=%d: %v", max, n, err)
				}
				if len(got) > 0 {
					padded[LengthSize] ^= 255
					if !bytes.Equal(got, payload) {
						t.Fatal("Unpad aliases envelope")
					}
				}
			}
		}
	}
}

func TestPaddingRejectedInputs(t *testing.T) {
	for _, max := range []int{-1, 0, 1} {
		if _, err := Pad(nil, max); !errors.Is(err, ErrSize) {
			t.Fatalf("max=%d: %v", max, err)
		}
	}
	if _, err := Pad([]byte("abc"), 4); !errors.Is(err, ErrSize) {
		t.Fatal(err)
	}
	if _, err := Pad(make([]byte, 65536), 70000); !errors.Is(err, ErrSize) {
		t.Fatal(err)
	}
	for _, in := range [][]byte{nil, {1}, {0, 3, 1, 2}, {255, 255}} {
		if _, err := Unpad(in); !errors.Is(err, ErrMalformed) {
			t.Fatalf("malformed %x: %v", in, err)
		}
	}
}

func TestPaddingUsesRandomBytesAndPreservesOnlyDeclaredPayload(t *testing.T) {
	payload := []byte("payload")
	var previous []byte
	randomized := false
	for i := 0; i < 16; i++ {
		padded, err := Pad(payload, 1156)
		if err != nil {
			t.Fatal(err)
		}
		if len(padded) > 1156 || len(padded)-len(payload) < LengthSize || len(padded)-len(payload) > MaxOverhead {
			t.Fatalf("padding exceeded the unchanged LIGHT budget: %d", len(padded))
		}
		if previous != nil && !bytes.Equal(previous, padded) {
			randomized = true
		}
		previous = padded
		// Padding can contain any byte, including application-like content.
		copy(padded[LengthSize+len(payload):], []byte("untrusted trailing bytes"))
		got, err := Unpad(padded)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatal("padding was delivered as application data")
		}
	}
	if !randomized {
		t.Fatal("padding envelopes unexpectedly deterministic")
	}
}

func TestPaddingBoundedBucketTailEdges(t *testing.T) {
	cases := []struct {
		name                   string
		payload, max, overhead int
		draws                  []byte
		want                   int
	}{
		{"feedback-zero-tail", 52, 1152, 66, []byte{0}, 64},
		{"feedback-nonzero-tail", 52, 1152, 66, []byte{1}, 65},
		{"feedback-full-budget", 52, 1152, 66, []byte{54}, 118},
		{"ordinary-middle-tail", 7, 1152, 256, []byte{0, 17}, 81},
		{"udp-full-record", 928, 1152, 256, []byte{3}, 1152},
		{"below-first-bucket", 1, 63, 256, []byte{60}, 63},
		{"no-carrier-room", 63, 65, 256, nil, 65},
		{"mandatory-length-only", 20, 500, 2, nil, 22},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xa7}, tc.payload)
			random := io.MultiReader(bytes.NewReader(tc.draws), bytes.NewReader(make([]byte, tc.max)))
			padded, err := padBounded(payload, tc.max, tc.overhead, random)
			if err != nil || len(padded) != tc.want {
				t.Fatalf("envelope=%d want=%d err=%v", len(padded), tc.want, err)
			}
			if len(padded) > tc.max || len(padded)-len(payload) < LengthSize || len(padded)-len(payload) > tc.overhead {
				t.Fatal("tail escaped the carrier or overhead budget")
			}
			got, err := Unpad(padded)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatal("tail changed the declared payload", err)
			}
		})
	}
}

func TestPaddingBoundedBudgets(t *testing.T) {
	for _, overhead := range []int{2, 3, 33, 66, MaxOverhead} {
		for _, maximum := range []int{2, 63, 64, 65, 1152, 16336} {
			for _, size := range []int{0, 1, maximum / 2, maximum - LengthSize} {
				if size > maximum-LengthSize {
					continue
				}
				for _, draw := range []byte{0, 1} {
					payload := bytes.Repeat([]byte{42}, size)
					padded, err := padBounded(payload, maximum, overhead, bytes.NewReader(bytes.Repeat([]byte{draw}, maximum+8)))
					if err != nil || len(padded) > maximum || len(padded)-size > overhead || len(padded)-size < LengthSize {
						t.Fatalf("overhead=%d max=%d size=%d envelope=%d err=%v", overhead, maximum, size, len(padded), err)
					}
					got, err := Unpad(padded)
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatal("bounded round trip changed payload", err)
					}
				}
			}
		}
	}
	for _, overhead := range []int{-1, 0, 1, MaxOverhead + 1} {
		if _, err := PadBounded(nil, 1152, overhead); !errors.Is(err, ErrSize) {
			t.Fatalf("accepted invalid overhead %d: %v", overhead, err)
		}
	}
}

func TestPaddingRandomFailureDoesNotReturnEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name     string
		overhead int
		draws    []byte
	}{
		{"bucket", MaxOverhead, nil},
		{"tail", MaxOverhead, []byte{0}},
		{"padding-bytes", MaxOverhead, []byte{0, 0}},
		{"feedback-tail", 66, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := padBounded(make([]byte, 52), 1152, tc.overhead, bytes.NewReader(tc.draws))
			if err == nil || out != nil {
				t.Fatal("random-source failure returned a sendable envelope", err)
			}
		})
	}
}

func FuzzUnpad(f *testing.F) {
	f.Add([]byte{0, 1, 42, 99})
	f.Add([]byte{})
	f.Add([]byte{255, 255})
	f.Fuzz(func(t *testing.T, input []byte) {
		out, err := Unpad(input)
		if err != nil {
			return
		}
		if len(input) < LengthSize || len(out) != int(binary.BigEndian.Uint16(input[:2])) || !bytes.Equal(out, input[2:2+len(out)]) {
			t.Fatal("invalid accepted envelope")
		}
	})
}
