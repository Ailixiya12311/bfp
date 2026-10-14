package security

import "sync"

const ReplayWindowSize = 4096

// ReplayWindow uses fixed storage. Accept must only follow successful AEAD and
// structural validation; unauthenticated record numbers must never move it.
type ReplayWindow struct {
	mu          sync.Mutex
	bits        [ReplayWindowSize / 64]uint64
	latest      uint64
	initialized bool
}

func (w *ReplayWindow) Accept(number uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.initialized {
		w.initialized = true
		w.latest = number
		w.bits[0] = 1
		return true
	}
	if number > w.latest {
		difference := number - w.latest
		if difference >= ReplayWindowSize {
			clear(w.bits[:])
		} else {
			words, bits := int(difference/64), uint(difference%64)
			for i := len(w.bits) - 1; i >= 0; i-- {
				var shifted uint64
				if i >= words {
					shifted = w.bits[i-words] << bits
					if bits != 0 && i > words {
						shifted |= w.bits[i-words-1] >> (64 - bits)
					}
				}
				w.bits[i] = shifted
			}
		}
		w.latest = number
		w.bits[0] |= 1
		return true
	}
	difference := w.latest - number
	if difference >= ReplayWindowSize {
		return false
	}
	word, bit := difference/64, difference%64
	mask := uint64(1) << bit
	if w.bits[word]&mask != 0 {
		return false
	}
	w.bits[word] |= mask
	return true
}
