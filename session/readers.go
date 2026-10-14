package session

import "sync"

// Server's shared UDP loop is not a Session reader. Only private carriers are
// registered here, including retired generations that are still leaving Read.
type readerRegistry struct {
	mu      sync.Mutex
	retired bool
	active  map[*carrier]int
	wg      sync.WaitGroup
}

func (s *Session) startReader(c *carrier) {
	if c == nil {
		return
	}
	r := &s.readerState
	r.mu.Lock()
	if r.retired {
		r.mu.Unlock()
		c.close()
		return
	}
	if r.active == nil {
		r.active = make(map[*carrier]int)
	}
	r.active[c]++
	r.wg.Add(1)
	r.mu.Unlock()
	go func() {
		defer func() {
			r.mu.Lock()
			if r.active[c] <= 1 {
				delete(r.active, c)
			} else {
				r.active[c]--
			}
			r.mu.Unlock()
			r.wg.Done()
		}()
		s.readCarrier(c)
	}()
}

func (s *Session) retireReaders() {
	r := &s.readerState
	r.mu.Lock()
	r.retired = true
	carriers := make([]*carrier, 0, len(r.active))
	for c := range r.active {
		carriers = append(carriers, c)
	}
	r.mu.Unlock()
	// Closing a private socket releases Read. carrier.close deliberately does
	// not close a shared server UDP socket. Arbitrary noncooperative Conn
	// implementations still cannot be given a hard termination guarantee.
	for _, c := range carriers {
		c.close()
	}
	r.wg.Wait()
	r.mu.Lock()
	r.active = nil
	r.mu.Unlock()
}
