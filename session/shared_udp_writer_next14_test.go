package session

import (
	"bfp/security"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type next14BlockingUDPSocket struct {
	mu        sync.Mutex
	deadlines []time.Time
	wake      chan struct{}
	once      sync.Once
	writes    int
}

func newNext14BlockingUDPSocket() *next14BlockingUDPSocket {
	return &next14BlockingUDPSocket{wake: make(chan struct{})}
}

func (s *next14BlockingUDPSocket) SetWriteDeadline(deadline time.Time) error {
	s.mu.Lock()
	s.deadlines = append(s.deadlines, deadline)
	s.mu.Unlock()
	if !deadline.IsZero() {
		wait := time.Until(deadline)
		go func() {
			if wait > 0 {
				time.Sleep(wait)
			}
			s.once.Do(func() { close(s.wake) })
		}()
	}
	return nil
}

func (s *next14BlockingUDPSocket) WriteToUDP([]byte, *net.UDPAddr) (int, error) {
	<-s.wake
	s.mu.Lock()
	s.writes++
	s.mu.Unlock()
	return 0, timeoutError{}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func next14TestCarrier(t *testing.T, kind string) *carrier {
	t.Helper()
	keys := &security.TransportKeys{}
	c, err := makeCarrier(kind, 1, make([]byte, 16), keys, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNext14SharedUDPWriterDeadlineAndRetire(t *testing.T) {
	socket := newNext14BlockingUDPSocket()
	writer := newSharedUDPWriter(socket)
	carrier := next14TestCarrier(t, "udp")
	carrier.udpWriter = writer
	carrier.udp = nil // test injects the writer directly below
	carrier.remote = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	start := time.Now()
	err := writer.write([]byte("bounded"), carrier.remote, carrier, start.Add(40*time.Millisecond))
	if err == nil {
		t.Fatal("blocked shared write unexpectedly succeeded")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("shared write exceeded bounded wall clock: err=%v elapsed=%v", err, time.Since(start))
	}
	writer.retire()
	if err := writer.write([]byte("late"), carrier.remote, carrier, time.Now().Add(time.Second)); !errors.Is(err, errSharedUDPWriterClosed) {
		t.Fatalf("late shared write was accepted after retirement: %v", err)
	}
}

func TestNext14SharedUDPWriterQueuedCarrierCloseCancels(t *testing.T) {
	socket := newNext14BlockingUDPSocket()
	// Keep the first request active until its carrier closes. The fake socket
	// wakes on the initial deadline; its result still reports a write failure.
	writer := newSharedUDPWriter(socket)
	first := next14TestCarrier(t, "udp")
	second := next14TestCarrier(t, "udp")
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}
	firstDone := make(chan error, 1)
	go func() { firstDone <- writer.write([]byte("first"), addr, first, time.Now().Add(time.Second)) }()
	select {
	case <-socket.wake:
	case <-time.After(2 * time.Second):
		t.Fatal("first shared write did not reach socket")
	}
	secondDone := make(chan error, 1)
	go func() { secondDone <- writer.write([]byte("second"), addr, second, time.Now().Add(time.Second)) }()
	second.close()
	select {
	case err := <-secondDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("queued carrier close returned %v", err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("queued carrier close did not cancel admission")
	}
	first.close()
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("active shared write did not retire after carrier close")
	}
	writer.retire()
}
