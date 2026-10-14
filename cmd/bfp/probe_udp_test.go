package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type probeUDPCountConn struct {
	net.Conn
	writes    atomic.Int32
	mu        sync.Mutex
	deadlines []time.Time
}

func (c *probeUDPCountConn) Write(data []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(data)
}
func (c *probeUDPCountConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, deadline)
	c.mu.Unlock()
	return c.Conn.SetDeadline(deadline)
}
func (c *probeUDPCountConn) assertOperations(t *testing.T, deadlines ...time.Time) {
	t.Helper()
	if c.writes.Load() != int32(len(deadlines)) {
		t.Fatalf("write count=%d, want one write per operation=%d", c.writes.Load(), len(deadlines))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.deadlines) != len(deadlines) {
		t.Fatalf("deadline reset count=%d, want %d", len(c.deadlines), len(deadlines))
	}
	for i, deadline := range deadlines {
		if !c.deadlines[i].Equal(deadline) {
			t.Fatal("correlation changed an operation's absolute deadline")
		}
	}
}

func probeUDPRealPair(t *testing.T) (*probeUDPCountConn, *net.UDPConn) {
	t.Helper()
	target, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	conn, e := net.DialUDP("udp", nil, target.LocalAddr().(*net.UDPAddr))
	if e != nil {
		target.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { conn.Close(); target.Close() })
	return &probeUDPCountConn{Conn: conn}, target
}

func probeUDPReceive(target *net.UDPConn, expected []byte) (*net.UDPAddr, error) {
	_ = target.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 64)
	n, peer, e := target.ReadFromUDP(buffer)
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(buffer[:n], expected) {
		return nil, errors.New("fixture request differs from expected iteration")
	}
	return peer, nil
}

func probeUDPSend(target *net.UDPConn, peer *net.UDPAddr, payload []byte) error {
	n, e := target.WriteToUDP(payload, peer)
	if e == nil && n != len(payload) {
		e = io.ErrShortWrite
	}
	return e
}

func TestExchangeUDPDelayedFirstReplyCannotPoisonFollowingOperations(t *testing.T) {
	for _, currentFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("current_reply_first_%t", currentFirst), func(t *testing.T) {
			conn, target := probeUDPRealPair(t)
			done := make(chan error, 1)
			go func() {
				_, e := probeUDPReceive(target, []byte("message-0"))
				if e != nil {
					done <- e
					return
				}
				// No first reply until the next request arrives: its first
				// deadline must already have expired before this delayed echo.
				peer, e := probeUDPReceive(target, []byte("message-1"))
				if e != nil {
					done <- e
					return
				}
				first, second := []byte("message-0"), []byte("message-1")
				if currentFirst {
					first, second = second, first
				}
				if e = probeUDPSend(target, peer, first); e == nil {
					time.Sleep(10 * time.Millisecond)
					e = probeUDPSend(target, peer, second)
				}
				if e != nil {
					done <- e
					return
				}
				peer, e = probeUDPReceive(target, []byte("message-2"))
				if e == nil {
					// A duplicate and a short malformed packet are also not
					// acknowledgements of message-2.
					e = probeUDPSend(target, peer, []byte("message-1"))
				}
				if e == nil {
					e = probeUDPSend(target, peer, []byte("m"))
				}
				if e == nil {
					e = probeUDPSend(target, peer, []byte("message-2"))
				}
				done <- e
			}()
			firstDeadline := time.Now().Add(80 * time.Millisecond)
			first, e := exchangeUDP(conn, []byte("message-0"), firstDeadline)
			if e == nil || first.ErrorKind != "timeout" || !first.TimedOut || first.Unmatched != 0 {
				t.Fatalf("first timeout was not retained: %+v, %v", first, e)
			}
			if first.ErrorPhase != "read" || !first.WriteAttempted || !first.WriteAccepted || first.ReadElapsedMS < 60 {
				t.Fatalf("a missing reply was misreported as pre-write/admission failure: %+v", first)
			}
			secondDeadline := time.Now().Add(500 * time.Millisecond)
			second, e := exchangeUDP(conn, []byte("message-1"), secondDeadline)
			if e != nil || second.TimedOut || second.ErrorKind != "" ||
				second.ReceivedIteration == nil || *second.ReceivedIteration != 1 {
				t.Fatalf("second operation did not recover: %+v, %v", second, e)
			}
			if second.ErrorPhase != "" || !second.WriteAttempted || !second.WriteAccepted {
				t.Fatal("successful correlation retained a failing stage")
			}
			thirdDeadline := time.Now().Add(500 * time.Millisecond)
			third, e := exchangeUDP(conn, []byte("message-2"), thirdDeadline)
			if e != nil || third.ReceivedIteration == nil || *third.ReceivedIteration != 2 ||
				third.Unmatched < 2 || third.Late < 1 || third.Unexpected < 1 {
				t.Fatalf("third operation accepted an unrelated reply: %+v, %v", third, e)
			}
			if !currentFirst && (second.Unmatched != 1 || second.Late != 1) {
				t.Fatalf("late first response was not discarded: %+v", second)
			}
			if currentFirst && third.Late < 2 {
				t.Fatalf("reordered first response was not discarded by third operation: %+v", third)
			}
			// Recovery of following operations must never retroactively turn
			// the first expired operation into success.
			if first.ErrorKind != "timeout" || !first.TimedOut {
				t.Fatal("subsequent correlation rewrote the first failure")
			}
			conn.assertOperations(t, firstDeadline, secondDeadline, thirdDeadline)
			select {
			case e = <-done:
				if e != nil {
					t.Fatal(e)
				}
			case <-time.After(time.Second):
				t.Fatal("real UDP fixture did not finish")
			}
		})
	}
}

func TestExchangeUDPUnmatchedRepliesDoNotExtendDeadline(t *testing.T) {
	conn, target := probeUDPRealPair(t)
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		peer, e := probeUDPReceive(target, []byte("message-7"))
		if e != nil {
			done <- e
			return
		}
		for {
			if e = probeUDPSend(target, peer, []byte("message-99")); e != nil {
				done <- e
				return
			}
			select {
			case <-stop:
				done <- nil
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()
	started := time.Now()
	deadline := started.Add(100 * time.Millisecond)
	result, e := exchangeUDP(conn, []byte("message-7"), deadline)
	elapsed := time.Since(started)
	close(stop)
	if e == nil || !result.TimedOut || result.ErrorKind != "mismatch" ||
		result.Unmatched < 2 || result.Unexpected != result.Unmatched || result.Late != 0 {
		t.Fatalf("continuous wrong replies were accepted: %+v, %v", result, e)
	}
	if result.ErrorPhase != "read" || !result.WriteAccepted || result.ReadElapsedMS < 80 {
		t.Fatalf("wrong-reply deadline did not identify the read phase: %+v", result)
	}
	if elapsed < 80*time.Millisecond || elapsed > 350*time.Millisecond {
		t.Fatalf("absolute 100ms budget was changed: elapsed=%s", elapsed)
	}
	if result.ExpectedIteration == nil || *result.ExpectedIteration != 7 ||
		result.LastUnmatchedIteration == nil || *result.LastUnmatchedIteration != 99 {
		t.Fatal("bounded iteration telemetry was not preserved")
	}
	conn.assertOperations(t, deadline)
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("wrong-reply fixture did not stop")
	}
}

type probeUDPStubConn struct {
	net.Conn
	writes     int
	short      bool
	writeErr   error
	readErr    error
	readData   []byte
	writeDelay time.Duration
	reads      int
}

func (c *probeUDPStubConn) SetDeadline(time.Time) error { return nil }
func (c *probeUDPStubConn) Write(data []byte) (int, error) {
	c.writes++
	if c.writeDelay > 0 {
		time.Sleep(c.writeDelay)
	}
	if c.short {
		return len(data) - 1, nil
	}
	return len(data), c.writeErr
}
func (c *probeUDPStubConn) Read(data []byte) (int, error) {
	c.reads++
	if c.readErr != nil {
		return 0, c.readErr
	}
	return copy(data, c.readData), nil
}

func TestExchangeUDPShortWriteClosedAndBufferedDeadline(t *testing.T) {
	for _, tc := range []struct {
		name string
		conn *probeUDPStubConn
		kind string
	}{
		{"short_write", &probeUDPStubConn{short: true}, "io"},
		{"closed_write", &probeUDPStubConn{writeErr: net.ErrClosed}, "closed"},
		{"closed_read", &probeUDPStubConn{readErr: io.EOF}, "closed"},
		{"generic_read", &probeUDPStubConn{readErr: errors.New("fixture error")}, "io"},
		{"buffered_wrong_forever", &probeUDPStubConn{readData: []byte("message-6")}, "mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started := time.Now()
			result, e := exchangeUDP(tc.conn, []byte("message-7"), started.Add(20*time.Millisecond))
			if e == nil || result.ErrorKind != tc.kind || tc.conn.writes != 1 {
				t.Fatalf("error/write contract: %+v, %v, writes=%d", result, e, tc.conn.writes)
			}
			if tc.kind == "mismatch" && (!result.TimedOut || !errors.Is(e, context.DeadlineExceeded) || time.Since(started) > 200*time.Millisecond) {
				t.Fatal("immediately buffered mismatches bypassed the deadline")
			}
		})
	}
}

func TestProbeMessageIterationRejectsUnboundedOrPrivatePayloads(t *testing.T) {
	for _, payload := range []string{"message-0", "message-9999"} {
		if probeMessageIteration([]byte(payload)) == nil {
			t.Fatal("generated probe iteration was not recognized")
		}
	}
	for _, payload := range []string{"message-", "message--1", "message-01", "message-10000", "message-999999999999999999999999999", "message-1-secret", "private=do-not-log", "message-7\x00"} {
		if probeMessageIteration([]byte(payload)) != nil {
			t.Fatal("noncanonical or unbounded reply became numeric metadata")
		}
	}
}

func TestExchangeUDPExpiredBeforeAdmissionDoesNotWrite(t *testing.T) {
	conn := &probeUDPStubConn{readData: []byte("message-7")}
	result, e := exchangeUDP(conn, []byte("message-7"), time.Now().Add(-time.Millisecond))
	if !errors.Is(e, context.DeadlineExceeded) || !result.TimedOut || result.ErrorPhase != "before_write" ||
		conn.writes != 0 || result.WriteAttempted || result.WriteAccepted || result.ReadElapsedMS != 0 {
		t.Fatalf("expired operation changed the budget or was reported as reply loss: %+v, %v", result, e)
	}
}

func TestExchangeUDPWriteConsumesBudgetBeforeCachedReplyRead(t *testing.T) {
	conn := &probeUDPStubConn{readData: []byte("message-7"), writeDelay: 80 * time.Millisecond}
	result, e := exchangeUDP(conn, []byte("message-7"), time.Now().Add(20*time.Millisecond))
	if !errors.Is(e, context.DeadlineExceeded) || !result.TimedOut || result.ErrorPhase != "before_read" ||
		conn.writes != 1 || conn.reads != 0 || !result.WriteAccepted || result.WriteElapsedMS < 60 {
		t.Fatalf("late write extended the original budget or accepted a cached reply: %+v, %v", result, e)
	}
}
