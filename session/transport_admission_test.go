package session

import (
	"bfp/protocol"
	"bfp/security"
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// transportGateConn blocks an actual framed carrier Write, not an actor command.
// It is installed before the reader starts and armed only after synchronization.
type transportGateConn struct {
	net.Conn
	armed   atomic.Bool
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *transportGateConn) Write(b []byte) (int, error) {
	if c.armed.CompareAndSwap(true, false) {
		close(c.started)
		<-c.release
	}
	return c.Conn.Write(b)
}

func (c *transportGateConn) unblock() { c.once.Do(func() { close(c.release) }) }

func transportUDPEcho(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	c, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		t.Fatal(e)
	}
	received := &atomic.Int32{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 16<<10)
		for {
			n, peer, e := c.ReadFromUDP(buf)
			if e != nil {
				return
			}
			received.Add(1)
			if _, e = c.WriteToUDP(buf[:n], peer); e != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		c.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("UDP echo worker did not stop")
		}
	})
	return c.LocalAddr().String(), received
}

func TestTransportUDPDeadlineCancelsAdmissionBehindTCPWrite(t *testing.T) {
	var gate *transportGateConn
	f := newRuntimeFixtureWith(t, "tcp", Options{HandshakeTimeout: time.Second, ProbeInterval: time.Hour, FailureTimeout: 5 * time.Second, RetainTimeout: 5 * time.Second, KeyUpdateBytes: 1 << 30, KeyUpdateInterval: time.Hour}, func(s *Session, c *carrier) {
		gate = &transportGateConn{Conn: c.conn, started: make(chan struct{}), release: make(chan struct{})}
		c.conn = gate
		var e error
		c.framer, e = security.NewFramer(gate, c.keys.Send[:], c.keys.Receive[:])
		if e != nil {
			t.Fatal(e)
		}
		s.startReader(c)
	})
	t.Cleanup(gate.unblock)
	address, received := transportUDPEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, e := f.client.DialClass(ctx, protocol.Target{Network: "udp", Address: address, Class: protocol.Normal})
	if e != nil {
		t.Fatal(e)
	}
	flow := conn.(*Flow)
	if e = flow.SetDeadline(time.Now().Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	baseline := []byte("baseline")
	if _, e = flow.Write(baseline); e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 2048)
	if n, e := flow.Read(buf); e != nil || !bytes.Equal(buf[:n], baseline) {
		t.Fatalf("baseline echo: %d %v", n, e)
	}
	var before uint64
	var beforeAppBytes uint64
	if e = f.client.call(ctx, func() {
		st := f.client.streams[flow.id]
		before = st.messageNext
		beforeAppBytes = st.txClassifier.Snapshot().TotalBytes
	}); e != nil {
		t.Fatal(e)
	}
	gate.armed.Store(true)
	f.client.post(func() { f.client.enqueue(protocol.Frame{Kind: protocol.Ping, Value: 17}, protocol.Interactive) })
	select {
	case <-gate.started:
	case <-time.After(time.Second):
		t.Fatal("carrier Write did not enter the gate")
	}
	deadline := time.Now().Add(120 * time.Millisecond)
	flow.SetWriteDeadline(deadline)
	type result struct {
		n       int
		e       error
		elapsed time.Duration
	}
	done := make(chan result, 1)
	started := time.Now()
	go func() {
		n, e := flow.Write(bytes.Repeat([]byte("x"), 1800))
		done <- result{n, e, time.Since(started)}
	}()
	var out result
	returned := false
	select {
	case out = <-done:
		returned = true
	case <-time.After(260 * time.Millisecond):
		t.Error("UDP Write did not honor its 120ms deadline while TCP actor write was held")
	}
	gate.unblock()
	if !returned {
		select {
		case out = <-done:
		case <-time.After(time.Second):
			t.Fatal("UDP Write did not finish after gate release")
		}
	}
	t.Logf("held TCP Write: UDP n=%d timeout=%t elapsed=%s", out.n, errors.Is(out.e, context.DeadlineExceeded), out.elapsed)
	if out.n != 0 || !errors.Is(out.e, context.DeadlineExceeded) {
		t.Errorf("uncommitted admission must time out: n=%d err=%v", out.n, out.e)
	}
	if timeout, ok := out.e.(net.Error); !ok || !timeout.Timeout() {
		t.Errorf("deadline must satisfy net.Error timeout: %v", out.e)
	}
	// An actor barrier after releasing the TCP write processes the canceled call.
	if e = f.client.call(context.Background(), func() {
		st := f.client.streams[flow.id]
		if st.messageNext != before {
			t.Errorf("timed-out UDP admission consumed message id: before=%d after=%d", before, st.messageNext)
		}
		if st.txClassifier.Snapshot().TotalBytes != beforeAppBytes {
			t.Error("timed-out UDP admission changed classification byte count")
		}
	}); e != nil {
		t.Fatal(e)
	}
	flow.SetDeadline(time.Now().Add(time.Second))
	recovery := []byte("recovery")
	if _, e = flow.Write(recovery); e != nil {
		t.Fatal(e)
	}
	if n, e := flow.Read(buf); e != nil || !bytes.Equal(buf[:n], recovery) {
		t.Errorf("canceled UDP request leaked into recovery echo: n=%d err=%v", n, e)
	}
	if received.Load() != 2 {
		t.Errorf("target received canceled or partial UDP: packets=%d want=2", received.Load())
	}
}

type transportReadWatchConn struct {
	net.Conn
	readBytes atomic.Int64
	expected  int64
	readAgain chan struct{}
	once      sync.Once
}

func (c *transportReadWatchConn) Read(b []byte) (int, error) {
	if c.readBytes.Load() >= c.expected {
		c.once.Do(func() { close(c.readAgain) })
	}
	n, e := c.Conn.Read(b)
	c.readBytes.Add(int64(n))
	return n, e
}

func transportTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	type accepted struct {
		c net.Conn
		e error
	}
	done := make(chan accepted, 1)
	go func() { c, e := listener.Accept(); done <- accepted{c, e} }()
	left, e := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	right := <-done
	if right.e != nil {
		left.Close()
		t.Fatal(right.e)
	}
	t.Cleanup(func() { left.Close(); right.c.Close() })
	return left, right.c
}

func transportPassiveSession(t *testing.T, capacity int) *Session {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &Session{ctx: ctx, cancel: cancel, incoming: make(chan packet, capacity), done: make(chan struct{})}
}

func TestTransportTCPReaderBackpressuresFullIncoming(t *testing.T) {
	left, right := transportTCPPair(t)
	const count = 3
	records := [][]byte{[]byte("record-a"), []byte("record-b"), []byte("record-c")}
	watch := &transportReadWatchConn{Conn: right, expected: count * int64(len(records[0])+security.BootstrapOverhead), readAgain: make(chan struct{})}
	keys := &security.TransportKeys{}
	for i := range keys.Send {
		keys.Send[i], keys.Receive[i] = byte(i+1), byte(i+1)
	}
	handle := make([]byte, 16)
	sender, e := makeCarrier("tcp", 1, handle, keys, left, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	receiver, e := makeCarrier("tcp", 1, handle, keys, watch, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(sender.close)
	t.Cleanup(receiver.close)
	s := transportPassiveSession(t, 2)
	s.startReader(receiver)
	for _, b := range records {
		if e := sender.write(b); e != nil {
			t.Fatal(e)
		}
	}
	runtimeWait(t, "three complete TCP envelopes read", func() bool { return watch.readBytes.Load() >= watch.expected })
	select {
	case <-watch.readAgain:
		t.Error("TCP reader read past a complete record while incoming was full (record was discarded)")
	case <-time.After(40 * time.Millisecond):
	}
	for i, expected := range records {
		select {
		case p := <-s.incoming:
			if p.err != nil || !bytes.Equal(p.wire, expected) {
				t.Errorf("record %d: wire=%q err=%v", i, p.wire, p.err)
			}
		case <-time.After(300 * time.Millisecond):
			t.Errorf("missing TCP record %d after releasing incoming backpressure", i)
		}
	}
	select {
	case <-watch.readAgain:
	case <-time.After(time.Second):
		t.Error("TCP reader did not resume after queue space became available")
	}
}

func TestTransportTCPAdmissionExitsOnCancelOrCarrierClose(t *testing.T) {
	for _, mode := range []string{"session-cancel", "carrier-close"} {
		t.Run(mode, func(t *testing.T) {
			left, right := transportTCPPair(t)
			keys := &security.TransportKeys{}
			c, e := makeCarrier("tcp", 1, make([]byte, 16), keys, right, nil, nil)
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(c.close)
			_ = left
			s := transportPassiveSession(t, 1)
			s.incoming <- packet{c: c, wire: []byte("occupied")}
			done := make(chan struct{})
			go func() { s.deliver(c, []byte("blocked")); close(done) }()
			select {
			case <-done:
				t.Error("full TCP incoming admission returned before cancellation (silent drop)")
			case <-time.After(30 * time.Millisecond):
			}
			if mode == "session-cancel" {
				s.cancel()
			} else {
				c.close()
			}
			select {
			case <-done:
			case <-time.After(200 * time.Millisecond):
				t.Fatal("TCP incoming admission did not exit directly on cancellation/close")
			}
			if p := <-s.incoming; !bytes.Equal(p.wire, []byte("occupied")) {
				t.Error("canceled record replaced an admitted record")
			}
		})
	}
}

// Keep UDP delivery nonblocking: the server UDP reader serves multiple owners.
func TestTransportUDPFullIncomingRemainsNonblocking(t *testing.T) {
	s := transportPassiveSession(t, 1)
	c := &carrier{kind: "udp"}
	s.incoming <- packet{c: c, wire: []byte("occupied")}
	done := make(chan struct{})
	go func() { s.deliver(c, []byte("best-effort")); close(done) }()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("UDP admission blocked shared reader")
	}
	if p := <-s.incoming; !bytes.Equal(p.wire, []byte("occupied")) {
		t.Fatal("full UDP incoming queue changed existing record")
	}
}

func TestTransportUDPRejectedAdmissionDoesNotMutate(t *testing.T) {
	for _, mode := range []string{"expired", "commands-full", "buffer-limit", "message-id-limit"} {
		t.Run(mode, func(t *testing.T) {
			s, flow, st := transportUDPActor(t, 1024)
			if e := s.call(context.Background(), func() {
				st.target.Network = "udp"
				st.messageNext = 31
				s.active, s.peerDone = true, true
				if mode == "message-id-limit" {
					st.messageNext = ^uint64(0)
				}
			}); e != nil {
				t.Fatal(e)
			}
			payload := bytes.Repeat([]byte("x"), 1800)
			var expected error
			var release chan struct{}
			switch mode {
			case "expired":
				flow.SetWriteDeadline(time.Now().Add(-time.Second))
				expected = context.DeadlineExceeded
			case "commands-full":
				started := make(chan struct{})
				release = make(chan struct{})
				s.post(func() { close(started); <-release })
				<-started
				for i := 0; i < cap(s.commands); i++ {
					s.commands <- func() {}
				}
				flow.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
				expected = context.DeadlineExceeded
			case "buffer-limit":
				payload = bytes.Repeat([]byte("x"), 4096)
				expected = ErrLimit
			case "message-id-limit":
				expected = ErrLimit
			}
			n, e := flow.Write(payload)
			if release != nil {
				close(release)
			}
			if n != 0 || !errors.Is(e, expected) {
				t.Fatalf("rejected admission: n=%d err=%v want=%v", n, e, expected)
			}
			if e := s.call(context.Background(), func() {
				want := uint64(31)
				if mode == "message-id-limit" {
					want = ^uint64(0)
				}
				if st.messageNext != want || s.queue.Len() != 0 || s.queue.Bytes() != 0 {
					t.Errorf("rejection changed id/partial queue: id=%d items=%d bytes=%d", st.messageNext, s.queue.Len(), s.queue.Bytes())
				}
			}); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestTransportUDPAdmissionEmptyAndMaximumDatagram(t *testing.T) {
	s, flow, st := transportUDPActor(t, 16384)
	if e := s.call(context.Background(), func() {
		st.target.Network = "udp"
		st.messageNext = 1
		s.active, s.peerDone = true, true
	}); e != nil {
		t.Fatal(e)
	}
	flow.SetWriteDeadline(time.Now().Add(time.Second))
	for _, size := range []int{0, 16 << 10} {
		if n, e := flow.Write(make([]byte, size)); e != nil || n != size {
			t.Fatalf("datagram %d admission: n=%d err=%v", size, n, e)
		}
	}
	if e := s.call(context.Background(), func() {
		if st.messageNext != 3 || s.queue.Len() != 20 {
			t.Errorf("empty+maximum datagram id/fragments: id=%d items=%d", st.messageNext, s.queue.Len())
		}
	}); e != nil {
		t.Fatal(e)
	}
}

// This admission-only fixture runs the actual command wrapper without sockets,
// maintain or flush. The separate gate regression above covers a real carrier.
func transportUDPActor(t *testing.T, buffer int) (*Session, *Flow, *streamState) {
	t.Helper()
	s, st := stateSession(t, "udp")
	s.opts.MaxFlowBuffer, s.opts.MaxSessionBuffer = buffer, buffer*4
	go func() {
		defer close(s.done)
		for {
			select {
			case fn := <-s.commands:
				fn()
			case <-s.ctx.Done():
				return
			}
		}
	}()
	t.Cleanup(func() { s.cancel(); <-s.done })
	return s, st.flow, st
}

func TestTransportTCPReaderRetiresWhileIncomingFull(t *testing.T) {
	for _, mode := range []string{"session-cancel", "carrier-close"} {
		t.Run(mode, func(t *testing.T) {
			left, right := transportTCPPair(t)
			record := []byte("old-generation-record")
			watch := &transportReadWatchConn{Conn: right, expected: int64(len(record) + security.BootstrapOverhead), readAgain: make(chan struct{})}
			keys := &security.TransportKeys{}
			sender, e := makeCarrier("tcp", 1, make([]byte, 16), keys, left, nil, nil)
			if e != nil {
				t.Fatal(e)
			}
			receiver, e := makeCarrier("tcp", 1, make([]byte, 16), keys, watch, nil, nil)
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(sender.close)
			t.Cleanup(receiver.close)
			s := transportPassiveSession(t, 1)
			s.incoming <- packet{c: receiver, wire: []byte("occupied")}
			done := make(chan struct{})
			go func() { s.readCarrier(receiver); close(done) }()
			if e := sender.write(record); e != nil {
				t.Fatal(e)
			}
			runtimeWait(t, "old-generation complete record", func() bool { return watch.readBytes.Load() >= watch.expected })
			select {
			case <-watch.readAgain:
				t.Error("reader failed to hold complete record under backpressure")
			case <-time.After(30 * time.Millisecond):
			}
			if mode == "session-cancel" {
				s.cancel()
			} else {
				receiver.close()
			}
			select {
			case <-done:
			case <-time.After(200 * time.Millisecond):
				t.Fatal("old-generation reader remained blocked after direct cancellation/close")
			}
			if p := <-s.incoming; !bytes.Equal(p.wire, []byte("occupied")) {
				t.Fatal("old reader changed an admitted record")
			}
			if mode == "carrier-close" {
				// Reuse this owner with a new generation after the old reader exits.
				newLeft, newRight := transportTCPPair(t)
				newSender, e := makeCarrier("tcp", 2, make([]byte, 16), keys, newLeft, nil, nil)
				if e != nil {
					t.Fatal(e)
				}
				newReceiver, e := makeCarrier("tcp", 2, make([]byte, 16), keys, newRight, nil, nil)
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(newSender.close)
				t.Cleanup(newReceiver.close)
				s.startReader(newReceiver)
				if e := newSender.write([]byte("new-generation")); e != nil {
					t.Fatal(e)
				}
				select {
				case p := <-s.incoming:
					if p.c != newReceiver || p.c.generation != 2 || !bytes.Equal(p.wire, []byte("new-generation")) {
						t.Fatal("new generation received old or incorrect record")
					}
				case <-time.After(time.Second):
					t.Fatal("new-generation reader did not admit record")
				}
			}
		})
	}
}

func TestTransportTCPReadErrorAdmissionExitsOnCancelOrClose(t *testing.T) {
	for _, mode := range []string{"session-cancel", "carrier-close"} {
		t.Run(mode, func(t *testing.T) {
			left, right := transportTCPPair(t)
			watch := &transportReadWatchConn{Conn: right, readAgain: make(chan struct{})}
			c, e := makeCarrier("tcp", 1, make([]byte, 16), &security.TransportKeys{}, watch, nil, nil)
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(c.close)
			s := transportPassiveSession(t, 1)
			s.incoming <- packet{c: c, wire: []byte("occupied")}
			done := make(chan struct{})
			go func() { s.readCarrier(c); close(done) }()
			select {
			case <-watch.readAgain:
			case <-time.After(time.Second):
				t.Fatal("reader did not enter socket Read")
			}
			left.Close()
			select {
			case <-done:
				t.Fatal("read error was silently dropped before cancellation/close")
			case <-time.After(30 * time.Millisecond):
			}
			if mode == "session-cancel" {
				s.cancel()
			} else {
				c.close()
			}
			select {
			case <-done:
			case <-time.After(200 * time.Millisecond):
				t.Fatal("read error admission waited for held actor after cancellation/close")
			}
		})
	}
}
