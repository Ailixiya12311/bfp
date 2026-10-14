package packet

import (
	"bfp/classification"
	"bfp/protocol"
	"bfp/security"
	"bfp/session"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Every transport test uses real authenticated BFP carriers and real UDP
// targets. The backend barrier is cooperative and watches its actual context.
type packetBackend struct {
	mu                                 sync.Mutex
	aliases                            map[string]string
	failTargets                        map[string]bool
	started                            chan struct{}
	release                            chan struct{}
	attempts, dials, cancelled, closed atomic.Int32
}

func (b *packetBackend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	b.attempts.Add(1)
	select {
	case b.started <- struct{}{}:
	default:
	}
	if b.release != nil {
		select {
		case <-ctx.Done():
			b.cancelled.Add(1)
			return nil, ctx.Err()
		case <-b.release:
		}
	}
	b.mu.Lock()
	if b.failTargets[address] {
		b.mu.Unlock()
		return nil, errors.New("packet fixture: target backend rejection")
	}
	if real := b.aliases[address]; real != "" {
		address = real
	}
	b.mu.Unlock()
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	b.dials.Add(1)
	return &packetTargetConn{Conn: conn, backend: b}, nil
}

type packetTargetConn struct {
	net.Conn
	backend *packetBackend
	once    sync.Once
}

func (c *packetTargetConn) Close() error {
	var err error
	c.once.Do(func() { c.backend.closed.Add(1); err = c.Conn.Close() })
	return err
}

type packetFaultSocket struct {
	net.PacketConn
	blackhole *atomic.Bool
}

func (c *packetFaultSocket) WriteTo(b []byte, a net.Addr) (int, error) {
	if c.blackhole.Load() {
		return len(b), nil
	}
	return c.PacketConn.WriteTo(b, a)
}
func (c *packetFaultSocket) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, a, err := c.PacketConn.ReadFrom(b)
		if err != nil || !c.blackhole.Load() {
			return n, a, err
		}
	}
}

type packetFixture struct {
	client             *session.Client
	server             *session.Server
	owner              *session.Session
	backend            *packetBackend
	blackhole          atomic.Bool
	udpDials, tcpDials atomic.Int32
}

func packetWait(t *testing.T, label string, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
	for !fn() {
		select {
		case <-deadline.C:
			t.Fatalf("timeout: %s", label)
		case <-tick.C:
		}
	}
}

func newPacketFixture(t *testing.T, initialBlocked, held bool, policy ...classification.Config) *packetFixture {
	t.Helper()
	clientKey, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	admission := make([]byte, 32)
	if _, err = rand.Read(admission); err != nil {
		t.Fatal(err)
	}
	b := &packetBackend{started: make(chan struct{}, 256)}
	if held {
		b.release = make(chan struct{})
	}
	f := &packetFixture{backend: b}
	f.blackhole.Store(initialBlocked)
	opts := session.Options{HandshakeTimeout: 350 * time.Millisecond, ProbeInterval: 100 * time.Millisecond, FailureTimeout: 5 * time.Second, UDPFailureBudget: 600 * time.Millisecond, RetainTimeout: 5 * time.Second, CloseTimeout: 400 * time.Millisecond, KeyUpdateBytes: 1 << 30, KeyUpdateInterval: time.Hour}
	f.server, err = session.NewServer(session.ServerConfig{Listen: "127.0.0.1:0", Backend: b, Options: opts, Credentials: session.Credentials{Admission: admission, Private: serverKey.Private, Public: serverKey.Public, AllowedClients: [][]byte{clientKey.Public}}})
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- f.server.Serve(context.Background()) }()
	t.Cleanup(func() {
		if f.client != nil {
			f.client.Abort()
		}
		f.server.Close()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("real server did not join")
		}
	})
	peer, err := net.ResolveUDPAddr("udp", f.server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg := session.ClientConfig{Server: "udp-packet.invalid:443", TCPServer: "tcp-packet.invalid:443", Options: opts, Credentials: session.Credentials{Admission: admission, Private: clientKey.Private, Public: clientKey.Public, ServerPublic: serverKey.Public}}
	if len(policy) != 0 {
		cfg.Classification = &policy[0]
	}
	cfg.DialUDP = func(ctx context.Context, network, address string) (net.PacketConn, *net.UDPAddr, error) {
		if network != "udp" || address != cfg.Server {
			return nil, nil, errors.New("wrong physical UDP hook target")
		}
		f.udpDials.Add(1)
		socket, err := (&net.ListenConfig{}).ListenPacket(ctx, network, "127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}
		return &packetFaultSocket{PacketConn: socket, blackhole: &f.blackhole}, peer, nil
	}
	cfg.DialTCP = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != cfg.TCPServer {
			return nil, errors.New("wrong physical TCP hook target")
		}
		f.tcpDials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, f.server.Addr().String())
	}
	f.client, err = session.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	f.owner, err = f.client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *packetFixture) packet(t *testing.T, cfg Config) *Conn {
	t.Helper()
	p, err := New(context.Background(), f.owner, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error("packet cleanup unconfirmed:", err)
		}
	})
	return p
}

type packetEcho struct {
	socket   net.PacketConn
	received atomic.Int32
	mu       sync.Mutex
	sources  map[string]int
}

func newPacketEcho(t *testing.T) *packetEcho {
	t.Helper()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &packetEcho{socket: socket, sources: make(map[string]int)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, MaxDatagramSize+1)
		for {
			n, from, err := socket.ReadFrom(b)
			if err != nil {
				return
			}
			e.received.Add(1)
			e.mu.Lock()
			e.sources[from.String()]++
			e.mu.Unlock()
			if _, err = socket.WriteTo(b[:n], from); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		socket.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("echo worker did not join")
		}
	})
	return e
}

func packetWrite(t *testing.T, p *Conn, data []byte, a net.Addr) {
	t.Helper()
	n, err := p.WriteTo(data, a)
	if err != nil || n != len(data) {
		t.Fatalf("WriteTo length=%d: n=%d err=%v", len(data), n, err)
	}
}

func packetRead(t *testing.T, p *Conn, data []byte, want net.Addr) {
	t.Helper()
	if err := p.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, MaxDatagramSize+1)
	n, from, err := p.ReadFrom(b)
	if err != nil || from == nil || from.Network() != "udp" || from.String() != want.String() || !bytes.Equal(b[:n], data) {
		t.Fatalf("logical reply: n=%d from=%v err=%v expected bytes=%d addr=%v", n, from, err, len(data), want)
	}
	if err := p.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestPacketNext22TwoTargetsBoundariesAndLogicalAddress(t *testing.T) {
	f := newPacketFixture(t, false, false)
	p := f.packet(t, Config{})
	a, b := newPacketEcho(t), newPacketEcho(t)
	packetWrite(t, p, []byte("first"), a.socket.LocalAddr())
	packetRead(t, p, []byte("first"), a.socket.LocalAddr())
	packetWrite(t, p, []byte("second"), b.socket.LocalAddr())
	packetRead(t, p, []byte("second"), b.socket.LocalAddr())
	packetWrite(t, p, nil, a.socket.LocalAddr())
	packetRead(t, p, nil, a.socket.LocalAddr())
	large := bytes.Repeat([]byte{0x63}, MaxDatagramSize)
	packetWrite(t, p, large, b.socket.LocalAddr())
	packetRead(t, p, large, b.socket.LocalAddr())
	before := p.Stats()
	if n, err := p.WriteTo(make([]byte, MaxDatagramSize+1), Addr("127.0.0.1:1")); n != 0 || !errors.Is(err, ErrOversize) {
		t.Fatalf("oversize: n=%d err=%v", n, err)
	}
	if after := p.Stats(); after.Targets != before.Targets || after.BufferedBytes != before.BufferedBytes || f.backend.dials.Load() != 2 {
		t.Fatalf("oversize allocated a target: %+v -> %+v", before, after)
	}
	if p.Owner() != f.owner || f.client.Session() != f.owner || f.udpDials.Load() != 1 || f.tcpDials.Load() != 0 {
		t.Fatal("business targets did not reuse one owner/carrier")
	}
	// A short application buffer consumes exactly one whole queued datagram.
	packetWrite(t, p, []byte("truncate"), a.socket.LocalAddr())
	p.SetReadDeadline(time.Now().Add(time.Second))
	small := make([]byte, 3)
	n, from, err := p.ReadFrom(small)
	if n != 3 || err != nil || string(small) != "tru" || from.String() != a.socket.LocalAddr().String() {
		t.Fatalf("truncation: %d %v %v", n, from, err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if st := p.Stats(); st.Targets != 0 || st.PendingDials != 0 || st.PendingWrites != 0 || st.BufferedBytes != 0 || st.QueuedDatagrams != 0 {
		t.Fatalf("Close retains adapter resources: %+v", st)
	}
	packetWait(t, "both real target sockets closed", time.Second, func() bool { return f.backend.closed.Load() == 2 })
}

func TestPacketNext22ConcurrentFirstDialIsDeduplicated(t *testing.T) {
	f := newPacketFixture(t, false, true)
	p := f.packet(t, Config{})
	e := newPacketEcho(t)
	const count = 8
	start := make(chan struct{})
	done := make(chan error, count)
	for i := 0; i < count; i++ {
		go func(i int) {
			<-start
			data := []byte(fmt.Sprintf("message-%d", i))
			n, err := p.WriteTo(data, e.socket.LocalAddr())
			if err == nil && n != len(data) {
				err = errors.New("short write")
			}
			done <- err
		}(i)
	}
	close(start)
	packetWait(t, "eight writes share the pending real target dial", time.Second, func() bool { return p.Stats().PendingWrites == count && f.backend.attempts.Load() == 1 })
	close(f.backend.release)
	for i := 0; i < count; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("deduplicated writes did not finish")
		}
	}
	seen := make(map[string]bool)
	p.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < count; i++ {
		buf := make([]byte, 100)
		n, from, err := p.ReadFrom(buf)
		if err != nil || from.String() != e.socket.LocalAddr().String() {
			t.Fatalf("concurrent reply: %v %v", from, err)
		}
		key := string(buf[:n])
		if seen[key] {
			t.Fatal("duplicate/replayed message", key)
		}
		seen[key] = true
	}
	if len(seen) != count || f.backend.dials.Load() != 1 || f.backend.attempts.Load() != 1 || e.received.Load() != count {
		t.Fatalf("dedup: messages=%d dials=%d attempts=%d received=%d", len(seen), f.backend.dials.Load(), f.backend.attempts.Load(), e.received.Load())
	}
}

func TestPacketNext22MetadataCopyAndDomainAddress(t *testing.T) {
	f := newPacketFixture(t, false, false)
	e := newPacketEcho(t)
	hint := classification.ClassHint{Class: protocol.Interactive, Trusted: true, Locked: true}
	p := f.packet(t, Config{Metadata: classification.Metadata{Hint: &hint, DomainTrusted: true}})
	hint.Class = protocol.Bulk
	hint.Trusted = false
	_, port, _ := net.SplitHostPort(e.socket.LocalAddr().String())
	logical := Addr(net.JoinHostPort("packet-local.test", port))
	// Deterministic local fixture mapping: no DNS requests, IPv4/IPv6 resolver
	// preference, external host, or protocol production resolver alteration.
	f.backend.mu.Lock()
	f.backend.aliases = map[string]string{logical.String(): e.socket.LocalAddr().String()}
	f.backend.mu.Unlock()
	packetWrite(t, p, []byte("domain"), Addr(net.JoinHostPort("PACKET-LOCAL.TEST.", port)))
	packetRead(t, p, []byte("domain"), logical)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	classes, err := f.owner.FlowClassifications(ctx)
	if err != nil || len(classes) != 1 || classes[0].LocalTX.Class != protocol.Interactive || !classes[0].LocalTX.Baseline.Locked || classes[0].LocalTX.Baseline.Source != classification.SourceHint {
		t.Fatalf("metadata was not snapshotted: %+v err=%v", classes, err)
	}
}

func TestPacketNext22DomainClassificationFollowsEachTarget(t *testing.T) {
	policy := classification.DefaultConfig()
	policy.Rules = []classification.Rule{{Name: "actual", Domain: "packet-local.test", Class: protocol.Bulk, Locked: true}, {Name: "configured-wrong", Domain: "wrong.test", Class: protocol.Interactive, Locked: true}}
	f := newPacketFixture(t, false, false, policy)
	a, b := newPacketEcho(t), newPacketEcho(t)
	_, port, _ := net.SplitHostPort(a.socket.LocalAddr().String())
	logical := Addr(net.JoinHostPort("packet-local.test", port))
	f.backend.mu.Lock()
	f.backend.aliases = map[string]string{logical.String(): a.socket.LocalAddr().String()}
	f.backend.mu.Unlock()
	p := f.packet(t, Config{Metadata: classification.Metadata{Target: protocol.Target{Domain: "wrong.test"}, DomainTrusted: true}})
	packetWrite(t, p, []byte("domain"), logical)
	packetRead(t, p, []byte("domain"), logical)
	packetWrite(t, p, []byte("numeric"), b.socket.LocalAddr())
	packetRead(t, p, []byte("numeric"), b.socket.LocalAddr())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	views, err := f.owner.FlowClassifications(ctx)
	if err != nil || len(views) != 2 || views[0].LocalTX.Class != protocol.Bulk || views[0].LocalTX.Baseline.Rule != "actual" || views[1].LocalTX.Class != protocol.Normal || views[1].LocalTX.Baseline.Source != classification.SourceDefault {
		t.Fatalf("target metadata reused wrong configured domain: %+v err=%v", views, err)
	}
}

func TestPacketNext22InitialUDPBlockedFallsBackToTCP(t *testing.T) {
	f := newPacketFixture(t, true, false)
	p := f.packet(t, Config{})
	e := newPacketEcho(t)
	packetWrite(t, p, []byte("fallback"), e.socket.LocalAddr())
	packetRead(t, p, []byte("fallback"), e.socket.LocalAddr())
	if f.owner.Stats().Carrier != "tcp" || f.udpDials.Load() != 1 || f.tcpDials.Load() != 1 || f.backend.dials.Load() != 1 || p.Owner() != f.owner {
		t.Fatalf("initial fallback replaced owner or bypassed hooks: %+v", f.owner.Stats())
	}
}

func TestPacketNext22RuntimeSwitchKeepsOwnerTargetsAndNoReplay(t *testing.T) {
	f := newPacketFixture(t, false, false)
	p := f.packet(t, Config{})
	a, b := newPacketEcho(t), newPacketEcho(t)
	for _, e := range []*packetEcho{a, b} {
		packetWrite(t, p, []byte("before"), e.socket.LocalAddr())
		packetRead(t, p, []byte("before"), e.socket.LocalAddr())
	}
	before := f.owner.Stats()
	f.blackhole.Store(true)
	packetWait(t, "real UDP blackhole recovers same owner to TCP", 5*time.Second, func() bool { st := f.owner.Stats(); return st.Carrier == "tcp" && st.Generation > before.Generation })
	for _, e := range []*packetEcho{a, b} {
		packetWrite(t, p, []byte("after"), e.socket.LocalAddr())
		packetRead(t, p, []byte("after"), e.socket.LocalAddr())
	}
	after := f.owner.Stats()
	if p.Owner() != f.owner || f.client.Session() != f.owner || after.ID != before.ID || after.Generation != before.Generation+1 || after.Switches != 1 || f.backend.dials.Load() != 2 || f.udpDials.Load() != 1 || f.tcpDials.Load() != 1 {
		t.Fatalf("switch identity: before=%+v after=%+v target dials=%d", before, after, f.backend.dials.Load())
	}
	for _, e := range []*packetEcho{a, b} {
		e.mu.Lock()
		sources := len(e.sources)
		e.mu.Unlock()
		if e.received.Load() != 2 || sources != 1 {
			t.Fatalf("target socket replaced or data replayed: received=%d sources=%d", e.received.Load(), sources)
		}
	}
}

func TestPacketNext22OwnerEndFailsClosedIncludingIdleAdapter(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprintf("active-%v", active), func(t *testing.T) {
			f := newPacketFixture(t, false, false)
			p := f.packet(t, Config{})
			e := newPacketEcho(t)
			if active {
				packetWrite(t, p, []byte("old"), e.socket.LocalAddr())
				packetRead(t, p, []byte("old"), e.socket.LocalAddr())
			}
			if err := f.owner.Close(); err != nil {
				t.Fatal("normal authenticated owner close", err)
			}
			if _, err := p.WriteTo([]byte("forbidden"), e.socket.LocalAddr()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("old owner write: %v", err)
			}
			if _, _, err := p.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("old owner read: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			fresh, err := f.client.Connect(ctx)
			cancel()
			if err != nil || fresh == f.owner {
				t.Fatalf("explicit fresh Connect: fresh=%p old=%p err=%v", fresh, f.owner, err)
			}
			dials := f.backend.dials.Load()
			hooks := f.udpDials.Load()
			if _, err = p.WriteTo([]byte("still-forbidden"), e.socket.LocalAddr()); !errors.Is(err, net.ErrClosed) || p.Owner() != f.owner || f.backend.dials.Load() != dials || f.udpDials.Load() != hooks {
				t.Fatal("old PacketConn silently joined fresh owner")
			}
		})
	}
}

func TestPacketNext22BoundsHeldDialAndExpiredWrite(t *testing.T) {
	for _, kind := range []string{"writes", "targets", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			f := newPacketFixture(t, false, true)
			cfg := Config{MaxTargets: 2, MaxPendingWrites: 2}
			if kind == "writes" {
				cfg.MaxPendingWrites = 1
			}
			if kind == "targets" {
				cfg.MaxTargets = 1
			}
			if kind == "bytes" {
				cfg.MaxBufferedBytes = targetReservation + itemOverhead + 1
			}
			p := f.packet(t, cfg)
			a, b := newPacketEcho(t), newPacketEcho(t)
			result := make(chan error, 1)
			go func() { _, err := p.WriteTo([]byte{1}, a.socket.LocalAddr()); result <- err }()
			packetWait(t, "held actual target dial", time.Second, func() bool { return p.Stats().PendingWrites == 1 && f.backend.attempts.Load() == 1 })
			if _, err := p.WriteTo([]byte{2}, b.socket.LocalAddr()); !errors.Is(err, ErrLimit) {
				t.Fatalf("%s bound: %v", kind, err)
			}
			if st := p.Stats(); st.PendingWrites != 1 || st.Targets != 1 || st.PendingDials != 1 || st.BufferedBytes > p.cfg.MaxBufferedBytes {
				t.Fatalf("limit side effects: %+v", st)
			}
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if !errors.Is(err, net.ErrClosed) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("Close did not cancel pending write")
			}
			packetWait(t, "real cooperative target dial cancelled", time.Second, func() bool { return f.backend.cancelled.Load() == 1 })
			if f.backend.dials.Load() != 0 || p.Stats().BufferedBytes != 0 {
				t.Fatal("late target install or retained buffer")
			}
		})
	}
	// Entry expiry is checked before target allocation, independent of the timer.
	f := newPacketFixture(t, false, false)
	p := f.packet(t, Config{})
	p.SetWriteDeadline(time.Now().Add(-time.Second))
	if n, err := p.WriteTo(nil, Addr("127.0.0.1:1")); n != 0 || !errors.Is(err, context.DeadlineExceeded) || p.Stats().Targets != 0 || f.backend.attempts.Load() != 0 {
		t.Fatalf("expired entry allocated target: n=%d err=%v stats=%+v", n, err, p.Stats())
	}
}

func TestPacketNext22ReceiveQueueAndByteBudgetDrop(t *testing.T) {
	for _, kind := range []string{"items", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			f := newPacketFixture(t, false, false)
			cfg := Config{MaxReceiveQueue: 1}
			if kind == "bytes" {
				cfg.MaxReceiveQueue = 4
				cfg.MaxBufferedBytes = targetReservation + 2*itemOverhead + 2
			}
			p := f.packet(t, cfg)
			e := newPacketEcho(t)
			packetWrite(t, p, []byte{1}, e.socket.LocalAddr())
			packetWait(t, "first reply retained", time.Second, func() bool { return p.Stats().QueuedDatagrams == 1 })
			if kind == "bytes" {
				// Free the one write reservation by consuming the first reply, then
				// use a real target-originated burst while no writes reserve bytes.
				packetRead(t, p, []byte{1}, e.socket.LocalAddr())
				e.mu.Lock()
				var source string
				for source = range e.sources {
					break
				}
				e.mu.Unlock()
				to, err := net.ResolveUDPAddr("udp", source)
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 3; i++ {
					if _, err = e.socket.WriteTo(bytes.Repeat([]byte{3}, 130), to); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				packetWrite(t, p, []byte{2}, e.socket.LocalAddr())
			}
			packetWait(t, "bounded receive burst dropped", time.Second, func() bool { return p.Stats().Dropped > 0 })
			st := p.Stats()
			if st.QueuedDatagrams != 1 || st.BufferedBytes > p.cfg.MaxBufferedBytes {
				t.Fatalf("receive bound: %+v", st)
			}
			if kind == "items" {
				packetRead(t, p, []byte{1}, e.socket.LocalAddr())
			} else {
				packetRead(t, p, bytes.Repeat([]byte{3}, 130), e.socket.LocalAddr())
			}
			if p.Stats().QueuedDatagrams != 0 {
				t.Fatal("queue did not drain")
			}
		})
	}
}

func TestPacketNext22ReadDeadlineWakeExtendClearAndClose(t *testing.T) {
	f := newPacketFixture(t, false, false)
	p := f.packet(t, Config{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { _, _, err := p.ReadFrom(make([]byte, 1)); results <- err }()
	}
	packetWait(t, "two blocked readers", time.Second, func() bool { return p.Stats().PendingReads == 2 })
	p.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	p.SetReadDeadline(time.Now().Add(350 * time.Millisecond))
	select {
	case err := <-results:
		t.Fatal("extended read deadline used the old cutoff", err)
	case <-time.After(180 * time.Millisecond):
	}
	p.SetReadDeadline(time.Time{})
	select {
	case err := <-results:
		t.Fatal("cleared read deadline returned", err)
	case <-time.After(200 * time.Millisecond):
	}
	p.SetReadDeadline(time.Now().Add(-time.Millisecond))
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("short deadline did not wake every reader")
		}
	}
	p.SetReadDeadline(time.Time{})
	go func() { _, _, err := p.ReadFrom(nil); results <- err }()
	packetWait(t, "blocked reader before Close", time.Second, func() bool { return p.Stats().PendingReads == 1 })
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-results:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not wake ReadFrom")
	}
	if err := p.Close(); err != nil {
		t.Fatal("repeated Close", err)
	}
}

func TestPacketNext22WriteCutoffCannotBeRenewed(t *testing.T) {
	f := newPacketFixture(t, false, true)
	p := f.packet(t, Config{})
	e := newPacketEcho(t)
	result := make(chan error, 1)
	go func() { _, err := p.WriteTo([]byte("must-not-send"), e.socket.LocalAddr()); result <- err }()
	packetWait(t, "write waits on real target dial", time.Second, func() bool { return p.Stats().PendingWrites == 1 && f.backend.attempts.Load() == 1 })
	p.SetWriteDeadline(time.Now().Add(60 * time.Millisecond))
	p.SetWriteDeadline(time.Now().Add(time.Second))
	p.SetWriteDeadline(time.Time{})
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("pending write renewed its shortened budget")
	}
	close(f.backend.release)
	packetWait(t, "shared target completes without expired payload", time.Second, func() bool { return p.Stats().PendingDials == 0 })
	if e.received.Load() != 0 || p.Stats().PendingWrites != 0 {
		t.Fatal("expired write was replayed or retained")
	}
	packetWrite(t, p, []byte("explicit-new"), e.socket.LocalAddr())
	packetRead(t, p, []byte("explicit-new"), e.socket.LocalAddr())
	if e.received.Load() != 1 || f.backend.dials.Load() != 1 {
		t.Fatal("future write deadline clear did not reuse existing target")
	}
}

func TestPacketNext22IdleRetiresAndOnlyExplicitWriteReopens(t *testing.T) {
	f := newPacketFixture(t, false, false)
	p := f.packet(t, Config{IdleTimeout: 80 * time.Millisecond})
	e := newPacketEcho(t)
	packetWrite(t, p, []byte("first"), e.socket.LocalAddr())
	packetRead(t, p, []byte("first"), e.socket.LocalAddr())
	packetWait(t, "idle target/socket/scratch retired", time.Second, func() bool {
		st := p.Stats()
		return st.Targets == 0 && st.BufferedBytes == 0 && f.backend.closed.Load() == 1
	})
	if e.received.Load() != 1 || f.backend.dials.Load() != 1 {
		t.Fatal("idle expiration replayed or redialed automatically")
	}
	packetWrite(t, p, []byte("new"), e.socket.LocalAddr())
	packetRead(t, p, []byte("new"), e.socket.LocalAddr())
	if f.backend.dials.Load() != 2 || p.Owner() != f.owner || e.received.Load() != 2 {
		t.Fatal("explicit later write did not open only a new target under same owner")
	}
}

func TestPacketNext22AddressValidationAndImmutableUDPAddr(t *testing.T) {
	for _, a := range []net.Addr{nil, Addr("127.0.0.1:0"), Addr("host:65536"), Addr("bad host:1"), Addr("[127.0.0.1%zone]:1"), Addr("[fe80::1%bad zone]:53"), Addr("[fe80::1%接口]:53"), Addr("[fe80::1%" + string(bytes.Repeat([]byte{'z'}, 65)) + "]:53"), Addr("[fe80::1%" + string(bytes.Repeat([]byte{'z'}, 1000)) + "]:53"), Addr("x/y:1"), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}} {
		if _, _, err := normalize(a); !errors.Is(err, ErrAddress) {
			t.Fatalf("invalid address accepted: %v %v", a, err)
		}
	}
	if a, d, err := normalize(Addr("[fe80::1%eth0]:53")); err != nil || a.String() != "[fe80::1%eth0]:53" || d != "" {
		t.Fatalf("zone: %v %q %v", a, d, err)
	}
	maxZone := Addr("[fe80::1%" + string(bytes.Repeat([]byte{'z'}, 64)) + "]:53")
	if a, d, err := normalize(maxZone); err != nil || a != maxZone || d != "" {
		t.Fatalf("64 byte zone boundary: %v %q %v", a, d, err)
	}
	f := newPacketFixture(t, false, false)
	p := f.packet(t, Config{})
	e := newPacketEcho(t)
	ip := append(net.IP(nil), e.socket.LocalAddr().(*net.UDPAddr).IP...)
	dest := &net.UDPAddr{IP: ip, Port: e.socket.LocalAddr().(*net.UDPAddr).Port}
	packetWrite(t, p, []byte("immutable"), dest)
	for i := range dest.IP {
		dest.IP[i] = 0
	}
	packetRead(t, p, []byte("immutable"), e.socket.LocalAddr())
}

func TestPacketNext22ContextCancellationAndBorrowedOwner(t *testing.T) {
	f := newPacketFixture(t, false, false)
	e := newPacketEcho(t)
	ctx, cancel := context.WithCancel(context.Background())
	p, err := Connect(ctx, f.client, Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	packetWrite(t, p, []byte("context"), e.socket.LocalAddr())
	packetRead(t, p, []byte("context"), e.socket.LocalAddr())
	cancel()
	if _, err = p.WriteTo([]byte("cancelled"), e.socket.LocalAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("cancelled adapter write: %v", err)
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.owner.BusinessDone():
		t.Fatal("borrowed owner closed with adapter")
	default:
	}
	other := f.packet(t, Config{})
	packetWrite(t, other, []byte("same-owner"), e.socket.LocalAddr())
	packetRead(t, other, []byte("same-owner"), e.socket.LocalAddr())
	if other.Owner() != p.Owner() || f.udpDials.Load() != 1 || f.backend.dials.Load() != 2 {
		t.Fatal("adapter context retirement replaced shared owner")
	}
}

func TestPacketNext22TerminalDialHasNoImplicitRetry(t *testing.T) {
	f := newPacketFixture(t, false, false)
	p := f.packet(t, Config{})
	// Observe an actual remote OPEN/backend rejection before any target
	// socket or system resolver is called. The logical target is numeric.
	bad := Addr("127.0.0.1:1")
	f.backend.mu.Lock()
	f.backend.failTargets = map[string]bool{bad.String(): true}
	f.backend.mu.Unlock()
	_, first := p.WriteTo([]byte("first"), bad)
	if first == nil || f.backend.attempts.Load() != 1 || f.backend.dials.Load() != 0 {
		t.Fatal("remote backend rejection was not observed once")
	}
	st := p.Stats()
	attempts := f.backend.attempts.Load()
	_, second := p.WriteTo([]byte("second"), bad)
	if second == nil || p.Stats().Targets != st.Targets || f.backend.attempts.Load() != attempts || p.Stats().BufferedBytes != 0 {
		t.Fatalf("terminal association implicitly retried: first=%v second=%v stats=%+v", first, second, p.Stats())
	}
}

func TestPacketNext22CloseWithConcurrentIdleDeadlineUpdates(t *testing.T) {
	f := newPacketFixture(t, false, false)
	e := newPacketEcho(t)
	for round := 0; round < 8; round++ {
		p := f.packet(t, Config{IdleTimeout: time.Hour})
		packetWrite(t, p, []byte("start"), e.socket.LocalAddr())
		packetRead(t, p, []byte("start"), e.socket.LocalAddr())
		start := make(chan struct{})
		writeDone := make(chan error, 1)
		closeDone := make(chan error, 1)
		go func() { <-start; _, err := p.WriteTo([]byte("race"), e.socket.LocalAddr()); writeDone <- err }()
		go func() { <-start; closeDone <- p.Close() }()
		close(start)
		select {
		case err := <-closeDone:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("Close idle deadline was overwritten and real Flow.Read did not join")
		}
		select {
		case err := <-writeDone:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent writer did not join")
		}
		if st := p.Stats(); st.BufferedBytes != 0 || st.PendingDials != 0 || st.PendingWrites != 0 || st.Targets != 0 {
			t.Fatalf("closed round %d retains resources: %+v", round, st)
		}
	}
}
