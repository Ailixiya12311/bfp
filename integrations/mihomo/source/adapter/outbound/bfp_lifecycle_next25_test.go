package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"bfp/adapter/packet"
	"bfp/classification"
	C "github.com/metacubex/mihomo/constant"
)

func lifecycleMetadata(ip string, port uint16) *C.Metadata {
	return &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr(ip), DstPort: port}
}

func newLifecycleConn() *bfpPacketConn {
	return &bfpPacketConn{destinations: make(map[packet.Addr]bfpUDPDestination), preparations: make(map[*bfpUDPPreparation]struct{})}
}

func TestBFPNext25OriginValidityIsPartOfMappingIdentity(t *testing.T) {
	meta := lifecycleMetadata("203.0.113.10", 5353)
	valid := netip.MustParseAddrPort("192.0.2.10:41000")
	for _, tc := range []struct {
		name          string
		first, second netip.AddrPort
	}{
		{"invalid_then_valid", netip.AddrPort{}, valid},
		{"valid_then_invalid", valid, netip.AddrPort{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newLifecycleConn()
			if _, err := c.prepareMetadata(context.Background(), meta, tc.first); err != nil {
				t.Fatal(err)
			}
			if _, err := c.prepareMetadata(context.Background(), meta, tc.second); !errors.Is(err, packet.ErrAddress) {
				t.Fatalf("origin switch was accepted: %v", err)
			}
		})
	}
}

func TestBFPNext25AbortBeforeWriteReleasesEveryReservation(t *testing.T) {
	c := newLifecycleConn()
	for i := 0; i < 40; i++ {
		meta := lifecycleMetadata("203.0.113.11", uint16(10000+i))
		preparation, err := c.prepareMetadata(context.Background(), meta, netip.AddrPort{})
		if err != nil {
			t.Fatalf("Prepare %d: %v", i, err)
		}
		if err = c.commitMetadata(preparation); !errors.Is(err, packet.ErrTargetClosed) {
			t.Fatalf("Commit without a write succeeded: %v", err)
		}
		c.abortMetadata(preparation)
		c.abortMetadata(preparation)
		if len(c.destinations) != 0 || len(c.preparations) != 0 {
			t.Fatalf("Abort %d leaked map capacity", i)
		}
	}
}

func TestBFPNext25CanceledPrepareAutomaticallyReleasesReservation(t *testing.T) {
	c := newLifecycleConn()
	for round := 0; round < 40; round++ {
		ctx, cancel := context.WithCancel(context.Background())
		prepared, err := c.prepareMetadata(ctx, lifecycleMetadata("203.0.113.15", uint16(10000+round)), netip.AddrPort{})
		if err != nil {
			t.Fatal("Prepare without explicit Abort exhausted capacity", err)
		}
		cancel()
		select {
		case <-prepared.(*bfpUDPPreparation).done:
		case <-time.After(time.Second):
			t.Fatal("canceled preparation was not auto-aborted")
		}
		c.destMu.Lock()
		remaining, pending := len(c.destinations), len(c.preparations)
		c.destMu.Unlock()
		if remaining != 0 || pending != 0 {
			t.Fatal("automatic Abort leaked a destination/reservation")
		}
	}
}

type lifecycleForeignAddr struct{}

func (lifecycleForeignAddr) Network() string { return "tcp" }
func (lifecycleForeignAddr) String() string  { return "203.0.113.20:53" }

func TestBFPNext25RejectsForeignAndNilUDPAddresses(t *testing.T) {
	c := newLifecycleConn()
	var typedNil *net.UDPAddr
	for _, address := range []net.Addr{nil, typedNil, lifecycleForeignAddr{}} {
		if _, err := c.WriteTo([]byte("reject"), address); !errors.Is(err, packet.ErrAddress) {
			t.Fatalf("WriteTo accepted %T: %v", address, err)
		}
		if _, err := c.restoreSource(address); !errors.Is(err, packet.ErrAddress) {
			t.Fatalf("restore accepted %T: %v", address, err)
		}
		if err := c.commitMetadata(address); !errors.Is(err, packet.ErrAddress) {
			t.Fatalf("commit accepted %T: %v", address, err)
		}
	}
}

func TestBFPNext25RealTargetGenerationRetirementAndCapacity(t *testing.T) {
	path, credentials := bfpPrivateFixture(t)
	f := bfpStartNativeFixture(t, credentials)
	bfpFixtureEndpoint(t, path, f.server.Addr().String())
	h, err := NewBFP(BFPOption{Name: "next25-lifecycle", ClientConfigFile: path, UDP: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	owner, err := h.client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c := newLifecycleConn()
	var blockMetadata atomic.Bool
	entered := make(chan struct{})
	c.Conn, err = packet.New(h.ctx, owner, packet.Config{MetadataForTargetToken: func(ctx context.Context, target packet.TargetToken, base classification.Metadata) (classification.Metadata, error) {
		if blockMetadata.Load() {
			close(entered)
			<-ctx.Done()
			return base, ctx.Err()
		}
		return c.metadataForTarget(ctx, target, base)
	}, TargetRetired: c.targetRetired, ExposeTargetToken: true, IdleTimeout: 100 * time.Millisecond, CleanupTimeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Conn.Close(); err != nil {
			t.Error(err)
		}
	})
	host, portText, _ := net.SplitHostPort(f.udp[0])
	port, _ := strconv.ParseUint(portText, 10, 16)
	meta := lifecycleMetadata(host, uint16(port))
	// Cancel after the packet layer created a pending target but before the
	// metadata hook publishes its token. Abort must find and join this exact
	// pending generation rather than leave it alive behind an absent map.
	blockMetadata.Store(true)
	packetCtx, packetCancel := context.WithCancel(ctx)
	pendingPreparation, err := c.prepareMetadata(packetCtx, meta, netip.MustParseAddrPort("192.0.2.30:39999"))
	if err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() { _, err := c.WriteTo([]byte("pending-cancel"), pendingPreparation); written <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("real pending metadata hook did not start")
	}
	packetCancel()
	select {
	case err := <-written:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("packet context cancellation lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled actual write did not return")
	}
	c.abortMetadata(pendingPreparation)
	if c.Conn.Stats().Targets != 0 || c.Conn.Stats().PendingDials != 0 || len(c.destinations) != 0 || len(c.preparations) != 0 {
		t.Fatal("Abort failed to join an unpublished pending generation")
	}
	blockMetadata.Store(false)
	// Exercise an actual PacketConn admission failure before any target is
	// installed. Prepare/Abort must free capacity even after more than the
	// 16-target map limit has been attempted on this same owner.
	c.Conn.SetWriteDeadline(time.Now().Add(-time.Millisecond))
	for i := 0; i < 40; i++ {
		prepared, err := c.prepareMetadata(ctx, meta, netip.AddrPortFrom(netip.MustParseAddr("192.0.2.30"), uint16(40000+i)))
		if err != nil {
			t.Fatal("failed-write Prepare leaked capacity", err)
		}
		if _, err := c.WriteTo([]byte("must-not-dial"), prepared); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("actual pre-target failure: %v", err)
		}
		c.abortMetadata(prepared)
		c.destMu.Lock()
		remaining, pending := len(c.destinations), len(c.preparations)
		c.destMu.Unlock()
		if remaining != 0 || pending != 0 || c.Conn.Stats().Targets != 0 {
			t.Fatal("actual failed write retained preparation/target")
		}
	}
	if f.backend.udp.Load() != 0 || f.udpReceived.Load() != 0 {
		t.Fatal("failed transaction reached actual target")
	}
	c.Conn.SetWriteDeadline(time.Time{})
	// A real fast reply received after payload write must remain unpublished
	// until Commit. Canceling this transaction before Commit wakes and rejects
	// that exact reply, even though a datagram already reached the UDP socket.
	abortCtx, abortCancel := context.WithCancel(ctx)
	abortPreparation, err := c.prepareMetadata(abortCtx, meta, netip.MustParseAddrPort("192.0.2.30:40999"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteTo([]byte("abort-fast-reply"), abortPreparation); err != nil {
		t.Fatal(err)
	}
	c.Conn.SetReadDeadline(time.Now().Add(time.Second))
	_, unpublished, err := c.ReadFrom(make([]byte, 64))
	if err != nil {
		t.Fatal("real unpublished reply missing", err)
	}
	rejected := make(chan error, 1)
	go func() { _, err := c.restoreSource(unpublished); rejected <- err }()
	select {
	case err := <-rejected:
		t.Fatalf("source was published before Commit: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	abortCancel()
	c.abortMetadata(abortPreparation)
	select {
	case err := <-rejected:
		if err == nil {
			t.Fatal("canceled provisional fast reply was restored")
		}
	case <-time.After(time.Second):
		t.Fatal("Abort did not wake unpublished reply")
	}
	var oldSource net.Addr
	var oldToken packet.TargetToken
	for round := 0; round < 20; round++ {
		origin := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.30"), uint16(41000+round))
		prepared, err := c.prepareMetadata(ctx, meta, origin)
		if err != nil {
			t.Fatalf("Prepare %d: %v", round, err)
		}
		payload := []byte("generation-" + strconv.Itoa(round))
		if n, err := c.WriteTo(payload, prepared); err != nil || n != len(payload) {
			t.Fatalf("actual UDP WriteTo %d: n=%d err=%v", round, n, err)
		}
		if round != 0 {
			if err := c.commitMetadata(prepared); err != nil {
				t.Fatal(err)
			}
		}
		c.Conn.SetReadDeadline(time.Now().Add(time.Second))
		buffer := make([]byte, 64)
		n, from, err := c.ReadFrom(buffer)
		if err != nil || string(buffer[:n]) != string(payload) {
			t.Fatalf("actual UDP reply %d: %v", round, err)
		}
		token, ok := from.(packet.TargetToken)
		if !ok || token.Generation <= oldToken.Generation {
			t.Fatalf("reply did not preserve a fresh generation: %T %+v", from, token)
		}
		if round == 0 {
			result := make(chan error, 1)
			go func() {
				from, err := c.restoreSource(from)
				if err == nil && from.String() != origin.String() {
					err = errors.New("committed fast source differs")
				}
				result <- err
			}()
			select {
			case err := <-result:
				t.Fatalf("fast source was published before Commit: %v", err)
			case <-time.After(10 * time.Millisecond):
			}
			if err := c.commitMetadata(prepared); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatal("Commit did not publish real fast reply", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Commit failed to wake fast reply")
			}
		}
		restored, err := c.restoreSource(from)
		if err != nil || restored.String() != origin.String() {
			t.Fatalf("current source restoration %d: %v", round, err)
		}
		if oldSource != nil {
			if _, err := c.restoreSource(oldSource); !errors.Is(err, packet.ErrTargetClosed) {
				t.Fatalf("old generation rebound to new origin: %v", err)
			}
			if c.Conn.RetireTarget(oldToken) {
				t.Fatal("old token retired new generation")
			}
		}
		oldSource, oldToken = from, token
		limit := time.Now().Add(time.Second)
		for time.Now().Before(limit) {
			c.destMu.Lock()
			remaining := len(c.destinations)
			c.destMu.Unlock()
			if remaining == 0 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		c.destMu.Lock()
		remaining, pending := len(c.destinations), len(c.preparations)
		c.destMu.Unlock()
		if remaining != 0 || pending != 0 || c.Conn.Stats().Targets != 0 {
			t.Fatalf("real retirement retained stale capacity at %d: maps=%d pending=%d targets=%d", round, remaining, pending, c.Conn.Stats().Targets)
		}
	}
	if f.udpReceived.Load() != 21 {
		t.Fatalf("actual UDP target datagrams=%d", f.udpReceived.Load())
	}
}

func TestBFPSessionFakeIPLeaseDiesWithSessionAndFreshSessionGetsNewAddress(t *testing.T) {
	path, credentials := bfpPrivateFixture(t)
	f := bfpStartNativeFixture(t, credentials)
	bfpFixtureEndpoint(t, path, f.server.Addr().String())
	h, err := NewBFP(BFPOption{Name: "session-fake-ip-lifecycle", ClientConfigFile: path, UDP: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	first, err := h.AllocateSessionFakeIP(ctx, "example.test", false)
	if err != nil {
		t.Fatal("allocate first Session address", err)
	}
	v4, v6 := h.SessionFakeIPPrefixes()
	if !v4.Contains(first.Address()) || v6.Contains(first.Address()) {
		t.Fatalf("first address escaped the IPv4 Session pool: %s", first.Address())
	}
	if !h.OwnsSessionFakeIP(first) {
		t.Fatal("BFP did not retain ownership of its Session lease")
	}
	if remaining, err := first.Remaining(ctx); err != nil || remaining <= 0 {
		t.Fatalf("first lease was not live: remaining=%s err=%v", remaining, err)
	}
	old := first.Address()
	if err := h.FlushSessionFakeIP(); err != nil {
		t.Fatal("close first Session", err)
	}
	if _, err := h.LookupSessionFakeIP(ctx, old); err == nil {
		t.Fatal("retired Session address was still discoverable")
	}
	if _, err := first.Remaining(ctx); err == nil {
		t.Fatal("retired lease still validated")
	}

	second, err := h.AllocateSessionFakeIP(ctx, "example.test", false)
	if err != nil {
		t.Fatal("allocate replacement Session address", err)
	}
	if second.Address() == old {
		t.Fatalf("replacement Session reused retired address %s", old)
	}
}

func TestBFPNext25MetadataHookCannotBindAReplacementGeneration(t *testing.T) {
	c := newLifecycleConn()
	meta := lifecycleMetadata("203.0.113.21", 5353)
	prepared, err := c.prepareMetadata(context.Background(), meta, netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	key := prepared.(*bfpUDPPreparation).address
	first := packet.TargetToken{Address: key, Generation: 1}
	base := classification.Metadata{}
	if _, err := c.metadataForTarget(context.Background(), first, base); err != nil {
		t.Fatal(err)
	}
	if _, err := c.metadataForTarget(context.Background(), packet.TargetToken{Address: key, Generation: 2}, base); !errors.Is(err, packet.ErrTargetClosed) {
		t.Fatalf("second generation replaced original metadata: %v", err)
	}
}
