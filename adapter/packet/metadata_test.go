package packet

import (
	"bfp/classification"
	"bfp/protocol"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestPacketNext23RestoredDomainOnlyDescribesExactNumericTarget(t *testing.T) {
	policy := classification.DefaultConfig()
	policy.Rules = []classification.Rule{{Name: "restored", Domain: "restored.packet.test", Class: protocol.Bulk, Locked: true}}
	f := newPacketFixture(t, false, false, policy)
	a, b := newPacketEcho(t), newPacketEcho(t)
	var calls atomic.Int32
	p := f.packet(t, Config{Metadata: classification.Metadata{Target: protocol.Target{Domain: "wrong.test"}, DomainTrusted: true},
		MetadataForTarget: func(ctx context.Context, address Addr, base classification.Metadata) (classification.Metadata, error) {
			calls.Add(1)
			if base.Target.Network != "udp" || base.Target.Address != address.String() || base.Target.Domain != "" {
				return classification.Metadata{}, errors.New("hook received stale target metadata")
			}
			if address.String() == a.socket.LocalAddr().String() {
				base.Target.Domain, base.DomainTrusted = "restored.packet.test", true
			}
			return base, ctx.Err()
		}})
	packetWrite(t, p, []byte("first"), a.socket.LocalAddr())
	packetRead(t, p, []byte("first"), a.socket.LocalAddr())
	packetWrite(t, p, []byte("second"), b.socket.LocalAddr())
	packetRead(t, p, []byte("second"), b.socket.LocalAddr())
	packetWrite(t, p, []byte("same"), a.socket.LocalAddr())
	packetRead(t, p, []byte("same"), a.socket.LocalAddr())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	views, err := f.owner.FlowClassifications(ctx)
	if err != nil || len(views) != 2 || views[0].LocalTX.Class != protocol.Bulk || views[0].LocalTX.Baseline.Rule != "restored" || views[1].LocalTX.Class != protocol.Normal || calls.Load() != 2 || f.backend.dials.Load() != 2 {
		t.Fatalf("exact target/domain isolation: views=%+v calls=%d dials=%d err=%v", views, calls.Load(), f.backend.dials.Load(), err)
	}
}

func TestPacketNext23MetadataCannotRedirectNetworkOrAddress(t *testing.T) {
	for _, redirect := range []string{"network", "address"} {
		t.Run(redirect, func(t *testing.T) {
			f := newPacketFixture(t, false, false)
			e := newPacketEcho(t)
			var calls atomic.Int32
			p := f.packet(t, Config{MetadataForTarget: func(ctx context.Context, address Addr, base classification.Metadata) (classification.Metadata, error) {
				calls.Add(1)
				if redirect == "network" {
					base.Target.Network = "tcp"
				} else {
					base.Target.Address = "127.0.0.1:1"
				}
				return base, nil
			}})
			for i := 0; i < 2; i++ {
				if n, err := p.WriteTo([]byte("reject"), e.socket.LocalAddr()); n != 0 || !errors.Is(err, classification.ErrMetadata) {
					t.Fatalf("redirect accepted n=%d err=%v", n, err)
				}
			}
			if calls.Load() != 1 || f.backend.dials.Load() != 0 {
				t.Fatal("rejected metadata dialed or silently retried")
			}
		})
	}
}

func TestPacketNext23MetadataCancellationJoinsOwnedWorker(t *testing.T) {
	f := newPacketFixture(t, false, false)
	e := newPacketEcho(t)
	entered := make(chan struct{})
	finished := make(chan struct{})
	p := f.packet(t, Config{MetadataForTarget: func(ctx context.Context, address Addr, base classification.Metadata) (classification.Metadata, error) {
		close(entered)
		defer close(finished)
		<-ctx.Done()
		return base, ctx.Err()
	}})
	written := make(chan error, 1)
	go func() { _, err := p.WriteTo([]byte("cancel"), e.socket.LocalAddr()); written <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("metadata hook did not start")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("Close returned before owned metadata callback joined")
	}
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("canceled write admitted")
		}
	case <-time.After(time.Second):
		t.Fatal("write caller did not return")
	}
	if f.backend.dials.Load() != 0 || p.Stats().Targets != 0 {
		t.Fatal("canceled metadata created target resources")
	}
}
