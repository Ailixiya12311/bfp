package packet

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"bfp/classification"
)

func TestPacketNext25GenerationNeverWrapsOrAllocatesOnExhaustion(t *testing.T) {
	f := newPacketFixture(t, false, false)
	p := f.packet(t, Config{})
	p.mu.Lock()
	p.nextGeneration = ^uint64(0)
	p.mu.Unlock()
	if _, err := p.WriteTo([]byte("reject"), Addr("127.0.0.1:1")); !errors.Is(err, ErrLimit) {
		t.Fatalf("generation exhaustion did not fail closed: %v", err)
	}
	if st := p.Stats(); st.Targets != 0 || st.PendingDials != 0 || st.BufferedBytes != 0 || f.backend.attempts.Load() != 0 {
		t.Fatalf("exhaustion allocated a target: %+v", st)
	}
}

func TestPacketNext25TokenOwnerAndGenerationAreRequiredForWrites(t *testing.T) {
	f := newPacketFixture(t, false, false)
	e := newPacketEcho(t)
	retired := make(chan TargetToken, 4)
	p := f.packet(t, Config{ExposeTargetToken: true, TargetRetired: func(token TargetToken) { retired <- token }})
	packetWrite(t, p, []byte("first"), e.socket.LocalAddr())
	p.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 32)
	n, source, err := p.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "first" {
		t.Fatal("real reply missing", err)
	}
	first, ok := source.(TargetToken)
	if !ok || first.Generation == 0 || !p.TargetAlive(first) {
		t.Fatalf("reply is missing its owner token: %T", source)
	}
	foreign := f.packet(t, Config{ExposeTargetToken: true})
	for _, conn := range []*Conn{foreign} {
		if _, err := conn.WriteTo([]byte("reject"), first); !errors.Is(err, ErrTargetClosed) {
			t.Fatalf("foreign token accepted: %v", err)
		}
		if conn.RetireTarget(first) {
			t.Fatal("foreign token retired a target")
		}
	}
	if !p.RetireTarget(first) || p.TargetAlive(first) {
		t.Fatal("explicit retirement did not finish exact generation")
	}
	select {
	case token := <-retired:
		if token != first {
			t.Fatal("wrong retirement token")
		}
	default:
		t.Fatal("retirement callback was not complete before return")
	}
	packetWrite(t, p, []byte("second"), e.socket.LocalAddr())
	n, source, err = p.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "second" {
		t.Fatal("second real reply missing", err)
	}
	second := source.(TargetToken)
	if second.Generation <= first.Generation {
		t.Fatal("new generation reused the old token")
	}
	for _, addr := range []net.Addr{first, &first} {
		if _, err := p.WriteTo([]byte("stale"), addr); !errors.Is(err, ErrTargetClosed) {
			t.Fatalf("stale generation accepted: %v", err)
		}
	}
	if p.RetireTarget(first) || !p.TargetAlive(second) || e.received.Load() != 2 {
		t.Fatal("old token affected the replacement generation")
	}
}

func TestPacketNext25RetirementCallbackPanicIsContained(t *testing.T) {
	f := newPacketFixture(t, false, false)
	e := newPacketEcho(t)
	p, err := New(context.Background(), f.owner, Config{ExposeTargetToken: true, TargetRetired: func(TargetToken) { panic("synthetic local callback fault") }})
	if err != nil {
		t.Fatal(err)
	}
	packetWrite(t, p, []byte("callback"), e.socket.LocalAddr())
	p.SetReadDeadline(time.Now().Add(time.Second))
	_, source, err := p.ReadFrom(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if !p.RetireTarget(source.(TargetToken)) {
		t.Fatal("retirement did not complete")
	}
	if err := p.Close(); err == nil || p.Stats().CleanupFailures != 1 {
		t.Fatalf("callback panic was hidden: close=%v stats=%+v", err, p.Stats())
	}
}

func TestPacketNext25NilAndMutuallyExclusiveMetadataHooks(t *testing.T) {
	var typedNil *net.UDPAddr
	if _, _, err := normalize(typedNil); !errors.Is(err, ErrAddress) {
		t.Fatalf("typed-nil address accepted: %v", err)
	}
	_, err := (Config{MetadataForTarget: func(context.Context, Addr, classification.Metadata) (classification.Metadata, error) {
		return classification.Metadata{}, nil
	}, MetadataForTargetToken: func(context.Context, TargetToken, classification.Metadata) (classification.Metadata, error) {
		return classification.Metadata{}, nil
	}}).defaults()
	if err == nil {
		t.Fatal("two conflicting metadata hooks accepted")
	}
}

func TestPacketNext25CanceledWriteCanRetirePendingMetadataGeneration(t *testing.T) {
	f := newPacketFixture(t, false, false)
	e := newPacketEcho(t)
	entered := make(chan struct{})
	p := f.packet(t, Config{MetadataForTargetToken: func(ctx context.Context, target TargetToken, base classification.Metadata) (classification.Metadata, error) {
		close(entered)
		<-ctx.Done()
		return base, ctx.Err()
	}})
	ctx, cancel := context.WithCancel(context.Background())
	written := make(chan error, 1)
	go func() {
		_, err := p.WriteToContext(ctx, []byte("pending-cancel"), e.socket.LocalAddr())
		written <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("metadata hook did not start")
	}
	cancel()
	select {
	case err := <-written:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("context cancellation lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("write caller did not cancel")
	}
	token, exists := p.TargetTokenForAddress(Addr(e.socket.LocalAddr().String()))
	if !exists || token.Generation == 0 || !p.RetireTarget(token) {
		t.Fatal("pending generation did not retire")
	}
	if st := p.Stats(); st.Targets != 0 || st.PendingDials != 0 || st.PendingWrites != 0 || st.BufferedBytes != 0 || f.backend.attempts.Load() != 0 {
		t.Fatalf("canceled pending generation left resources: %+v", st)
	}
}
