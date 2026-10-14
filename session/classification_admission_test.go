package session

import (
	"bfp/classification"
	"bfp/protocol"
	"bfp/scheduler"
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestClassificationInvalidConstructorPolicyPrecedesListen(t *testing.T) {
	seed, cred := newSecurityTestServer(t)
	sc := seed.cfg.Credentials
	seed.Close()
	busy, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { busy.Close() })
	bad := classification.DefaultConfig()
	bad.Rules = []classification.Rule{{Class: protocol.Normal}}
	if s, e := NewServer(ServerConfig{Listen: busy.Addr().String(), Credentials: sc, Backend: &runtimeBackend{}, Classification: &bad}); s != nil || !errors.Is(e, classification.ErrConfig) {
		if s != nil {
			s.Close()
		}
		t.Fatalf("bad policy did not fail before occupied Listen: %v", e)
	}
	if c, e := NewClient(ClientConfig{Server: "127.0.0.1:1", Credentials: cred, Classification: &bad}); c != nil || !errors.Is(e, classification.ErrConfig) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("bad client policy: %v", e)
	}
	// An explicit zero-value policy is meaningful (Interactive, behavior off)
	// while nil selects the documented Normal default.
	for _, tc := range []struct {
		cfg  *classification.Config
		want protocol.Class
	}{{nil, protocol.Normal}, {&classification.Config{}, protocol.Interactive}} {
		compiled, e := compileClassification(tc.cfg)
		if e != nil {
			t.Fatal(e)
		}
		d, e := compiled.Decide(classification.Metadata{Target: protocol.Target{Network: "tcp", Address: "127.0.0.1:443"}})
		if e != nil || d.Class != tc.want {
			t.Fatalf("explicit/default policy: %+v %v", d, e)
		}
	}
}

func TestClassificationRuntimeInvalidMetadataDoesNotAllocate(t *testing.T) {
	cfg := classification.DefaultConfig()
	cfg.Behavior.Enabled = false
	f := newClassFixture(t, "tcp", &cfg, &cfg)
	var next uint64
	var opened uint64
	if e := f.local.call(context.Background(), func() { next = f.local.nextFlow; opened = f.local.stats.Opened }); e != nil {
		t.Fatal(e)
	}
	for _, meta := range []classification.Metadata{
		{Target: protocol.Target{Network: "tcp", Address: f.address, Domain: "bad..test"}, DomainTrusted: true},
		{Target: protocol.Target{Network: "tcp", Address: f.address, RuleTag: "bad\n"}, RuleTagTrusted: true},
		{Target: protocol.Target{Network: "tcp", Address: f.address}, Hint: &classification.ClassHint{Class: protocol.Class(255), Trusted: true}},
	} {
		if c, e := f.local.DialMetadata(context.Background(), meta); c != nil || !errors.Is(e, classification.ErrMetadata) {
			t.Fatalf("invalid local metadata: %v", e)
		}
	}
	if e := f.local.call(context.Background(), func() {
		if f.local.nextFlow != next || f.local.stats.Opened != opened || len(f.local.streams) != 0 {
			t.Error("invalid metadata allocated flow/OPEN")
		}
	}); e != nil {
		t.Fatal(e)
	}
	if f.backend.dials.Load() != 0 {
		t.Fatal("invalid metadata dialed target")
	}

}

func TestClassificationRuntimeHintCopiedBeforeQueuedCommand(t *testing.T) {
	// This production-handshake fixture has no Client recovery goroutine
	// publishing unrelated commands while the actor is held.
	f := newRuntimeFixture(t, "tcp")
	started, release := make(chan struct{}), make(chan struct{})
	f.client.post(func() { close(started); <-release })
	<-started
	var once bool
	unblock := func() {
		if !once {
			once = true
			close(release)
		}
	}
	t.Cleanup(unblock)
	hint := &classification.ClassHint{Class: protocol.Interactive, Trusted: true, Locked: true}
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		c, e := f.client.DialMetadata(ctx, classification.Metadata{Target: protocol.Target{Network: "tcp", Address: f.target}, Hint: hint})
		done <- result{c, e}
	}()
	// Receiving/re-publishing (without executing) the queued owner command
	// establishes a channel happens-before relation after Hint has been copied.
	// It avoids treating a len(channel) observation as memory synchronization.
	var command func()
	select {
	case command = <-f.client.commands:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	hint.Class, hint.Trusted, hint.Locked = protocol.Bulk, false, false
	f.client.commands <- command
	unblock()
	var out result
	select {
	case out = <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if out.err != nil {
		t.Fatal(out.err)
	}
	flow := out.conn.(*Flow)
	t.Cleanup(func() { flow.Close() })
	if snap := classSnapshot(t, f.client, flow.id); snap.LocalTX.Class != protocol.Interactive || !snap.LocalTX.Baseline.Locked || snap.LocalTX.Baseline.Source != classification.SourceHint {
		t.Fatalf("queued hint aliased caller: %+v", snap)
	}
}

func TestClassificationRuntimeDatagramBoundsAndNoAdmissionSideEffects(t *testing.T) {
	cfg := classification.DefaultConfig()
	cfg.Behavior.Enabled = false
	f := newClassFixture(t, "tcp", &cfg, &cfg)
	address, received := transportUDPEcho(t)
	conn, e := f.client.DialContext(context.Background(), "udp", address)
	if e != nil {
		t.Fatal(e)
	}
	flow := conn.(*Flow)
	t.Cleanup(func() { flow.Close() })
	flow.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte{0x79}, 16<<10)
	if n, e := flow.Write(payload); e != nil || n != len(payload) {
		t.Fatalf("maximum datagram write: %d %v", n, e)
	}
	got := make([]byte, 16<<10)
	if n, e := flow.Read(got); e != nil || n != len(payload) || !bytes.Equal(got, payload) {
		t.Fatalf("maximum datagram read: %d %v", n, e)
	}
	var message uint64
	var queue *scheduler.Queue[protocol.Frame]
	var lastSync, lastProbe time.Time
	if e := f.local.call(context.Background(), func() {
		message = f.local.streams[flow.id].messageNext
		queue = f.local.queue
		lastSync, lastProbe = f.local.lastSync, f.local.lastProbe
		f.local.queue = scheduler.New[protocol.Frame](1200, f.local.opts.MaxSessionBuffer)
		f.local.localDoneAck = false
		f.local.lastSync, f.local.lastProbe = time.Now().Add(time.Hour), time.Now().Add(time.Hour)
	}); e != nil {
		t.Fatal(e)
	}
	restore := func() {
		f.local.streams[flow.id].messageNext = message
		f.local.peerDone = true
		f.local.localDoneAck = true
		f.local.queue = queue
		f.local.lastSync, f.local.lastProbe = lastSync, lastProbe
	}
	t.Cleanup(func() { _ = f.local.call(context.Background(), restore) })
	for _, tc := range []struct {
		name    string
		data    []byte
		prepare func()
		want    error
		drop    bool
	}{
		{"oversize", make([]byte, (16<<10)+1), func() {}, nil, false},
		{"expired", []byte("late"), func() { flow.SetWriteDeadline(time.Now().Add(-time.Second)) }, context.DeadlineExceeded, false},
		{"message-exhausted", []byte("overflow"), func() {
			_ = f.local.call(context.Background(), func() { f.local.streams[flow.id].messageNext = ^uint64(0) })
		}, ErrLimit, false},
		// A recovery wait is unaccepted until the peer is ready; the original
		// write deadline now returns an error instead of success with a drop.
		{"peer-not-ready", []byte("wait"), func() {
			_ = f.local.call(context.Background(), func() { f.local.streams[flow.id].messageNext = message; f.local.peerDone = false })
		}, context.DeadlineExceeded, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flow.SetWriteDeadline(time.Now().Add(time.Second))
			tc.prepare()
			n, e := flow.Write(tc.data)
			if tc.drop {
				if n != len(tc.data) || e != nil {
					t.Fatalf("best-effort drop: %d %v", n, e)
				}
			} else if n != 0 || e == nil || tc.want != nil && !errors.Is(e, tc.want) {
				t.Fatalf("unaccepted datagram: %d %v", n, e)
			}
			if e := f.local.call(context.Background(), func() {
				st := f.local.streams[flow.id]
				wantMessage := message
				if tc.name == "message-exhausted" {
					wantMessage = ^uint64(0)
				}
				if st.messageNext != wantMessage || st.txClassifier.Snapshot().TotalBytes != 16<<10 || f.local.queue.Len() != 0 {
					t.Error("unaccepted datagram mutated count/id/queue")
				}
			}); e != nil {
				t.Fatal(e)
			}
		})
	}
	if e := f.local.call(context.Background(), restore); e != nil {
		t.Fatal(e)
	}
	if received.Load() != 1 {
		t.Fatalf("unaccepted UDP reached target: %d", received.Load())
	}
}
