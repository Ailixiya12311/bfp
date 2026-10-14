package session

import (
	"bfp/protocol"
	"bfp/security"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The counters deliberately do not deduplicate Close: a double raw Close must
// remain visible even when the underlying socket accepts repeated Close calls.
type retirementNext13Conn struct {
	net.Conn
	reads, writes, closes atomic.Int32
	readBytes             atomic.Int64
	expected              int64
	entered, complete     chan struct{}
	readPast, readExited  chan struct{}
	closed                chan struct{}
	enterOnce             sync.Once
	completeOnce          sync.Once
	pastOnce              sync.Once
	exitOnce              sync.Once
	closedOnce            sync.Once
}

func retirementNext13Watch(c net.Conn, expected int64) *retirementNext13Conn {
	return &retirementNext13Conn{Conn: c, expected: expected, entered: make(chan struct{}), complete: make(chan struct{}), readPast: make(chan struct{}), readExited: make(chan struct{}), closed: make(chan struct{})}
}

func (c *retirementNext13Conn) Read(b []byte) (int, error) {
	c.reads.Add(1)
	c.enterOnce.Do(func() { close(c.entered) })
	if c.expected > 0 && c.readBytes.Load() >= c.expected {
		c.pastOnce.Do(func() { close(c.readPast) })
	}
	n, err := c.Conn.Read(b)
	if c.expected > 0 && c.readBytes.Add(int64(n)) >= c.expected {
		c.completeOnce.Do(func() { close(c.complete) })
	}
	if err != nil {
		c.exitOnce.Do(func() { close(c.readExited) })
	}
	return n, err
}

func (c *retirementNext13Conn) Write(b []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(b)
}

func (c *retirementNext13Conn) Close() error {
	c.closes.Add(1)
	err := c.Conn.Close()
	c.closedOnce.Do(func() { close(c.closed) })
	return err
}

func retirementNext13Await(t *testing.T, description string, event <-chan struct{}, limit time.Duration) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(limit):
		t.Fatal("bounded retirement observation expired: " + description)
	}
}

func retirementNext13Owner(t *testing.T, backend Backend) *Session {
	t.Helper()
	s := newSession(context.Background(), sessionInfo{ID: "next13-retirement"}, Options{CloseTimeout: 200 * time.Millisecond, ProbeInterval: time.Hour, KeyUpdateInterval: time.Hour}, false, backend)
	t.Cleanup(func() {
		s.cancel()
		retirementNext13Await(t, "owned actor cleanup", s.done, time.Second)
	})
	return s
}

func retirementNext13HoldActor(t *testing.T, s *Session) func() {
	t.Helper()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	s.post(func() { close(entered); <-release })
	t.Cleanup(finish)
	retirementNext13Await(t, "actor barrier entered", entered, time.Second)
	return finish
}

func retirementNext13AssertFinal(t *testing.T, s *Session) {
	t.Helper()
	if !s.closed() || len(s.incoming) != 0 || len(s.commands) != 0 {
		t.Fatalf("final actor/mailboxes: closed=%v incoming=%d commands=%d", s.closed(), len(s.incoming), len(s.commands))
	}
	s.mailbox.mu.Lock()
	retired, stopped := s.mailbox.retired, s.mailbox.stopped
	s.mailbox.mu.Unlock()
	if !retired {
		t.Fatal("done published before mailbox retirement")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("retired mailbox did not stop registered publishers")
	}
	s.readerState.mu.Lock()
	readerRetired, readers := s.readerState.retired, len(s.readerState.active)
	s.readerState.mu.Unlock()
	if !readerRetired || readers != 0 {
		t.Fatalf("done published before all readers joined: retired=%v readers=%d", readerRetired, readers)
	}
}

func retirementNext13RejectLatePublications(t *testing.T, s *Session, tcp *carrier) {
	t.Helper()
	udp := &carrier{kind: "udp", closed: make(chan struct{})}
	var invoked atomic.Int32
	// Both channels have free capacity after retirement. Repetition exercises
	// the old ready-send versus ready-done select ambiguity on each entry path.
	for i := 0; i < 64; i++ {
		if s.deliver(udp, []byte("late UDP record")) {
			t.Fatal("retired owner admitted a UDP record")
		}
		if tcp != nil && s.deliver(tcp, []byte("late TCP record")) {
			t.Fatal("retired owner admitted a TCP record")
		}
		if err := s.call(context.Background(), func() { invoked.Add(1) }); !errors.Is(err, ErrClosed) {
			t.Fatalf("retired call returned %v", err)
		}
		s.post(func() { invoked.Add(1) })
	}
	if invoked.Load() != 0 || len(s.incoming) != 0 || len(s.commands) != 0 {
		t.Fatalf("late publication retained work: invoked=%d incoming=%d commands=%d", invoked.Load(), len(s.incoming), len(s.commands))
	}
}

func TestNext13RetirementTCPReaderFullIncomingDrainsAndRejectsLatePublish(t *testing.T) {
	s := retirementNext13Owner(t, nil)
	left, right := transportTCPPair(t)
	record := []byte("next13-complete-TCP-record")
	count := cap(s.incoming) + 1
	watch := retirementNext13Watch(right, int64(count*(len(record)+security.BootstrapOverhead)))
	keys := &security.TransportKeys{}
	sender, err := makeCarrier("tcp", 1, make([]byte, 16), keys, left, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := makeCarrier("tcp", 1, make([]byte, 16), keys, watch, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sender.close)
	t.Cleanup(receiver.close)
	if err := s.attach(receiver, 0); err != nil {
		t.Fatal(err)
	}
	release := retirementNext13HoldActor(t, s)
	s.startReader(receiver)
	for i := 0; i < count; i++ {
		if err := sender.write(record); err != nil {
			t.Fatal(err)
		}
	}
	retirementNext13Await(t, "all complete envelopes read", watch.complete, time.Second)
	if len(s.incoming) != cap(s.incoming) {
		t.Fatalf("real TCP records did not fill incoming: %d/%d", len(s.incoming), cap(s.incoming))
	}
	select {
	case <-watch.readPast:
		t.Fatal("reader discarded its held complete record and read ahead")
	case <-time.After(30 * time.Millisecond):
	}
	s.cancel()
	release()
	retirementNext13Await(t, "final actor and blocked TCP reader join", s.done, time.Second)
	retirementNext13AssertFinal(t, s)
	if watch.closes.Load() != 1 {
		t.Fatalf("private TCP carrier raw Close count=%d", watch.closes.Load())
	}
	retirementNext13RejectLatePublications(t, s, receiver)
}

func TestNext13RetirementJoinsEveryGenerationAndRejectsLateReader(t *testing.T) {
	s := retirementNext13Owner(t, nil)
	var watches []*retirementNext13Conn
	var current *carrier
	for generation := uint64(1); generation <= 3; generation++ {
		_, right := transportTCPPair(t)
		watch := retirementNext13Watch(right, 0)
		c, err := makeCarrier("tcp", generation, make([]byte, 16), &security.TransportKeys{}, watch, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.close)
		if err := s.attach(c, generation-1); err != nil {
			t.Fatal(err)
		}
		s.startReader(c)
		retirementNext13Await(t, "generation socket Read entered", watch.entered, time.Second)
		if len(watches) > 0 {
			retirementNext13Await(t, "replaced generation left socket Read", watches[len(watches)-1].readExited, 200*time.Millisecond)
		}
		watches = append(watches, watch)
		current = c
	}
	if err := s.Close(); !errors.Is(err, ErrCloseUnconfirmed) {
		t.Fatalf("no peer close acknowledgement: %v", err)
	}
	retirementNext13AssertFinal(t, s)
	for i, watch := range watches {
		retirementNext13Await(t, "retired generation left socket Read", watch.readExited, 200*time.Millisecond)
		if watch.closes.Load() != 1 {
			t.Fatalf("generation %d raw Close count=%d", i+1, watch.closes.Load())
		}
	}
	_, lateRight := transportTCPPair(t)
	lateWatch := retirementNext13Watch(lateRight, 0)
	late, err := makeCarrier("tcp", 4, make([]byte, 16), &security.TransportKeys{}, lateWatch, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(late.close)
	s.startReader(late)
	retirementNext13Await(t, "late startReader rejected and closed private carrier", late.closed, 100*time.Millisecond)
	if lateWatch.closes.Load() != 1 || lateWatch.reads.Load() != 0 {
		t.Fatalf("late registration started work: closes=%d reads=%d", lateWatch.closes.Load(), lateWatch.reads.Load())
	}
	retirementNext13AssertFinal(t, s)
	retirementNext13RejectLatePublications(t, s, current)
}

func TestNext13RetirementOneServerSessionPreservesOtherSharedUDPBusiness(t *testing.T) {
	opts := Options{CloseTimeout: 250 * time.Millisecond, HandshakeTimeout: time.Second, ProbeInterval: time.Hour, FailureTimeout: 3 * time.Second, KeyUpdateInterval: time.Hour}
	f := newRuntimeFixtureWith(t, "udp", opts, nil)
	firstFlow := runtimeFlow(t, f)
	runtimeExchange(t, firstFlow, []byte("first session before close"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	car, info, err := establish(ctx, f.cfg, "udp", randomID(), nil)
	if err != nil {
		t.Fatal(err)
	}
	second := newSession(context.Background(), info, opts, true, nil)
	t.Cleanup(func() {
		second.cancel()
		retirementNext13Await(t, "second client actor cleanup", second.done, time.Second)
	})
	if err := second.attach(car, 0); err != nil {
		car.close()
		t.Fatal(err)
	}
	second.startReader(car)
	second.activate(car)
	f.server.mu.Lock()
	secondPeer := f.server.sessions[info.ID]
	f.server.mu.Unlock()
	if secondPeer == nil || secondPeer == f.peer || info.ID == f.client.Stats().ID {
		t.Fatal("two authenticated clients did not create distinct server Sessions")
	}
	runtimeWait(t, "second real UDP session synchronization", func() bool { return runtimeReady(second) && runtimeReady(secondPeer) })
	secondFlow, err := second.DialContext(ctx, "tcp", f.target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { secondFlow.Close() })
	runtimeExchange(t, secondFlow, []byte("second session before sibling close"))
	shared := f.server.udp
	if err := f.client.Close(); err != nil {
		t.Fatalf("first real Session close: %v", err)
	}
	runtimeExchange(t, secondFlow, []byte("second session during sibling responder drain"))
	retirementNext13Await(t, "first server Session final retirement", f.peer.done, time.Second)
	retirementNext13AssertFinal(t, f.peer)
	runtimeExchange(t, secondFlow, []byte("same second flow after sibling final retirement"))
	if f.server.udp != shared || second.closed() || secondPeer.closed() || second.Stats().Carrier != "udp" || secondPeer.Stats().Carrier != "udp" {
		t.Fatal("one Session retirement changed the shared socket or another Session's UDP carrier")
	}
	if f.backend.dials.Load() != 2 {
		t.Fatalf("sibling retirement redialed a target: backend dials=%d", f.backend.dials.Load())
	}
}

type retirementNext13Backend struct {
	started, release chan struct{}
	conn             net.Conn
}

func (b *retirementNext13Backend) DialContext(context.Context, string, string) (net.Conn, error) {
	close(b.started)
	// Deliberately noncooperative. Session.Close must not claim to join this
	// callback; the independent late-result owner must release its returned Conn.
	<-b.release
	return b.conn, nil
}

func TestNext13RetirementFullCommandRaceOwnsQueuedAndLateDialExactlyOnce(t *testing.T) {
	for _, completion := range []string{"queued-before-retirement", "returned-after-close"} {
		t.Run(completion, func(t *testing.T) {
			left, right := net.Pipe()
			watch := retirementNext13Watch(left, 0)
			t.Cleanup(func() { left.Close(); right.Close() })
			backend := &retirementNext13Backend{started: make(chan struct{}), release: make(chan struct{}), conn: watch}
			var releaseOnce sync.Once
			releaseDial := func() { releaseOnce.Do(func() { close(backend.release) }) }
			t.Cleanup(releaseDial)
			s := retirementNext13Owner(t, backend)
			var st *streamState
			var results *dialResultMailbox
			if err := s.call(context.Background(), func() {
				s.peerDone = true
				s.handleOpen(protocol.Frame{Kind: protocol.Open, Flow: 1, Data: encodeJSON(protocol.Target{Network: "tcp", Address: "next13.invalid:80", Class: protocol.Normal})})
				st, results = s.streams[1], s.dialResults
			}); err != nil {
				t.Fatal(err)
			}
			retirementNext13Await(t, "noncooperative dial entered", backend.started, time.Second)
			releaseActor := retirementNext13HoldActor(t, s)
			var invoked atomic.Int32
			for i := 0; i < cap(s.commands); i++ {
				s.post(func() { invoked.Add(1) })
			}
			if len(s.commands) != cap(s.commands) {
				t.Fatal("command queue did not reach its real capacity")
			}
			callDone, postDone := make(chan error, 1), make(chan struct{})
			go func() { callDone <- s.call(context.Background(), func() { invoked.Add(1) }) }()
			go func() { s.post(func() { invoked.Add(1) }); close(postDone) }()
			select {
			case err := <-callDone:
				t.Fatalf("full command queue did not backpressure call: %v", err)
			case <-postDone:
				t.Fatal("full command queue did not backpressure post")
			case <-time.After(30 * time.Millisecond):
			}
			if completion == "queued-before-retirement" {
				releaseDial()
				runtimeWait(t, "typed successful dial queued behind held actor", func() bool {
					results.mu.Lock()
					defer results.mu.Unlock()
					return len(results.queue) == 1
				})
			}
			closeDone := make(chan error, 1)
			go func() { closeDone <- s.Close() }()
			retirementNext13Await(t, "first close intent stopped business", s.ctx.Done(), time.Second)
			releaseActor()
			select {
			case err := <-closeDone:
				if !errors.Is(err, ErrCloseUnconfirmed) {
					t.Fatalf("no carrier falsely confirmed peer close: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("final Close waited for full commands or the noncooperative dial")
			}
			select {
			case err := <-callDone:
				if !errors.Is(err, ErrClosed) {
					t.Fatalf("retiring blocked call returned %v", err)
				}
			case <-time.After(100 * time.Millisecond):
				t.Fatal("retiring mailbox failed to release blocked call publisher")
			}
			retirementNext13Await(t, "blocked post publisher exit", postDone, 100*time.Millisecond)
			retirementNext13AssertFinal(t, s)
			if completion == "returned-after-close" {
				select {
				case <-watch.closed:
					t.Fatal("fixture dial completed before Close returned")
				default:
				}
				releaseDial()
			}
			retirementNext13Await(t, "successful unclaimed raw target Conn closed", watch.closed, 100*time.Millisecond)
			if invoked.Load() != 0 || watch.closes.Load() != 1 || watch.reads.Load() != 0 || watch.writes.Load() != 0 || st.targetConn != nil || len(s.streams) != 0 || s.dialing != 0 {
				t.Fatalf("retirement executed/installed/duplicated work: callbacks=%d closes=%d reads=%d writes=%d target=%v streams=%d dialing=%d", invoked.Load(), watch.closes.Load(), watch.reads.Load(), watch.writes.Load(), st.targetConn != nil, len(s.streams), s.dialing)
			}
			results.mu.Lock()
			retired, queued := results.retired, len(results.queue)
			results.mu.Unlock()
			if !retired || queued != 0 {
				t.Fatalf("typed dial mailbox retained a late result: retired=%v queued=%d", retired, queued)
			}
			retirementNext13RejectLatePublications(t, s, nil)
		})
	}
}

func TestNext13RetirementDialDeadlineDiscardsNoncooperativeLateSuccess(t *testing.T) {
	left, right := net.Pipe()
	t.Cleanup(func() { left.Close(); right.Close() })
	watch := retirementNext13Watch(left, 0)
	backend := &retirementNext13Backend{started: make(chan struct{}), release: make(chan struct{}), conn: watch}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(backend.release) }) }
	t.Cleanup(release)
	// This independent worker has a shorter test authority window; the existing
	// OPEN dial timeout remains 10 seconds. Its mailbox is deliberately live so
	// rejection cannot be attributed to Session or mailbox retirement.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	t.Cleanup(cancel)
	results := newDialResultMailbox(1)
	t.Cleanup(results.retire)
	token := &dialToken{}
	workerDone := make(chan struct{})
	go func() {
		runBackendDial(backend, ctx, cancel, "tcp", "next13.invalid:80", 1, token, results)
		close(workerDone)
	}()
	retirementNext13Await(t, "independent noncooperative backend entered", backend.started, time.Second)
	retirementNext13Await(t, "independent 150ms dial authority expired", ctx.Done(), 300*time.Millisecond)
	select {
	case <-workerDone:
		t.Fatal("fixture backend stopped before its explicit release")
	default:
	}
	release()
	retirementNext13Await(t, "late success released by the worker", workerDone, 100*time.Millisecond)
	if watch.closes.Load() != 1 || watch.reads.Load() != 0 || watch.writes.Load() != 0 {
		t.Fatalf("expired worker retained/used/duplicated success: closes=%d reads=%d writes=%d", watch.closes.Load(), watch.reads.Load(), watch.writes.Load())
	}
	queued, overflow := results.take()
	if overflow || len(queued) != 1 || queued[0].flow != 1 || queued[0].token != token || queued[0].conn != nil || !errors.Is(queued[0].err, context.DeadlineExceeded) {
		t.Fatalf("live mailbox did not retain only the typed deadline result: overflow=%v results=%+v", overflow, queued)
	}
}
