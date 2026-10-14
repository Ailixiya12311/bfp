package session

import (
	"bfp/classification"
	"bfp/internal/backend"
	"bfp/internal/classcontrol"
	"bfp/internal/controlreceipt"
	"bfp/internal/latestcontrol"
	"bfp/internal/operation"
	"bfp/internal/udptransport"
	"bfp/obfuscation"
	"bfp/protocol"
	"bfp/scheduler"
	"bfp/security"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type packet struct {
	c    *carrier
	wire []byte
	err  error
}
type sentRecord struct {
	frame protocol.Frame
	sent  time.Time
	size  int
}
type chunk struct {
	offset         uint64
	data           []byte
	queued         time.Time
	sentGeneration uint64
}
type streamState struct {
	flow   *Flow
	target protocol.Target
	// delivery and fecProfile are the immutable OPEN admission contract. The
	// ClassUpdate path only changes effectiveClass/scheduler budget.
	delivery                                            protocol.DeliveryContract
	fecProfile                                          protocol.FECProfile
	effectiveClass                                      protocol.Class
	txClassifier                                        *classification.Flow
	classTX                                             classcontrol.State
	targetConn                                          net.Conn
	openResult                                          string
	opening                                             bool
	sendNext, sendAck, receiveNext, consumed, maxRemote uint64
	chunks                                              []chunk
	segments                                            map[uint64][]byte
	remoteFinal                                         *uint64
	localFinal                                          *uint64
	finAck                                              bool
	reset                                               bool
	messageNext                                         uint64
	txDatagrams                                         map[uint64]*txDatagram
	txDatagramReserved                                  int
	datagrams                                           map[uint64]*assembly
	messageHigh                                         uint64
	completed                                           map[uint64]bool
	lastOpen, lastFin                                   time.Time
	lastReset                                           time.Time
	bridgeWritten                                       uint64
	bridgeCloseWrite                                    bool
	finAckSent                                          bool
	dialCancel                                          context.CancelFunc
	dialToken                                           *dialToken
	streamAckRevision, streamAckValue                   uint64
	maxFlowRevision, maxFlowValue                       uint64
	openResultRevision                                  uint64
	resetPending, resetAcked                            bool
	peerStreamAckRevision, peerStreamAckValue           uint64
	peerMaxFlowRevision, peerMaxFlowValue               uint64
	peerOpenResultRevision                              uint64
	peerOpenResultValue                                 string
	openOp, finOp, resetOp                              operation.Key
	openOpSet, finOpSet, resetOpSet                     bool
}
type assembly struct {
	data    []byte
	seen    []bool
	parity  []byte // optional, scoped to this one authenticated datagram
	count   int
	created time.Time
	// handoverUntil extends the normal one-second incomplete-message lifetime
	// across a carrier replacement.  It is set only for an assembly that was
	// already present when the authenticated replacement began.
	handoverUntil time.Time
}

func (st *streamState) terminal() bool {
	return st.reset || st.localFinal != nil && st.finAck && st.remoteFinal != nil && st.consumed >= *st.remoteFinal
}

type flowSnapshot struct {
	TXClass *classWireSnapshot `json:"tc,omitempty"`
	ID      uint64             `json:"i"`
	Receive uint64             `json:"r"`
	Max     uint64             `json:"m"`
	Result  string             `json:"o"`
	Final   *uint64            `json:"f,omitempty"`
	Reset   bool               `json:"x,omitempty"`
	AckRev  uint64             `json:"ar,omitempty"`
	MaxRev  uint64             `json:"mr,omitempty"`
	OpenRev uint64             `json:"or,omitempty"`
}

type Session struct {
	ctx                           context.Context
	cancel                        context.CancelFunc
	controlCtx                    context.Context
	stopControl                   context.CancelFunc
	stopBusiness                  context.CancelFunc
	admissionMu                   sync.RWMutex
	closeIntent                   atomic.Pointer[closeIntent]
	terminationSource             atomic.Pointer[string]
	businessStopSource            *atomic.Pointer[string] // raw business-stop boundary; immutable before actor start
	parentTerminationSource       *atomic.Pointer[string] // immutable before Client publication; no Client retained
	boundCarrier                  atomic.Pointer[carrier]
	localClose                    atomic.Bool
	closeWake                     chan struct{}
	closing                       closeState
	businessCleaned               bool
	closeErr                      error // actor-owned, immutable after done
	finalStats                    Stats // immutable after done
	info                          sessionInfo
	opts                          Options
	client                        bool
	backend                       Backend
	backendGuard                  *backendLifetime
	closeBackend                  func()
	localAddressScope             ClientAddressScope // actor-owned after construction
	localAddressGuard             *clientScopeLifetime
	closeLocalAddressScope        func()
	authority                     *deviceAuthority // immutable, server-side device owner
	commands                      chan func()
	incoming                      chan packet
	mailbox                       publishGate
	readerState                   readerRegistry
	dialResults                   *dialResultMailbox
	done                          chan struct{}
	classifier                    *classification.Classifier // immutable constructor-owned policy
	datagramFEC                   datagramFECPolicy          // immutable constructor-owned initial OPEN policy
	classOrigin                   time.Time
	classNow                      func() time.Time // owner-confined test seam, defaults to time.Now
	classTable                    *classcontrol.Table
	classAckTurn                  bool
	classTXCursor, classACKCursor uint64
	// Everything below is owned by run().
	current                                  *carrier
	active                                   bool
	synced                                   bool
	peerDone                                 bool
	streams                                  map[uint64]*streamState
	nextFlow                                 uint64
	queue                                    *scheduler.Queue[protocol.Frame]
	txDatagramReserved, txDatagramQueued     int
	handoverDatagrams                        map[datagramHandoverKey]protocol.Frame
	pending                                  map[security.RecordMeta]sentRecord
	flight, cwnd                             int
	ssthresh                                 int
	rtt                                      time.Duration
	lastReceive, lastProbe, lastKey          time.Time
	rxDrainAt, txDrainAt                     time.Time
	rxCurrentUsed, txCurrentUsed             bool
	suspendedAt                              time.Time
	stats                                    Stats
	keyPending                               bool
	keyLastSend                              time.Time
	bytesSinceKey                            uint64
	lastRXKey                                time.Time
	pendingRXKey                             uint32
	totalSent, totalConsumed, peerSessionMax uint64
	totalReceived                            uint64
	paceTokens                               float64
	paceTime                                 time.Time
	dialing                                  int
	syncFrames                               []protocol.Frame
	syncAck                                  map[uint64]bool
	syncReceived                             map[uint64]bool
	peerSyncCount                            int
	lastSync                                 time.Time
	syncCursor                               int
	localDoneAck                             bool
	resumeNextID                             uint64
	resumeID                                 uint64
	resumeSessionRevision                    uint64
	resumeSessionValue                       uint64
	resumeBaseline                           map[latestcontrol.Key]uint64
	peerResumeDone                           *resumeDoneState
	ticketPending                            uint64
	lastTicketSend                           time.Time
	controlReceipts                          map[controlReceiptKey]uint64
	controlTable                             *latestcontrol.Table
	controlQueued                            map[controlReceiptKey]uint64
	controlClock                             time.Duration
	controlOrigin                            time.Time
	operations                               *operation.Table
	operationClock                           time.Duration
	operationOrigin                          time.Time
	maxSessionRevision                       uint64
	maxSessionValue                          uint64
	peerMaxSessionRevision                   uint64
	peerMaxSessionValue                      uint64
	// resetTombstones covers an authenticated RESET that arrives before its
	// OPEN (or after the stream state has been compacted). It prevents a
	// reordered/duplicated OPEN from ever creating a target socket for a flow
	// that already has a terminal decision. The map is deliberately bounded by
	// the same flow lifetime limit as streams.
	resetTombstones map[uint64]time.Time
	udpPath         *udpPath
	transportNow    func() time.Time // owner-confined virtual clock seam
	closeNow        func() time.Time // immutable close-clock seam for owner-only transition tests
	udpSuspect      bool
	recoveryCancel  context.CancelFunc
	udpBlockedTotal time.Duration
	udpBlockedMax   time.Duration
}

type controlReceiptKey struct {
	kind protocol.Kind
	flow uint64
}

const (
	maxSessionFlowStates = 4096
	maxResetTombstones   = maxSessionFlowStates
	// Retained flows can each own StreamAck, MaxFlowData, and OpenResult;
	// MaxSessionData is the one Session-scoped latest-control key. Keep the
	// terminal publication history within the same fixed lifetime budget.
	maxSessionControlKeys = 3*maxSessionFlowStates + 1
)

// rememberResetTombstone records a terminal decision for a flow even when no
// streamState exists yet. The caller is the Session owner, so no extra lock is
// needed. Returning false means accepting this new tombstone would exceed the
// bounded flow lifetime budget; the authenticated Session must then fail
// closed instead of forgetting the decision and risking a later redial.
func (s *Session) rememberResetTombstone(flow uint64, now time.Time) bool {
	if flow == 0 {
		return false
	}
	if s.resetTombstones == nil {
		s.resetTombstones = make(map[uint64]time.Time)
	}
	if _, exists := s.resetTombstones[flow]; exists {
		s.resetTombstones[flow] = now
		return true
	}
	if len(s.resetTombstones) >= maxResetTombstones {
		return false
	}
	s.resetTombstones[flow] = now
	return true
}

func (s *Session) hasResetTombstone(flow uint64) bool {
	_, ok := s.resetTombstones[flow]
	return ok
}

func newSession(parent context.Context, info sessionInfo, opts Options, client bool, backend Backend, policies ...*classification.Classifier) *Session {
	return newSessionWithFECPolicy(parent, info, opts, client, backend, datagramFECPolicy{}, policies...)
}

func newSessionWithFECPolicy(parent context.Context, info sessionInfo, opts Options, client bool, backend Backend, datagramFEC datagramFECPolicy, policies ...*classification.Classifier) *Session {
	s, err := newSessionWithAddressScope(parent, info, opts, client, backend, datagramFEC, nil, policies...)
	if err != nil {
		panic(err) // No local factory is installed by this legacy constructor.
	}
	return s
}

func newSessionWithAddressScope(parent context.Context, info sessionInfo, opts Options, client bool, backend Backend, datagramFEC datagramFECPolicy, factory ClientAddressScopeFactory, policies ...*classification.Classifier) (*Session, error) {
	return newSessionWithAddressScopeOperation(parent, parent, info, opts, client, backend, datagramFEC, factory, nil, policies...)
}

func newSessionWithAddressScopeOperation(parent, operationCtx context.Context, info sessionInfo, opts Options, client bool, backend Backend, datagramFEC datagramFECPolicy, factory ClientAddressScopeFactory, creation *clientAddressCreationSlot, policies ...*classification.Classifier) (*Session, error) {
	ctx, rawBusinessCancel := context.WithCancel(parent)
	// All business cancellation closures, including scope retirement bindings,
	// share this boundary. Record before raw cancellation wakes BusinessDone;
	// higher-level abort/graceful sources retain precedence. The separate cell
	// does not let a retained scope cancellation closure keep Session reachable.
	businessStopSource := &atomic.Pointer[string]{}
	cancel := func() {
		// Retirement after an already-observed parent cancellation must not
		// relabel that termination as a new local business-stop invocation.
		// This read is diagnostic only, not an atomic cancellation decision.
		if ctx.Err() == nil {
			source := "unknown"
			if _, file, line, ok := runtime.Caller(1); ok {
				source = filepath.Base(file) + ":" + strconv.Itoa(line)
			}
			businessStopSource.CompareAndSwap(nil, &source)
		}
		rawBusinessCancel()
	}
	controlCtx, stopControl := context.WithCancel(parent)
	opts = opts.defaults()
	creationCtx, stopCreation := context.WithTimeout(operationCtx, opts.HandshakeTimeout)
	defer stopCreation()
	policy, err := compileClassification(nil)
	if err != nil {
		panic(err)
	}
	if len(policies) > 0 && policies[0] != nil {
		policy = policies[0]
	}
	controlConfig := latestcontrol.DefaultConfig()
	controlConfig.MaxKeys = maxSessionControlKeys
	controlTable, err := latestcontrol.New(controlConfig)
	if err != nil {
		panic(err)
	}
	operations, err := operation.New(operation.DefaultConfig())
	if err != nil {
		panic(err)
	}
	s := &Session{ctx: ctx, cancel: cancel, info: info, opts: opts, client: client, backend: backend, authority: info.authority, commands: make(chan func(), 128), incoming: make(chan packet, 128), done: make(chan struct{}), streams: map[uint64]*streamState{}, resetTombstones: map[uint64]time.Time{}, queue: scheduler.New[protocol.Frame](1200, opts.MaxSessionBuffer), pending: map[security.RecordMeta]sentRecord{}, controlReceipts: map[controlReceiptKey]uint64{}, controlTable: controlTable, controlQueued: map[controlReceiptKey]uint64{}, operations: operations, cwnd: 12000, ssthresh: 1 << 20, rtt: 200 * time.Millisecond, nextFlow: 1, lastReceive: time.Now(), lastKey: time.Now()}
	s.controlCtx, s.stopControl, s.stopBusiness = controlCtx, stopControl, cancel
	s.businessStopSource = businessStopSource
	s.dialResults = newDialResultMailbox(opts.MaxFlows)
	s.closeWake = make(chan struct{}, 1)
	s.closeErr = ErrCloseUnconfirmed
	s.cancel = func() {
		// Capture only the first cancel invocation's source before business
		// termination becomes observable. This is diagnostic metadata, not a
		// termination reason, and does not serialize or alter cancellation.
		source := ""
		if _, file, line, ok := runtime.Caller(1); ok {
			source = filepath.Base(file) + ":" + strconv.Itoa(line)
		}
		s.terminationSource.CompareAndSwap(nil, &source)
		s.markBackendTerminal()
		s.stopBusiness()
		stopControl()
		if c := s.boundCarrier.Load(); c != nil {
			c.close()
		}
	}
	s.stats = Stats{ID: info.ID, ClientAddress: info.ClientAddress, ServerAddress: info.ServerAddress}
	s.classifier, s.classOrigin, s.classNow = policy, time.Now(), time.Now
	s.datagramFEC = datagramFEC
	s.bindSessionBackend(backend, cancel)
	if err := s.bindClientAddressScope(factory, cancel, creationCtx, creation); err != nil {
		s.cancel()
		return nil, err
	}
	if validCapabilitySelection(info.Profile, info.Capabilities) {
		s.classTable, err = classcontrol.New(classcontrol.DefaultConfig())
		if err != nil {
			panic(err)
		}
	}
	s.peerSessionMax = uint64(opts.MaxSessionBuffer)
	s.paceTokens = 4800
	s.paceTime = time.Now()
	go s.run()
	return s, nil
}
func (s *Session) closed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// TerminationSource returns the first recorded cancellation or graceful-close
// origin. Cancellation records basename:line; graceful intent records
// local_close@basename:line or peer_close@basename:line. Empty recorded source
// or an @unknown suffix means caller metadata was unavailable. After business
// has ended, raw_business_stop@basename:line identifies the immediate caller
// when no higher-level origin was recorded. Otherwise a Client parent stop
// records parent_context_end@basename:line. Legacy parent cancellation without
// metadata retains the unrecorded result.
// This read-only observation does not infer a cause or call actor methods, so
// it remains safe during and after Session retirement.
func (s *Session) TerminationSource() (source string, recorded bool) {
	if s == nil {
		return "", false
	}
	if value := s.terminationSource.Load(); value != nil {
		return *value, true
	}
	if s.ctx != nil && s.ctx.Err() != nil && s.businessStopSource != nil {
		if value := s.businessStopSource.Load(); value != nil {
			return "raw_business_stop@" + *value, true
		}
	}
	if s.ctx != nil && s.ctx.Err() != nil && s.parentTerminationSource != nil {
		if value := s.parentTerminationSource.Load(); value != nil {
			return "parent_context_end@" + *value, true
		}
	}
	return "", false
}

// TerminationState contains only fixed lifecycle observations. Its fields are
// independent snapshots, not an actor transaction or a termination cause.
type TerminationState struct {
	BusinessEnded bool
	ControlEnded  bool
	CloseIntent   bool
	LocalClose    bool
}

// TerminationState reads immutable contexts and atomic intent flags. It never
// enters the actor mailbox, so it is safe while resources are being retired.
func (s *Session) TerminationState() TerminationState {
	if s == nil {
		return TerminationState{}
	}
	return TerminationState{
		BusinessEnded: s.ctx != nil && s.ctx.Err() != nil,
		ControlEnded:  s.controlContext().Err() != nil,
		CloseIntent:   s.closeIntent.Load() != nil,
		LocalClose:    s.localClose.Load(),
	}
}

// AddressAllocator returns the optional Session-owned logical-address scope
// installed by a backend SessionFactory. A client Session normally has no
// backend and therefore returns (nil, false). The returned allocator is
// invalidated synchronously when this Session terminates.
func (s *Session) AddressAllocator() (SessionAddressAllocator, bool) {
	if s == nil || s.terminating() {
		return nil, false
	}
	var allocator SessionAddressAllocator
	err := s.call(context.Background(), func() {
		if s.terminating() || backend.IsNil(s.backend) {
			return
		}
		allocator, _ = s.backend.(SessionAddressAllocator)
	})
	return allocator, err == nil && allocator != nil
}

func (s *Session) call(ctx context.Context, fn func()) error {
	done := make(chan struct{})
	var state atomic.Int32
	err := s.publishCommand(ctx, func() {
		if ctx.Err() != nil {
			state.CompareAndSwap(0, 2)
		}
		if state.CompareAndSwap(0, 1) {
			fn()
		}
		close(done)
	})
	if err != nil {
		return err
	}
	select {
	case <-done:
		if state.Load() == 2 {
			return ctx.Err()
		}
		return nil
	case <-s.done:
		return ErrClosed
	case <-ctx.Done():
		if state.CompareAndSwap(0, 2) {
			return ctx.Err()
		}
		select {
		case <-done:
			if state.Load() == 2 {
				return ctx.Err()
			}
			return nil
		case <-s.done:
			return ErrClosed
		}
	}
}
func (s *Session) post(fn func()) {
	_ = s.publishCommand(context.Background(), fn)
}
func (s *Session) Stats() Stats {
	var out Stats
	if err := s.call(context.Background(), func() {
		out = s.snapshotStats(s.transportTime())
	}); err != nil {
		if s.closed() {
			return s.finalStats
		}
		// stopControl is cancelled before the actor publishes finalStats. Do
		// not expose the zero-value observation from the failed call during
		// that short retirement window; finalStats is owner-written and is
		// safe to read after done closes.
		if s.controlContext().Err() != nil || s.terminating() {
			<-s.done
			return s.finalStats
		}
	}
	return out
}

// snapshotStats is owner-confined, so transport gauges and cumulative counters
// describe one observation without reading mutable path state from the caller.
func (s *Session) snapshotStats(now time.Time) Stats {
	out := s.stats
	out.Flows = 0
	for _, f := range s.streams {
		if !f.terminal() {
			out.Flows++
		}
	}
	if p := s.udpPath; p != nil {
		out.UDPPathPresent = true
		out.UDPSuspect = s.udpSuspect
		out.UDPNoResponseDeadlines = p.noResponseDeadlines
		out.UDPPTORounds = p.pto.Rounds()
		out.UDPBasePTOMS = nonnegativeMS(p.rtt.BasePTO())
		if !p.deadline.IsZero() {
			out.UDPDeadlineRemainingMS = nonnegativeMS(p.deadline.Sub(now))
		}
		out.UDPNoProgressAgeMS = nonnegativeMS(now.Sub(p.lastProgress))
		out.UDPPathGeneration = p.generation
		out.UDPPathActive = s.active && s.current != nil && s.current.kind == "udp"
		out.UDPCwndBytes = uint64(max(0, s.cwnd))
		out.UDPFlightBytes = uint64(max(0, s.flight))
		out.UDPPacerTokens = s.paceTokens
		out.UDPFeedbackTokens = p.ackTokens
		out.UDPLastCommittedBytes = p.lastCommittedBytes
		rtt := p.rtt.Snapshot()
		out.UDPRTTSmoothedUS = nonnegativeUS(rtt.Smoothed)
		out.UDPRTTVarianceUS = nonnegativeUS(rtt.Variance)
		out.UDPRTTMinUS = nonnegativeUS(rtt.Min)
		out.UDPRTTLatestUS = nonnegativeUS(rtt.Latest)
		out.UDPRTTSamples = rtt.Samples
	}
	blocked := time.Duration(0)
	if p := s.udpPath; p != nil && p.budgetBlocked {
		blocked = max(time.Duration(0), now.Sub(p.budgetBlockedSince))
		out.UDPBudgetBlocked, out.UDPBlockedByCwnd, out.UDPBlockedByPacer = true, p.blockedByCwnd, p.blockedByPacer
	}
	out.UDPBudgetBlockedMS = nonnegativeMS(addTransportDuration(s.udpBlockedTotal, blocked))
	out.UDPBudgetBlockedMaxMS = nonnegativeMS(max(s.udpBlockedMax, blocked))
	return out
}
func nonnegativeUS(d time.Duration) uint64 {
	if d <= 0 {
		return 0
	}
	return uint64(d / time.Microsecond)
}
func nonnegativeMS(d time.Duration) uint64 {
	if d <= 0 {
		return 0
	}
	return uint64(d / time.Millisecond)
}
func (s *Session) Close() error {
	if !s.closed() {
		s.requestClose(true, s.closeTime())
	}
	<-s.done
	return s.closeErr
}
func (s *Session) attach(c *carrier, expected uint64) error {
	return s.attachGuarded(c, expected, nil)
}
func (s *Session) attachGuarded(c *carrier, expected uint64, guard func() bool) error {
	var e error
	err := s.call(context.Background(), func() {
		s.admissionMu.RLock()
		defer s.admissionMu.RUnlock()
		if s.terminating() || s.authority != nil && s.authority.revoked.Load() || !s.info.lifetimeUntil.IsZero() && !s.info.lifetimeUntil.After(time.Now()) || guard != nil && !guard() {
			e = ErrClosed
			return
		}
		if s.current != nil && s.current.generation != expected {
			e = ErrState
			return
		}
		if c.profile != s.info.Profile || c.capabilities != s.info.Capabilities {
			e = ErrState
			return
		}
		handoverAt := s.transportTime()
		handoverWall := time.Now()
		// Capture before closing the old carrier or resetting its UDP ledger.
		// This is intentionally limited to a carrier replacement; ordinary UDP
		// loss remains best-effort and is not turned into an unbounded datagram
		// retransmission queue.
		s.captureHandoverDatagrams(handoverWall)
		s.finishUDPBudgetEpisode(handoverAt)
		if s.current != nil {
			s.current.close()
			s.stats.Switches++
		}
		s.current = c
		s.boundCarrier.Store(c)
		s.info.Generation = c.generation
		s.info.Handle = append([]byte(nil), c.handle[:]...)
		s.stats.Generation = c.generation
		s.stats.Carrier = c.kind
		s.active = false
		s.peerDone = false
		s.synced = false
		s.localDoneAck = false
		s.resumeID = 0
		s.resumeSessionRevision = 0
		s.resumeSessionValue = 0
		s.resumeBaseline = nil
		s.peerResumeDone = nil
		s.syncAck = map[uint64]bool{}
		s.syncReceived = map[uint64]bool{}
		s.peerSyncCount = -1
		s.lastSync = time.Time{}
		s.syncFrames = nil
		s.syncCursor = 0
		s.pending = map[security.RecordMeta]sentRecord{}
		s.flight = 0
		s.queue = scheduler.New[protocol.Frame](1200, s.opts.MaxSessionBuffer)
		s.rebindTXDatagrams(handoverWall)
		s.requeueHandoverDatagrams()
		s.controlQueued = map[controlReceiptKey]uint64{}
		if s.controlTable != nil {
			s.controlTable.RebindCarrier()
		}
		if s.classTable != nil {
			s.classTable.RebindCarrier()
		}
		if s.operations != nil {
			// ResumeState/ResumeDone identify the carrier generation in their
			// immutable Serial field. Once this carrier is installed, a pending
			// operation from an older generation has no valid wire image: the
			// recovery snapshot is rebuilt below for the new generation. KeyUpdate
			// is carrier-scoped too: the new handshake starts at epoch zero, so a
			// completed epoch-1 operation from the previous carrier must not block
			// the next epoch-1 update, and a pending update cannot be replayed on
			// the new keys. Drop those superseded entries before rebinding the
			// remaining Session operations so an old control cannot later exhaust
			// the no-progress budget.
			s.operations.ForgetWhere(func(k operation.Key, _ operation.State) bool {
				if k.Kind == protocol.KeyUpdate {
					return true
				}
				return (k.Kind == protocol.ResumeState || k.Kind == protocol.ResumeDone) && k.Serial != c.generation
			})
			s.operations.RebindCarrier(c.generation)
		}
		s.lastReceive = time.Now()
		s.resetTransport(s.transportTime())
		if s.suspendedAt.IsZero() {
			s.suspendedAt = time.Now()
		}
		s.keyPending = false
		s.keyLastSend = time.Time{}
		s.bytesSinceKey = 0
		s.lastKey = time.Now()
		s.lastRXKey = time.Time{}
		s.rxDrainAt, s.txDrainAt = time.Time{}, time.Time{}
		s.rxCurrentUsed, s.txCurrentUsed = false, false
		s.pendingRXKey = 0
		for _, f := range s.streams {
			// Preserve incomplete datagram assemblies across the authenticated
			// replacement.  The sender may replay their missing fragments on the
			// new carrier; completed-message tombstones still suppress duplicates.
			if len(f.datagrams) > 0 {
				until := handoverWall.Add(max(time.Second, s.opts.defaults().RetainTimeout))
				for _, a := range f.datagrams {
					a.created = handoverWall
					a.handoverUntil = until
				}
			}
			for i := range f.chunks {
				f.chunks[i].queued = time.Time{}
			}
		}
	})
	if err != nil {
		return err
	}
	return e
}
func (s *Session) activate(bound ...*carrier) {
	s.post(func() {
		s.admissionMu.RLock()
		defer s.admissionMu.RUnlock()
		if s.terminating() {
			return
		}
		if len(bound) > 0 && s.current != bound[0] {
			return
		}
		if s.current == nil {
			return
		}
		if s.active {
			return
		}
		if s.resumeNextID == ^uint64(0) {
			s.cancel()
			return
		}
		s.resumeNextID++
		s.resumeID = s.resumeNextID
		// Establish a Session-level credit revision before freezing Flow
		// snapshots. The revision is included in ResumeDone even when no dirty
		// latest-control value changed after the snapshot boundary.
		sessionMax := s.maxSessionFrame()
		s.resumeSessionRevision = sessionMax.Offset
		s.resumeSessionValue = sessionMax.Value
		s.captureResumeBaseline()
		s.active = true
		ids := make([]uint64, 0, len(s.streams))
		for id := range s.streams {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			f := s.streams[id]
			snap := s.flowSnapshot(f)
			s.syncFrames = append(s.syncFrames, protocol.Frame{Kind: protocol.ResumeState, Flow: id, Value: s.current.generation, Data: encodeJSON(snap)})
		}
		s.synced = false
		s.peerResumeDone = nil
		s.scheduleLatestControls()
	})
}

// flowSnapshot freezes the semantic Flow state for one carrier generation.
// The revision fields are lower bounds for the peer's receive-side control
// state; they are deliberately distinct from ControlReceipt. A snapshot can
// establish a recovery baseline, but it never clears a latest-control retry
// record by itself.
func (s *Session) flowSnapshot(st *streamState) flowSnapshot {
	snap := flowSnapshot{ID: st.flow.id, Receive: st.receiveNext,
		Max: st.consumed + uint64(s.opts.MaxFlowBuffer), Result: st.openResult,
		Final: st.remoteFinal, Reset: st.reset}
	if s.classTable != nil && !st.reset && st.classTX.Valid() {
		snap.TXClass = &classWireSnapshot{Version: st.classTX.Version, Class: uint64(st.classTX.Class)}
	}
	if st.streamAckRevision != 0 && st.streamAckValue == snap.Receive {
		snap.AckRev = st.streamAckRevision
	}
	if st.maxFlowRevision != 0 && st.maxFlowValue == snap.Max {
		snap.MaxRev = st.maxFlowRevision
	}
	if st.openResultRevision != 0 && snap.Result != "" {
		snap.OpenRev = st.openResultRevision
	}
	if s.controlTable == nil {
		return snap
	}
	if v, err := s.controlTable.Snapshot(latestcontrol.Key{Kind: protocol.StreamAck, Flow: st.flow.id}); err == nil && v.State.Value == snap.Receive {
		snap.AckRev = v.State.Revision
	}
	if v, err := s.controlTable.Snapshot(latestcontrol.Key{Kind: protocol.MaxFlowData, Flow: st.flow.id}); err == nil && v.State.Value == snap.Max {
		snap.MaxRev = v.State.Revision
	}
	if snap.Result != "" {
		if v, err := s.controlTable.Snapshot(latestcontrol.Key{Kind: protocol.OpenResult, Flow: st.flow.id}); err == nil && string(v.State.Data) == snap.Result {
			snap.OpenRev = v.State.Revision
		}
	}
	return snap
}
func (s *Session) deliver(c *carrier, wire []byte) bool {
	return s.deliverPacket(packet{c: c, wire: wire})
}
func (s *Session) deliverPacket(p packet) bool {
	// Complete TCP records backpressure rather than drop. UDP remains a
	// nonblocking best-effort offer. Both use the same final retirement gate.
	return s.publishPacket(p, p.c != nil && p.c.kind == "tcp")
}
func (s *Session) readCarrier(c *carrier) {
	for {
		b, e := c.read()
		if e != nil {
			s.publishPacket(packet{c: c, err: e}, true)
			return
		}
		if !s.deliver(c, b) && c.kind == "tcp" {
			return
		}
	}
}
func (s *Session) run() {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	defer close(s.done)
	defer func() {
		s.stopBusiness()
		s.cleanupBusiness(s.transportTime())
		s.stopControl()
		s.retireMailbox()
		s.retireReaders()
		s.finalStats = s.snapshotStats(s.transportTime())
		if s.current != nil {
			s.current.close()
			s.current.keys = security.TransportKeys{}
			s.current = nil
		}
		s.boundCarrier.Store(nil)
	}()
	for {
		if s.controlContext().Err() != nil {
			return
		}
		if s.closeIntent.Load() != nil {
			s.closeTick(s.closeTime())
		}
		select {
		case <-s.controlContext().Done():
			return
		case <-s.closeWake:
			s.closeTick(s.closeTime())
		case fn := <-s.commands:
			fn()
		case p := <-s.incoming:
			s.receive(p)
		case <-s.dialResultWake():
			s.finishDialResults()
		case <-tick.C:
			s.maintain(s.transportTime())
		}
		s.flush()
	}
}
func (s *Session) enqueue(f protocol.Frame, class protocol.Class) bool {
	if s.terminating() {
		return false
	}
	f = s.normalizeLatestControl(f)
	if _, revision, tracked := latestControlRevision(f); tracked && s.controlTable != nil && revision == 0 {
		// Missing publication state is a local admission failure. Never put
		// an unversioned control on the wire or terminate unrelated flows.
		return false
	}
	if !s.ensureOperation(f) {
		return false
	}
	var key controlReceiptKey
	var revision uint64
	var tracked bool
	if lk, rev, ok := latestControlRevision(f); ok {
		key = controlReceiptKey{kind: lk.Kind, flow: lk.Flow}
		revision = rev
		tracked = true
	}
	cost := frameCost(f)
	// Requeued fragments already have a full-message reservation.
	if s.txDatagramReserved != 0 && s.txMessage(f) == nil && cost > s.opts.MaxSessionBuffer-s.pendingSendBytes() {
		return false
	}
	if s.queue.Push(f.Flow, class, cost, f) != nil {
		return false
	}
	s.datagramRequeued(f)
	if tracked {
		if s.controlQueued == nil {
			s.controlQueued = make(map[controlReceiptKey]uint64)
		}
		s.controlQueued[key] = revision
	}
	return true
}
func frameCost(f protocol.Frame) int {
	return protocol.HeaderSize + len(f.Data) + security.RecordOverhead + min(256, 1200-protocol.HeaderSize-len(f.Data)-security.RecordOverhead)
}

// operationStamp is a Session-owner monotonic clock. It survives carrier
// replacement, so a retry budget cannot be renewed by repeatedly switching
// UDP and TCP.
func (s *Session) operationStamp(now time.Time) time.Duration {
	if s.operationOrigin.IsZero() {
		s.operationOrigin = now
	}
	d := now.Sub(s.operationOrigin)
	if d < s.operationClock {
		d = s.operationClock
	}
	s.operationClock = d
	return d
}

// requestOperationKey returns the immutable identity for frames that require
// an operation-level terminal receipt. StreamData and Datagram retain their
// byte-offset/message semantics and are intentionally excluded.
func requestOperationKey(f protocol.Frame) (operation.Key, bool) {
	switch f.Kind {
	case protocol.Open:
		return operation.Key{Kind: f.Kind, Flow: f.Flow}, true
	case protocol.Fin:
		return operation.Key{Kind: f.Kind, Flow: f.Flow, Serial: f.Offset}, true
	case protocol.Reset:
		return operation.Key{Kind: f.Kind, Flow: f.Flow}, true
	case protocol.KeyUpdate:
		return operation.Key{Kind: f.Kind, Serial: f.Value}, true
	case protocol.TicketRefresh:
		return operation.Key{Kind: f.Kind, Serial: f.Value}, true
	case protocol.ResumeState:
		if f.Flags == 0 {
			return operation.Key{Kind: f.Kind, Flow: f.Flow, Serial: f.Value}, true
		}
	case protocol.ResumeDone:
		if f.Flags == 0 {
			// The peer's acknowledgement may report its own snapshot count;
			// only the generation belongs to this operation's identity.
			return operation.Key{Kind: f.Kind, Serial: f.Offset}, true
		}
	}
	return operation.Key{}, false
}

func acknowledgementOperationKey(f protocol.Frame) (operation.Key, bool) {
	switch f.Kind {
	case protocol.OpenResult:
		return operation.Key{Kind: protocol.Open, Flow: f.Flow}, true
	case protocol.FinAck:
		return operation.Key{Kind: protocol.Fin, Flow: f.Flow, Serial: f.Offset}, true
	case protocol.ResetAck:
		return operation.Key{Kind: protocol.Reset, Flow: f.Flow}, true
	case protocol.KeyUpdateAck:
		return operation.Key{Kind: protocol.KeyUpdate, Serial: f.Value}, true
	case protocol.TicketRefreshAck:
		return operation.Key{Kind: protocol.TicketRefresh, Serial: f.Value}, true
	case protocol.ResumeState:
		if f.Flags == 1 {
			return operation.Key{Kind: protocol.ResumeState, Flow: f.Flow, Serial: f.Value}, true
		}
	case protocol.ResumeDone:
		if f.Flags == 1 {
			return operation.Key{Kind: protocol.ResumeDone, Serial: f.Offset}, true
		}
	}
	return operation.Key{}, false
}

func (s *Session) ensureOperation(f protocol.Frame) bool {
	key, ok := requestOperationKey(f)
	if !ok || s.operations == nil {
		return true
	}
	_, _, err := s.operations.Ensure(key, s.operationStamp(s.transportTime()))
	return err == nil
}

func (s *Session) prepareOperation(f protocol.Frame) (*operation.Publication, bool, error) {
	key, ok := requestOperationKey(f)
	if !ok || s.operations == nil {
		return nil, false, nil
	}
	if !s.operations.Has(key) && !s.ensureOperation(f) {
		return nil, false, operation.ErrLimit
	}
	p, err := s.operations.Prepare(key, s.operationStamp(s.transportTime()))
	if err == operation.ErrCompleted {
		return nil, true, nil
	}
	if err == operation.ErrNotDue {
		return nil, false, err
	}
	if err != nil {
		return nil, false, err
	}
	return p, false, nil
}

func (s *Session) publishOperation(p *operation.Publication) error {
	if p == nil || s.operations == nil {
		return nil
	}
	return s.operations.Publish(p, s.operationStamp(s.transportTime()), s.current.generation)
}

func (s *Session) acknowledgeOperation(f protocol.Frame) {
	key, ok := acknowledgementOperationKey(f)
	if !ok || s.operations == nil || !s.operations.Has(key) {
		return
	}
	_, err := s.operations.Ack(key, s.operationStamp(s.transportTime()))
	if err == operation.ErrAckBeforeSend || err == operation.ErrUnknown {
		// A response can be observed immediately after the peer processes a
		// write but before local queue bookkeeping is serviced. The protocol
		// response is still valid and may be repeated by its logical sender.
		return
	}
	if err != nil {
		s.cancel()
	}
}

func (s *Session) maintainOperations(now time.Time) bool {
	if s.operations == nil {
		return true
	}
	_, exhausted, err := s.operations.Ready(s.operationStamp(now), s.operations.Usage())
	if err != nil {
		s.cancel()
		return false
	}
	for _, key := range exhausted {
		_ = s.operations.Fail(key, s.operationStamp(now))
		if key.Flow != 0 && (key.Kind == protocol.Open || key.Kind == protocol.Fin || key.Kind == protocol.Reset) {
			if st := s.streams[key.Flow]; st != nil {
				if !st.reset {
					s.reset(st, ErrState, false)
				} else {
					st.resetPending, st.resetAcked = false, true
					st.flow.fail(ErrState)
				}
				continue
			}
		}
		// Key epoch, ticket, and recovery completion are Session operations:
		// once their bounded lifetime is exhausted, fail the Session instead
		// of allowing an unbounded periodic resend loop.
		s.cancel()
		return false
	}
	return true
}

// operationReadyForSchedule reports whether the logical request can be
// placed back on the carrier queue. The operation table owns the retry
// deadline; TCP maintenance must not add a second fixed-period clock that
// can race that budget. A missing entry is treated as ready because enqueue
// will create the operation atomically before the frame is written.
func (s *Session) operationReadyForSchedule(f protocol.Frame, now time.Time) bool {
	key, ok := requestOperationKey(f)
	if !ok || s.operations == nil {
		return true
	}
	state, err := s.operations.Snapshot(key)
	if err == operation.ErrUnknown {
		return true
	}
	if err != nil || state.Completed || state.Failed {
		return false
	}
	stamp := s.operationStamp(now)
	return state.Attempts == 0 || state.Resend || stamp >= state.NextSend
}

// maintainKeyDrain retires an old record epoch only after the new epoch has
// been used on the wire. The use proof prevents a timer from deleting the
// only key that can authenticate a peer which has not installed the update
// yet. UDP additionally keeps the old ACK scope until its pending ACK is
// written; if that drain cannot complete within the bounded lifetime, the
// carrier is suspended and recovered with a fresh authenticated path.
func (s *Session) maintainKeyDrain(now time.Time) bool {
	if s.rxDrainAt.IsZero() && s.txDrainAt.IsZero() {
		return true
	}
	minimum := max(100*time.Millisecond, min(2*time.Second, 2*s.rtt))
	timeout := s.opts.KeyDrainTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if !s.rxDrainAt.IsZero() && now.Sub(s.rxDrainAt) >= timeout && !s.rxCurrentUsed {
		s.transportStalled()
		return false
	}
	if !s.txDrainAt.IsZero() && now.Sub(s.txDrainAt) >= timeout && !s.txCurrentUsed {
		s.transportStalled()
		return false
	}
	if !s.rxDrainAt.IsZero() && s.rxCurrentUsed && now.Sub(s.rxDrainAt) >= minimum {
		pending := s.udpPath != nil && s.udpPath.history.PreviousPending()
		if !pending {
			s.current.rx.RetirePrevious()
			if s.udpPath != nil {
				s.udpPath.history.RetirePrevious()
				s.udpPath.rxPrevious = nil
			}
			s.rxDrainAt = time.Time{}
			s.rxCurrentUsed = false
		} else if now.Sub(s.rxDrainAt) >= timeout {
			s.transportStalled()
			return false
		}
	}
	if !s.txDrainAt.IsZero() && s.txCurrentUsed && now.Sub(s.txDrainAt) >= minimum {
		if s.udpPath != nil {
			if err := s.udpPath.ledger.RetirePrevious(); err != nil {
				if now.Sub(s.txDrainAt) >= timeout {
					s.transportStalled()
					return false
				}
			} else {
				s.udpPath.txPrevious = nil
				s.txDrainAt = time.Time{}
				s.txCurrentUsed = false
			}
		} else {
			s.current.tx.RetirePrevious()
			s.txDrainAt = time.Time{}
			s.txCurrentUsed = false
		}
	}
	return s.active
}

func (s *Session) classForFrame(f protocol.Frame) protocol.Class {
	if f.Kind == protocol.StreamData || f.Kind == protocol.Datagram || f.Kind == protocol.DatagramRepairFrame {
		return s.classFor(f.Flow)
	}
	return protocol.Interactive
}

// controlStamp is an owner-confined monotonic clock for latest-control. It is
// independent from carrier health time so a new carrier or a test clock cannot
// move the bounded retry table backwards.
func (s *Session) controlStamp(now time.Time) time.Duration {
	if s.controlOrigin.IsZero() {
		s.controlOrigin = now
	}
	d := now.Sub(s.controlOrigin)
	if d < s.controlClock {
		d = s.controlClock
	}
	s.controlClock = d
	return d
}

func latestControlRevision(f protocol.Frame) (latestcontrol.Key, uint64, bool) {
	var key latestcontrol.Key
	var revision uint64
	switch f.Kind {
	case protocol.StreamAck:
		key = latestcontrol.Key{Kind: f.Kind, Flow: f.Flow}
		revision = f.Value
	case protocol.MaxFlowData:
		key = latestcontrol.Key{Kind: f.Kind, Flow: f.Flow}
		revision = f.Offset
	case protocol.MaxSessionData:
		key = latestcontrol.Key{Kind: f.Kind}
		revision = f.Offset
	case protocol.OpenResult:
		key = latestcontrol.Key{Kind: f.Kind, Flow: f.Flow}
		revision = f.Offset
	default:
		return latestcontrol.Key{}, 0, false
	}
	return key, revision, true
}

// normalizeLatestControl records semantic state in the bounded table and
// returns the current wire representation. Stale queued copies therefore
// collapse to the newest revision before any carrier write.
func (s *Session) normalizeLatestControl(f protocol.Frame) protocol.Frame {
	if s.controlTable == nil {
		return f
	}
	var (
		key  latestcontrol.Key
		v    uint64
		data []byte
	)
	switch f.Kind {
	case protocol.StreamAck:
		key, v = latestcontrol.Key{Kind: f.Kind, Flow: f.Flow}, f.Offset
	case protocol.MaxFlowData:
		key, v = latestcontrol.Key{Kind: f.Kind, Flow: f.Flow}, f.Value
	case protocol.MaxSessionData:
		key, v = latestcontrol.Key{Kind: f.Kind}, f.Value
	case protocol.OpenResult:
		key, data = latestcontrol.Key{Kind: f.Kind, Flow: f.Flow}, f.Data
	default:
		return f
	}
	state, _, err := s.controlTable.Update(key, v, data, s.controlStamp(s.transportTime()))
	if err != nil {
		if snap, snapErr := s.controlTable.Snapshot(key); snapErr == nil {
			state = snap.State
		} else {
			// Preserve a rejected sentinel through every caller, including a
			// queued frame that arrived with a stale nonzero revision. The
			// enqueue and send preflight gates both reject revision zero.
			if f.Kind == protocol.StreamAck {
				f.Value = 0
			} else {
				f.Offset = 0
			}
			return f
		}
	}
	switch f.Kind {
	case protocol.StreamAck:
		return protocol.Frame{Kind: f.Kind, Flags: f.Flags, Flow: f.Flow, Offset: state.Value, Value: state.Revision}
	case protocol.MaxFlowData, protocol.MaxSessionData:
		return protocol.Frame{Kind: f.Kind, Flags: f.Flags, Flow: f.Flow, Offset: state.Revision, Value: state.Value}
	case protocol.OpenResult:
		return protocol.Frame{Kind: f.Kind, Flags: f.Flags, Flow: f.Flow, Offset: state.Revision, Data: append([]byte(nil), state.Data...)}
	default:
		return f
	}
}

func (s *Session) streamAckFrame(st *streamState) protocol.Frame {
	f := s.normalizeLatestControl(protocol.Frame{Kind: protocol.StreamAck, Flow: st.flow.id, Offset: st.receiveNext})
	st.streamAckRevision, st.streamAckValue = f.Value, f.Offset
	return f
}

func (s *Session) maxFlowFrame(st *streamState) protocol.Frame {
	f := s.normalizeLatestControl(protocol.Frame{Kind: protocol.MaxFlowData, Flow: st.flow.id, Value: st.consumed + uint64(s.opts.MaxFlowBuffer)})
	st.maxFlowRevision, st.maxFlowValue = f.Offset, f.Value
	return f
}

func (s *Session) maxSessionFrame() protocol.Frame {
	f := s.normalizeLatestControl(protocol.Frame{Kind: protocol.MaxSessionData, Value: s.totalConsumed + uint64(s.opts.MaxSessionBuffer)})
	s.maxSessionRevision, s.maxSessionValue = f.Offset, f.Value
	return f
}

func (s *Session) openResultFrame(st *streamState) protocol.Frame {
	f := s.normalizeLatestControl(protocol.Frame{Kind: protocol.OpenResult, Flow: st.flow.id, Data: []byte(st.openResult)})
	st.openResultRevision = f.Offset
	return f
}

func (s *Session) latestStateFrame(st latestcontrol.State) protocol.Frame {
	switch st.Key.Kind {
	case protocol.StreamAck:
		return protocol.Frame{Kind: st.Key.Kind, Flow: st.Key.Flow, Offset: st.Value, Value: st.Revision}
	case protocol.MaxFlowData, protocol.MaxSessionData:
		return protocol.Frame{Kind: st.Key.Kind, Flow: st.Key.Flow, Offset: st.Revision, Value: st.Value}
	case protocol.OpenResult:
		return protocol.Frame{Kind: st.Key.Kind, Flow: st.Key.Flow, Offset: st.Revision, Data: append([]byte(nil), st.Data...)}
	default:
		return protocol.Frame{}
	}
}

func (s *Session) scheduleLatestControls() {
	if s.controlTable == nil {
		return
	}
	ready, exhausted, err := s.controlTable.Ready(s.controlStamp(s.transportTime()), 32)
	if err != nil {
		return
	}
	if len(exhausted) > 0 {
		s.transportStalled()
		return
	}
	for _, state := range ready {
		key := controlReceiptKey{kind: state.Key.Kind, flow: state.Key.Flow}
		if s.controlQueued[key] == state.Revision {
			continue
		}
		s.enqueue(s.latestStateFrame(state), protocol.Interactive)
	}
}

func (s *Session) prepareLatestControl(f protocol.Frame) (*latestcontrol.Publication, bool, error) {
	key, revision, ok := latestControlRevision(f)
	if !ok || s.controlTable == nil {
		return nil, false, nil
	}
	if revision == 0 {
		return nil, true, nil
	}
	p, err := s.controlTable.Prepare(key, revision, s.controlStamp(s.transportTime()))
	if err == latestcontrol.ErrNotDue || err == latestcontrol.ErrStale || err == latestcontrol.ErrExhausted {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	return p, false, nil
}

func (s *Session) publishLatestControl(p *latestcontrol.Publication, base time.Duration) error {
	if p == nil || s.controlTable == nil {
		return nil
	}
	base = max(200*time.Millisecond, min(2*time.Second, base))
	return s.controlTable.Publish(p, s.controlStamp(s.transportTime()), base)
}

func (s *Session) enqueueControlReceipt(kind protocol.Kind, flow, revision uint64) {
	f, err := controlreceipt.New(kind, flow, revision)
	if err == nil {
		s.enqueue(f, protocol.Interactive)
	}
}
func (s *Session) flush() {
	if s.terminating() {
		s.closeTick(s.closeTime())
		return
	}
	s.maintainClassControls()
	if s.current == nil || !s.active {
		return
	}
	if s.current.kind == "udp" {
		s.flushUDP()
		return
	}
	for count := 0; count < 4; count++ {
		if s.terminating() {
			return
		}
		f, ok := s.nextSendFrame(count)
		if !ok {
			return
		}
		if !s.datagramCanSend(f, time.Now()) {
			continue
		}
		f = s.normalizeLatestControl(f)
		if key, revision, tracked := latestControlRevision(f); tracked {
			ck := controlReceiptKey{kind: key.Kind, flow: key.Flow}
			if s.controlQueued[ck] == revision {
				delete(s.controlQueued, ck)
			}
		}
		operationPublication, operationSkip, operationErr := s.prepareOperation(f)
		if operationErr != nil {
			if operationErr == operation.ErrNotDue {
				s.enqueue(f, s.classForFrame(f))
				return
			}
			if operationErr == operation.ErrExhausted {
				s.maintainOperations(s.transportTime())
				return
			}
			s.cancel()
			return
		}
		if operationSkip {
			continue
		}
		publication, skip, prepErr := s.prepareLatestControl(f)
		if prepErr != nil {
			s.cancel()
			return
		}
		if skip {
			continue
		}
		classPublication, classSkip, classErr := s.prepareClassControl(f)
		if classErr != nil {
			s.cancel()
			return
		}
		if classSkip {
			continue
		}
		if (!s.peerDone || !s.localDoneAck) && !syncAllowed(f) {
			s.enqueue(f, s.classForFrame(f))
			return
		}
		plain, e := protocol.Encode([]protocol.Frame{f})
		if e != nil {
			s.cancel()
			return
		}
		plain, e = obfuscation.Pad(plain, security.MaxRecordSize-security.RecordOverhead)
		if e != nil {
			s.cancel()
			return
		}
		wire, meta, e := s.current.tx.Seal(plain)
		if e != nil {
			s.cancel()
			return
		}
		if s.terminating() {
			return
		}
		if e = s.current.writeUntil(wire, s.datagramWriteDeadline(f)); e != nil {
			s.datagramWriteFailed(f)
			// The latest-control publication remains uncommitted on failed I/O;
			// the carrier will be rebound and the state scheduled again.
			s.suspend()
			return
		}
		s.datagramCommitted(f)
		s.handoverDatagramCommitted(f)
		if !s.txDrainAt.IsZero() && meta.Epoch == s.current.tx.Epoch() {
			s.txCurrentUsed = true
		}
		if e = s.publishOperation(operationPublication); e != nil {
			s.cancel()
			return
		}
		if e = s.publishLatestControl(publication, 2*s.rtt); e != nil {
			s.cancel()
			return
		}
		if e = s.publishClassControl(f, classPublication, 2*s.rtt); e != nil {
			s.cancel()
			return
		}
		s.stats.WireSent += uint64(len(wire))
		s.bytesSinceKey += uint64(len(wire))
	}
}
func (s *Session) receive(p packet) {
	if s.current != p.c {
		return
	}
	if p.err != nil {
		if s.terminating() {
			s.stopCloseControl()
			return
		}
		s.suspend()
		return
	}
	plain, meta, e := p.c.rx.Open(p.wire)
	if e != nil {
		s.stats.Dropped++
		return
	}
	// A newly installed receive epoch is not considered usable merely because
	// KEY_UPDATE was accepted. Seeing an authenticated record under that epoch
	// is the proof that the peer installed its sending key; only then may the
	// old receive epoch enter its bounded drain lifecycle.
	if !s.rxDrainAt.IsZero() && meta.Epoch == p.c.rx.Epoch() {
		s.rxCurrentUsed = true
	}
	plain, e = obfuscation.Unpad(plain)
	if e != nil {
		s.cancel()
		return
	}
	frames, e := protocol.Decode(plain)
	if e != nil {
		s.cancel()
		return
	}
	s.lastReceive = s.transportTime()
	s.stats.WireReceived += uint64(len(p.wire))
	if p.c.kind == "udp" && !s.terminating() {
		if !s.observeUDPRecord(meta, frames, s.lastReceive) {
			return
		}
	}
	for _, f := range frames {
		s.handle(f)
	}
}
func (s *Session) handle(f protocol.Frame) {
	if f.Kind == protocol.SessionClose || f.Kind == protocol.SessionCloseAck {
		s.handleCloseControl(f, s.closeTime())
		return
	}
	s.admissionMu.RLock()
	defer s.admissionMu.RUnlock()
	if s.terminating() {
		return
	}
	switch f.Kind {
	case protocol.PacketAck:
		s.receiveUDPACK(f)
	case protocol.Ping:
		s.enqueue(protocol.Frame{Kind: protocol.Pong, Value: f.Value}, protocol.Interactive)
	case protocol.Pong:
		if s.current != nil && s.current.kind == "udp" {
			s.receiveUDPPong(f.Value, s.transportTime())
		}
	case protocol.ResumeState:
		if f.Flow == 0 || f.Offset != 0 || f.Flags > 1 || len(f.Data) == 0 && f.Flags == 0 {
			s.cancel()
			return
		}
		if len(s.syncReceived) >= maxSessionFlowStates && !s.syncReceived[f.Flow] {
			s.cancel()
			return
		}
		if s.current == nil || f.Value != s.current.generation {
			s.cancel()
			return
		}
		if f.Flags == 1 {
			known := false
			for _, frame := range s.syncFrames {
				if frame.Flow == f.Flow {
					known = true
					break
				}
			}
			if !known {
				s.cancel()
				return
			}
			// Only a snapshot that belongs to this carrier generation and to the
			// concrete recovery set may complete its operation.  In particular,
			// do not let an old/unknown receipt consume a newly rebuilt snapshot.
			s.acknowledgeOperation(f)
			s.syncAck[f.Flow] = true
			return
		}
		if f.Flags != 0 {
			s.cancel()
			return
		}
		var snap flowSnapshot
		if decodeJSON(f.Data, &snap) != nil || snap.ID != f.Flow || !s.validClassSnapshot(snap) {
			s.cancel()
			return
		}
		st := s.streams[f.Flow]
		if st == nil {
			if s.client && !snap.Reset {
				s.cancel()
				return
			}
			s.syncReceived[f.Flow] = true
			s.enqueue(protocol.Frame{Kind: protocol.ResumeState, Flags: 1, Flow: f.Flow, Value: f.Value}, protocol.Interactive)
			s.maybePeerSync()
			return
		}
		if snap.Reset {
			s.reset(st, io.EOF, false)
		} else {
			if !s.mergeClassSnapshot(st, snap) {
				s.cancel()
				return
			}
			if !s.applyResumeControls(st, snap) || snap.Receive < st.sendAck || !s.ack(st, snap.Receive) {
				s.cancel()
				return
			}
			st.maxRemote = max(st.maxRemote, snap.Max)
			if s.client && snap.Result != "" {
				s.result(st, snap.Result)
			}
		}
		s.syncReceived[f.Flow] = true
		s.enqueue(protocol.Frame{Kind: protocol.ResumeState, Flags: 1, Flow: f.Flow, Value: f.Value}, protocol.Interactive)
		s.maybePeerSync()
	case protocol.ResumeDone:
		if s.current == nil || f.Offset != s.current.generation || f.Flow > maxSessionFlowStates {
			s.cancel()
			return
		}
		state, legacy, err := decodeResumeDoneFrame(f)
		if err != nil || state.Generation != s.current.generation || state.SnapshotCount != f.Flow {
			s.cancel()
			return
		}
		if f.Flags == 1 {
			if f.Value != 0 || f.Flow != uint64(len(s.syncFrames)) || len(s.syncAck) != len(s.syncFrames) {
				s.cancel()
				return
			}
			if !legacy {
				want, ok, resumeErr := s.resumeDoneState()
				if resumeErr != nil {
					s.cancel()
					return
				}
				if !ok {
					s.cancel()
					return
				}
				if !resumeStateCovers(want, state) {
					if resumeStateSupersedes(want, state) {
						// A receipt for the frozen snapshot is valid, but it
						// predates a dirty latest-control revision created while
						// the peer was applying it. Keep the operation pending and
						// publish a new barrier instead of clearing newer state.
						if frame, ok := s.resumeDoneFrame(0); ok {
							s.enqueue(frame, protocol.Interactive)
						}
						return
					}
					s.cancel()
					return
				}
			}
			s.acknowledgeOperation(f)
			if s.localDoneAck {
				return
			}
			s.localDoneAck = true
			s.synced = true
			s.signalFlows()
			if s.peerDone {
				s.suspendedAt = time.Time{}
			}
			return
		}
		if f.Flags != 0 {
			s.cancel()
			return
		}
		if f.Value == 0 {
			s.cancel()
			return
		}
		if !legacy && state.SnapshotID == 0 {
			s.cancel()
			return
		}
		if s.peerResumeDone != nil {
			if s.peerResumeDone.Generation != state.Generation || s.peerResumeDone.SnapshotCount != state.SnapshotCount {
				s.cancel()
				return
			}
			if !legacy && s.peerResumeDone.Version == resumeDoneVersion {
				existing := *s.peerResumeDone
				switch {
				case resumeStateCovers(existing, state):
					// The same barrier is a normal retry; re-emit its receipt.
					s.maybePeerSync()
					return
				case resumeStateSupersedes(state, existing):
					// A sender may publish a higher dirty revision while the
					// peer is applying the previous barrier. Apply the newer
					// monotonic state and acknowledge that barrier instead of
					// treating it as a conflicting duplicate.
					if !s.applyResumeDoneState(state) {
						s.cancel()
						return
					}
					s.peerResumeDone = &state
					s.maybePeerSync()
					return
				case resumeStateSupersedes(existing, state):
					// A stale request is harmless; the current barrier receipt
					// still gives the sender a chance to converge.
					s.maybePeerSync()
					return
				default:
					s.cancel()
					return
				}
			}
			// Duplicate request: leave the applied barrier intact and let
			// maybePeerSync re-emit its acknowledgement when needed. This is
			// required when the first snapshot receipt was lost on the carrier.
			s.maybePeerSync()
			return
		}
		s.peerSyncCount = int(state.SnapshotCount)
		s.peerResumeDone = &state
		s.maybePeerSync()
	case protocol.Open:
		s.handleOpen(f)
	case protocol.OpenResult:
		st := s.streams[f.Flow]
		if !s.client || st == nil || f.Flags != 0 || f.Value != 0 || f.Offset == 0 || len(f.Data) == 0 {
			s.cancel()
			return
		}
		result := string(f.Data)
		if st.peerOpenResultRevision != 0 {
			if f.Offset < st.peerOpenResultRevision {
				s.acknowledgeOperation(f)
				s.enqueueControlReceipt(protocol.OpenResult, f.Flow, f.Offset)
				return
			}
			if result != st.peerOpenResultValue {
				s.cancel()
				return
			}
		}
		st.peerOpenResultRevision = max(st.peerOpenResultRevision, f.Offset)
		st.peerOpenResultValue = result
		s.acknowledgeOperation(f)
		s.result(st, result)
		s.enqueueControlReceipt(protocol.OpenResult, f.Flow, f.Offset)
	case protocol.StreamData:
		st := s.streams[f.Flow]
		if st == nil || st.reset {
			return
		}
		if !s.peerDone {
			s.cancel()
			return
		}
		s.data(st, f)
	case protocol.StreamAck:
		st := s.streams[f.Flow]
		if st == nil {
			return
		}
		if f.Value != 0 {
			if f.Value < st.peerStreamAckRevision {
				if f.Offset > st.sendNext {
					s.cancel()
					return
				}
				s.enqueueControlReceipt(protocol.StreamAck, f.Flow, f.Value)
				return
			}
			if f.Value == st.peerStreamAckRevision && f.Offset != st.peerStreamAckValue {
				s.cancel()
				return
			}
			if f.Value > st.peerStreamAckRevision && f.Offset < st.peerStreamAckValue {
				s.cancel()
				return
			}
		}
		if !s.ack(st, f.Offset) {
			s.cancel()
			return
		}
		if f.Value != 0 {
			st.peerStreamAckRevision, st.peerStreamAckValue = f.Value, f.Offset
			s.enqueueControlReceipt(protocol.StreamAck, f.Flow, f.Value)
		}
	case protocol.MaxFlowData:
		st := s.streams[f.Flow]
		if st != nil {
			if f.Offset != 0 {
				if f.Offset < st.peerMaxFlowRevision {
					s.enqueueControlReceipt(protocol.MaxFlowData, f.Flow, f.Offset)
					return
				}
				if f.Offset == st.peerMaxFlowRevision && f.Value != st.peerMaxFlowValue || f.Offset > st.peerMaxFlowRevision && f.Value < st.peerMaxFlowValue {
					s.cancel()
					return
				}
				st.peerMaxFlowRevision, st.peerMaxFlowValue = f.Offset, f.Value
			}
			st.maxRemote = max(st.maxRemote, f.Value)
			st.flow.signal()
			if f.Offset != 0 {
				s.enqueueControlReceipt(protocol.MaxFlowData, f.Flow, f.Offset)
			}
		}
	case protocol.MaxSessionData:
		if f.Offset != 0 {
			if f.Offset < s.peerMaxSessionRevision {
				s.enqueueControlReceipt(protocol.MaxSessionData, 0, f.Offset)
				return
			}
			if f.Offset == s.peerMaxSessionRevision && f.Value != s.peerMaxSessionValue || f.Offset > s.peerMaxSessionRevision && f.Value < s.peerMaxSessionValue {
				s.cancel()
				return
			}
			s.peerMaxSessionRevision, s.peerMaxSessionValue = f.Offset, f.Value
		}
		s.peerSessionMax = max(s.peerSessionMax, f.Value)
		for _, st := range s.streams {
			st.flow.signal()
		}
		if f.Offset != 0 {
			s.enqueueControlReceipt(protocol.MaxSessionData, 0, f.Offset)
		}
	case protocol.ControlReceipt:
		r, err := controlreceipt.Decode(f)
		if err != nil {
			s.cancel()
			return
		}
		if s.controlReceipts == nil {
			s.controlReceipts = make(map[controlReceiptKey]uint64)
		}
		key := controlReceiptKey{kind: r.Kind, flow: r.Flow}
		if r.Revision > s.controlReceipts[key] {
			s.controlReceipts[key] = r.Revision
		}
		if s.controlTable != nil {
			lk := latestcontrol.Key{Kind: r.Kind, Flow: r.Flow}
			if _, snapErr := s.controlTable.Snapshot(lk); snapErr != nil {
				s.cancel()
				return
			}
			receipt, receiptErr := s.controlTable.Receipt(lk, r.Revision, s.controlStamp(s.transportTime()))
			if receiptErr != nil {
				s.cancel()
				return
			}
			if !s.client && r.Kind == protocol.OpenResult && receipt.Installed {
				if st := s.streams[r.Flow]; st != nil && st.openResult == "ok" {
					s.enableClassControl(st)
				}
			}
			delete(s.controlQueued, key)
		}
	case protocol.Fin:
		st := s.streams[f.Flow]
		if st == nil || st.reset {
			return
		}
		if st.target.Network != "tcp" {
			s.cancel()
			return
		}
		if f.Offset < st.receiveNext || st.remoteFinal != nil && *st.remoteFinal != f.Offset {
			s.cancel()
			return
		}
		final := f.Offset
		st.remoteFinal = &final
		if st.finAckSent {
			// A duplicate FIN is the operation-level retry path when the
			// original FinAck was lost after the peer committed the FIN.
			s.enqueue(protocol.Frame{Kind: protocol.FinAck, Flow: st.flow.id, Offset: final}, protocol.Interactive)
			return
		}
		s.finishReceive(st)
	case protocol.FinAck:
		st := s.streams[f.Flow]
		if f.Flow == 0 || f.Flags != 0 || f.Value != 0 || len(f.Data) != 0 {
			s.cancel()
			return
		}
		if st == nil || st.reset {
			return
		}
		if st.localFinal == nil || *st.localFinal != f.Offset {
			s.cancel()
			return
		}
		s.acknowledgeOperation(f)
		st.finAck = true
		s.ack(st, f.Offset)
	case protocol.Reset:
		if f.Flow == 0 || f.Flags != 0 || f.Offset != 0 || f.Value != 0 || len(f.Data) != 0 {
			s.cancel()
			return
		}
		st := s.streams[f.Flow]
		if st != nil {
			s.reset(st, io.EOF, false)
		} else if !s.rememberResetTombstone(f.Flow, s.transportTime()) {
			// Forgetting an authenticated terminal decision could allow a
			// reordered OPEN to allocate a target after the tombstone budget is
			// exhausted. Failing the Session is safer than evicting silently.
			s.cancel()
			return
		}
		s.enqueue(protocol.Frame{Kind: protocol.ResetAck, Flow: f.Flow}, protocol.Interactive)
	case protocol.ResetAck:
		if f.Flow == 0 || f.Flags != 0 || f.Offset != 0 || f.Value != 0 || len(f.Data) != 0 {
			s.cancel()
			return
		}
		if st := s.streams[f.Flow]; st != nil {
			if st.resetAcked {
				s.acknowledgeOperation(f)
				return
			}
			if !st.resetPending {
				return
			}
			s.acknowledgeOperation(f)
			st.resetAcked = true
			st.resetPending = false
		}
	case protocol.Datagram:
		if s.peerDone {
			s.datagram(f)
		}
	case protocol.DatagramRepairFrame:
		if s.peerDone {
			s.datagramRepair(f)
		}
	case protocol.ClassUpdate:
		s.handleClassControl(f)
	case protocol.KeyUpdate:
		if s.current == nil || f.Flags != 0 || f.Flow != 0 || f.Offset != 0 || len(f.Data) != 0 || f.Value == 0 {
			s.cancel()
			return
		}
		current := uint64(s.current.rx.Epoch())
		if current >= uint64(^uint32(0)) {
			s.cancel()
			return
		}
		if f.Value == current+1 {
			if s.current.kind == "udp" {
				if s.udpPath == nil {
					s.transportStalled()
					return
				}
				old := s.current.rx.Epoch()
				if err := s.udpPath.history.AdvanceEpoch(uint32(f.Value)); err != nil {
					// A second peer update can arrive before the prior RX epoch
					// is retired. Hold the authenticated proposal until the old
					// ACK scope is drained; treating this ordering as a dead path
					// would destroy an otherwise healthy Session.
					if errors.Is(err, udptransport.ErrEpochBusy) {
						s.pendingRXKey = uint32(f.Value)
						return
					}
					s.transportStalled()
					return
				}
				s.udpPath.rxPrevious = &old
			}
			if s.current.rx.UpdateKey(uint32(f.Value)) != nil {
				s.cancel()
				return
			}
			s.lastRXKey = s.transportTime()
			s.rxDrainAt = s.transportTime()
			s.rxCurrentUsed = false
			s.enqueue(protocol.Frame{Kind: protocol.KeyUpdateAck, Value: f.Value}, protocol.Interactive)
		} else if f.Value == current {
			// A duplicate request is the normal loss-recovery path.  Re-emit
			// the acknowledgement without changing the receive key again.
			s.enqueue(protocol.Frame{Kind: protocol.KeyUpdateAck, Value: f.Value}, protocol.Interactive)
		} else if f.Value < current {
			// Older authenticated records can arrive during the bounded drain.
			// They are stale, but cannot move the key backwards.
			return
		} else {
			s.cancel()
			return
		}
	case protocol.KeyUpdateAck:
		if s.current == nil || f.Flags != 0 || f.Flow != 0 || f.Offset != 0 || len(f.Data) != 0 || f.Value == 0 {
			s.cancel()
			return
		}
		current := uint64(s.current.tx.Epoch())
		if current >= uint64(^uint32(0)) {
			s.cancel()
			return
		}
		if f.Value <= current {
			return
		}
		if f.Value > current+1 || !s.keyPending {
			if f.Value > current+1 {
				s.cancel()
			}
			return
		}
		if f.Value == current+1 {
			if s.current.kind == "udp" {
				if s.udpPath == nil {
					s.transportStalled()
					return
				}
				old := s.current.tx.Epoch()
				if err := s.udpPath.ledger.AdvanceEpoch(uint32(f.Value)); err != nil {
					s.transportStalled()
					return
				}
				s.udpPath.txPrevious = &old
			}
			if s.current.tx.UpdateKey(uint32(f.Value)) != nil {
				s.cancel()
				return
			}
			s.keyPending = false
			s.keyLastSend = time.Time{}
			s.bytesSinceKey = 0
			s.lastKey = s.transportTime()
			s.txDrainAt = s.transportTime()
			s.txCurrentUsed = false
			s.acknowledgeOperation(f)
		}
	case protocol.TicketRefresh:
		s.receiveTicket(f, time.Now())
	case protocol.TicketRefreshAck:
		if s.client || f.Flow != 0 || f.Flags != 0 || f.Offset != 0 || len(f.Data) != 0 || f.Value == 0 {
			s.cancel()
			return
		}
		if s.ticketPending == 0 || f.Value != s.ticketPending {
			// Stale/future ACKs do not authorize a ticket transition and are
			// intentionally ignored; the pending issue remains retransmittable.
			return
		}
		s.acknowledgeOperation(f)
		s.ticketPending = 0
	default:
		s.cancel()
	}
}

// applyResumeControls installs only monotonic lower bounds learned from a
// recovery snapshot. It intentionally does not call latestcontrol.Receipt:
// snapshot application is a separate recovery transaction and cannot prove
// that a particular latest-control record was published on this carrier.
func (s *Session) applyResumeControls(st *streamState, snap flowSnapshot) bool {
	if snap.AckRev != 0 {
		if snap.AckRev < st.peerStreamAckRevision {
			if snap.Receive > st.peerStreamAckValue {
				return false
			}
		} else if snap.AckRev == st.peerStreamAckRevision {
			if st.peerStreamAckRevision != 0 && snap.Receive != st.peerStreamAckValue {
				return false
			}
		} else {
			if snap.Receive < st.peerStreamAckValue {
				return false
			}
			st.peerStreamAckRevision = snap.AckRev
			st.peerStreamAckValue = snap.Receive
		}
	}
	if snap.MaxRev != 0 {
		if snap.MaxRev < st.peerMaxFlowRevision {
			if snap.Max > st.peerMaxFlowValue {
				return false
			}
		} else if snap.MaxRev == st.peerMaxFlowRevision {
			if st.peerMaxFlowRevision != 0 && snap.Max != st.peerMaxFlowValue {
				return false
			}
		} else {
			if snap.Max < st.peerMaxFlowValue {
				return false
			}
			st.peerMaxFlowRevision = snap.MaxRev
			st.peerMaxFlowValue = snap.Max
		}
	}
	if snap.OpenRev != 0 {
		if snap.Result == "" {
			return false
		}
		if st.peerOpenResultRevision != 0 && snap.OpenRev <= st.peerOpenResultRevision {
			return snap.Result == st.peerOpenResultValue
		}
		if st.peerOpenResultRevision != 0 && snap.Result != st.peerOpenResultValue {
			return false
		}
		st.peerOpenResultRevision = snap.OpenRev
		st.peerOpenResultValue = snap.Result
	} else if st.peerOpenResultRevision != 0 && snap.Result != "" && snap.Result != st.peerOpenResultValue {
		return false
	}
	return true
}
func (s *Session) suspend() {
	if s.terminating() {
		return
	}
	s.finishUDPBudgetEpisode(s.transportTime())
	if s.current != nil {
		s.current.close()
	}
	s.active = false
	if s.suspendedAt.IsZero() {
		s.suspendedAt = time.Now()
	}
	s.stats.Carrier = "suspended"
}
func (s *Session) maintain(now time.Time) {
	if s.terminating() {
		s.closeTick(s.closeTime())
		return
	}
	s.expireTXDatagrams(time.Now())
	s.tickClassification()
	s.maintainClassControls()
	if s.authority != nil && s.authority.revoked.Load() || !s.info.lifetimeUntil.IsZero() && !s.info.lifetimeUntil.After(now) {
		s.cancel()
		return
	}
	for _, st := range s.streams {
		for id, a := range st.datagrams {
			expired := !a.handoverUntil.IsZero() && !now.Before(a.handoverUntil)
			if a.handoverUntil.IsZero() {
				expired = now.Sub(a.created) > time.Second
			}
			if expired {
				delete(st.datagrams, id)
				st.completed[id] = true
			}
		}
	}
	if !s.suspendedAt.IsZero() && now.Sub(s.suspendedAt) > s.opts.RetainTimeout {
		s.cancel()
		return
	}
	if !s.active {
		if !s.suspendedAt.IsZero() && now.Sub(s.suspendedAt) > s.opts.RetainTimeout {
			s.cancel()
		}
		return
	}
	if !s.maintainOperations(now) {
		return
	}
	s.scheduleLatestControls()
	if !s.active {
		return
	}
	if s.current.kind == "tcp" && now.Sub(s.lastReceive) > s.opts.FailureTimeout {
		s.suspend()
		return
	}
	if now.Sub(s.lastProbe) > s.opts.ProbeInterval && (s.current.kind != "udp" || s.udpPath != nil && s.udpPath.ledger.Snapshot().Live == 0) {
		s.enqueue(protocol.Frame{Kind: protocol.Ping, Value: uint64(now.UnixNano())}, protocol.Interactive)
		s.lastProbe = now
	}
	rto := max(200*time.Millisecond, min(2*time.Second, 2*s.rtt))
	if s.current.kind == "udp" {
		s.maintainUDP(now)
		if !s.active {
			return
		}
	}
	// Keep one old TX epoch until its outstanding records are retired. A new
	// proposal before that drain would overwrite the single previous-epoch
	// slot and make a valid KeyUpdateAck look like a dead path.
	txEpochBusy := !s.txDrainAt.IsZero()
	if !s.keyPending && !txEpochBusy && (s.bytesSinceKey >= s.opts.KeyUpdateBytes || now.Sub(s.lastKey) > s.opts.KeyUpdateInterval) {
		s.keyPending = true
		s.keyLastSend = now
		s.enqueue(protocol.Frame{Kind: protocol.KeyUpdate, Value: uint64(s.current.tx.Epoch()) + 1}, protocol.Interactive)
	}
	if s.keyPending && s.current.kind == "tcp" && now.Sub(s.keyLastSend) >= 500*time.Millisecond {
		if s.enqueue(protocol.Frame{Kind: protocol.KeyUpdate, Value: uint64(s.current.tx.Epoch()) + 1}, protocol.Interactive) {
			s.keyLastSend = now
		}
	}
	if !s.maintainKeyDrain(now) {
		return
	}
	if s.pendingRXKey != 0 && s.current.kind == "udp" && s.pendingRXKey == uint32(s.current.rx.Epoch())+1 {
		if err := s.udpPath.history.AdvanceEpoch(s.pendingRXKey); err == nil {
			old := s.current.rx.Epoch()
			s.udpPath.rxPrevious = &old
			if err := s.current.rx.UpdateKey(s.pendingRXKey); err != nil {
				s.cancel()
				return
			}
			s.lastRXKey = now
			s.rxDrainAt = now
			s.rxCurrentUsed = false
			s.enqueue(protocol.Frame{Kind: protocol.KeyUpdateAck, Value: uint64(s.current.rx.Epoch())}, protocol.Interactive)
			s.pendingRXKey = 0
		}
	}
	if now.Sub(s.lastSync) > 100*time.Millisecond {
		s.lastSync = now
		sent := 0
		for i := 0; i < len(s.syncFrames) && sent < 16; i++ {
			index := (s.syncCursor + i) % max(1, len(s.syncFrames))
			frame := s.syncFrames[index]
			if !s.syncAck[frame.Flow] && s.enqueue(frame, protocol.Interactive) {
				sent++
			}
		}
		if len(s.syncFrames) > 0 {
			s.syncCursor = (s.syncCursor + 16) % len(s.syncFrames)
		}
		if len(s.syncAck) == len(s.syncFrames) && !s.localDoneAck {
			if frame, ok := s.resumeDoneFrame(0); ok {
				s.enqueue(frame, protocol.Interactive)
			}
		}
	}
	if !s.peerDone || !s.localDoneAck {
		return
	}
	s.maintainTicket(now)
	for _, st := range s.streams {
		if st.reset {
			if st.resetPending && !st.resetAcked {
				resetFrame := protocol.Frame{Kind: protocol.Reset, Flow: st.flow.id}
				if s.current.kind == "tcp" {
					if s.operationReadyForSchedule(resetFrame, now) {
						s.enqueue(resetFrame, protocol.Interactive)
					}
				} else if now.Sub(st.lastReset) >= 500*time.Millisecond {
					if s.enqueue(resetFrame, protocol.Interactive) {
						st.lastReset = now
					}
				}
			}
			continue
		}
		if st.opening && s.client {
			openFrame := protocol.Frame{Kind: protocol.Open, Flow: st.flow.id, Data: encodeJSON(st.target)}
			if s.current.kind == "tcp" {
				if s.operationReadyForSchedule(openFrame, now) {
					s.enqueue(openFrame, protocol.Interactive)
				}
			} else if now.Sub(st.lastOpen) > 500*time.Millisecond {
				s.enqueue(openFrame, protocol.Interactive)
				st.lastOpen = now
			}
		}
		for i := range st.chunks {
			ch := &st.chunks[i]
			if s.current.kind == "udp" && ch.queued.IsZero() || s.current.kind == "tcp" && now.Sub(ch.queued) > max(rto, 500*time.Millisecond) {
				if s.enqueue(protocol.Frame{Kind: protocol.StreamData, Flow: st.flow.id, Offset: ch.offset, Data: ch.data}, st.effectiveClass) {
					ch.queued = now
				}
			}
		}
		if st.localFinal != nil && !st.finAck {
			finFrame := protocol.Frame{Kind: protocol.Fin, Flow: st.flow.id, Offset: *st.localFinal}
			if s.current.kind == "tcp" {
				if s.operationReadyForSchedule(finFrame, now) {
					s.enqueue(finFrame, protocol.Interactive)
				}
			} else if now.Sub(st.lastFin) > 500*time.Millisecond {
				s.enqueue(finFrame, protocol.Interactive)
				st.lastFin = now
			}
		}
		for id, a := range st.datagrams {
			expired := !a.handoverUntil.IsZero() && !now.Before(a.handoverUntil)
			if a.handoverUntil.IsZero() {
				expired = now.Sub(a.created) > time.Second
			}
			if expired {
				delete(st.datagrams, id)
				st.completed[id] = true
			}
		}
	}
}
func (s *Session) classFor(id uint64) protocol.Class {
	if st := s.streams[id]; st != nil {
		return st.effectiveClass
	}
	return protocol.Interactive
}
func (s *Session) maybePeerSync() {
	if s.peerSyncCount < 0 || len(s.syncReceived) != s.peerSyncCount || s.peerResumeDone == nil {
		return
	}
	if !s.peerDone {
		if !s.applyResumeDoneState(*s.peerResumeDone) {
			s.cancel()
			return
		}
		s.peerDone = true
		s.signalFlows()
		if s.localDoneAck {
			s.suspendedAt = time.Time{}
		}
	}
	if s.peerResumeDone.Version == 0 {
		s.enqueue(protocol.Frame{Kind: protocol.ResumeDone, Flags: 1, Flow: uint64(s.peerSyncCount), Offset: s.current.generation}, protocol.Interactive)
		return
	}
	if frame, ok := s.resumeDoneFrame(1); ok {
		s.enqueue(frame, protocol.Interactive)
	}
}
func (s *Session) ack(st *streamState, offset uint64) bool {
	if offset > st.sendNext {
		return false
	}
	if offset < st.sendAck {
		return true
	}
	st.sendAck = offset
	for len(st.chunks) > 0 && st.chunks[0].offset+uint64(len(st.chunks[0].data)) <= offset {
		s.stats.TXBuffered -= len(st.chunks[0].data)
		st.chunks = st.chunks[1:]
	}
	st.flow.signal()
	return true
}
func (s *Session) result(st *streamState, result string) {
	if !st.opening {
		return
	}
	st.opening = false
	st.openResult = result
	if result == "ok" {
		s.enableClassControl(st)
	} else if s.classTable != nil {
		s.classTable.Forget(st.flow.id)
	}
	st.flow.mu.Lock()
	if result != "ok" {
		st.flow.openErr = errors.New("session: target refused")
	}
	close(st.flow.openDone)
	st.flow.mu.Unlock()
}
func (s *Session) data(st *streamState, f protocol.Frame) {
	if len(f.Data) == 0 {
		return
	}
	if st.target.Network != "tcp" {
		s.cancel()
		return
	}
	end := f.Offset + uint64(len(f.Data))
	if end < f.Offset || end > st.consumed+uint64(s.opts.MaxFlowBuffer) || st.remoteFinal != nil && end > *st.remoteFinal {
		s.cancel()
		return
	}
	if end <= st.receiveNext {
		s.enqueue(s.streamAckFrame(st), protocol.Interactive)
		return
	}
	if f.Offset < st.receiveNext {
		f.Data = f.Data[st.receiveNext-f.Offset:]
		f.Offset = st.receiveNext
	}
	for off, b := range st.segments {
		if f.Offset < uint64(len(b))+off && off < end {
			if off == f.Offset && string(b) == string(f.Data) {
				return
			}
			s.cancel()
			return
		}
	}
	if len(st.segments) >= 256 || s.stats.RXBuffered+len(f.Data) > s.opts.MaxSessionBuffer || s.totalReceived+uint64(len(f.Data)) > s.totalConsumed+uint64(s.opts.MaxSessionBuffer) {
		return
	}
	st.segments[f.Offset] = f.Data
	s.totalReceived += uint64(len(f.Data))
	s.stats.RXBuffered += len(f.Data)
	for {
		b := st.segments[st.receiveNext]
		if b == nil {
			break
		}
		delete(st.segments, st.receiveNext)
		st.receiveNext += uint64(len(b))
		st.flow.push(b)
	}
	s.enqueue(s.streamAckFrame(st), protocol.Interactive)
	s.finishReceive(st)
}
func (s *Session) finishReceive(st *streamState) {
	if st.remoteFinal == nil || *st.remoteFinal != st.receiveNext || st.finAckSent {
		return
	}
	final := *st.remoteFinal
	if st.targetConn == nil {
		// A direct client Flow may expose EOF while its already received bytes
		// remain buffered. Its logical FIN receipt still waits for application
		// consumption below.
		st.flow.endRead()
		if st.consumed < final {
			return
		}
	} else {
		if st.bridgeWritten < final {
			return
		}
		if !st.bridgeCloseWrite {
			cw, ok := st.targetConn.(interface{ CloseWrite() error })
			if !ok {
				s.reset(st, io.ErrClosedPipe, true)
				return
			}
			if err := cw.CloseWrite(); err != nil {
				s.reset(st, err, true)
				return
			}
			st.bridgeCloseWrite = true
		}
	}
	st.flow.endRead()
	st.finAckSent = true
	s.enqueue(protocol.Frame{Kind: protocol.FinAck, Flow: st.flow.id, Offset: final}, protocol.Interactive)
}
func (s *Session) reset(st *streamState, e error, send bool) {
	// Keep a compact terminal decision even if the stream state is later
	// compacted. This also makes the invariant explicit for recovery code:
	// RESET is terminal and never a trigger for a later redial.
	if st != nil && !s.rememberResetTombstone(st.flow.id, s.transportTime()) {
		s.cancel()
		return
	}
	if st.reset {
		return
	}
	st.reset = true
	for id := range st.txDatagrams {
		s.retireTXDatagram(st, id, false)
	}
	if s.classTable != nil {
		s.classTable.Forget(st.flow.id)
	}
	for _, ch := range st.chunks {
		s.stats.TXBuffered -= len(ch.data)
	}
	st.chunks = nil
	discarded := 0
	for _, b := range st.segments {
		s.stats.RXBuffered -= len(b)
		discarded += len(b)
	}
	st.segments = nil
	st.datagrams = nil
	st.completed = nil
	st.flow.mu.Lock()
	discarded += st.flow.buffer.Len()
	s.stats.RXBuffered -= st.flow.buffer.Len()
	st.flow.buffer.Reset()
	for _, msg := range st.flow.messages {
		s.stats.RXBuffered -= len(msg)
	}
	st.flow.messages = nil
	st.flow.mu.Unlock()
	s.totalConsumed += uint64(discarded)
	if discarded > 0 {
		s.enqueue(s.maxSessionFrame(), protocol.Interactive)
	}
	if st.targetConn != nil {
		st.targetConn.Close()
	}
	if st.dialCancel != nil {
		st.dialCancel()
	}
	st.flow.fail(e)
	if send {
		st.resetPending = true
		st.resetAcked = false
		st.lastReset = s.transportTime()
		s.enqueue(protocol.Frame{Kind: protocol.Reset, Flow: st.flow.id}, protocol.Interactive)
	}
}

func (s *Session) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return s.DialMetadata(ctx, classification.Metadata{Target: protocol.Target{Network: network, Address: address, Class: protocol.Normal}})
}
func (s *Session) DialClass(ctx context.Context, target protocol.Target) (net.Conn, error) {
	return s.DialMetadata(ctx, classification.Metadata{Target: target, Hint: &classification.ClassHint{Class: target.Class, Trusted: true}})
}

// DialMetadata accepts trust from a local adapter/API caller. Trust flags are
// never serialized into OPEN and a peer cannot supply them to handleOpen.
func (s *Session) DialMetadata(ctx context.Context, meta classification.Metadata) (net.Conn, error) {
	if s.terminating() {
		return nil, ErrClosed
	}
	if meta.Hint != nil {
		hint := *meta.Hint
		meta.Hint = &hint
	}
	target := meta.Target
	// OPEN retries must never observe later caller mutations of optional
	// contract pointers. The resolved stream contract and wire target both own
	// their copies before entering the actor mailbox.
	target = cloneTarget(target)
	meta.Target = target
	var f *Flow
	var e error
	err := s.businessCall(ctx, func() {
		if s.localAddressScope != nil {
			if s.localAddressGuard.check() != nil {
				e = ErrClosed
				return
			}
			var restoreErr error
			target, restoreErr = restoreLocalAddress(s.localAddressScope, target)
			if restoreErr != nil {
				e = restoreErr
				return
			}
			meta.Target = target
		}
		active := 0
		for _, st := range s.streams {
			if !st.terminal() {
				active++
			}
		}
		if !s.client || active >= s.opts.MaxFlows || len(s.streams) >= maxSessionFlowStates {
			e = ErrLimit
			return
		}
		if target.Network != "tcp" && target.Network != "udp" || !target.Class.Valid() {
			e = errors.New("session: invalid target")
			return
		}
		tx, txErr := s.classifier.NewFlow(meta, s.classTime())
		if txErr != nil {
			e = txErr
			return
		}
		target.Class = tx.Snapshot().Class
		target = s.selectDatagramFEC(target)
		delivery, fecProfile, contractErr := protocol.ResolveDelivery(target.Network, target.Delivery, target.FEC)
		if contractErr != nil {
			e = contractErr
			return
		}
		if fecProfile.Enabled() && !s.fecPermitted(fecProfile) {
			e = ErrFECNotNegotiated
			return
		}
		id := s.nextFlow
		s.nextFlow++
		f = newFlow(s, id, target.Network)
		st := &streamState{flow: f, target: target, delivery: delivery, fecProfile: fecProfile, effectiveClass: target.Class, txClassifier: tx, opening: true, maxRemote: uint64(s.opts.MaxFlowBuffer), segments: map[uint64][]byte{}, datagrams: map[uint64]*assembly{}, completed: map[uint64]bool{}, messageNext: 1}
		s.streams[id] = st
		if !s.startClassControl(st) {
			e = ErrLimit
			return
		}
		s.stats.Opened++
		s.enqueue(protocol.Frame{Kind: protocol.Open, Flow: id, Data: encodeJSON(target)}, protocol.Interactive)
	})
	if err != nil {
		return nil, err
	}
	if e != nil {
		return nil, e
	}
	select {
	case <-f.openDone:
		f.mu.Lock()
		e = f.openErr
		f.mu.Unlock()
		if e != nil {
			f.Close()
			return nil, e
		}
		return f, nil
	case <-ctx.Done():
		f.Close()
		return nil, ctx.Err()
	case <-s.done:
		return nil, ErrClosed
	case <-s.ctx.Done():
		return nil, ErrClosed
	}
}
func (s *Session) handleOpen(f protocol.Frame) {
	if s.terminating() {
		return
	}
	if s.client || !s.peerDone {
		s.cancel()
		return
	}
	var target protocol.Target
	if json.Unmarshal(f.Data, &target) != nil || !target.Class.Valid() || (target.Network != "tcp" && target.Network != "udp") {
		s.cancel()
		return
	}
	delivery, fecProfile, contractErr := protocol.ResolveDelivery(target.Network, target.Delivery, target.FEC)
	if contractErr != nil {
		s.cancel()
		return
	}
	if fecProfile.Enabled() && !s.fecPermitted(fecProfile) {
		// Authenticated peers may not silently request a different delivery
		// contract. Reject before allocating a Flow or dialing a destination.
		s.cancel()
		return
	}
	// A RESET may arrive before its OPEN when UDP records are reordered. Keep
	// the terminal decision independent of stream allocation so this OPEN can
	// never create a new target connection after the flow was cancelled.
	if s.hasResetTombstone(f.Flow) {
		s.enqueue(s.normalizeLatestControl(protocol.Frame{Kind: protocol.OpenResult, Flow: f.Flow, Data: []byte("reset")}), protocol.Interactive)
		return
	}
	if st := s.streams[f.Flow]; st != nil {
		if string(encodeJSON(st.target)) != string(encodeJSON(target)) {
			s.cancel()
			return
		}
		if st.reset {
			if st.openResult == "" {
				st.openResult = "reset"
			}
			s.enqueue(s.openResultFrame(st), protocol.Interactive)
			return
		}
		if st.openResult != "" {
			s.enqueue(s.openResultFrame(st), protocol.Interactive)
		}
		return
	}
	active := 0
	for _, st := range s.streams {
		if !st.terminal() {
			active++
		}
	}
	if active >= s.opts.MaxFlows || s.dialing >= s.opts.MaxFlows || len(s.streams) >= maxSessionFlowStates {
		if len(s.streams) < maxSessionFlowStates {
			rejected := newFlow(s, f.Flow, target.Network)
			rejected.fail(ErrLimit)
			s.streams[f.Flow] = &streamState{flow: rejected, target: target, effectiveClass: target.Class, reset: true, openResult: "limit"}
		}
		if st := s.streams[f.Flow]; st != nil {
			s.enqueue(s.openResultFrame(st), protocol.Interactive)
		} else {
			s.enqueue(s.normalizeLatestControl(protocol.Frame{Kind: protocol.OpenResult, Flow: f.Flow, Data: []byte("limit")}), protocol.Interactive)
		}
		return
	}
	tx, txErr := s.classifier.NewFlow(classification.Metadata{Target: target}, s.classTime())
	if txErr != nil {
		s.cancel()
		return
	}
	flow := newFlow(s, f.Flow, target.Network)
	st := &streamState{flow: flow, target: target, delivery: delivery, fecProfile: fecProfile, effectiveClass: tx.Snapshot().Class, txClassifier: tx, opening: true, maxRemote: uint64(s.opts.MaxFlowBuffer), segments: map[uint64][]byte{}, datagrams: map[uint64]*assembly{}, completed: map[uint64]bool{}, messageNext: 1}
	s.streams[f.Flow] = st
	if !s.startClassControl(st) {
		return
	}
	s.stats.Opened++
	dialCtx, dialCancel := context.WithTimeout(s.ctx, 10*time.Second)
	st.dialCancel = dialCancel
	st.dialToken = &dialToken{}
	s.dialing++
	if s.dialResults == nil {
		s.dialResults = newDialResultMailbox(s.opts.MaxFlows)
	}
	// Evaluate these immutable arguments before launching. The worker's only
	// retained protocol object is a Session-independent typed result owner.
	go runBackendDial(s.backend, dialCtx, dialCancel, target.Network, target.Address, f.Flow, st.dialToken, s.dialResults)
}
