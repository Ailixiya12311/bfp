package session

import (
	"bfp/classification"
	"bfp/internal/addressscope"
	"bfp/protocol"
	"bfp/security"
	"context"
	"errors"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type Client struct {
	classifier  *classification.Classifier
	datagramFEC datagramFECPolicy
	cfg         ClientConfig
	mu          contextMutex
	current     *Session
	owners      map[*Session]struct{} // Live actors, including a replaced Session's close drain.
	ctx         context.Context
	cancel      context.CancelFunc
	sessionCtx  context.Context
	stopSession context.CancelFunc
	// Independent metadata storage does not retain Client from a Session.
	sessionParentSource *atomic.Pointer[string]
	wg                  sync.WaitGroup
	closed              atomic.Bool
	closeOnce           sync.Once
	closeErr            error // Immutable after closeOnce completes; concurrent Close waits.
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.AddressScopeFactory != nil && addressscope.IsNil(cfg.AddressScopeFactory) {
		return nil, ErrClientAddressScope
	}
	negotiation, e := normalizeNegotiation(cfg.Negotiation)
	if e != nil {
		return nil, e
	}
	cfg.Negotiation = negotiation
	datagramFEC, e := compileDatagramFECPolicy(cfg.DatagramFEC, negotiation)
	if e != nil {
		return nil, e
	}
	cfg.DatagramFEC = nil // Keep only the immutable compiled policy.
	cfg.Credentials = copyCredentials(cfg.Credentials)
	if e := validateCredentials(cfg.Credentials, true); e != nil {
		return nil, e
	}
	cfg.Options = cfg.Options.defaults()
	if e := validateTicketOptions(cfg.Options); e != nil {
		return nil, e
	}
	classifier, e := compileClassification(cfg.Classification)
	if e != nil {
		return nil, e
	}
	cfg.Classification = nil // Keep only the immutable compiled policy.
	cfg.carrierDials = newCarrierDialState()
	if cfg.AddressScopeFactory != nil {
		cfg.addressCreations = newClientAddressCreationState()
	}
	ctx, cancel := context.WithCancel(context.Background())
	sessionCtx, rawStopSession := context.WithCancel(context.Background())
	parentSource := &atomic.Pointer[string]{}
	stopSession := func() {
		// Publication precedes raw parent cancellation so a BusinessDone
		// observer can read the caller immediately, without a watcher callback.
		source := "unknown"
		if _, file, line, ok := runtime.Caller(1); ok {
			source = filepath.Base(file) + ":" + strconv.Itoa(line)
		}
		parentSource.CompareAndSwap(nil, &source)
		rawStopSession()
	}
	return &Client{cfg: cfg, classifier: classifier, datagramFEC: datagramFEC, ctx: ctx, cancel: cancel, owners: make(map[*Session]struct{}),
		sessionCtx: sessionCtx, stopSession: stopSession, sessionParentSource: parentSource}, nil
}
func (c *Client) Connect(ctx context.Context) (*Session, error) {
	if c.closed.Load() {
		return nil, ErrClosed
	}
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	after := context.AfterFunc(c.ctx, stop)
	defer after()
	if err := c.mu.LockContext(ctx); err != nil {
		if c.closed.Load() {
			return nil, ErrClosed
		}
		return nil, err
	}
	defer c.mu.Unlock()
	if c.closed.Load() {
		return nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.current != nil && !c.current.closed() && !c.current.terminating() {
		return c.current, nil
	}
	c.current = nil
	creation, e := c.cfg.addressCreations.reserve(ctx)
	if e != nil {
		return nil, e
	}
	defer creation.releaseUnused()
	attempt := randomID()
	car, info, e := establish(ctx, c.cfg, "udp", attempt, nil)
	if e != nil {
		if errors.Is(e, security.ErrAuthentication) || errors.Is(e, ErrCarrierDialContract) {
			return nil, e
		}
		car, info, e = establish(ctx, c.cfg, "tcp", attempt, nil)
	}
	if e != nil {
		return nil, e
	}
	if c.closed.Load() || ctx.Err() != nil {
		car.close()
		if c.closed.Load() {
			return nil, ErrClosed
		}
		return nil, ctx.Err()
	}
	s, e := newSessionWithAddressScopeOperation(c.sessionCtx, ctx, info, c.cfg.Options, true, nil, c.datagramFEC, c.cfg.AddressScopeFactory, creation, c.classifier)
	if e != nil {
		car.close()
		return nil, e
	}
	// Assigned before attach/readers/current/owners can publish this Session.
	// The actor does not read this immutable pointer; its target is atomic and
	// may already contain a concurrent parent cancellation's diagnostic.
	s.parentTerminationSource = c.sessionParentSource
	if e = s.attach(car, 0); e != nil {
		// An unattached carrier is not owned by Session cleanup. There was no
		// established Session to notify, so abort rather than start a drain.
		car.close()
		s.cancel()
		<-s.done
		return nil, e
	}
	if c.closed.Load() || ctx.Err() != nil || s.terminating() {
		closed := c.closed.Load() || s.terminating()
		car.close()
		s.cancel()
		<-s.done
		if closed {
			return nil, ErrClosed
		}
		return nil, ctx.Err()
	}
	s.startReader(car)
	s.activate()
	c.current = s
	c.owners[s] = struct{}{}
	c.wg.Add(1)
	go c.recover(s)
	return s, nil
}
func (c *Client) Session() *Session { c.mu.Lock(); defer c.mu.Unlock(); return c.current }

// RestoresSessionTargets advertises that Dial* selects one Session and restores
// its addresses at OPEN admission. Entry adapters must not install a separate
// restorer that could decode a retired scope before Client chooses a new one.
func (c *Client) RestoresSessionTargets() bool {
	return c.cfg.AddressScopeFactory != nil
}
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	s, e := c.Connect(ctx)
	if e != nil {
		return nil, e
	}
	return s.DialContext(ctx, network, address)
}
func (c *Client) DialClass(ctx context.Context, target protocol.Target) (net.Conn, error) {
	s, e := c.Connect(ctx)
	if e != nil {
		return nil, e
	}
	return s.DialClass(ctx, target)
}
func (c *Client) DialMetadata(ctx context.Context, meta classification.Metadata) (net.Conn, error) {
	s, e := c.Connect(ctx)
	if e != nil {
		return nil, e
	}
	return s.DialMetadata(ctx, meta)
}
func (c *Client) Close() error {
	// Once blocks concurrent callers until the first caller has both obtained
	// the bounded Session close result and joined the recovery workers.
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		// Stop handshake/recovery first. The Session parent remains alive for
		// its independent authenticated control drain until Close returns.
		c.cancel()
		c.mu.Lock()
		s := c.current
		c.mu.Unlock()
		if s != nil {
			c.closeErr = s.Close()
		}
		c.stopSession()
		c.wg.Wait()
	})
	return c.closeErr
}

// Abort destroys the Client's local network and joins its owned Session actors
// and recovery workers. It cancels any handshake before waiting for Connect's
// lock. It does not send a close request or claim that the peer has closed.
//
// Concurrent or repeated Abort calls are safe. Abort may interrupt an ongoing
// graceful Close; Close retains the Session's actual confirmation result,
// including ErrCloseUnconfirmed when no valid peer acknowledgement arrived.
func (c *Client) Abort() error {
	c.closed.Store(true)
	c.cancel()
	c.stopSession()
	c.mu.Lock()
	owners := make([]*Session, 0, len(c.owners)+1)
	for s := range c.owners {
		owners = append(owners, s)
	}
	// The current accessor can retain a completed Session after its worker has
	// retired the ownership entry. Joining that result again is harmless.
	if s := c.current; s != nil {
		if _, tracked := c.owners[s]; !tracked {
			owners = append(owners, s)
		}
	}
	c.mu.Unlock()
	// Cancel every actor before joining any one of them. Closing each private
	// carrier also releases an in-progress socket write/read during local abort.
	for _, s := range owners {
		s.cancel()
	}
	for _, s := range owners {
		<-s.done
	}
	c.wg.Wait()
	return nil
}

func (c *Client) recover(s *Session) {
	defer func() {
		// Recovery may stop when business cancellation begins while the Session
		// actor still drains close control. Keep ownership until that actor ends.
		<-s.done
		c.mu.Lock()
		delete(c.owners, s)
		c.mu.Unlock()
		c.wg.Done()
	}()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	var attempt string
	var recoveryInfo sessionInfo
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-s.done:
			return
		case <-s.ctx.Done():
			return
		case <-tick.C:
			var active bool
			var suspect bool
			var info sessionInfo
			if s.terminating() {
				return
			}
			if e := s.call(c.ctx, func() {
				s.admissionMu.RLock()
				defer s.admissionMu.RUnlock()
				if !s.terminating() {
					active, suspect, info = s.active, s.udpSuspect, s.info
				}
			}); e != nil || s.terminating() {
				return
			}
			if active && !suspect {
				attempt = ""
				continue
			}
			if attempt == "" {
				attempt = randomID()
				recoveryInfo = info
			}
			ctx, cancel := context.WithTimeout(c.ctx, c.cfg.Options.HandshakeTimeout)
			stopOnTermination := context.AfterFunc(s.ctx, cancel)
			allowed := false
			_ = s.call(c.ctx, func() {
				s.admissionMu.RLock()
				defer s.admissionMu.RUnlock()
				allowed = !s.terminating() && s.info.Generation == info.Generation && (!s.active || s.udpSuspect)
				if allowed {
					s.setRecoveryCancel(cancel)
					s.beginRecoveryAttempt()
				}
			})
			if !allowed {
				stopOnTermination()
				cancel()
				if s.terminating() {
					return
				}
				attempt = ""
				continue
			}
			car, newInfo, e := establish(ctx, c.cfg, "tcp", attempt, &recoveryInfo)
			stopOnTermination()
			cancel()
			if c.closed.Load() || c.ctx.Err() != nil || s.terminating() {
				if car != nil {
					car.close()
				}
				return
			}
			if e != nil {
				_ = s.call(context.Background(), func() { s.finishRecoveryAttempt(true) })
				continue
			}
			if e = s.attachGuarded(car, info.Generation, func() bool { return !s.terminating() && (!s.active || s.udpSuspect) }); e != nil {
				car.close()
				if s.terminating() {
					return
				}
				_ = s.call(context.Background(), func() { s.finishRecoveryAttempt(true) })
				continue
			}
			// Ownership has transferred. Its reader must remain available for
			// authenticated close ACKs even if termination rejects the late merge.
			s.startReader(car)
			var mergeErr error
			if e = s.call(c.ctx, func() {
				mergeErr = s.mergeInfo(newInfo)
				s.finishRecoveryAttempt(mergeErr != nil)
			}); e != nil || mergeErr != nil {
				if e != nil {
					_ = s.call(context.Background(), func() { s.finishRecoveryAttempt(true) })
				}
				// A local close already owns this carrier's finite drain. Do not
				// turn a rejected late merge into an abort of that close result.
				if !s.terminating() && !c.closed.Load() {
					car.close()
					s.cancel()
				}
				return
			}
			if s.terminating() {
				return
			}
			s.activate()
		}
	}
}

// Recovery telemetry is confined to the Session owner and has a fixed memory
// footprint. Saturation preserves monotonic counters even at the integer bound.
func (s *Session) beginRecoveryAttempt() {
	if s.stats.TCPRecoveryAttempts != ^uint64(0) {
		s.stats.TCPRecoveryAttempts++
	}
	s.stats.TCPRecoveryInFlight = true
}
func (s *Session) finishRecoveryAttempt(failed bool) {
	if !s.stats.TCPRecoveryInFlight {
		return
	}
	s.stats.TCPRecoveryInFlight = false
	s.signalFlows()
	if failed && s.stats.TCPRecoveryFailures != ^uint64(0) {
		s.stats.TCPRecoveryFailures++
	}
}
