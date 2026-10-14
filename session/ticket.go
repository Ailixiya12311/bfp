package session

import (
	"bfp/protocol"
	"bfp/security"
	"encoding/hex"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const maxCredentialDuration = 30 * 24 * time.Hour

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// gate serializes handshake commits with administrative revocation. The actor
// never waits for gate; signing and revocation also share Server.mu.
type deviceAuthority struct {
	gate    sync.Mutex
	revoked atomic.Bool
}

type ticketRecord struct {
	session   *Session
	authority *deviceAuthority
	serial    uint64
	expires   time.Time
}

func validateTicketOptions(o Options) error {
	if o.TicketTTL < 40*time.Millisecond || o.TicketTTL > maxCredentialDuration ||
		o.TicketRefreshLead < time.Millisecond || o.TicketRefreshLead >= o.TicketTTL ||
		o.TicketOverlap < time.Millisecond || o.TicketOverlap > o.TicketTTL ||
		o.KeyDrainTimeout < 100*time.Millisecond || o.KeyDrainTimeout > maxCredentialDuration ||
		o.MaxSessionLifetime < 40*time.Millisecond || o.MaxSessionLifetime > maxCredentialDuration {
		return errors.New("session: invalid ticket or lifetime options")
	}
	return nil
}

func remainingMS(until, now time.Time) uint64 {
	if !until.After(now) {
		return 0
	}
	return uint64(until.Sub(now) / time.Millisecond)
}

func credentialDuration(ms uint64) (time.Duration, error) {
	if ms == 0 || ms > uint64(maxCredentialDuration/time.Millisecond) {
		return 0, security.ErrAuthentication
	}
	return time.Duration(ms) * time.Millisecond, nil
}

func validLocator(s string) bool {
	if len(s) != 32 {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil
}

func installInfoDeadlines(info *sessionInfo, started time.Time) error {
	ttl, e := credentialDuration(info.TicketRemainingMS)
	if e != nil || info.TicketSerial == 0 || !validLocator(info.Ticket) || !validLocator(info.ID) {
		return security.ErrAuthentication
	}
	life, e := credentialDuration(info.LifetimeRemainingMS)
	if e != nil {
		return e
	}
	// Measuring from the start of the handshake conservatively includes its
	// round trips. Server monotonic deadlines remain the authorization source.
	info.ticketUntil = started.Add(ttl)
	info.lifetimeUntil = started.Add(life)
	return nil
}

func exportDeadlines(info sessionInfo, now time.Time) sessionInfo {
	info.TicketRemainingMS = remainingMS(info.ticketUntil, now)
	info.LifetimeRemainingMS = remainingMS(info.lifetimeUntil, now)
	return info
}

// mergeInfo does not let a late carrier handshake roll back credentials or
// extend the fixed session deadline. Called only by the client actor.
func (s *Session) mergeInfo(info sessionInfo) error {
	s.admissionMu.RLock()
	defer s.admissionMu.RUnlock()
	if s.terminating() {
		return ErrClosed
	}
	if info.Profile != s.info.Profile || info.Capabilities != s.info.Capabilities {
		return ErrState
	}
	if info.ID != s.info.ID || !equalSecret(info.Secret, s.info.Secret) {
		return ErrState
	}
	if info.TicketSerial == s.info.TicketSerial && info.Ticket != s.info.Ticket {
		return ErrState
	}
	if info.TicketSerial > s.info.TicketSerial {
		s.info.Ticket, s.info.TicketSerial, s.info.ticketUntil = info.Ticket, info.TicketSerial, info.ticketUntil
	} else if info.TicketSerial == s.info.TicketSerial && info.ticketUntil.Before(s.info.ticketUntil) {
		s.info.ticketUntil = info.ticketUntil
	}
	if info.lifetimeUntil.Before(s.info.lifetimeUntil) {
		s.info.lifetimeUntil = info.lifetimeUntil
		if s.localAddressGuard != nil {
			s.localAddressGuard.shorten(info.lifetimeUntil)
		}
	}
	s.info.Generation, s.info.Handle, s.info.Challenge = info.Generation, info.Handle, info.Challenge
	return nil
}

// ticketValidLocked checks use-time expiry rather than waiting for maintenance.
func (s *Server) ticketValidLocked(locator string, owner *Session, now time.Time) bool {
	r := s.tickets[locator]
	return owner != nil && r != nil && r.session == owner && r.authority != nil && !r.authority.revoked.Load() && r.expires.After(now) && !owner.closed() && !owner.terminating()
}

// The candidate's group is either locked by the caller or immutable while the
// caller waits for its actor guard. Server.mu is held for ticket lookup.
func (s *Server) candidateValidLocked(p *pending, now time.Time) bool {
	if p == nil || p.info.authority == nil || p.info.authority.revoked.Load() || !p.info.lifetimeUntil.After(now) || s.ctx.Err() != nil {
		return false
	}
	if p.session != nil && (p.session.closed() || p.session.terminating()) {
		return false
	}
	// A sibling initial candidate may not yet have p.session installed when
	// another carrier committed the group's Session. Its cached INIT and later
	// CONFIRM must lose eligibility with that owner as well.
	if p.group != nil && p.group.session != nil && p.group.session.terminating() {
		return false
	}
	if p.mode == "resume" {
		return s.ticketValidLocked(p.ticketAlias, p.session, now)
	}
	return p.info.ticketUntil.After(now)
}

// rotateTicket is called by the owning actor. It never waits for a device gate
// while confirm may wait for the actor; the in-lock revocation check prevents
// a concurrent administrative deletion from being undone by late signing.
func (s *Server) rotateTicket(owner *Session, now time.Time) error {
	owner.admissionMu.RLock()
	defer owner.admissionMu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	i := &owner.info
	if owner.terminating() || owner.closed() || s.ctx.Err() != nil || i.authority == nil || i.authority.revoked.Load() || !i.lifetimeUntil.After(now) || s.sessions[i.ID] != owner {
		return ErrClosed
	}
	if i.TicketSerial == math.MaxUint64 {
		return ErrLimit
	}
	for locator, r := range s.tickets {
		if r.session != owner {
			continue
		}
		if locator != i.Ticket {
			delete(s.tickets, locator)
			continue
		}
		r.expires = earlier(r.expires, now.Add(owner.opts.TicketOverlap))
		if !r.expires.After(now) {
			delete(s.tickets, locator)
		}
	}
	i.Ticket = randomID()
	i.TicketSerial++
	i.ticketUntil = earlier(now.Add(owner.opts.TicketTTL), i.lifetimeUntil)
	s.tickets[i.Ticket] = &ticketRecord{owner, i.authority, i.TicketSerial, i.ticketUntil}
	owner.ticketPending = i.TicketSerial
	owner.lastTicketSend = time.Time{}
	owner.stats.TicketRefreshes++
	return nil
}

func (s *Session) maintainTicket(now time.Time) {
	if s.terminating() || s.client || s.info.issuer == nil {
		return
	}
	if s.ticketPending != 0 && !s.info.ticketUntil.After(now) {
		// A healthy, authenticated carrier may replace an unacknowledged expired
		// locator. Expired locators themselves never authorize this operation.
		s.ticketPending = 0
	}
	// Once an installed ticket covers the entire remaining session lifetime,
	// refreshing cannot extend eligibility. In particular, a shortened final
	// ticket must not trigger another rotation on every ACK/maintenance tick.
	if s.ticketPending == 0 && s.info.ticketUntil.Equal(s.info.lifetimeUntil) && s.info.ticketUntil.After(now) {
		return
	}
	if s.ticketPending == 0 && !now.Before(s.info.ticketUntil.Add(-s.opts.TicketRefreshLead)) {
		if e := s.info.issuer.rotateTicket(s, now); e != nil {
			// A close may win the admission gate after this tick's first guard.
			// Losing a business rotation must not abort its authenticated drain.
			if s.terminating() {
				return
			}
			s.cancel()
			return
		}
	}
	if s.ticketPending != 0 && now.Sub(s.lastTicketSend) >= max(10*time.Millisecond, min(time.Second, s.opts.TicketTTL/8)) {
		ms := remainingMS(s.info.ticketUntil, now)
		if ms > 0 && s.enqueue(protocol.Frame{Kind: protocol.TicketRefresh, Value: s.info.TicketSerial, Offset: ms, Data: []byte(s.info.Ticket)}, protocol.Interactive) {
			s.lastTicketSend = now
		}
	}
}

func (s *Session) receiveTicket(f protocol.Frame, now time.Time) {
	if s.terminating() {
		return
	}
	if !s.client || f.Flow != 0 || f.Flags != 0 || f.Value == 0 || !validLocator(string(f.Data)) {
		s.cancel()
		return
	}
	ttl, e := credentialDuration(f.Offset)
	if e != nil {
		s.cancel()
		return
	}
	if f.Value == s.info.TicketSerial && string(f.Data) != s.info.Ticket {
		s.cancel()
		return
	}
	if f.Value < s.info.TicketSerial {
		return
	}
	deadline := earlier(now.Add(ttl), s.info.lifetimeUntil)
	if f.Value > s.info.TicketSerial {
		s.info.Ticket, s.info.TicketSerial, s.info.ticketUntil = string(f.Data), f.Value, deadline
		s.stats.TicketRefreshes++
	} else if deadline.Before(s.info.ticketUntil) {
		s.info.ticketUntil = deadline
	}
	s.enqueue(protocol.Frame{Kind: protocol.TicketRefreshAck, Value: f.Value}, protocol.Interactive)
}

// RevokeDevice is an in-process administrative API. It permanently revokes a
// configured static key for this Server instance and returns after its sessions
// stop and their registered target sockets close. It is not a network endpoint.
func (s *Server) RevokeDevice(public []byte) error {
	if len(public) != 32 {
		return errors.New("session: invalid device key")
	}
	s.mu.Lock()
	a := s.devices[string(public)]
	s.mu.Unlock()
	if a == nil {
		return errors.New("session: unknown device")
	}
	a.gate.Lock()
	s.mu.Lock()
	a.revoked.Store(true)
	list := make([]*Session, 0)
	for _, owner := range s.sessions {
		if owner.authority == a {
			list = append(list, owner)
		}
	}
	for locator, r := range s.tickets {
		if r.authority == a {
			delete(s.tickets, locator)
		}
	}
	s.mu.Unlock()
	a.gate.Unlock()
	// Scope cleanup and private socket shutdown may call user-supplied code.
	// Revocation is already visible; never run cleanup under registry locks.
	for _, owner := range list {
		owner.cancel()
	}
	for _, owner := range list {
		<-owner.done
	}
	return nil
}
