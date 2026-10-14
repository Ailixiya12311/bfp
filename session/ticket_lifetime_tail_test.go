package session

import (
	"bfp/protocol"
	"context"
	"testing"
	"time"
)

func TestTicketLifetimeTailAcknowledgedCoverageDoesNotRotate(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	p, _, _ := ticketAdversarialCommit(t, s, cred, 47201)
	owner := p.session
	if e := owner.call(context.Background(), func() {
		now := time.Now()
		owner.opts.TicketTTL = time.Minute
		owner.opts.TicketRefreshLead = 15 * time.Second
		owner.opts.TicketOverlap = 5 * time.Second
		owner.info.lifetimeUntil = now.Add(10 * time.Second)
		if e := s.rotateTicket(owner, now); e != nil {
			t.Error(e)
			return
		}
		issue := owner.info
		owner.handle(protocol.Frame{Kind: protocol.TicketRefreshAck, Value: issue.TicketSerial})
		s.mu.Lock()
		initialAliases := len(s.tickets)
		s.mu.Unlock()
		// Every time is inside the lead window, but the current ticket already
		// covers all remaining lifetime. Matching ACK must not trigger a storm.
		for i := 1; i <= 40; i++ {
			owner.maintainTicket(now.Add(time.Duration(i) * 100 * time.Millisecond))
		}
		s.mu.Lock()
		finalAliases := len(s.tickets)
		s.mu.Unlock()
		if owner.info.Ticket != issue.Ticket || owner.info.TicketSerial != issue.TicketSerial || !owner.info.ticketUntil.Equal(issue.ticketUntil) || owner.ticketPending != 0 || finalAliases != initialAliases {
			t.Error("ACKed tail coverage rotated credentials or changed registered aliases")
		}
		if owner.stats.TicketRefreshes != 1 {
			t.Errorf("tail triggered %d rotations, want one original issue", owner.stats.TicketRefreshes)
		}
		owner.maintain(issue.lifetimeUntil)
	}); e != nil {
		t.Fatal(e)
	}
	select {
	case <-owner.done:
	case <-time.After(time.Second):
		t.Fatal("ACKed tail coverage bypassed maximum Session lifetime")
	}
}

func TestTicketLifetimeTailPendingCoverageStillRetransmits(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	p, _, _ := ticketAdversarialCommit(t, s, cred, 47202)
	owner := p.session
	if e := owner.call(context.Background(), func() {
		now := time.Now()
		owner.opts.TicketTTL = time.Minute
		owner.opts.TicketRefreshLead = 15 * time.Second
		owner.info.lifetimeUntil = now.Add(10 * time.Second)
		if e := s.rotateTicket(owner, now); e != nil {
			t.Error(e)
			return
		}
		issue := owner.info
		var first, second protocol.Frame
		owner.maintainTicket(now)
		first, ok := owner.queue.Pop()
		if !ok || first.Kind != protocol.TicketRefresh {
			t.Error("tail coverage suppressed unacknowledged initial refresh")
			return
		}
		owner.maintainTicket(now.Add(time.Second))
		second, ok = owner.queue.Pop()
		if !ok || second.Kind != protocol.TicketRefresh {
			t.Error("tail coverage suppressed unacknowledged refresh retry")
			return
		}
		if first.Value != issue.TicketSerial || second.Value != issue.TicketSerial || string(first.Data) != issue.Ticket || string(second.Data) != issue.Ticket || second.Offset >= first.Offset || owner.ticketPending != issue.TicketSerial || !owner.info.ticketUntil.Equal(issue.ticketUntil) {
			t.Error("tail retry changed the issue or extended its remaining TTL")
		}
		owner.maintain(issue.lifetimeUntil)
	}); e != nil {
		t.Fatal(e)
	}
	select {
	case <-owner.done:
	case <-time.After(time.Second):
		t.Fatal("lost refresh ACK bypassed maximum Session lifetime")
	}
}
