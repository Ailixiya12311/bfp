package session

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync/atomic"
	"time"

	"bfp/internal/addressscope"
	"bfp/protocol"
)

var ErrClientAddressScope = errors.New("session: invalid client address scope")

// A retained mapping cannot keep a terminated actor reachable. Eligibility is
// independent of actor state, including a deadline shortened by resume info.
type clientScopeLifetime struct {
	ctx      context.Context
	until    atomic.Pointer[time.Time]
	terminal atomic.Bool
}

func (g *clientScopeLifetime) shorten(until time.Time) {
	if until.IsZero() {
		return
	}
	for {
		old := g.until.Load()
		if old != nil && !until.Before(*old) {
			return
		}
		deadline := until
		if g.until.CompareAndSwap(old, &deadline) {
			return
		}
	}
}

func (g *clientScopeLifetime) check() error {
	if g.terminal.Load() || g.ctx.Err() != nil {
		return ErrClosed
	}
	if deadline := g.until.Load(); deadline != nil && !time.Now().Before(*deadline) {
		return ErrClosed
	}
	return nil
}

func (s *Session) bindClientAddressScope(factory ClientAddressScopeFactory, cancel context.CancelFunc, operationCtx context.Context, creation *clientAddressCreationSlot) error {
	if !s.client || addressscope.IsNil(factory) {
		return nil
	}
	guard := &clientScopeLifetime{ctx: s.ctx}
	guard.shorten(s.info.lifetimeUntil)
	scope, stopScope, err := createClientAddressScope(s.ctx, operationCtx, factory, guard.check, creation)
	if err != nil {
		return err
	}
	if err := guard.check(); err != nil {
		stopScope()
		_ = scope.Close()
		return err
	}
	s.localAddressScope, s.localAddressGuard = scope, guard
	binding := newBackendRetirement(s.ctx, func() { stopScope(); _ = scope.Close() })
	s.closeLocalAddressScope = binding.retire
	s.stopBusiness = func() {
		cancel()
		binding.retire()
	}
	return nil
}

// LocalAddressAllocator returns only the map belonging to this exact client
// Session. A caller may retain it across carrier recovery. It fails closed when
// its Session terminates; a later Client.Connect receives a new empty scope.
// Pair this accessor with Session.Dial* when an operation must stay pinned to
// the allocator's owner. Client.Dial* selects its Session once, then restores and
// commits OPEN within that selected Session's admission gate.
func (s *Session) LocalAddressAllocator() (ClientAddressAllocator, bool) {
	if s == nil || s.terminating() {
		return nil, false
	}
	var allocator ClientAddressAllocator
	err := s.call(context.Background(), func() {
		if !s.terminating() && s.localAddressGuard != nil && s.localAddressGuard.check() == nil {
			allocator = s.localAddressScope
		}
	})
	return allocator, err == nil && allocator != nil
}

// A scope may only change Address. Use a deep copy when invoking a custom
// mapper so it cannot mutate delivery/FEC pointers in the admitted target.
// Local trust flags and provenance are never inferred from a restored name.
func restoreLocalAddress(scope ClientAddressScope, target protocol.Target) (protocol.Target, error) {
	restored, err := scope.RestoreTarget(cloneTarget(target))
	if err != nil {
		return protocol.Target{}, err
	}
	address := restored.Address
	restored.Address = target.Address
	if !reflect.DeepEqual(restored, target) {
		return protocol.Target{}, ErrClientAddressScope
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return protocol.Target{}, ErrClientAddressScope
	}
	target.Address = address
	return target, nil
}
