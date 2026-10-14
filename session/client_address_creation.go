package session

import (
	"context"
	"errors"
	"sync"

	"bfp/internal/addressscope"
)

// ErrClientAddressScopeBusy means a canceled factory callback has not returned.
// A Client admits at most one callback, and rejects new Connect attempts before
// dialing a carrier until that owner has retired its eventual result.
var ErrClientAddressScopeBusy = errors.New("session: client address scope factory still running")

type clientAddressCreationState struct {
	gate chan struct{}
}

type clientAddressCreationSlot struct {
	gate     chan struct{}
	once     sync.Once
	launched bool // accessed only by the Connect/constructor caller
}

func newClientAddressCreationState() *clientAddressCreationState {
	return &clientAddressCreationState{gate: make(chan struct{}, 1)}
}

func (s *clientAddressCreationState) reserve(ctx context.Context) (*clientAddressCreationSlot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, nil
	}
	select {
	case s.gate <- struct{}{}:
		return &clientAddressCreationSlot{gate: s.gate}, nil
	default:
		return nil, ErrClientAddressScopeBusy
	}
}

func (s *clientAddressCreationSlot) release() {
	if s != nil {
		s.once.Do(func() { <-s.gate })
	}
}

func (s *clientAddressCreationSlot) releaseUnused() {
	if s != nil && !s.launched {
		s.release()
	}
}

type clientAddressCreationResult struct {
	scope ClientAddressScope
	err   error
}

// The callback owns only its contexts, guard, factory and reservation. It does
// not retain Session, Client, actor queues or credentials. A noncooperative
// callback can outlive cancellation, but cannot install a late scope or spawn
// more callbacks for the same Client.
func createClientAddressScope(parent, operationCtx context.Context, factory ClientAddressScopeFactory, valid func() error, slot *clientAddressCreationSlot) (ClientAddressScope, context.CancelFunc, error) {
	if err := operationCtx.Err(); err != nil {
		return nil, nil, err
	}
	if slot == nil {
		// Legacy internal constructors have no Client state. Their scope owner
		// still has one reservation for this single construction attempt.
		var err error
		slot, err = newClientAddressCreationState().reserve(operationCtx)
		if err != nil {
			return nil, nil, err
		}
	}
	defer slot.releaseUnused()
	factoryCtx, cancelFactory := context.WithCancel(parent)
	cancelDone := make(chan struct{})
	stopCancel := context.AfterFunc(operationCtx, func() {
		cancelFactory()
		close(cancelDone)
	})
	stopWatching := func() {
		if !stopCancel() {
			<-cancelDone
		}
	}
	results := make(chan clientAddressCreationResult)
	slot.launched = true
	go func() {
		defer slot.release()
		scope, err := factory.ForClientSession(factoryCtx, valid)
		if addressscope.IsNil(scope) {
			scope = nil
			if err == nil {
				err = ErrClientAddressScope
			}
		}
		if err != nil && scope != nil {
			_ = scope.Close()
			scope = nil
		}
		select {
		case results <- clientAddressCreationResult{scope: scope, err: err}:
		case <-factoryCtx.Done():
			if scope != nil {
				_ = scope.Close()
			}
		}
	}()
	select {
	case result := <-results:
		// Join the cancellation callback before transferring ownership. A
		// deferred stop alone can race and retire a successfully installed map.
		stopWatching()
		if err := operationCtx.Err(); err != nil {
			cancelFactory()
			if result.scope != nil {
				_ = result.scope.Close()
			}
			return nil, nil, err
		}
		if err := factoryCtx.Err(); err != nil {
			cancelFactory()
			if result.scope != nil {
				_ = result.scope.Close()
			}
			return nil, nil, ErrClosed
		}
		if result.err != nil {
			cancelFactory()
			return nil, nil, result.err
		}
		return result.scope, cancelFactory, nil
	case <-operationCtx.Done():
		stopWatching()
		cancelFactory()
		return nil, nil, operationCtx.Err()
	case <-factoryCtx.Done():
		stopWatching()
		cancelFactory()
		if err := operationCtx.Err(); err != nil {
			return nil, nil, err
		}
		return nil, nil, ErrClosed
	}
}
