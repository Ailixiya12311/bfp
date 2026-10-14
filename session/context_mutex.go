package session

import (
	"context"
	"sync"
)

// contextMutex preserves the ordinary Lock/Unlock boundary for Client accessors
// and lifecycle workers. Connect may leave the queue when its own or Client's
// context ends, without borrowing the lock owner's handshake/session context.
// The zero value is usable. Client and this lock must not be copied after use.
type contextMutex struct {
	once  sync.Once
	token chan struct{}
}

func (m *contextMutex) init() {
	m.once.Do(func() {
		m.token = make(chan struct{}, 1)
		m.token <- struct{}{}
	})
}

func (m *contextMutex) Lock() {
	m.init()
	<-m.token
}

func (m *contextMutex) Unlock() {
	m.init()
	select {
	case m.token <- struct{}{}:
	default:
		panic("session: unlock of unlocked context mutex")
	}
}

func (m *contextMutex) LockContext(ctx context.Context) error {
	// Check both before and after selecting the token. When cancellation and an
	// available token are simultaneously ready, select alone can admit work.
	if err := ctx.Err(); err != nil {
		return err
	}
	m.init()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.token:
		if err := ctx.Err(); err != nil {
			m.Unlock()
			return err
		}
		return nil
	}
}
