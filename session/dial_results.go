package session

import (
	"bfp/protocol"
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// A nonzero-sized token has distinct allocation identity for each OPEN.
type dialToken struct{ marker byte }

type dialResult struct {
	flow  uint64
	token *dialToken
	conn  net.Conn
	err   error
}

// Background tasks retain this bounded result owner, never Session, Flow, or
// streamState. Retirement transfers unconsumed connections to cleanup; a late
// result is closed by its returning worker instead of entering an actor queue.
type dialResultMailbox struct {
	mu       sync.Mutex
	retired  bool
	overflow bool
	limit    int
	queue    []dialResult
	wake     chan struct{}
}

func newDialResultMailbox(limit int) *dialResultMailbox {
	return &dialResultMailbox{limit: max(1, min(limit, 4096)), wake: make(chan struct{}, 1)}
}

func (m *dialResultMailbox) publish(result dialResult) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.retired {
		return false
	}
	if len(m.queue) >= m.limit {
		m.overflow = true
		select {
		case m.wake <- struct{}{}:
		default:
		}
		return false
	}
	m.queue = append(m.queue, result)
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return true
}

func (m *dialResultMailbox) take() ([]dialResult, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	results, overflow := m.queue, m.overflow
	m.queue, m.overflow = nil, false
	return results, overflow
}

func (m *dialResultMailbox) retire() {
	m.mu.Lock()
	m.retired = true
	results := m.queue
	m.queue = nil
	m.mu.Unlock()
	for _, result := range results {
		if result.conn != nil {
			_ = result.conn.Close()
		}
	}
}

func runBackendDial(base Backend, ctx context.Context, cancel context.CancelFunc, network, address string, id uint64, token *dialToken, results *dialResultMailbox) {
	defer cancel()
	conn, err := base.DialContext(ctx, network, address)
	if canceled := ctx.Err(); canceled != nil {
		if conn != nil {
			_ = conn.Close()
			conn = nil
		}
		err = canceled
	}
	if !results.publish(dialResult{flow: id, token: token, conn: conn, err: err}) && conn != nil {
		_ = conn.Close()
	}
}

func (s *Session) dialResultWake() <-chan struct{} {
	if s.dialResults == nil {
		return nil
	}
	return s.dialResults.wake
}

func (s *Session) finishDialResults() {
	results, overflow := s.dialResults.take()
	if overflow {
		s.cancel()
	}
	for _, result := range results {
		s.finishDialResult(result)
	}
}

func (s *Session) finishDialResult(result dialResult) {
	s.admissionMu.RLock()
	st := s.streams[result.flow]
	if s.dialing > 0 {
		s.dialing--
	}
	if s.terminating() || st == nil || st.reset || st.dialToken != result.token ||
		s.authority != nil && s.authority.revoked.Load() ||
		!s.info.lifetimeUntil.IsZero() && !time.Now().Before(s.info.lifetimeUntil) {
		s.admissionMu.RUnlock()
		if result.conn != nil {
			_ = result.conn.Close()
		}
		return
	}
	st.dialToken, st.dialCancel = nil, nil
	st.opening = false
	st.openResult = "ok"
	err := result.err
	if err == nil && result.conn == nil {
		err = errors.New("session: backend returned no target connection")
	}
	if err != nil {
		st.openResult = "failed"
		st.reset = true
		if s.classTable != nil {
			s.classTable.Forget(st.flow.id)
		}
		st.flow.fail(err)
	} else {
		st.targetConn = result.conn
		s.bridge(st)
	}
	s.enqueue(s.openResultFrame(st), protocol.Interactive)
	s.admissionMu.RUnlock()
	// Even an unusual backend returning both a connection and an error has an
	// explicit owner for the unaccepted socket. No callback is discarded here.
	if err != nil && result.conn != nil {
		_ = result.conn.Close()
	}
}
