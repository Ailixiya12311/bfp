package main

import (
	"context"
	"net"
	"sync"
	"time"
)

// probeContextConn serializes cancellation with every deadline setter. Once
// its context is cancelled, no caller can replace the immediate deadline with
// a future time (or clear it with the zero time). The context's terminal state
// is checked under the same lock, including before AfterFunc has acquired it.
// Read and Write retain the underlying net.Conn's delivery semantics.
type probeContextConn struct {
	net.Conn
	ctx  context.Context
	mu   sync.Mutex
	stop func() bool
}

func newProbeContextConn(ctx context.Context, conn net.Conn) *probeContextConn {
	c := &probeContextConn{Conn: conn, ctx: ctx}
	c.stop = context.AfterFunc(ctx, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		_ = c.Conn.SetDeadline(time.Now())
	})
	return c
}

func (c *probeContextConn) deadline(deadline time.Time) time.Time {
	if c.ctx.Err() != nil {
		return time.Now()
	}
	if limit, ok := c.ctx.Deadline(); ok && (deadline.IsZero() || limit.Before(deadline)) {
		return limit
	}
	return deadline
}

func (c *probeContextConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.SetDeadline(c.deadline(deadline))
}

func (c *probeContextConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.SetReadDeadline(c.deadline(deadline))
}

func (c *probeContextConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.SetWriteDeadline(c.deadline(deadline))
}

func (c *probeContextConn) Read(data []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.Conn.Read(data)
}

func (c *probeContextConn) Write(data []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.Conn.Write(data)
}

func (c *probeContextConn) stopCancellation() { c.stop() }
