package session

import (
	"bfp/security"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type carrier struct {
	profile       string
	capabilities  Capabilities
	kind          string
	generation    uint64
	handle        [16]byte
	tx, rx        *security.RecordCipher
	keys          security.TransportKeys
	conn          net.Conn
	udp           *net.UDPConn
	remote        *net.UDPAddr
	framer        *security.Framer
	closed        chan struct{}
	closeOnce     sync.Once
	writeMu       sync.Mutex // protects deadline installation, never held during I/O
	writeLimit    time.Time
	writeDeadline time.Time
	// writeWake is replaced and closed whenever writeLimit becomes tighter.
	// Shared UDP owners observe it without touching the shared socket from a
	// Session goroutine. The channel is carrier-local, so one Session cannot
	// shorten a sibling's active shared write.
	writeWake chan struct{}
	udpWriter *sharedUDPWriter
}

func makeCarrier(kind string, gen uint64, handle []byte, keys *security.TransportKeys, conn net.Conn, udp *net.UDPConn, remote *net.UDPAddr) (*carrier, error) {
	if len(handle) != 16 || keys == nil {
		return nil, errors.New("session: invalid carrier binding")
	}
	c := &carrier{kind: kind, generation: gen, keys: *keys, conn: conn, udp: udp, remote: remote, closed: make(chan struct{}), writeWake: make(chan struct{})}
	copy(c.handle[:], handle)
	var e error
	c.tx, e = security.NewRecordCipher(keys.Send[:], c.handle, 0)
	if e != nil {
		return nil, e
	}
	c.rx, e = security.NewRecordCipher(keys.Receive[:], c.handle, 0)
	if e != nil {
		return nil, e
	}
	if kind == "tcp" {
		c.framer, e = security.NewFramer(conn, keys.Send[:], keys.Receive[:])
		if e != nil {
			return nil, e
		}
	}
	return c, nil
}
func (c *carrier) write(record []byte) error {
	return c.writeUntil(record, time.Time{})
}

func (c *carrier) writeUntil(record []byte, until time.Time) error {
	if c.kind == "tcp" {
		deadline := time.Now().Add(2 * time.Second)
		if !until.IsZero() {
			deadline = earlier(deadline, until)
		}
		c.writeMu.Lock()
		if !c.writeLimit.IsZero() {
			deadline = earlier(deadline, c.writeLimit)
		}
		c.writeDeadline = deadline
		err := c.conn.SetWriteDeadline(deadline)
		c.writeMu.Unlock()
		if err != nil {
			return err
		}
		e := c.framer.Write(record)
		c.writeMu.Lock()
		c.writeDeadline = time.Time{}
		_ = c.conn.SetWriteDeadline(c.writeLimit)
		c.writeMu.Unlock()
		return e
	}
	if len(record) > security.MaxUDPRecordSize {
		return security.ErrSize
	}
	if c.udp != nil {
		if c.udpWriter != nil {
			return c.udpWriter.write(record, c.remote, c, until)
		}
		// A carrier constructed by an owner-only unit test may not have the
		// Server writer. Keep that path bounded as well, but never use it for
		// production shared sockets.
		return writeUDPConn(c.udp, record, c.remote, until)
	}
	if c.conn == nil {
		return net.ErrClosed
	}
	deadline := time.Now().Add(privateUDPWriteBudget)
	if !until.IsZero() {
		deadline = earlier(deadline, until)
	}
	c.writeMu.Lock()
	if !c.writeLimit.IsZero() {
		deadline = earlier(deadline, c.writeLimit)
	}
	c.writeDeadline = deadline
	err := c.conn.SetWriteDeadline(deadline)
	c.writeMu.Unlock()
	if err != nil {
		return err
	}
	n, e := c.conn.Write(record)
	c.writeMu.Lock()
	c.writeDeadline = time.Time{}
	_ = c.conn.SetWriteDeadline(c.writeLimit)
	c.writeMu.Unlock()
	if e == nil && n != len(record) {
		e = io.ErrShortWrite
	}
	return e
}

const privateUDPWriteBudget = 2 * time.Second

func writeUDPConn(conn *net.UDPConn, record []byte, remote *net.UDPAddr, until time.Time) error {
	deadline := time.Now().Add(privateUDPWriteBudget)
	if !until.IsZero() {
		deadline = earlier(deadline, until)
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	n, err := conn.WriteToUDP(record, remote)
	_ = conn.SetWriteDeadline(time.Time{})
	if err == nil && n != len(record) {
		err = io.ErrShortWrite
	}
	return err
}

func (c *carrier) limitWrite(until time.Time) {
	if c.kind == "tcp" && c.conn == nil {
		return
	}
	if c.kind != "tcp" && (c.kind != "udp" || c.udp == nil && c.conn == nil) {
		return
	}
	c.writeMu.Lock()
	if c.writeLimit.IsZero() || until.Before(c.writeLimit) {
		c.writeLimit = until
		if c.writeWake == nil {
			c.writeWake = make(chan struct{})
		}
		wake := c.writeWake
		c.writeWake = make(chan struct{})
		close(wake)
	}
	deadline := c.writeLimit
	if !c.writeDeadline.IsZero() {
		deadline = earlier(deadline, c.writeDeadline)
	}
	if c.kind == "udp" && c.udp != nil {
		// The shared writer is the only goroutine allowed to touch the
		// shared socket deadline. Closing writeWake above is its wakeup.
		c.writeMu.Unlock()
		return
	}
	_ = c.conn.SetWriteDeadline(deadline)
	c.writeMu.Unlock()
}

func (c *carrier) writeState() (time.Time, <-chan struct{}) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeLimit, c.writeWake
}
func (c *carrier) read() ([]byte, error) {
	if c.kind == "tcp" {
		return c.framer.Read()
	}
	buf := make([]byte, security.MaxUDPRecordSize+1)
	n, e := c.conn.Read(buf)
	if e != nil {
		return nil, e
	}
	if n > security.MaxUDPRecordSize {
		return nil, security.ErrSize
	}
	return buf[:n], nil
}
func (c *carrier) close() {
	c.closeOnce.Do(func() {
		// Release a reader waiting for actor admission before closing the socket.
		// Some state tests construct carriers without a live lifecycle channel.
		if c.closed != nil {
			close(c.closed)
		}
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
}
