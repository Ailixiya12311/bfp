package tunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"bfp/adapter/packet"
	C "github.com/metacubex/mihomo/constant"
)

type logicalUDPTransactionConn struct {
	logicalUDPBoundaryConn
	writeErr                  error
	short                     bool
	prepared                  net.Addr
	prepares, commits, aborts atomic.Int32
}

func (c *logicalUDPTransactionConn) PrepareUDPMetadata(context.Context, *C.Metadata, netip.AddrPort) (net.Addr, error) {
	c.prepares.Add(1)
	return c.prepared, nil
}
func (c *logicalUDPTransactionConn) CommitUDPMetadata(address net.Addr) error {
	if address != c.prepared {
		return errors.New("wrong transaction address")
	}
	c.commits.Add(1)
	return nil
}
func (c *logicalUDPTransactionConn) AbortUDPMetadata(address net.Addr) {
	if address == c.prepared {
		c.aborts.Add(1)
	}
}
func (c *logicalUDPTransactionConn) WriteTo(b []byte, address net.Addr) (int, error) {
	c.writes.Add(1)
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.short {
		return len(b) - 1, nil
	}
	return len(b), nil
}

type logicalUDPTransactionPacket struct{ drops *atomic.Int32 }

func (p logicalUDPTransactionPacket) Data() []byte { return []byte("transaction-payload") }
func (p logicalUDPTransactionPacket) Drop()        { p.drops.Add(1) }
func (p logicalUDPTransactionPacket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}
func (p logicalUDPTransactionPacket) WriteBack([]byte, net.Addr) (int, error) {
	return 0, net.ErrClosed
}

func TestBFPNext25SenderCommitsOnlySuccessfulFullUDPWrite(t *testing.T) {
	for _, tc := range []struct {
		name                             string
		err                              error
		short                            bool
		address                          net.Addr
		wantWrite, wantCommit, wantAbort int32
	}{
		{"full_success", nil, false, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, 1, 1, 0},
		{"canceled", context.Canceled, false, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, 1, 0, 1},
		{"closed", net.ErrClosed, false, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, 1, 0, 1},
		{"pending_limit", packet.ErrLimit, false, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, 1, 0, 1},
		{"short_write", nil, true, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, 1, 0, 1},
		{"wrong_network", nil, false, logicalTCPAddr{}, 0, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc := &logicalUDPTransactionConn{writeErr: tc.err, short: tc.short, prepared: tc.address}
			var drops atomic.Int32
			metadata := &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: 1234}
			sender := newPacketSender().(*packetSender)
			defer sender.Close()
			sender.processPacket(pc, C.NewPacketAdapter(logicalUDPTransactionPacket{&drops}, metadata))
			if pc.prepares.Load() != 1 || pc.writes.Load() != tc.wantWrite || pc.commits.Load() != tc.wantCommit || pc.aborts.Load() != tc.wantAbort || drops.Load() != 1 {
				t.Fatalf("transaction boundary: prepares=%d writes=%d commits=%d aborts=%d drops=%d", pc.prepares.Load(), pc.writes.Load(), pc.commits.Load(), pc.aborts.Load(), drops.Load())
			}
		})
	}
}
