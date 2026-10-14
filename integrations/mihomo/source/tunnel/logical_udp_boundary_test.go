package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// These directed injection tests cover invalid local adapter results and pool
// release. Real BFP/SOCKS/target behavior is covered separately by the external
// TestBFPLogicalUDPRealTunnelMultiTargetAndFakeIP integration test.
type logicalUDPBoundaryConn struct {
	C.PacketConn
	restore                     net.Addr
	err                         error
	reads, puts, closes, writes atomic.Int32
}

func (c *logicalUDPBoundaryConn) SetReadDeadline(time.Time) error { return nil }
func (c *logicalUDPBoundaryConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	if c.reads.Add(1) > 1 {
		return nil, nil, nil, io.EOF
	}
	return []byte("owned-buffer"), func() { c.puts.Add(1) }, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, nil
}
func (c *logicalUDPBoundaryConn) Close() error { c.closes.Add(1); return nil }
func (c *logicalUDPBoundaryConn) WriteTo(b []byte, destination net.Addr) (int, error) {
	c.writes.Add(1)
	return len(b), nil
}
func (c *logicalUDPBoundaryConn) PrepareUDPMetadata(context.Context, *C.Metadata, netip.AddrPort) (net.Addr, error) {
	return nil, errors.New("boundary fixture does not prepare sends")
}
func (c *logicalUDPBoundaryConn) RestoreUDPSource(net.Addr) (net.Addr, error) {
	return c.restore, c.err
}

type logicalUDPBoundaryWriteBack struct{ writes atomic.Int32 }

func (w *logicalUDPBoundaryWriteBack) WriteBack(b []byte, source net.Addr) (int, error) {
	w.writes.Add(1)
	return len(b), nil
}

type logicalUDPBoundaryPacket struct{}

func (logicalUDPBoundaryPacket) Data() []byte { return []byte("payload") }
func (logicalUDPBoundaryPacket) Drop()        {}
func (logicalUDPBoundaryPacket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}
func (logicalUDPBoundaryPacket) WriteBack([]byte, net.Addr) (int, error) { return 0, io.ErrClosedPipe }

func TestBFPLogicalUDPNilRemoteAddressStillRejected(t *testing.T) {
	var typedNil *net.UDPAddr
	for _, destination := range []net.Addr{nil, typedNil, logicalTCPAddr{}} {
		pc := new(logicalUDPBoundaryConn)
		if err := handleUDPToRemote(logicalUDPBoundaryPacket{}, pc, destination); err == nil || pc.writes.Load() != 0 {
			t.Fatal("non-UDP destination bypassed the UDP address contract")
		}
	}
}

type logicalTCPAddr struct{}

func (logicalTCPAddr) Network() string { return "tcp" }
func (logicalTCPAddr) String() string  { return "127.0.0.1:1234" }

func TestBFPLogicalUDPRejectedRestoreNeverUsesFirstTarget(t *testing.T) {
	var typedNil *net.UDPAddr
	cases := []struct {
		name    string
		restore net.Addr
		err     error
	}{
		{"error", nil, errors.New("unregistered source")},
		{"nil", nil, nil},
		{"typed_nil", typedNil, nil},
		{"non_udp_network", logicalTCPAddr{}, nil},
		{"invalid_numeric", &net.UDPAddr{Port: 1234}, nil},
		{"zero_port", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc := &logicalUDPBoundaryConn{restore: tc.restore, err: tc.err}
			writeBack := new(logicalUDPBoundaryWriteBack)
			sender := newPacketSender().(*packetSender)
			handleUDPToLocal(writeBack, pc, sender, "bfp-logical-rejection-"+tc.name, netip.MustParseAddrPort("127.0.0.2:5678"))
			if writeBack.writes.Load() != 0 || pc.puts.Load() != 1 || pc.closes.Load() != 1 || pc.reads.Load() != 1 {
				t.Fatal("rejected source fell back, lost its pool release or continued receiving")
			}
			select {
			case <-sender.ctx.Done():
			default:
				t.Fatal("rejection did not stop sender")
			}
		})
	}
}
