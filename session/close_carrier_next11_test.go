package session

import (
	"errors"
	"net"
	"testing"
)

// Removing a part of an authenticated binding must fail locally before any
// record number, write attempt, or successful publication can be allocated.
// This includes the synthetic TCP carrier that panicked in next10's full gate.
func TestCloseRejectsIncompleteAuthenticatedBinding(t *testing.T) {
	for _, mode := range []string{"synthetic-tcp", "missing-tx", "missing-rx", "missing-socket", "missing-tcp-framer", "shared-udp-missing-peer-with-private-conn"} {
		t.Run(mode, func(t *testing.T) {
			s, conn, _, now := closeOwnerFixture(t, false)
			switch mode {
			case "synthetic-tcp":
				s.current = &carrier{kind: "tcp", generation: 1}
			case "missing-tx":
				s.current.tx = nil
			case "missing-rx":
				s.current.rx = nil
			case "missing-socket":
				s.current.conn = nil
			case "missing-tcp-framer":
				s.current.kind = "tcp"
			case "shared-udp-missing-peer-with-private-conn":
				// writeUntil chooses the shared socket even if conn is nonnil.
				udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = udp.Close() })
				s.current.udp = udp
				s.current.remote = nil
			}
			s.requestClose(true, now)
			s.closeTick(now)
			if !s.businessCleaned || s.controlContext().Err() == nil || !errors.Is(s.closeErr, ErrCloseUnconfirmed) {
				t.Fatal("incomplete binding did not finish local cleanup with an unconfirmed result")
			}
			if len(conn.writes) != 0 || s.closing.requestAttempts != 0 || s.closing.ackAttempts != 0 || s.closing.attemptedBytes != 0 || s.closing.localPublished {
				t.Fatal("incomplete binding fabricated record publication or charged a physical write")
			}
		})
	}
}
