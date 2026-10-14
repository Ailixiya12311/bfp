package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"bfp/adapter/socks"
	"bfp/session"
)

func clientAddressSOCKSRequest(t *testing.T, listener net.Addr, cmd byte, ip net.IP, port int, ctx context.Context) (net.Conn, byte, *net.UDPAddr) {
	t.Helper()
	conn, err := net.Dial("tcp", listener.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatalf("SOCKS greeting=%v err=%v", greeting, err)
	}
	request := append([]byte{5, cmd, 0, 1}, ip.To4()...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply[0] != 5 || reply[3] != 1 {
		t.Fatalf("SOCKS reply=%v err=%v", reply, err)
	}
	return conn, reply[1], &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:10]))}
}

func TestClientAddressScopeSOCKSRealTCPUDPAndRejectsSplitRestorer(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			var port int
			var targets *atomic.Int32
			if network == "tcp" {
				port, targets = sessionDNSRuntimeEcho(t, deadline)
			} else {
				echo, messages := sessionFakeIPRuntimeUDPEcho(t)
				port, targets = echo.LocalAddr().(*net.UDPAddr).Port, messages
			}
			base, err := New(Policy{AllowPrivate: true, AllowedCIDRs: []string{"127.0.0.0/8"}, AllowedPorts: []int{port}, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			const host = "client-socks.test"
			base.lookup = func(_ context.Context, name string) ([]net.IPAddr, error) {
				if name != host {
					return nil, errors.New("SOCKS did not restore through selected Session")
				}
				return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
			}
			server, credentials := sessionDNSTerminationServer(t, ctx, &sessionDNSRuntimeFactory{base: base}, session.Options{})
			recorder := newClientAddressScopeRecorder(t)
			client, connected, allocator := newClientAddressScoped(t, ctx, server, credentials, session.Options{}, recorder, "")
			ip, err := allocator.AllocateSessionAddress(host)
			if err != nil {
				t.Fatal(err)
			}
			if entry, err := socks.New(socks.Config{Backend: client, TargetRestorer: recorder.snapshot()[0]}); entry != nil || !errors.Is(err, socks.ErrTargetRestorerConflict) {
				if entry != nil {
					entry.Close()
				}
				t.Fatalf("split restorer accepted: %v", err)
			}
			entry, err := socks.New(socks.Config{Backend: client, DomainSource: socks.DomainSourceSOCKSAddress})
			if err != nil {
				t.Fatal(err)
			}
			serveDone := make(chan error, 1)
			go func() { serveDone <- entry.Serve(ctx) }()
			t.Cleanup(func() {
				entry.Close()
				select {
				case err := <-serveDone:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(time.Second):
					t.Error("SOCKS entry did not stop")
				}
			})
			payload := []byte("SOCKS fake IP resolves inside selected Session")
			if network == "tcp" {
				conn, code, _ := clientAddressSOCKSRequest(t, entry.Addr(), 1, net.ParseIP(ip.String()), port, ctx)
				if code != 0 {
					t.Fatalf("CONNECT failed=%d", code)
				}
				if _, err := conn.Write(payload); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("SOCKS TCP echo=%q err=%v", got, err)
				}
			} else {
				_, code, relay := clientAddressSOCKSRequest(t, entry.Addr(), 3, net.IPv4zero, 0, ctx)
				if code != 0 {
					t.Fatalf("UDP ASSOCIATE failed=%d", code)
				}
				udp, err := net.DialUDP("udp", nil, relay)
				if err != nil {
					t.Fatal(err)
				}
				defer udp.Close()
				udp.SetDeadline(deadline)
				packet := append([]byte{0, 0, 0, 1}, net.ParseIP(ip.String()).To4()...)
				packet = binary.BigEndian.AppendUint16(packet, uint16(port))
				packet = append(packet, payload...)
				if _, err := udp.Write(packet); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, 4096)
				n, err := udp.Read(got)
				if err != nil || !bytes.Equal(got[:n], packet) {
					t.Fatalf("SOCKS UDP response differs n=%d err=%v", n, err)
				}
			}
			if targets.Load() != 1 || connected.Stats().Opened != 1 || len(recorder.snapshot()) != 1 {
				t.Fatal("SOCKS did not use one target and owner scope")
			}
			// Close only the Session. A later request through the same SOCKS entry
			// causes Client's automatic new Session; its map has no old fake IP.
			if err := connected.Close(); err != nil {
				t.Fatal(err)
			}
			_, code, _ := clientAddressSOCKSRequest(t, entry.Addr(), 1, net.ParseIP(ip.String()), port, ctx)
			if code == 0 {
				t.Fatal("SOCKS accepted old scope address after Client replacement")
			}
			if targets.Load() != 1 || client.Session().Stats().Opened != 0 || len(recorder.snapshot()) != 2 {
				t.Fatal("stale SOCKS target created a new flow/socket")
			}
			if _, err := client.Session().DialContext(ctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(port))); !errors.Is(err, ErrFakeIPUnmapped) {
				t.Fatalf("stale direct target error=%v", err)
			}
		})
	}
}

func TestClientAddressScopeFactoryNeverWrapsOrReusesRetiredAddress(t *testing.T) {
	factory, err := NewFakeIPScopeFactory(time.Minute, 64)
	if err != nil {
		t.Fatal(err)
	}
	firstRaw, err := factory.ForClientSession(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	first := firstRaw.(*FakeIPScope)
	ip, err := first.Allocate("first.test")
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	secondRaw, err := factory.ForClientSession(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	second := secondRaw.(*FakeIPScope)
	defer second.Close()
	next, err := second.Allocate("second.test")
	if err != nil || next == ip {
		t.Fatalf("retired address reused: %s old=%s err=%v", next, ip, err)
	}
	if _, err := second.Resolve(ip); !errors.Is(err, ErrFakeIPUnmapped) {
		t.Fatal("new map resolved an old address")
	}
	factory.mu.Lock()
	factory.next = fakeIPScopePrefix.Addr().Prev()
	factory.mu.Unlock()
	if _, err := second.Allocate("after-exhaustion.test"); !errors.Is(err, ErrFakeIPCapacity) {
		t.Fatalf("exhausted factory wrapped address pool: %v", err)
	}
}
