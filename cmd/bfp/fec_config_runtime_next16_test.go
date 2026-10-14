package main

import (
	"bfp/adapter/socks"
	"bfp/classification"
	"bfp/protocol"
	"bfp/session"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This numeric target seam avoids external DNS. It validates the requested
// business domain/port, but does not claim gateway DNS or target-policy coverage.
type fecCLIExitNext16 struct {
	udp, tcp           string
	udpDials, tcpDials atomic.Int32
}

func (b *fecCLIExitNext16) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	target := b.udp
	if network == "tcp" {
		target = b.tcp
	}
	host, port, err := net.SplitHostPort(address)
	_, expected, splitErr := net.SplitHostPort(target)
	if err != nil || splitErr != nil || host != "fec.example.test" || port != expected {
		return nil, errors.New("unexpected FEC fixture target")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, target)
	if err == nil {
		if network == "tcp" {
			b.tcpDials.Add(1)
		} else {
			b.udpDials.Add(1)
		}
	}
	return conn, err
}

func fecCLITargetsNext16(t *testing.T) (*fecCLIExitNext16, *atomic.Int32) {
	t.Helper()
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		u.Close()
		t.Fatal(err)
	}
	count := &atomic.Int32{}
	udpDone, tcpDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(udpDone)
		buffer := make([]byte, 16<<10)
		for {
			n, peer, err := u.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			count.Add(1)
			u.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err = u.WriteToUDP(buffer[:n], peer); err != nil {
				return
			}
		}
	}()
	var mu sync.Mutex
	var accepted net.Conn
	closed := false
	go func() {
		defer close(tcpDone)
		conn, err := l.Accept()
		if err != nil {
			return
		}
		mu.Lock()
		if closed {
			mu.Unlock()
			conn.Close()
			return
		}
		accepted = conn
		mu.Unlock()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		io.Copy(conn, conn)
		conn.Close()
	}()
	t.Cleanup(func() {
		u.Close()
		l.Close()
		mu.Lock()
		closed = true
		if accepted != nil {
			accepted.Close()
		}
		mu.Unlock()
		for _, done := range []chan struct{}{udpDone, tcpDone} {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("FEC target worker did not join")
			}
		}
	})
	return &fecCLIExitNext16{udp: u.LocalAddr().String(), tcp: l.Addr().String()}, count
}

func fecCLIRewriteNext16(t *testing.T, path string, value any, decoded any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("could not encode private fixture config")
	}
	// keygen already created this existing file with private permissions/ACL.
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err = readConfig(path, decoded); err != nil {
		t.Fatal(err)
	}
}

func fecCLISocksCommandNext16(t *testing.T, endpoint string, command byte, target string) (net.Conn, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", endpoint, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err = io.ReadFull(conn, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatal("SOCKS greeting failed")
	}
	request := []byte{5, command, 0}
	if command == 3 {
		request = append(request, 1, 0, 0, 0, 0, 0, 0)
	} else {
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			t.Fatal(err)
		}
		p, err := strconv.Atoi(port)
		if err != nil || len(host) > 255 {
			t.Fatal("invalid fixture SOCKS destination")
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
		request = binary.BigEndian.AppendUint16(request, uint16(p))
	}
	if _, err = conn.Write(request); err != nil {
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err = io.ReadFull(conn, reply[:]); err != nil || reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
		t.Fatal("SOCKS command failed")
	}
	size := 4
	if reply[3] == 4 {
		size = 16
	} else if reply[3] != 1 {
		t.Fatal("unexpected fixture SOCKS reply address")
	}
	address := make([]byte, size+2)
	if _, err = io.ReadFull(conn, address); err != nil {
		t.Fatal(err)
	}
	bound := net.JoinHostPort(net.IP(address[:size]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(address[size:]))))
	return conn, bound
}

func fecCLIWaitNext16(t *testing.T, name string, ready func() bool) {
	t.Helper()
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		if ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("bounded observation did not reach %s", name)
}

func TestDatagramFECCLIRealSOCKSNext16(t *testing.T) {
	for _, tc := range []struct {
		name, clientFEC, serverFEC string
		repairs                    uint64
	}{
		{"required-final-cap-xor", `{"mode":"required","by_class":{"normal":"xor1"}}`, `{"mode":"required"}`, 2},
		{"optional-default-peer", `{"mode":"optional","by_class":{"normal":"xor1"}}`, "", 0},
		{"cap-denies-interactive-profile", `{"mode":"optional","by_class":{"interactive":"xor1"}}`, `{"mode":"optional"}`, 0},
		{"omitted-old-config", "", "", 0},
		{"support-only-no-policy", `{"mode":"optional"}`, `{"mode":"optional"}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend, received := fecCLITargetsNext16(t)
			keydir := filepath.Join(t.TempDir(), "keys")
			if err := keygen(keydir); err != nil {
				t.Fatal("could not generate private test config")
			}
			clientPath, serverPath := filepath.Join(keydir, "client.json"), filepath.Join(keydir, "server.json")
			var sourceClient clientConfig
			var sourceServer serverConfig
			if err := readConfig(clientPath, &sourceClient); err != nil {
				t.Fatal(err)
			}
			if err := readConfig(serverPath, &sourceServer); err != nil {
				t.Fatal(err)
			}
			sourceServer.Listen = "127.0.0.1:0"
			sourceServer.DatagramFEC = json.RawMessage(tc.serverFEC)
			sourceServer.Classification = json.RawMessage(`{"default_class":"bulk","highest_allowed":"bulk","behavior":{"enabled":false}}`)
			var loadedServer serverConfig
			fecCLIRewriteNext16(t, serverPath, sourceServer, &loadedServer)
			sc, err := loadedServer.sessionConfig(backend)
			if err != nil {
				t.Fatal(err)
			}
			srv, err := session.NewServer(sc)
			if err != nil {
				t.Fatal(err)
			}
			serverDone := make(chan error, 1)
			go func() { serverDone <- srv.Serve(context.Background()) }()
			t.Cleanup(func() {
				srv.Close()
				select {
				case err := <-serverDone:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(time.Second):
					t.Error("FEC server did not join")
				}
			})
			sourceClient.Server, sourceClient.TCPServer = srv.Addr().String(), srv.Addr().String()
			sourceClient.SOCKS = "127.0.0.1:0"
			sourceClient.SOCKSMetadata = json.RawMessage(`{"domain_source":"socks_address"}`)
			sourceClient.Classification = json.RawMessage(`{"default_class":"bulk","highest_allowed":"normal","rules":[{"name":"fec-domain","domain_suffix":"example.test","class":"interactive"}],"behavior":{"enabled":false}}`)
			sourceClient.DatagramFEC = json.RawMessage(tc.clientFEC)
			var loadedClient clientConfig
			fecCLIRewriteNext16(t, clientPath, sourceClient, &loadedClient)
			cc, err := loadedClient.sessionConfig()
			if err != nil {
				t.Fatal(err)
			}
			client, err := session.NewClient(cc)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { client.Abort() })
			// Later caller changes must not alter either the compiled class map
			// or the initial authenticated offer in this actual runtime.
			if cc.DatagramFEC != nil {
				cc.DatagramFEC.ByClass[protocol.Normal] = protocol.DisabledFECProfile()
			}
			if cc.Negotiation != nil {
				cc.Negotiation.OfferedCapabilities, cc.Negotiation.RequiredCapabilities = 1, 1
			}
			tap := &cliClassBackend{client: client, flows: make(chan *session.Flow, 4)}
			socksCfg, err := loadedClient.socksConfig(tap)
			if err != nil {
				t.Fatal(err)
			}
			proxy, err := socks.New(socksCfg)
			if err != nil {
				t.Fatal(err)
			}
			proxyDone := make(chan error, 1)
			go func() { proxyDone <- proxy.Serve(context.Background()) }()
			t.Cleanup(func() {
				proxy.Close()
				select {
				case err := <-proxyDone:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(time.Second):
					t.Error("FEC SOCKS did not join")
				}
			})
			control, relay := fecCLISocksCommandNext16(t, proxy.Addr().String(), 3, "")
			address, err := net.ResolveUDPAddr("udp", relay)
			if err != nil {
				t.Fatal(err)
			}
			udp, err := net.DialUDP("udp", nil, address)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { udp.Close() })
			_, port, _ := net.SplitHostPort(backend.udp)
			p, _ := strconv.Atoi(port)
			header := append([]byte{0, 0, 0, 3, 16}, []byte("fec.example.test")...)
			header = binary.BigEndian.AppendUint16(header, uint16(p))
			for i, size := range []int{1813, 37} {
				packet := append(append([]byte(nil), header...), bytes.Repeat([]byte{byte(65 + i)}, size)...)
				udp.SetDeadline(time.Now().Add(2 * time.Second))
				if n, err := udp.Write(packet); err != nil || n != len(packet) {
					t.Fatal("SOCKS UDP whole write failed")
				}
				buffer := make([]byte, 16<<10)
				n, err := udp.Read(buffer)
				if err != nil || !bytes.Equal(buffer[:n], packet) {
					t.Fatal("CLI/SOCKS encrypted UDP round trip changed message")
				}
			}
			var flow *session.Flow
			select {
			case flow = <-tap.flows:
			case <-time.After(time.Second):
				t.Fatal("actual UDP Flow was not captured")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			snap, err := flow.Classification(ctx)
			if err != nil || snap.LocalTX.Class != protocol.Normal || snap.LocalTX.Baseline.Source != classification.SourceMetadata || snap.LocalTX.Baseline.Rule != "fec-domain" {
				t.Fatal("CLI domain rule/cap did not determine the actual initial class")
			}
			live := client.Session()
			if live == nil || live.Stats().Carrier != "udp" || backend.udpDials.Load() != 1 || received.Load() != 2 {
				t.Fatal("UDP target was redialed or messages duplicated")
			}
			fecCLIWaitNext16(t, "both real repair totals", func() bool {
				states := srv.Snapshot()
				return len(states) == 1 && states[0].FECRepairSent == tc.repairs && live.Stats().FECRepairSent == tc.repairs
			})
			_, tcpPort, _ := net.SplitHostPort(backend.tcp)
			stream, _ := fecCLISocksCommandNext16(t, proxy.Addr().String(), 1, net.JoinHostPort("fec.example.test", tcpPort))
			payload := []byte("reliable-tcp-with-class-fec-policy")
			if _, err := stream.Write(payload); err != nil {
				t.Fatal(err)
			}
			echo := make([]byte, len(payload))
			if _, err := io.ReadFull(stream, echo); err != nil || !bytes.Equal(echo, payload) {
				t.Fatal("TCP reliability changed under the UDP FEC policy")
			}
			if backend.tcpDials.Load() != 1 || live.Stats().FECRepairSent != tc.repairs {
				t.Fatal("TCP flow caused parity or an extra target dial")
			}
			stream.Close()
			control.Close()
		})
	}
}
