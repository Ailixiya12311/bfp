package session

import (
	"bfp/obfuscation"
	"bfp/protocol"
	"bfp/security"
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The relay forwards the original encrypted records. Its independently owned
// receive cipher is installed through the relay actor only to select loss; it
// never seals records, edits plaintext, or injects a synthetic Session state.
type fecRuntimeRelayPacketNext15 struct {
	wire   []byte
	client *net.UDPAddr
	toExit bool
}

type fecRuntimeRelayCommandNext15 struct {
	shadow  *security.RecordCipher
	message uint64
	offsets []uint32
	release bool
	done    chan error
}

type fecRuntimeRelayNext15 struct {
	front     *net.UDPConn
	back      *net.UDPConn
	packets   chan fecRuntimeRelayPacketNext15
	commands  chan fecRuntimeRelayCommandNext15
	stop      chan struct{}
	done      chan struct{}
	readers   sync.WaitGroup
	once      sync.Once
	dropped   atomic.Uint64
	repairs   atomic.Uint64
	forwarded atomic.Uint64
	failed    atomic.Bool
}

func newFECRuntimeRelayNext15(t *testing.T, exit string) *fecRuntimeRelayNext15 {
	t.Helper()
	address, err := net.ResolveUDPAddr("udp", exit)
	if err != nil {
		t.Fatal(err)
	}
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	back, err := net.DialUDP("udp", nil, address)
	if err != nil {
		front.Close()
		t.Fatal(err)
	}
	r := &fecRuntimeRelayNext15{front: front, back: back, packets: make(chan fecRuntimeRelayPacketNext15, 64), commands: make(chan fecRuntimeRelayCommandNext15, 4), stop: make(chan struct{}), done: make(chan struct{})}
	r.readers.Add(2)
	go r.read(front, true)
	go r.read(back, false)
	go r.run()
	t.Cleanup(func() {
		r.once.Do(func() { close(r.stop); r.front.Close(); r.back.Close() })
		select {
		case <-r.done:
		case <-time.After(time.Second):
			t.Error("FEC UDP relay actor did not stop within 1s")
		}
		readersDone := make(chan struct{})
		go func() { r.readers.Wait(); close(readersDone) }()
		select {
		case <-readersDone:
		case <-time.After(time.Second):
			t.Error("FEC UDP relay readers did not join within 1s")
		}
	})
	return r
}

func (r *fecRuntimeRelayNext15) read(conn *net.UDPConn, toExit bool) {
	defer r.readers.Done()
	buffer := make([]byte, security.MaxRecordSize)
	for {
		n, peer, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		p := fecRuntimeRelayPacketNext15{wire: append([]byte(nil), buffer[:n]...), client: peer, toExit: toExit}
		select {
		case r.packets <- p:
		case <-r.stop:
			return
		}
	}
}

func (r *fecRuntimeRelayNext15) writeExit(wire []byte) error {
	if err := r.back.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	_, err := r.back.Write(wire)
	return err
}

func (r *fecRuntimeRelayNext15) run() {
	defer close(r.done)
	var client *net.UDPAddr
	var shadow *security.RecordCipher
	var message uint64
	var dropped [][]byte // at most the requested bounded loss offsets
	offsets := make(map[uint32]bool)
	for {
		select {
		case <-r.stop:
			return
		case command := <-r.commands:
			var err error
			if command.release {
				for _, wire := range dropped {
					if err = r.writeExit(wire); err != nil {
						break
					}
				}
				dropped = nil
			} else {
				shadow, message = command.shadow, command.message
				clear(offsets)
				for _, offset := range command.offsets {
					offsets[offset] = false
				}
			}
			command.done <- err
		case packet := <-r.packets:
			if !packet.toExit {
				if client == nil {
					r.failed.Store(true)
					continue
				}
				if err := r.front.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
					r.failed.Store(true)
					continue
				}
				if _, err := r.front.WriteToUDP(packet.wire, client); err != nil {
					r.failed.Store(true)
				}
				continue
			}
			client = packet.client
			drop := false
			if shadow != nil {
				plain, _, err := shadow.Open(packet.wire)
				if err == nil {
					plain, err = obfuscation.Unpad(plain)
					if err == nil {
						frames, decodeErr := protocol.Decode(plain)
						if decodeErr != nil {
							r.failed.Store(true)
						}
						for _, frame := range frames {
							if frame.Kind == protocol.DatagramRepairFrame {
								r.repairs.Add(1)
							}
							if frame.Kind == protocol.Datagram && frame.Offset == message {
								offset := uint32(frame.Value)
								if already, selected := offsets[offset]; selected && !already {
									if len(frames) != 1 {
										r.failed.Store(true) // do not hide unrelated controls
										continue
									}
									offsets[offset] = true
									drop = true
								}
							}
						}
					} else {
						r.failed.Store(true)
					}
				}
			}
			if drop {
				dropped = append(dropped, append([]byte(nil), packet.wire...))
				r.dropped.Add(1)
				continue
			}
			if err := r.writeExit(packet.wire); err != nil {
				r.failed.Store(true)
			} else {
				r.forwarded.Add(1)
			}
		}
	}
}

func (r *fecRuntimeRelayNext15) command(t *testing.T, command fecRuntimeRelayCommandNext15) {
	t.Helper()
	command.done = make(chan error, 1)
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	select {
	case r.commands <- command:
	case <-r.done:
		t.Fatal("FEC relay terminated before command")
	case <-timeout.C:
		t.Fatal("FEC relay command admission exceeded 1s")
	}
	select {
	case err := <-command.done:
		if err != nil {
			t.Fatal("FEC relay command write failed")
		}
	case <-r.done:
		t.Fatal("FEC relay terminated during command")
	case <-timeout.C:
		t.Fatal("FEC relay command completion exceeded 1s")
	}
}

type fecRuntimeBackendNext15 struct {
	address string
	dials   atomic.Uint64
}

func (b *fecRuntimeBackendNext15) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "udp" || address != b.address {
		return nil, errors.New("FEC fixture target is outside its bounded UDP echo")
	}
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
	if err == nil {
		b.dials.Add(1)
	}
	return conn, err
}

type fecRuntimeFixtureNext15 struct {
	client, peer *Session
	flow         *Flow
	relay        *fecRuntimeRelayNext15
	backend      *fecRuntimeBackendNext15
	received     *atomic.Int32
}

func fecRuntimeEchoNext15(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	received := &atomic.Int32{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 16<<10)
		for {
			n, peer, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			received.Add(1)
			if err = conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
				return
			}
			if _, err = conn.WriteToUDP(buffer[:n], peer); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		conn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("bounded FEC UDP echo worker did not join within 1s")
		}
	})
	return conn.LocalAddr().String(), received
}

func newFECRuntimeFixtureNext15(t *testing.T, losses []uint32) *fecRuntimeFixtureNext15 {
	t.Helper()
	address, received := fecRuntimeEchoNext15(t)
	backend := &fecRuntimeBackendNext15{address: address}
	clientKeys, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	exitKeys, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	admission := randomBytes(32)
	selected := CapabilityClassAnnouncementV1 | CapabilityDatagramXORV1
	negotiation := &NegotiationConfig{Profile: ProfileClassAnnouncementV1, OfferedCapabilities: selected, RequiredCapabilities: selected}
	opts := Options{HandshakeTimeout: time.Second, ProbeInterval: 100 * time.Millisecond, FailureTimeout: 5 * time.Second, RetainTimeout: 5 * time.Second, KeyUpdateBytes: 1 << 30, KeyUpdateInterval: time.Hour}
	server, err := NewServer(ServerConfig{Listen: "127.0.0.1:0", Backend: backend, Options: opts, Negotiation: negotiation,
		Credentials: Credentials{Admission: admission, Private: exitKeys.Private, Public: exitKeys.Public, AllowedClients: [][]byte{clientKeys.Public}}})
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background()) }()
	t.Cleanup(func() {
		server.Close()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Error("FEC runtime server returned an error")
			}
		case <-time.After(time.Second):
			t.Error("FEC runtime server did not join within 1s")
		}
	})
	relay := newFECRuntimeRelayNext15(t, server.Addr().String())
	client, err := NewClient(ClientConfig{Server: relay.front.LocalAddr().String(), TCPServer: server.Addr().String(), Options: opts, Negotiation: negotiation,
		Credentials: Credentials{Admission: admission, Private: clientKeys.Private, Public: clientKeys.Public, ServerPublic: exitKeys.Public}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Abort() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s, err := client.Connect(ctx)
	if err != nil {
		t.Fatal("FEC runtime authenticated UDP connection failed")
	}
	id := s.Stats().ID
	server.mu.Lock()
	peer := server.sessions[id]
	server.mu.Unlock()
	if peer == nil {
		t.Fatal("FEC runtime handshake did not commit its peer Session")
	}
	runtimeWait(t, "FEC real UDP Session synchronization", func() bool { return runtimeReady(s) && runtimeReady(peer) })
	var shadow *security.RecordCipher
	var shadowErr error
	var udp, selectedFEC bool
	if err = s.call(ctx, func() {
		udp = s.current != nil && s.current.kind == "udp" && s.current.generation == 1
		selectedFEC = s.info.Capabilities == selected && s.current.capabilities == selected
		if udp {
			key := s.current.keys.Send
			shadow, shadowErr = security.NewRecordCipher(key[:], s.current.handle, s.current.tx.Epoch())
			clear(key[:])
		}
	}); err != nil || shadowErr != nil || !udp || !selectedFEC {
		t.Fatal("FEC runtime did not retain its selected UDP capability binding")
	}
	relay.command(t, fecRuntimeRelayCommandNext15{shadow: shadow, message: 1, offsets: append([]uint32(nil), losses...)})
	profile := protocol.FECProfile{Version: protocol.FECWireVersion, Algorithm: protocol.FECXOR1, MaxDataShards: 32, ParityShards: 1, ShardSize: 900, MaxBlockSize: 28800}
	conn, err := client.DialClass(ctx, protocol.Target{Network: "udp", Address: address, Class: protocol.Normal, FEC: &profile})
	if err != nil {
		t.Fatal("FEC runtime OPEN failed")
	}
	flow := conn.(*Flow)
	t.Cleanup(func() { flow.Close() })
	flow.SetDeadline(time.Now().Add(2 * time.Second))
	return &fecRuntimeFixtureNext15{client: s, peer: peer, flow: flow, relay: relay, backend: backend, received: received}
}

func fecRuntimeExchangeNext15(t *testing.T, f *fecRuntimeFixtureNext15, payload []byte) {
	t.Helper()
	f.flow.SetDeadline(time.Now().Add(2 * time.Second))
	if n, err := f.flow.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("FEC UDP Datagram write: bytes=%d want=%d error=%v", n, len(payload), err)
	}
	buffer := make([]byte, 16<<10)
	n, err := f.flow.Read(buffer)
	if err != nil || !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("FEC UDP echo differs: bytes=%d want=%d error=%v", n, len(payload), err)
	}
}

func fecRuntimeNoEchoNext15(t *testing.T, f *fecRuntimeFixtureNext15) {
	t.Helper()
	f.flow.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buffer := make([]byte, 16<<10)
	n, err := f.flow.Read(buffer)
	if n != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late/duplicate Datagram reached application: bytes=%d error=%v", n, err)
	}
}

func TestFECRealUDPRecoversOneLostCiphertextShardNext15(t *testing.T) {
	f := newFECRuntimeFixtureNext15(t, []uint32{900})
	payload := fecPayloadNext15(1813)
	fecRuntimeExchangeNext15(t, f, payload)
	runtimeWait(t, "one actual Datagram repair commit and recovery", func() bool {
		return f.relay.dropped.Load() == 1 && f.relay.repairs.Load() >= 1 && f.client.Stats().FECRepairSent == 1 && f.peer.Stats().FECRecoveredDatagrams == 1
	})
	if f.received.Load() != 1 || f.backend.dials.Load() != 1 || f.relay.failed.Load() {
		t.Fatal("single-loss test did not deliver exactly one message through its bounded target")
	}
	// The missing original ciphertext is now delivered late. This is a unique
	// authenticated packet that the receiver has never seen, so the once-only
	// target assertion exercises the Datagram tombstone, not only AEAD replay.
	f.relay.command(t, fecRuntimeRelayCommandNext15{release: true})
	fecRuntimeNoEchoNext15(t, f)
	if f.received.Load() != 1 || f.peer.Stats().FECRecoveredDatagrams != 1 {
		t.Fatal("late original shard duplicated a repaired Datagram")
	}
	for _, payload := range [][]byte{fecPayloadNext15(37), fecPayloadNext15(901)} {
		fecRuntimeExchangeNext15(t, f, payload)
	}
	runtimeWait(t, "three committed per-message repair records", func() bool { return f.client.Stats().FECRepairSent == 3 })
	fecRuntimeNoEchoNext15(t, f)
	if f.received.Load() != 3 || f.backend.dials.Load() != 1 || f.peer.Stats().FECRecoveredDatagrams != 1 || f.relay.failed.Load() {
		t.Fatal("independent message boundaries/counts changed after repair")
	}
}

func TestFECRealUDPTwoLostShardsExpireWithoutDeliveryNext15(t *testing.T) {
	f := newFECRuntimeFixtureNext15(t, []uint32{900, 1800})
	payload := fecPayloadNext15(1813)
	if n, err := f.flow.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("two-loss Datagram write: bytes=%d error=%v", n, err)
	}
	runtimeWait(t, "two actual ciphertext losses and received parity", func() bool {
		return f.relay.dropped.Load() == 2 && f.client.Stats().FECRepairSent == 1 && f.peer.Stats().FECRepairReceived == 1
	})
	fecRuntimeNoEchoNext15(t, f)
	if f.received.Load() != 0 || f.peer.Stats().FECRecoveredDatagrams != 0 {
		t.Fatal("one XOR parity falsely recovered two missing shards")
	}
	runtimeWait(t, "real-clock incomplete message expiry", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		expired := false
		_ = f.peer.call(ctx, func() {
			st := f.peer.streams[f.flow.id]
			expired = st != nil && st.datagrams[1] == nil && st.completed[1]
		})
		return expired
	})
	f.relay.command(t, fecRuntimeRelayCommandNext15{release: true})
	fecRuntimeNoEchoNext15(t, f)
	if f.received.Load() != 0 || f.peer.Stats().FECRecoveredDatagrams != 0 {
		t.Fatal("late ciphertext revived an expired incomplete Datagram")
	}
	fecRuntimeExchangeNext15(t, f, fecPayloadNext15(73))
	if f.received.Load() != 1 || f.backend.dials.Load() != 1 || f.relay.failed.Load() {
		t.Fatal("expired message damaged the next intact Datagram")
	}
}
