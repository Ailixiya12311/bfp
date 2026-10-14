package session

import (
	"bfp/security"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
)

func capabilityCandidate(t *testing.T, s *Server, cred Credentials, kind, attempt string, port int, previous *sessionInfo, payload []byte) (*pending, *security.Handshake, boot, error) {
	t.Helper()
	mode, expected, ticket := "new", uint64(0), ""
	var secret []byte
	if previous != nil {
		mode, expected, ticket, secret = "resume", previous.Generation, previous.Ticket, previous.Secret
	}
	hs, err := newHandshake(true, mode, kind, attempt, expected, cred, secret)
	if err != nil {
		t.Fatal(err)
	}
	message, _, err := hs.WriteMessage(payload)
	if err != nil {
		t.Fatal(err)
	}
	b := boot{Version: wireVersion, Action: "init", Mode: mode, Attempt: attempt, Expected: expected, Ticket: ticket, Message: message}
	var conn net.Conn
	var addr *net.UDPAddr
	if kind == "udp" {
		addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	} else {
		client, server := net.Pipe()
		conn = server
		t.Cleanup(func() { client.Close(); server.Close() })
	}
	p, err := s.initialize(b, kind, conn, addr)
	return p, hs, b, err
}

func capabilityCommit(t *testing.T, s *Server, cred Credentials, p *pending, hs *security.Handshake, b boot) sessionInfo {
	t.Helper()
	plain, err := security.OpenBootstrap(cred.Admission, p.reply)
	if err != nil {
		t.Fatal(err)
	}
	var reply boot
	if err = decodeJSON(plain, &reply); err != nil {
		t.Fatal(err)
	}
	payload, keys, err := hs.ReadMessage(reply.Message)
	if err != nil || keys == nil {
		t.Fatal("server Noise reply", err)
	}
	var info sessionInfo
	if err = decodeJSON(payload, &info); err != nil {
		t.Fatal(err)
	}
	offer, err := decodeCapabilityOffer(encodeJSON(defaultCapabilityOffer()))
	if err != nil || validateServerSelection(payload, offer, info, nil) != nil {
		t.Fatal("invalid authenticated selection", err)
	}
	var handle [16]byte
	copy(handle[:], info.Handle)
	tx, err := security.NewRecordCipher(keys.Send[:], handle, 0)
	if err != nil {
		t.Fatal(err)
	}
	proof, _, err := tx.Seal(encodeJSON(confirm{info.Challenge, hs.ChannelBinding()}))
	if err != nil {
		t.Fatal(err)
	}
	confirmation := boot{Version: wireVersion, Action: "confirm", Attempt: b.Attempt, Handle: info.Handle, Message: proof}
	if _, _, err = s.confirm(confirmation, p.carrier.kind, p.peer); err != nil {
		t.Fatal("commit", err)
	}
	return info
}

func TestCapabilityWireContract(t *testing.T) {
	if wireVersion != 3 || string(prologue("resume", "tcp", "attempt", 7)) != "bfp/v3-class-announcement1/resume/tcp/attempt/7" {
		t.Fatal("experimental wire/profile binding changed")
	}
	want := []byte(`{"p":"class-announcement-v1","o":1,"r":1}`)
	if got := encodeJSON(defaultCapabilityOffer()); !bytes.Equal(got, want) {
		t.Fatalf("frozen offer encoding: %s", got)
	}
	if offer, err := decodeCapabilityOffer(want); err != nil || offer != defaultCapabilityOffer() {
		t.Fatal("frozen offer decoding", err)
	}
}

func TestCapabilityAuthenticatedNewAndResume(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	go s.Serve(context.Background())
	cfg := ClientConfig{Server: s.Addr().String(), TCPServer: s.Addr().String(), Credentials: cred, Options: Options{HandshakeTimeout: time.Second}}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	initial, previous, err := establish(ctx, cfg, "udp", randomID(), nil)
	if err != nil {
		t.Fatal("UDP initial", err)
	}
	defer initial.close()
	if previous.Profile != ProfileClassAnnouncementV1 || previous.Capabilities != CapabilityClassAnnouncementV1 {
		t.Fatal("missing initial selected capability")
	}
	// Session selection overrides a changed caller config on recovery.
	cfg.Negotiation = &NegotiationConfig{Profile: "changed-config"}
	resumed, info, err := establish(ctx, cfg, "tcp", randomID(), &previous)
	if err != nil {
		t.Fatal("TCP resume", err)
	}
	defer resumed.close()
	if info.ID != previous.ID || info.Generation != previous.Generation+1 || info.Profile != previous.Profile || info.Capabilities != previous.Capabilities {
		t.Fatal("resume changed pinned Session selection")
	}
	s.mu.Lock()
	owner := s.sessions[info.ID]
	s.mu.Unlock()
	snapshot, err := sessionSnapshot(owner)
	if err != nil || snapshot.Profile != info.Profile || snapshot.Capabilities != info.Capabilities {
		t.Fatal("server did not retain selection", err)
	}
}

func TestCapabilityAuthenticatedMalformedOffersRejected(t *testing.T) {
	cases := map[string]string{
		"empty":              "",
		"array":              "[]",
		"null":               "null",
		"missing-profile":    `{"o":1,"r":1}`,
		"missing-offer":      `{"p":"class-announcement-v1","r":1}`,
		"missing-required":   `{"p":"class-announcement-v1","o":1}`,
		"missing-mandatory":  `{"p":"class-announcement-v1","o":1,"r":0}`,
		"unoffered-required": `{"p":"class-announcement-v1","o":0,"r":1}`,
		"unknown-required":   `{"p":"class-announcement-v1","o":3,"r":3}`,
		"unknown-field":      `{"p":"class-announcement-v1","o":1,"r":1,"x":0}`,
		"duplicate":          `{"p":"class-announcement-v1","o":0,"o":1,"r":1}`,
		"case-alias":         `{"p":"legacy","P":"class-announcement-v1","o":1,"r":1}`,
		"null-required":      `{"p":"class-announcement-v1","o":1,"r":null}`,
		"wrong-profile":      `{"p":"legacy","o":1,"r":1}`,
		"overflow":           `{"p":"class-announcement-v1","o":18446744073709551616,"r":1}`,
		"negative":           `{"p":"class-announcement-v1","o":-1,"r":1}`,
		"fractional":         `{"p":"class-announcement-v1","o":1.0,"r":1}`,
		"trailing":           `{"p":"class-announcement-v1","o":1,"r":1}{}`,
		"oversized":          string(bytes.Repeat([]byte(" "), maxCapabilityOfferSize+1)),
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			s, cred := newSecurityTestServer(t)
			p, _, _, err := capabilityCandidate(t, s, cred, "udp", randomID(), 44500, nil, []byte(payload))
			if p != nil || !errors.Is(err, security.ErrAuthentication) {
				t.Fatalf("malformed authenticated offer accepted: %v", err)
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if len(s.pending) != 0 || len(s.attempts) != 0 || len(s.sessions) != 0 || len(s.handles) != 0 {
				t.Fatal("rejected capability offer allocated persistent state")
			}
		})
	}
}

func TestCapabilitySameAttemptRejectsChangedOffer(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	attempt := randomID()
	first, _, _, err := capabilityCandidate(t, s, cred, "udp", attempt, 44510, nil, encodeJSON(defaultCapabilityOffer()))
	if err != nil {
		t.Fatal(err)
	}
	changed := defaultCapabilityOffer()
	changed.Offered |= 2 // unknown optional offers are safe only on new attempts.
	second, _, _, err := capabilityCandidate(t, s, cred, "tcp", attempt, 0, nil, encodeJSON(changed))
	if second != nil || !errors.Is(err, security.ErrAuthentication) {
		t.Fatal("same attempt accepted different authenticated offer", err)
	}
	third, _, _, err := capabilityCandidate(t, s, cred, "tcp", attempt, 0, nil, encodeJSON(defaultCapabilityOffer()))
	if err != nil || third.info.ID != first.info.ID || third.info.Profile != first.info.Profile || third.info.Capabilities != first.info.Capabilities {
		t.Fatal("same offer diverged between UDP and TCP candidates", err)
	}
	optional, _, _, err := capabilityCandidate(t, s, cred, "udp", randomID(), 44511, nil, encodeJSON(changed))
	if err != nil || optional.info.Capabilities != CapabilityClassAnnouncementV1 {
		t.Fatal("server selected unknown optional capability", err)
	}
}

func TestCapabilityResumeRejectsAddedOrDowngradedOffer(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	p, hs, b, err := capabilityCandidate(t, s, cred, "udp", randomID(), 44520, nil, encodeJSON(defaultCapabilityOffer()))
	if err != nil {
		t.Fatal(err)
	}
	previous := capabilityCommit(t, s, cred, p, hs, b)
	for name, offer := range map[string]capabilityOffer{
		"added-optional":      {ProfileClassAnnouncementV1, 3, 1},
		"dropped-capability":  {ProfileClassAnnouncementV1, 0, 0},
		"dropped-requirement": {ProfileClassAnnouncementV1, 1, 0},
		"changed-profile":     {"legacy", 1, 1},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, _, _, err := capabilityCandidate(t, s, cred, "udp", randomID(), 44521, &previous, encodeJSON(offer))
			if candidate != nil || !errors.Is(err, security.ErrAuthentication) {
				t.Fatal("resume renegotiated pinned selection", err)
			}
		})
	}
}

func TestCapabilityWire2NoiseAndBootRejected(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	if _, err := s.initialize(boot{Version: 2}, "udp", nil, &net.UDPAddr{}); !errors.Is(err, security.ErrAuthentication) {
		t.Fatal("wire2 INIT accepted", err)
	}
	if _, _, err := s.confirm(boot{Version: 2}, "udp", ""); !errors.Is(err, security.ErrAuthentication) {
		t.Fatal("wire2 CONFIRM accepted", err)
	}
	for _, mode := range []string{"new", "resume"} {
		t.Run(mode, func(t *testing.T) {
			secret, attempt := randomBytes(32), randomID()
			initiator, err := newHandshake(true, mode, "udp", attempt, 0, cred, secret)
			if err != nil {
				t.Fatal(err)
			}
			old := []byte("bfp/v2-udp-ack1/" + mode + "/udp/" + attempt + "/0")
			var responder *security.Handshake
			if mode == "new" {
				responder, err = security.NewIKHandshake(false, keyPair(s.cfg.Credentials), nil, old)
			} else {
				responder, err = security.NewResumeHandshake(false, secret, old)
			}
			if err != nil {
				t.Fatal(err)
			}
			message, _, err := initiator.WriteMessage(encodeJSON(defaultCapabilityOffer()))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = responder.ReadMessage(message); err == nil {
				t.Fatal("wire2/wire3 mismatched Noise transcript authenticated")
			}
		})
	}
}

func TestCapabilityFirstPayloadTamperRejected(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	attempt := randomID()
	hs, err := newHandshake(true, "new", "udp", attempt, 0, cred, nil)
	if err != nil {
		t.Fatal(err)
	}
	message, _, err := hs.WriteMessage(encodeJSON(defaultCapabilityOffer()))
	if err != nil {
		t.Fatal(err)
	}
	message[len(message)-1] ^= 1
	b := boot{Version: wireVersion, Action: "init", Mode: "new", Attempt: attempt, Message: message}
	if p, err := s.initialize(b, "udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 44525}); p != nil || err == nil {
		t.Fatal("modified authenticated capability offer accepted", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) != 0 || len(s.attempts) != 0 || len(s.sessions) != 0 || len(s.handles) != 0 {
		t.Fatal("unauthenticated capability mutation allocated persistent state")
	}
}

func TestCapabilityConfirmBindsOfferAndSelection(t *testing.T) {
	for _, changed := range []string{"offer", "selection"} {
		t.Run(changed, func(t *testing.T) {
			s, cred := newSecurityTestServer(t)
			attempt := randomID()
			p, hs, _, err := capabilityCandidate(t, s, cred, "udp", attempt, 44526, nil, encodeJSON(defaultCapabilityOffer()))
			if err != nil {
				t.Fatal(err)
			}
			plain, err := security.OpenBootstrap(cred.Admission, p.reply)
			if err != nil {
				t.Fatal(err)
			}
			var reply boot
			if err = decodeJSON(plain, &reply); err != nil {
				t.Fatal(err)
			}
			_, keys, err := hs.ReadMessage(reply.Message)
			if err != nil || keys == nil {
				t.Fatal(err)
			}

			// Build another valid Noise transcript with one changed authenticated
			// negotiation field, then try its binding on the original carrier keys.
			otherI, err := newHandshake(true, "new", "udp", attempt, 0, cred, nil)
			if err != nil {
				t.Fatal(err)
			}
			otherR, err := newHandshake(false, "new", "udp", attempt, 0, s.cfg.Credentials, nil)
			if err != nil {
				t.Fatal(err)
			}
			offer := defaultCapabilityOffer()
			info := p.info
			if changed == "offer" {
				offer.Offered |= 2
			} else {
				info.Capabilities = 0
			}
			message, _, err := otherI.WriteMessage(encodeJSON(offer))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = otherR.ReadMessage(message); err != nil {
				t.Fatal(err)
			}
			message, _, err = otherR.WriteMessage(encodeJSON(info))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = otherI.ReadMessage(message); err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(hs.ChannelBinding(), otherI.ChannelBinding()) {
				t.Fatal("negotiation fields absent from Noise binding")
			}
			var handle [16]byte
			copy(handle[:], p.info.Handle)
			tx, err := security.NewRecordCipher(keys.Send[:], handle, 0)
			if err != nil {
				t.Fatal(err)
			}
			proof, _, err := tx.Seal(encodeJSON(confirm{p.info.Challenge, otherI.ChannelBinding()}))
			if err != nil {
				t.Fatal(err)
			}
			b := boot{Version: wireVersion, Action: "confirm", Attempt: attempt, Handle: p.info.Handle, Message: proof}
			if _, _, err = s.confirm(b, "udp", p.peer); !errors.Is(err, security.ErrAuthentication) {
				t.Fatal("modified negotiation transcript committed", err)
			}
			if len(s.Snapshot()) != 0 {
				t.Fatal("failed channel binding committed Session")
			}
		})
	}
}

// A fake, pinned server uses real Noise to return adversarial sessionInfo. The
// client must reject the selection before it emits any freshness confirmation.
func TestCapabilityEncryptedSelectionRejectedBeforeConfirm(t *testing.T) {
	for _, mode := range []string{"new", "resume"} {
		for _, name := range []string{"missing-profile", "missing-capability", "null-capability", "wrong-profile", "downgrade", "unoffered", "unknown-selected", "duplicate-capability", "case-alias", "ciphertext-tamper"} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				s, cred := newSecurityTestServer(t)
				var previous *sessionInfo
				var secret []byte
				if mode == "resume" {
					secret = randomBytes(32)
					previous = &sessionInfo{ID: randomID(), Ticket: randomID(), Secret: secret, Generation: 1, Profile: ProfileClassAnnouncementV1, Capabilities: 1}
				}
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				done := make(chan error, 1)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						done <- err
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
					plain, err := security.ReadBootstrap(conn, cred.Admission)
					if err != nil {
						done <- err
						return
					}
					var initial boot
					if err = decodeJSON(plain, &initial); err != nil {
						done <- err
						return
					}
					hs, err := newHandshake(false, mode, "tcp", initial.Attempt, initial.Expected, s.cfg.Credentials, secret)
					if err != nil {
						done <- err
						return
					}
					if _, _, err = hs.ReadMessage(initial.Message); err != nil {
						done <- err
						return
					}
					info := sessionInfo{ID: randomID(), ClientAddress: randomID(), ServerAddress: randomID(), Ticket: randomID(), Secret: randomBytes(32), Generation: 1, Handle: randomBytes(16), Challenge: randomBytes(32), TicketSerial: 1, TicketRemainingMS: 60000, LifetimeRemainingMS: 60000, Profile: ProfileClassAnnouncementV1, Capabilities: 1}
					if previous != nil {
						info.ID, info.Generation = previous.ID, previous.Generation+1
					}
					payload := encodeJSON(info)
					var fields map[string]json.RawMessage
					_ = json.Unmarshal(payload, &fields)
					switch name {
					case "missing-profile":
						delete(fields, "p")
					case "missing-capability":
						delete(fields, "z")
					case "null-capability":
						fields["z"] = json.RawMessage("null")
					case "wrong-profile":
						fields["p"] = json.RawMessage(`"legacy"`)
					case "downgrade":
						fields["z"] = json.RawMessage("0")
					case "unoffered", "unknown-selected":
						fields["z"] = json.RawMessage("3")
					case "case-alias":
						fields["Z"] = json.RawMessage("1")
					}
					payload, _ = json.Marshal(fields)
					if name == "duplicate-capability" {
						payload = append(payload[:len(payload)-1], []byte(`,"z":1}`)...)
					}
					message, _, err := hs.WriteMessage(payload)
					if err != nil {
						done <- err
						return
					}
					if name == "ciphertext-tamper" {
						message[len(message)-1] ^= 1
					}
					wire, err := sealBoot(cred.Admission, boot{Version: wireVersion, Action: "reply", Attempt: initial.Attempt, Message: message}, 1200, false)
					if err != nil {
						done <- err
						return
					}
					if err = security.WriteBootstrap(conn, wire); err != nil {
						done <- err
						return
					}
					if _, err = security.ReadBootstrap(conn, cred.Admission); err == nil {
						done <- errors.New("invalid selection emitted confirmation")
						return
					}
					done <- nil
				}()
				cfg := ClientConfig{Server: listener.Addr().String(), Credentials: cred, Options: Options{HandshakeTimeout: time.Second}}
				if name == "unknown-selected" {
					cfg.Negotiation = &NegotiationConfig{ProfileClassAnnouncementV1, 3, 1}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				carrier, _, err := establish(ctx, cfg, "tcp", randomID(), previous)
				if carrier != nil || !errors.Is(err, security.ErrAuthentication) {
					t.Fatal("invalid selection accepted", err)
				}
				if err = <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestCapabilityUDPRejectedOffersRemainSilent(t *testing.T) {
	s, cred := newSecurityTestServer(t)
	go s.Serve(context.Background())
	for _, name := range []string{"malformed-offer", "wrong-profile", "wire2"} {
		t.Run(name, func(t *testing.T) {
			conn, err := net.Dial("udp", s.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			attempt := randomID()
			hs, err := newHandshake(true, "new", "udp", attempt, 0, cred, nil)
			if err != nil {
				t.Fatal(err)
			}
			offer := defaultCapabilityOffer()
			if name == "wrong-profile" {
				offer.Profile = "legacy"
			}
			payload := encodeJSON(offer)
			if name == "malformed-offer" {
				payload = []byte(`{}`)
			}
			message, _, err := hs.WriteMessage(payload)
			if err != nil {
				t.Fatal(err)
			}
			b := boot{Version: wireVersion, Action: "init", Mode: "new", Attempt: attempt, Message: message}
			if name == "wire2" {
				b.Version = 2
			}
			wire, err := sealBoot(cred.Admission, b, 1200, true)
			if err != nil || len(wire) > 1200 {
				t.Fatal("bootstrap budget", err)
			}
			_ = conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
			if _, err = conn.Write(wire); err != nil {
				t.Fatal(err)
			}
			if _, err = conn.Read(make([]byte, 1201)); err == nil {
				t.Fatal("rejected offer received application response")
			}
			if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
				t.Fatal("unexpected response error", err)
			}
		})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) != 0 || len(s.sessions) != 0 || len(s.attempts) != 0 || len(s.handles) != 0 {
		t.Fatal("rejected network input allocated persistent candidate state")
	}
}

func TestCapabilityConfigValidationAndCopy(t *testing.T) {
	for name, cfg := range map[string]*NegotiationConfig{
		"nil":              nil,
		"explicit":         {ProfileClassAnnouncementV1, 1, 1},
		"optional-unknown": {ProfileClassAnnouncementV1, 3, 1},
	} {
		t.Run(name, func(t *testing.T) {
			normalized, err := normalizeNegotiation(cfg)
			if err != nil || normalized.Profile != ProfileClassAnnouncementV1 || normalized.RequiredCapabilities != 1 {
				t.Fatal("valid config rejected", err)
			}
			if cfg != nil {
				cfg.Profile = "mutated"
				if normalized.Profile != ProfileClassAnnouncementV1 {
					t.Fatal("config retains caller mutable pointer")
				}
			}
		})
	}
	for name, cfg := range map[string]*NegotiationConfig{
		"empty":              {},
		"unoffered":          {ProfileClassAnnouncementV1, 0, 1},
		"optional-mandatory": {ProfileClassAnnouncementV1, 1, 0},
		"unknown-required":   {ProfileClassAnnouncementV1, 3, 3},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeNegotiation(cfg); !errors.Is(err, security.ErrAuthentication) {
				t.Fatal("invalid config accepted", err)
			}
		})
	}
}
