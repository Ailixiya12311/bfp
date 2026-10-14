package session

import (
	"bfp/security"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// wireVersion binds authenticated class announcements and capability selection.
// Initial and resume transcripts reject all previous experimental revisions.
const wireVersion = 3

type boot struct {
	Version  int    `json:"v"`
	Action   string `json:"a"`
	Mode     string `json:"m,omitempty"`
	Attempt  string `json:"i"`
	Expected uint64 `json:"g,omitempty"`
	Ticket   string `json:"t,omitempty"`
	Handle   []byte `json:"h,omitempty"`
	Message  []byte `json:"n,omitempty"`
	Padding  []byte `json:"p,omitempty"`
}
type sessionInfo struct {
	ID                  string       `json:"s"`
	ClientAddress       string       `json:"c"`
	ServerAddress       string       `json:"r"`
	Ticket              string       `json:"t"`
	Secret              []byte       `json:"k"`
	Generation          uint64       `json:"g"`
	Handle              []byte       `json:"h"`
	Challenge           []byte       `json:"q"`
	TicketSerial        uint64       `json:"u"`
	TicketRemainingMS   uint64       `json:"e"`
	LifetimeRemainingMS uint64       `json:"l"`
	Profile             string       `json:"p"`
	Capabilities        Capabilities `json:"z"`
	// Local monotonic deadlines and device authority are never serialized.
	ticketUntil   time.Time
	lifetimeUntil time.Time
	authority     *deviceAuthority
	issuer        *Server
}
type confirm struct {
	Challenge []byte `json:"q"`
	Binding   []byte `json:"b"`
}

func decodeJSON(data []byte, v any) error {
	if len(data) > security.MaxBootstrapSize {
		return security.ErrSize
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	var trailing any
	if e := d.Decode(&trailing); e != io.EOF {
		return errors.New("session: trailing JSON")
	}
	return nil
}
func encodeJSON(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}
func prologue(mode, kind, attempt string, gen uint64) []byte {
	return []byte("bfp/v3-class-announcement1/" + mode + "/" + kind + "/" + attempt + "/" + strconv.FormatUint(gen, 10))
}
func sealBoot(admit []byte, b boot, max int, padded bool) ([]byte, error) {
	if padded {
		base := len(encodeJSON(b))
		n := (1040 - base) * 3 / 4
		if n > 0 {
			b.Padding = randomBytes(n)
		}
	}
	return security.SealBootstrap(admit, encodeJSON(b), max)
}
func newHandshake(initiator bool, mode, kind, attempt string, expected uint64, cred Credentials, secret []byte) (*security.Handshake, error) {
	p := prologue(mode, kind, attempt, expected)
	if mode == "resume" {
		return security.NewResumeHandshake(initiator, secret, p)
	}
	peer := cred.ServerPublic
	if !initiator {
		peer = nil
	}
	return security.NewIKHandshake(initiator, keyPair(cred), peer, p)
}

// establish returns a new, cryptographically bound carrier without opening flows.
func establish(ctx context.Context, cfg ClientConfig, kind, attempt string, previous *sessionInfo) (resultCarrier *carrier, resultInfo sessionInfo, resultErr error) {
	var zero sessionInfo
	if e := ctx.Err(); e != nil {
		return nil, zero, e
	}
	if kind != "udp" && kind != "tcp" {
		return nil, zero, fmt.Errorf("%w: unsupported network %q", ErrCarrierDialContract, kind)
	}
	offer, e := clientCapabilityOffer(cfg, previous)
	if e != nil {
		return nil, zero, e
	}
	started := time.Now()
	address := cfg.Server
	if kind == "tcp" && cfg.TCPServer != "" {
		address = cfg.TCPServer
	}
	conn, e := dialPhysicalCarrier(ctx, cfg, kind, address)
	if e != nil {
		return nil, zero, e
	}
	// DialContext only governs the dial. During bootstrap this private socket
	// remains owned here, so cancellation must also interrupt a blocked read or
	// write and prevent another INIT/CONFIRM retry. Before ownership transfers,
	// stop and join the callback: a deferred stop alone can race a successful
	// return and close a carrier already owned by the caller.
	var socketClose sync.Once
	closeConn := func() { socketClose.Do(func() { _ = conn.Close() }) }
	cancelDone := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() {
		closeConn()
		close(cancelDone)
	})
	watching := true
	stopWatching := func() {
		if watching {
			watching = false
			if !stopCancel() {
				<-cancelDone
			}
		}
	}
	ok := false
	defer func() {
		stopWatching()
		if !ok {
			closeConn()
			if e := ctx.Err(); e != nil {
				resultErr = e
			}
		}
	}()
	if e = ctx.Err(); e != nil {
		return nil, zero, e
	}
	deadline := time.Now().Add(cfg.Options.HandshakeTimeout)
	if dl, yes := ctx.Deadline(); yes && dl.Before(deadline) {
		deadline = dl
	}
	if e = conn.SetDeadline(deadline); e != nil {
		return nil, zero, e
	}
	mode := "new"
	expected := uint64(0)
	ticket := ""
	var secret []byte
	if previous != nil {
		mode = "resume"
		expected = previous.Generation
		ticket = previous.Ticket
		secret = previous.Secret
	}
	hs, e := newHandshake(true, mode, kind, attempt, expected, cfg.Credentials, secret)
	if e != nil {
		return nil, zero, e
	}
	first, _, e := hs.WriteMessage(encodeJSON(offer))
	if e != nil {
		return nil, zero, e
	}
	initial := boot{Version: wireVersion, Action: "init", Mode: mode, Attempt: attempt, Expected: expected, Ticket: ticket, Message: first}
	exchange := func(b boot, padded bool) (reply boot, err error) {
		defer func() {
			// Closing the socket wakes physical I/O with a network error; expose
			// the cancellation cause to callers instead of hiding it behind that.
			if e := ctx.Err(); e != nil {
				err = e
			}
		}()
		for tries := 0; time.Now().Before(deadline); tries++ {
			if err = ctx.Err(); err != nil {
				return reply, err
			}
			wire, err := sealBoot(cfg.Credentials.Admission, b, 1200, padded)
			if err != nil {
				return reply, err
			}
			if err = ctx.Err(); err != nil {
				return reply, err
			}
			if kind == "tcp" {
				if err = security.WriteBootstrap(conn, wire); err != nil {
					return reply, err
				}
				plain, err := security.ReadBootstrap(conn, cfg.Credentials.Admission)
				if err != nil {
					return reply, err
				}
				err = decodeJSON(plain, &reply)
				if err == nil && reply.Attempt != attempt {
					err = security.ErrAuthentication
				}
				return reply, err
			}
			if n, writeErr := conn.Write(wire); writeErr != nil || n != len(wire) {
				if writeErr != nil {
					return reply, writeErr
				}
				return reply, io.ErrShortWrite
			}
			wait := min(350*time.Millisecond, time.Until(deadline))
			if err = conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
				return reply, err
			}
			buf := make([]byte, 1201)
			for {
				if err = ctx.Err(); err != nil {
					return reply, err
				}
				n, re := conn.Read(buf)
				if re != nil {
					if ne, yes := re.(net.Error); yes && ne.Timeout() {
						break
					}
					return reply, re
				}
				if n > 1200 {
					continue
				}
				plain, pe := security.OpenBootstrap(cfg.Credentials.Admission, buf[:n])
				if pe != nil {
					continue
				}
				if decodeJSON(plain, &reply) != nil || reply.Attempt != attempt {
					continue
				}
				return reply, nil
			}
		}
		return reply, context.DeadlineExceeded
	}
	response, e := exchange(initial, true)
	if e != nil {
		return nil, zero, e
	}
	if response.Action != "reply" || response.Version != wireVersion {
		return nil, zero, security.ErrAuthentication
	}
	payload, keys, e := hs.ReadMessage(response.Message)
	if e != nil {
		return nil, zero, fmt.Errorf("session: server proof: %w", security.ErrAuthentication)
	}
	var info sessionInfo
	if e = decodeJSON(payload, &info); e != nil || keys == nil || len(info.Secret) != 32 || len(info.Handle) != 16 || len(info.Challenge) != 32 {
		return nil, zero, security.ErrAuthentication
	}
	if e = validateServerSelection(payload, offer, info, previous); e != nil {
		return nil, zero, e
	}
	if e = installInfoDeadlines(&info, started); e != nil {
		return nil, zero, e
	}
	if previous != nil && (info.ID != previous.ID || info.Generation != previous.Generation+1) {
		return nil, zero, ErrState
	}
	c, e := makeCarrier(kind, info.Generation, info.Handle, keys, conn, nil, nil)
	if e != nil {
		return nil, zero, e
	}
	c.profile, c.capabilities = info.Profile, info.Capabilities
	proof, _, e := c.tx.Seal(encodeJSON(confirm{info.Challenge, hs.ChannelBinding()}))
	if e != nil {
		return nil, zero, e
	}
	// Each UDP confirmation must fund the largest randomly padded READY,
	// including retries whose cached response padding can exceed their own.
	done, e := exchange(boot{Version: wireVersion, Action: "confirm", Attempt: attempt, Handle: info.Handle, Message: proof}, kind == "udp")
	if e != nil {
		return nil, info, e
	}
	if done.Action != "ready" || done.Version != wireVersion {
		return nil, info, ErrState
	}
	ready, _, e := c.rx.Open(done.Message)
	if e != nil || !bytes.Equal(ready, []byte("ready")) {
		return nil, info, security.ErrAuthentication
	}
	stopWatching()
	if e = ctx.Err(); e != nil {
		return nil, info, e
	}
	if e = conn.SetDeadline(time.Time{}); e != nil {
		return nil, info, e
	}
	ok = true
	return c, info, nil
}
func equalSecret(a, b []byte) bool { return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1 }
func digest(data []byte) [32]byte  { return sha256.Sum256(data) }
