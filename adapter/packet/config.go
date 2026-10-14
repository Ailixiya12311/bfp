// Package packet adapts fixed-target BFP UDP Flows to one Session-bound,
// bounded multi-target net.PacketConn. It never creates a replacement Session.
package packet

import (
	"bfp/classification"
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const MaxDatagramSize = 16 << 10
const itemOverhead = 128
const targetReservation = MaxDatagramSize + 1 + itemOverhead

var (
	ErrLimit        = errors.New("packet: resource limit")
	ErrAddress      = errors.New("packet: invalid UDP target address")
	ErrOversize     = errors.New("packet: datagram exceeds 16 KiB")
	ErrTargetClosed = errors.New("packet: target association ended")
)

// Addr preserves a domain or numeric UDP target without resolving it locally.
// WriteTo validates and canonicalizes its host, port and optional IPv6 zone.
type Addr string

func (a Addr) Network() string { return "udp" }
func (a Addr) String() string  { return string(a) }

// TargetToken identifies one exact target lifecycle on one PacketConn owner.
// Generations are never reused, even when an idle target address is reopened.
// It is returned as a reply address only when ExposeTargetToken is enabled.
type TargetToken struct {
	Address    Addr
	Generation uint64
	owner      *Conn
}

func (t TargetToken) Network() string { return "udp" }
func (t TargetToken) String() string  { return t.Address.String() }

type Config struct {
	// Metadata is copied at construction. Network/Address are supplied by each
	// WriteTo target. Domain always describes that same actual target (empty
	// for numeric addresses); a fixed configured Domain is not propagated to
	// unrelated targets. Trust flags, Hint, delivery and FEC keep local policy.
	Metadata classification.Metadata
	// MetadataForTarget is an optional trusted local adapter hook. It runs once
	// for each newly opened exact logical target, outside the adapter mutex.
	// It may attach a restored/sniffed domain to a numeric target for local
	// classification, but must keep Network and Address unchanged. The hook
	// must cooperate with ctx; workers/targets remain bounded by MaxTargets.
	// Arguments and results copy optional policy pointers. No peer metadata
	// is promoted to trusted by this hook or by ordinary packet construction.
	MetadataForTarget func(ctx context.Context, address Addr, base classification.Metadata) (classification.Metadata, error)
	// MetadataForTargetToken provides the same trusted hook with the exact
	// lifecycle token. It is mutually exclusive with MetadataForTarget.
	MetadataForTargetToken func(ctx context.Context, target TargetToken, base classification.Metadata) (classification.Metadata, error)
	// TargetRetired runs once, outside the adapter mutex, after that target's
	// dial/read loop has stopped and its Flow cleanup has completed. The callback
	// is synchronous and must be bounded/cooperative: arbitrary blocking
	// local callback code can extend RetireTarget and Close. A callback panic
	// is contained and reported through CleanupFailures and Close's error.
	TargetRetired     func(target TargetToken)
	ExposeTargetToken bool
	MaxTargets        int
	MaxPendingWrites  int
	MaxReceiveQueue   int
	MaxBufferedBytes  int
	DialTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	CleanupTimeout    time.Duration
}

func (c Config) defaults() (Config, error) {
	if c.MetadataForTarget != nil && c.MetadataForTargetToken != nil {
		return c, errors.New("packet: only one target metadata hook may be configured")
	}
	if c.MaxTargets < 0 || c.MaxPendingWrites < 0 || c.MaxReceiveQueue < 0 || c.MaxBufferedBytes < 0 || c.DialTimeout < 0 || c.WriteTimeout < 0 || c.IdleTimeout < 0 || c.CleanupTimeout < 0 {
		return c, errors.New("packet: negative limit or timeout")
	}
	if c.MaxTargets == 0 {
		c.MaxTargets = 16
	}
	if c.MaxPendingWrites == 0 {
		c.MaxPendingWrites = 32
	}
	if c.MaxReceiveQueue == 0 {
		c.MaxReceiveQueue = 64
	}
	if c.MaxBufferedBytes == 0 {
		c.MaxBufferedBytes = 2 << 20
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = 2 * time.Second
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = 5 * time.Second
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = time.Minute
	}
	if c.CleanupTimeout == 0 {
		c.CleanupTimeout = 500 * time.Millisecond
	}
	if c.MaxTargets > 256 || c.MaxPendingWrites > 256 || c.MaxReceiveQueue > 4096 || c.MaxBufferedBytes < targetReservation || c.MaxBufferedBytes > 64<<20 || c.DialTimeout > time.Minute || c.WriteTimeout > 2*time.Minute || c.IdleTimeout > 24*time.Hour || c.CleanupTimeout > 10*time.Second {
		return c, errors.New("packet: configuration exceeds supported bounds")
	}
	c.Metadata = copyMetadata(c.Metadata)
	return c, nil
}

func normalize(addr net.Addr) (Addr, string, error) {
	if addr == nil || nilAddress(addr) || addr.Network() != "udp" {
		return "", "", ErrAddress
	}
	text := addr.String()
	if len(text) > 320 {
		return "", "", ErrAddress
	}
	host, portText, err := net.SplitHostPort(text)
	if err != nil || host == "" {
		return "", "", ErrAddress
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", "", ErrAddress
	}
	domain := ""
	ipHost, zone := host, ""
	if at := strings.LastIndexByte(host, '%'); at >= 0 {
		ipHost, zone = host[:at], host[at:]
		if len(zone) > 65 {
			return "", "", ErrAddress
		}
		for _, ch := range zone[1:] {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' || ch == '.') {
				return "", "", ErrAddress
			}
		}
	}
	if ip := net.ParseIP(ipHost); ip != nil {
		if zone != "" && (ip.To4() != nil || len(zone) == 1) {
			return "", "", ErrAddress
		}
		host = ip.String() + zone
	} else {
		if zone != "" || strings.ContainsAny(host, " \t\r\n/\\\x00") {
			return "", "", ErrAddress
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if host == "" || len(host) > 253 {
			return "", "", ErrAddress
		}
		domain = host
	}
	return Addr(net.JoinHostPort(host, strconv.Itoa(port))), domain, nil
}

func nilAddress(addr net.Addr) bool {
	v := reflect.ValueOf(addr)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}
