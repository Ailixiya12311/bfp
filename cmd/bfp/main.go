package main

import (
	"bfp/gateway"
	"bfp/internal/securefile"
	"bfp/security"
	"bfp/session"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"
)

type serverConfig struct {
	Listen         string              `json:"listen"`
	Credentials    session.Credentials `json:"credentials"`
	Policy         gateway.Policy      `json:"policy"`
	MaxSessions    int                 `json:"max_sessions"`
	Options        *configOptions      `json:"options,omitempty"`
	Classification json.RawMessage     `json:"classification,omitempty"`
	DatagramFEC    json.RawMessage     `json:"datagram_fec,omitempty"`
}
type clientConfig struct {
	Server         string              `json:"server"`
	TCPServer      string              `json:"tcp_server"`
	SOCKS          string              `json:"socks"`
	Credentials    session.Credentials `json:"credentials"`
	Options        *configOptions      `json:"options,omitempty"`
	Classification json.RawMessage     `json:"classification,omitempty"`
	SOCKSMetadata  json.RawMessage     `json:"socks_metadata,omitempty"`
	DatagramFEC    json.RawMessage     `json:"datagram_fec,omitempty"`
	DNS            json.RawMessage     `json:"dns,omitempty"`
}

func readConfig(path string, v any) error {
	b, e := securefile.Read(path, 65536)
	if e != nil {
		return e
	}
	if e = checkConfigEntryKeys(b); e != nil {
		return e
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if e = dec.Decode(v); e != nil {
		return errors.New("invalid configuration")
	}
	var trailing any
	if e = dec.Decode(&trailing); e != io.EOF {
		return errors.New("invalid configuration: trailing data")
	}
	if validator, ok := v.(interface{ validateOptions() error }); ok {
		return validator.validateOptions()
	}
	return nil
}
func emit(v any) { _ = json.NewEncoder(os.Stdout).Encode(v) }
func main() {
	if len(os.Args) >= 2 && (os.Args[1] == "native-supervise" || os.Args[1] == "native-recover") {
		var status int
		var err error
		if os.Args[1] == "native-recover" {
			status, err = nativeRecover(os.Args[2:])
		} else {
			status, err = nativeSupervise(os.Args[2:])
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "bfp:", err)
			os.Exit(1)
		}
		os.Exit(status)
	}
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "bfp:", e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		printUsage(os.Stderr)
		return errors.New("a command is required")
	}
	if os.Args[1] == "help" || os.Args[1] == "--help" || os.Args[1] == "-h" {
		printUsage(os.Stdout)
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	f := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	f.Usage = func() { printCommandUsage(os.Stderr, os.Args[1]) }
	config := f.String("config", "", "configuration file")
	out := f.String("out", "credentials", "keygen output directory")
	serverListen := f.String("server-listen", "127.0.0.1:51880", "keygen server listen endpoint")
	serverEndpoint := f.String("server", "127.0.0.1:51880", "keygen client server endpoint")
	tcpEndpoint := f.String("tcp-server", "", "keygen TCP endpoint; empty uses -server")
	socksEndpoint := f.String("socks", "127.0.0.1:1080", "keygen local SOCKS endpoint")
	classificationProfile := f.String("classification-profile", "standard", "keygen classification policy: standard or low-bandwidth")
	listen := f.String("listen", "127.0.0.1:0", "fixture/relay listen")
	target := f.String("target", "", "probe TCP target or relay destination")
	udpTarget := f.String("udp-target", "", "probe UDP target")
	result := f.String("result", "", "probe result JSON path")
	count := f.Int("count", 50, "probe operation count")
	size := f.Int("size", 16384, "probe TCP bytes per operation")
	interval := f.Duration("interval", 100*time.Millisecond, "probe interval")
	blackhole := f.Duration("blackhole-after", 0, "relay drops UDP after duration")
	duration := f.Duration("duration", 30*time.Second, "probe total deadline, or business deadline with -setup-duration")
	setupDuration := f.Duration("setup-duration", 0, "optional independent probe setup deadline; zero keeps the total -duration deadline")
	statsInterval := f.Duration("stats", time.Second, "stats interval")
	classStats := f.Bool("class-stats", false, "include bounded read-only flow classification evidence in server stats")
	if e := f.Parse(os.Args[2:]); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if *statsInterval <= 0 {
		return errors.New("stats interval must be positive")
	}
	switch os.Args[1] {
	case "version":
		fmt.Printf("bfp %s (commit=%s, built=%s)\n", buildVersion, buildCommit, buildDate)
		return nil
	case "demo":
		return runDemo(ctx)
	case "keygen":
		return keygenWithClassificationProfile(*out, *serverListen, *serverEndpoint, *tcpEndpoint, *socksEndpoint, *classificationProfile)
	case "server":
		var cfg serverConfig
		if e := readConfig(*config, &cfg); e != nil {
			return e
		}
		d, e := gateway.New(cfg.Policy)
		if e != nil {
			return e
		}
		sessionCfg, e := cfg.sessionConfig(d)
		if e != nil {
			return e
		}
		s, e := session.NewServer(sessionCfg)
		if e != nil {
			return e
		}
		defer s.Close()
		emit(map[string]any{"event": "listening", "address": s.Addr().String()})
		go func() {
			tick := time.NewTicker(*statsInterval)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					event := map[string]any{"event": "stats", "sessions": s.Snapshot()}
					if *classStats {
						queryCtx, stop := context.WithTimeout(ctx, 500*time.Millisecond)
						views, err := s.ClassificationSnapshot(queryCtx)
						stop()
						event["classification_snapshot_ok"] = err == nil
						if err == nil {
							event["classifications"] = views
						}
					}
					emit(event)
				}
			}
		}()
		return s.Serve(ctx)
	case "client":
		var cfg clientConfig
		if e := readConfig(*config, &cfg); e != nil {
			return e
		}
		sessionCfg, e := cfg.sessionConfig()
		if e != nil {
			return e
		}
		c, e := session.NewClient(sessionCfg)
		if e != nil {
			return e
		}
		defer c.Close()
		if _, e = c.Connect(ctx); e != nil {
			return e
		}
		return serveClientEntries(ctx, cfg, c)
	case "probe":
		return probeWithSetupBudget(ctx, *config, *target, *udpTarget, *result, *count, *size, *interval, *duration, *setupDuration)
	case "class-probe":
		return classProbe(ctx, *config, *target, *result, *count, *size, *interval, *duration)
	case "fixture":
		return fixture(ctx, *listen)
	case "relay":
		return relay(ctx, *listen, *target, *blackhole)
	default:
		return fmt.Errorf("unknown command %q; use --help", os.Args[1])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "BFP independent session protocol")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage: bfp <command> [options]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  version   print the build and protocol version")
	fmt.Fprintln(w, "  keygen    create protected server.json and client.json")
	fmt.Fprintln(w, "  server    listen on UDP and TCP and serve authenticated sessions")
	fmt.Fprintln(w, "  client    connect and expose a local SOCKS5 listener")
	fmt.Fprintln(w, "  demo      run a self-contained TCP/UDP product smoke")
	fmt.Fprintln(w, "  probe     run a bounded TCP/UDP echo probe")
	fmt.Fprintln(w, "  fixture   run a local TCP/UDP echo fixture")
	fmt.Fprintln(w, "  relay     run a bounded UDP black-hole relay for testing")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Use 'bfp <command> --help' for command options.")
}

func printCommandUsage(w io.Writer, command string) {
	fmt.Fprintf(w, "Usage: bfp %s [options]\n\n", command)
	switch command {
	case "version":
		fmt.Fprintln(w, "Print build and protocol version.")
	case "keygen":
		fmt.Fprintln(w, "  -out DIR   create a new protected credential directory (default credentials)")
		fmt.Fprintln(w, "  -server-listen ADDR   server listen endpoint written to server.json")
		fmt.Fprintln(w, "  -server ADDR   client UDP server endpoint (default 127.0.0.1:51880)")
		fmt.Fprintln(w, "  -tcp-server ADDR   client TCP fallback endpoint (default same as -server)")
		fmt.Fprintln(w, "  -socks ADDR   local SOCKS endpoint recorded in client.json")
		fmt.Fprintln(w, "  -classification-profile NAME   standard (default) or low-bandwidth")
	case "server":
		fmt.Fprintln(w, "  -config FILE   protected server configuration")
		fmt.Fprintln(w, "  -stats DURATION   stats interval (default 1s)")
		fmt.Fprintln(w, "  -class-stats   include live classification and publication/ACK state")
	case "client":
		fmt.Fprintln(w, "  -config FILE   protected client configuration")
	case "demo":
		fmt.Fprintln(w, "  no options; all credentials and echo fixtures stay in memory")
	case "probe":
		fmt.Fprintln(w, "  -config FILE   protected client configuration")
		fmt.Fprintln(w, "  -target ADDR   TCP target")
		fmt.Fprintln(w, "  -udp-target ADDR   UDP target")
		fmt.Fprintln(w, "  -result FILE   JSON result path")
		fmt.Fprintln(w, "  -count N -size BYTES -interval DURATION -duration DURATION")
	case "fixture":
		fmt.Fprintln(w, "  -listen ADDR   TCP/UDP echo address (default 127.0.0.1:0)")
	case "relay":
		fmt.Fprintln(w, "  -listen ADDR -target ADDR -blackhole-after DURATION")
	default:
		printUsage(w)
	}
}
func keygen(out string) error {
	return keygenWithEndpoints(out, "127.0.0.1:51880", "127.0.0.1:51880", "", "127.0.0.1:1080")
}

func keygenWithEndpoints(out, serverListen, serverEndpoint, tcpEndpoint, socksEndpoint string) error {
	return keygenWithClassificationProfile(out, serverListen, serverEndpoint, tcpEndpoint, socksEndpoint, "standard")
}

func keygenWithClassificationProfile(out, serverListen, serverEndpoint, tcpEndpoint, socksEndpoint, profile string) error {
	classification, err := keygenClassificationProfile(profile)
	if err != nil {
		return err
	}
	if serverListen == "" {
		return errors.New("server listen endpoint is required")
	}
	if serverEndpoint == "" {
		return errors.New("server endpoint is required")
	}
	if e := securefile.MakePrivateDir(out); e != nil {
		return e
	}
	server, e := security.GenerateKeyPair()
	if e != nil {
		return e
	}
	client, e := security.GenerateKeyPair()
	if e != nil {
		return e
	}
	admit := make([]byte, 32)
	if _, e = rand.Read(admit); e != nil {
		return e
	}
	files := map[string]any{"server.json": serverConfig{Listen: serverListen, Credentials: session.Credentials{Admission: admit, Private: server.Private, Public: server.Public, AllowedClients: [][]byte{client.Public}}, Policy: gateway.Policy{MaxConcurrent: 16, Timeout: 10 * time.Second}, MaxSessions: 16}, "client.json": clientConfig{Server: serverEndpoint, TCPServer: tcpEndpoint, SOCKS: socksEndpoint, Credentials: session.Credentials{Admission: admit, Private: client.Private, Public: client.Public, ServerPublic: server.Public}}}
	serverCfg := files["server.json"].(serverConfig)
	clientCfg := files["client.json"].(clientConfig)
	serverCfg.Classification, clientCfg.Classification = classification, classification
	files["server.json"], files["client.json"] = serverCfg, clientCfg
	for name, v := range files {
		b, e := json.MarshalIndent(v, "", "  ")
		if e != nil {
			return e
		}
		p := filepath.Join(out, name)
		if e = securefile.WriteExclusive(p, b); e != nil {
			return e
		}
	}
	emit(map[string]any{"event": "keygen", "directory": out})
	return nil
}
func fixture(ctx context.Context, address string) error {
	ln, e := net.Listen("tcp", address)
	if e != nil {
		return e
	}
	defer ln.Close()
	udp, e := net.ListenPacket("udp", ln.Addr().String())
	if e != nil {
		return e
	}
	defer udp.Close()
	var opened atomic.Uint64
	emit(map[string]any{"event": "fixture", "address": ln.Addr().String()})
	go func() { <-ctx.Done(); ln.Close(); udp.Close() }()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, a, e := udp.ReadFrom(buf)
			if e != nil {
				return
			}
			_, _ = udp.WriteTo(buf[:n], a)
		}
	}()
	for {
		c, e := ln.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		opened.Add(1)
		emit(map[string]any{"event": "target_open", "opened": opened.Load()})
		go func() { defer c.Close(); _ = c.SetDeadline(time.Now().Add(2 * time.Minute)); _, _ = io.Copy(c, c) }()
	}
}
func relay(ctx context.Context, address, target string, after time.Duration) error {
	local, e := net.ListenUDP("udp", mustUDP(address))
	if e != nil {
		return e
	}
	defer local.Close()
	up, e := net.DialUDP("udp", nil, mustUDP(target))
	if e != nil {
		return e
	}
	defer up.Close()
	// The black-hole window belongs to the probe traffic, not to the time
	// spent starting the relay process over SSH.  Start the bounded fault clock
	// when the first owned packet is observed so a slow sender does not lose a
	// datagram before the advertised -blackhole-after instant.
	var trafficStarted atomic.Int64
	shouldBlackhole := func(now time.Time) bool {
		if after <= 0 {
			return false
		}
		stamp := trafficStarted.Load()
		if stamp == 0 {
			candidate := now.UnixNano()
			if trafficStarted.CompareAndSwap(0, candidate) {
				stamp = candidate
			} else {
				stamp = trafficStarted.Load()
			}
		}
		return stamp != 0 && now.Sub(time.Unix(0, stamp)) >= after
	}
	var peer atomic.Pointer[net.UDPAddr]
	emit(map[string]any{"event": "relay", "address": local.LocalAddr().String()})
	go func() { <-ctx.Done(); local.Close(); up.Close() }()
	go func() {
		buf := make([]byte, 1201)
		for {
			n, e := up.Read(buf)
			if e != nil {
				return
			}
			if shouldBlackhole(time.Now()) {
				continue
			}
			if p := peer.Load(); p != nil {
				_, _ = local.WriteToUDP(buf[:n], p)
			}
		}
	}()
	buf := make([]byte, 1201)
	for {
		n, a, e := local.ReadFromUDP(buf)
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		peer.Store(a)
		if shouldBlackhole(time.Now()) {
			continue
		}
		_, _ = up.Write(buf[:n])
	}
}
func mustUDP(s string) *net.UDPAddr {
	a, e := net.ResolveUDPAddr("udp", s)
	if e != nil {
		panic(e)
	}
	return a
}

type udpExchangeResult struct {
	Unmatched              int
	Late                   int
	Unexpected             int
	ExpectedIteration      *int
	ReceivedIteration      *int
	LastUnmatchedIteration *int
	ErrorKind              string
	TimedOut               bool
	WriteAttempted         bool
	// WriteAccepted means the net.Conn API reported a complete write. It is
	// not proof of Session queue admission, wire delivery, or target execution.
	WriteAccepted  bool
	WriteElapsedMS int64
	ReadElapsedMS  int64
	ErrorPhase     string
}

// probeMessageIteration accepts only the bounded, canonical payload generated
// by probe. Arbitrary reply bytes never become log text or numeric metadata.
func probeMessageIteration(payload []byte) *int {
	const prefix = "message-"
	if len(payload) <= len(prefix) || len(payload) > len(prefix)+4 ||
		!bytes.HasPrefix(payload, []byte(prefix)) {
		return nil
	}
	digits := payload[len(prefix):]
	if len(digits) > 1 && digits[0] == '0' {
		return nil
	}
	value := 0
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return nil
		}
		value = value*10 + int(digit-'0')
	}
	return &value
}

func (r udpExchangeResult) failed(e error) (udpExchangeResult, error) {
	var networkError net.Error
	r.TimedOut = errors.Is(e, context.DeadlineExceeded) || errors.Is(e, os.ErrDeadlineExceeded) ||
		errors.As(e, &networkError) && networkError.Timeout()
	switch {
	case r.TimedOut:
		r.ErrorKind = "timeout"
		if r.Unmatched > 0 {
			r.ErrorKind = "mismatch"
		}
	case errors.Is(e, net.ErrClosed), errors.Is(e, session.ErrClosed),
		errors.Is(e, io.ErrClosedPipe), errors.Is(e, io.EOF):
		r.ErrorKind = "closed"
	default:
		r.ErrorKind = "io"
	}
	return r, e
}

// exchangeUDP writes once, then consumes unrelated replies only until the same
// absolute deadline. A timeout remains a failed operation even if its reply is
// received and discarded by a later exchange. No retransmission is performed.
func exchangeUDP(conn net.Conn, message []byte, deadline time.Time) (result udpExchangeResult, resultErr error) {
	result = udpExchangeResult{ExpectedIteration: probeMessageIteration(message), ErrorPhase: "set_deadline"}
	var readStarted time.Time
	defer func() {
		if !readStarted.IsZero() {
			result.ReadElapsedMS = time.Since(readStarted).Milliseconds()
		}
	}()
	if e := conn.SetDeadline(deadline); e != nil {
		return result.failed(e)
	}
	result.ErrorPhase = "before_write"
	if !time.Now().Before(deadline) {
		return result.failed(context.DeadlineExceeded)
	}
	result.ErrorPhase = "write"
	result.WriteAttempted = true
	writeStarted := time.Now()
	n, e := conn.Write(message)
	result.WriteElapsedMS = time.Since(writeStarted).Milliseconds()
	if e != nil {
		return result.failed(e)
	}
	if n != len(message) {
		return result.failed(io.ErrShortWrite)
	}
	result.WriteAccepted = true
	result.ErrorPhase = "before_read"
	readStarted = time.Now()
	buffer := make([]byte, 16384)
	for {
		// Flow.Read can return queued datagrams before consulting its deadline.
		// Check time here too, so a busy queue cannot extend this operation.
		if !time.Now().Before(deadline) {
			return result.failed(context.DeadlineExceeded)
		}
		result.ErrorPhase = "read"
		n, e = conn.Read(buffer)
		if e != nil {
			return result.failed(e)
		}
		if n < 0 || n > len(buffer) {
			return result.failed(io.ErrUnexpectedEOF)
		}
		if !time.Now().Before(deadline) {
			return result.failed(context.DeadlineExceeded)
		}
		payload := buffer[:n]
		result.ReceivedIteration = probeMessageIteration(payload)
		if bytes.Equal(message, payload) {
			result.ErrorPhase = ""
			return result, nil
		}
		result.Unmatched++
		result.LastUnmatchedIteration = result.ReceivedIteration
		if result.ExpectedIteration != nil && result.ReceivedIteration != nil &&
			*result.ReceivedIteration < *result.ExpectedIteration {
			result.Late++
		} else {
			result.Unexpected++
		}
	}
}

func probe(parent context.Context, path, target, udpTarget, result string, count, size int, interval, duration time.Duration) error {
	return probeWithSetupBudget(parent, path, target, udpTarget, result, count, size, interval, duration, 0)
}

func writeProbeResult(path string, result map[string]any) error {
	emit(result)
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func probeWithSetupBudget(parent context.Context, path, target, udpTarget, result string, count, size int, interval, duration, setupDuration time.Duration) error {
	if count < 1 || count > 10000 || size < 0 || size > 1<<20 || interval < 0 || duration <= 0 || setupDuration < 0 {
		return errors.New("invalid probe budget")
	}
	started := time.Now()
	// By default -duration remains the original absolute total deadline. An
	// explicit -setup-duration opts into a separate, bounded setup phase. Both
	// phases remain children of parent, whose deadline can only shorten them.
	setupBudget := duration
	budgetMode := "absolute_total"
	if setupDuration > 0 {
		setupBudget = setupDuration
		budgetMode = "separate_setup"
	}
	setupCtx, setupCancel := context.WithTimeout(parent, setupBudget)
	defer setupCancel()
	var s *session.Session
	var initial session.Stats
	failSetup := func(phase string, cause error) error {
		var final session.Stats
		if s != nil {
			final = s.Stats()
		}
		elapsed := time.Since(started).Milliseconds()
		r := map[string]any{"pass": false, "failure": "probe setup failed", "failure_phase": phase, "error_kind": classProbeErrorKind(cause), "last_iteration_started": -1, "tcp_completed": 0, "udp_completed": 0, "udp_failed": 0, "elapsed_ms": 0, "business_elapsed_ms": 0, "setup_elapsed_ms": elapsed, "total_elapsed_ms": elapsed, "budget_mode": budgetMode, "duration_ms": duration.Milliseconds(), "setup_duration_ms": setupDuration.Milliseconds(), "max_tcp_operation_ms": 0, "echo_sha256": hex.EncodeToString(sha256.New().Sum(nil)), "initial": initial, "final": final, "same_session": s != nil && initial.ID == final.ID}
		if err := writeProbeResult(result, r); err != nil {
			return err
		}
		return cause
	}
	var cfg clientConfig
	if e := readConfig(path, &cfg); e != nil {
		return failSetup("setup_config_read", e)
	}
	sessionCfg, e := cfg.sessionConfig()
	if e != nil {
		return failSetup("setup_config", e)
	}
	c, e := session.NewClient(sessionCfg)
	if e != nil {
		return failSetup("setup_client", e)
	}
	defer c.Close()
	s, e = c.Connect(setupCtx)
	if e != nil {
		return failSetup("setup_connect", e)
	}
	initial = s.Stats()
	conn, e := c.DialContext(setupCtx, "tcp", target)
	if e != nil {
		return failSetup("tcp_open", e)
	}
	defer conn.Close()
	var udp net.Conn
	if udpTarget != "" {
		udp, e = c.DialContext(setupCtx, "udp", udpTarget)
		if e != nil {
			return failSetup("udp_open", e)
		}
		defer udp.Close()
	}
	setupElapsed := time.Since(started)
	ctx := setupCtx
	if setupDuration > 0 {
		setupCancel()
		var businessCancel context.CancelFunc
		ctx, businessCancel = context.WithTimeout(parent, duration)
		defer businessCancel()
	}
	// Every operation deadline and cancellation now uses the same serialized
	// wrapper, so cancellation cannot be overwritten by a later future setter.
	tcpCtxConn := newProbeContextConn(ctx, conn)
	defer tcpCtxConn.stopCancellation()
	conn = tcpCtxConn
	if udp != nil {
		udpCtxConn := newProbeContextConn(ctx, udp)
		defer udpCtxConn.stopCancellation()
		udp = udpCtxConn
	}
	var tcpOK, udpOK, udpFailed int
	start := time.Now()
	hash := sha256.New()
	var failure, failurePhase string
	lastIterationStarted := -1
	maxPause := time.Duration(0)
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			failure, failurePhase = "probe deadline", "business_start"
			break
		}
		lastIterationStarted = i
		begin := time.Now()
		data := make([]byte, size)
		_, _ = rand.Read(data)
		deadline := time.Now().Add(8 * time.Second)
		if probeDeadline, ok := ctx.Deadline(); ok && probeDeadline.Before(deadline) {
			deadline = probeDeadline
		}
		_ = conn.SetDeadline(deadline)
		writeDone := make(chan error, 1)
		go func() { _, e := conn.Write(data); writeDone <- e }()
		echo := make([]byte, len(data))
		_, e = io.ReadFull(conn, echo)
		if we := <-writeDone; e == nil {
			e = we
		}
		if e != nil {
			failure, failurePhase = "tcp operation failed", "tcp_exchange"
			break
		}
		if !bytes.Equal(data, echo) {
			failure, failurePhase = "tcp byte mismatch", "tcp_verify"
			break
		}
		tcpOK++
		hash.Write(echo)
		maxPause = max(maxPause, time.Since(begin))
		var udpObservation map[string]any
		if udp != nil {
			udpStarted := time.Now()
			udpBefore := s.Stats()
			statsBeforeMS := time.Since(udpStarted).Milliseconds()
			msg := []byte(fmt.Sprintf("message-%d", i))
			deadline := udpStarted.Add(time.Second)
			if probeDeadline, ok := ctx.Deadline(); ok && probeDeadline.Before(deadline) {
				deadline = probeDeadline
			}
			var exchange udpExchangeResult
			exchangeStarted := time.Now()
			exchange, e = exchangeUDP(udp, msg, deadline)
			exchangeElapsedMS := time.Since(exchangeStarted).Milliseconds()
			if e == nil {
				udpOK++
			} else {
				udpFailed++
			}
			statsAfterStarted := time.Now()
			udpAfter := s.Stats()
			statsAfterMS := time.Since(statsAfterStarted).Milliseconds()
			// These are operation-boundary observations, not packet delivery ACKs.
			udpObservation = map[string]any{"success": e == nil, "timeout": exchange.TimedOut, "error_kind": exchange.ErrorKind, "error_phase": exchange.ErrorPhase, "write_attempted": exchange.WriteAttempted, "write_accepted": exchange.WriteAccepted, "write_elapsed_ms": exchange.WriteElapsedMS, "read_elapsed_ms": exchange.ReadElapsedMS, "stats_before_ms": statsBeforeMS, "exchange_elapsed_ms": exchangeElapsedMS, "stats_after_ms": statsAfterMS, "unmatched_count": exchange.Unmatched, "late_count": exchange.Late, "unexpected_count": exchange.Unexpected, "expected_iteration": exchange.ExpectedIteration, "received_iteration": exchange.ReceivedIteration, "last_unmatched_iteration": exchange.LastUnmatchedIteration, "elapsed_ms": time.Since(udpStarted).Milliseconds(), "carrier_before": udpBefore.Carrier, "generation_before": udpBefore.Generation, "carrier_after": udpAfter.Carrier, "generation_after": udpAfter.Generation}
			budgetExpired := ctx.Err() != nil
			if limit, ok := ctx.Deadline(); ok && !time.Now().Before(limit) {
				budgetExpired = true
			}
			if e != nil && budgetExpired {
				// Preserve the operation that actually observed the deadline;
				// interval handling below must not overwrite its failure phase.
				failure, failurePhase = "probe deadline", "udp_exchange"
			}
		}
		emit(map[string]any{"event": "progress", "iteration": i, "elapsed_since_probe_ms": time.Since(start).Milliseconds(), "setup_elapsed_ms": setupElapsed.Milliseconds(), "budget_mode": budgetMode, "tcp_completed": tcpOK, "udp_completed": udpOK, "udp_failed": udpFailed, "udp": udpObservation, "session": s.Stats()})
		if failure != "" {
			break
		}
		select {
		case <-ctx.Done():
			failure, failurePhase = "probe deadline", "interval"
		case <-time.After(interval):
		}
		if failure != "" {
			break
		}
	}
	final := s.Stats()
	if failure == "" && udpTarget != "" && (udpOK != count || udpFailed != 0) {
		failure, failurePhase = "udp operations incomplete", "udp_exchange"
	}
	businessElapsed := time.Since(start).Milliseconds()
	r := map[string]any{"pass": failure == "" && tcpOK == count, "failure": failure, "failure_phase": failurePhase, "last_iteration_started": lastIterationStarted, "tcp_completed": tcpOK, "udp_completed": udpOK, "udp_failed": udpFailed, "elapsed_ms": businessElapsed, "business_elapsed_ms": businessElapsed, "setup_elapsed_ms": setupElapsed.Milliseconds(), "total_elapsed_ms": time.Since(started).Milliseconds(), "budget_mode": budgetMode, "duration_ms": duration.Milliseconds(), "setup_duration_ms": setupDuration.Milliseconds(), "max_tcp_operation_ms": maxPause.Milliseconds(), "echo_sha256": hex.EncodeToString(hash.Sum(nil)), "initial": initial, "final": final, "same_session": initial.ID == final.ID}
	if e = writeProbeResult(result, r); e != nil {
		return e
	}
	if failure != "" {
		return errors.New(failure)
	}
	return nil
}
