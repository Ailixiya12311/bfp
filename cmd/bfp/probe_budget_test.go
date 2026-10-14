package main

import (
	"bfp/internal/securefile"
	"bfp/security"
	"bfp/session"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type probeBudgetBackend struct {
	delay         time.Duration
	holdNetwork   string
	rejectNetwork string
	received      chan<- string
}

func (b probeBudgetBackend) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	if network == b.rejectNetwork {
		return nil, errors.New("private-backend-setup-error")
	}
	timer := time.NewTimer(b.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	local, target := net.Pipe()
	go func() {
		defer target.Close()
		data := make([]byte, 4096)
		for {
			n, err := target.Read(data)
			if err != nil {
				return
			}
			if b.received != nil {
				select {
				case b.received <- network:
				default:
				}
			}
			if network == b.holdNetwork {
				// Keep reading so only the peer's echo is withheld. This leaves
				// the CLI's read pending after its actual business write.
				continue
			}
			if _, err := target.Write(data[:n]); err != nil {
				return
			}
		}
	}()
	return local, nil
}

func probeBudgetFixture(t *testing.T, setupDelay time.Duration) string {
	return probeBudgetFixtureWithBackend(t, probeBudgetBackend{delay: setupDelay})
}

func probeBudgetFixtureWithBackend(t *testing.T, backend session.Backend) string {
	t.Helper()
	serverKey, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	admission := bytes.Repeat([]byte{0x5d}, 32)
	server, err := session.NewServer(session.ServerConfig{
		Listen: "127.0.0.1:0",
		Credentials: session.Credentials{Admission: admission, Private: serverKey.Private,
			Public: serverKey.Public, AllowedClients: [][]byte{clientKey.Public}},
		Backend: backend,
	})
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(context.Background()) }()
	t.Cleanup(func() {
		server.Close()
		select {
		case err := <-serverDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("probe budget server did not join")
		}
	})
	private := filepath.Join(t.TempDir(), "private")
	if err := securefile.MakePrivateDir(private); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "client.json")
	cfg := clientConfig{
		Server: server.Addr().String(), TCPServer: server.Addr().String(),
		Credentials: session.Credentials{Admission: admission, Private: clientKey.Private,
			Public: clientKey.Public, ServerPublic: serverKey.Public},
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.WriteExclusive(path, body); err != nil {
		t.Fatal(err)
	}
	return path
}

func readProbeBudgetResult(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"credentials"`, `"admission"`, `"private"`} {
		if bytes.Contains(data, []byte(field)) {
			t.Fatal("probe result contains credential fields")
		}
	}
	return result
}

// Execute the real CLI probe over a live encrypted Session. Delaying backend
// establishment consumes most of the default total budget, so the last
// iteration is never started in that mode. An explicit setup budget allows the
// same business sequence to finish; it does not reinterpret the default FAIL.
func TestProbeBudgetDefaultTotalAndExplicitSetup(t *testing.T) {
	const duration = 2 * time.Second
	const setupDelay = 1250 * time.Millisecond
	const interval = 450 * time.Millisecond
	for _, separate := range []bool{false, true} {
		name := "default-total"
		if separate {
			name = "explicit-setup"
		}
		t.Run(name, func(t *testing.T) {
			cfg := probeBudgetFixture(t, setupDelay)
			resultPath := filepath.Join(t.TempDir(), "result.json")
			var err error
			if separate {
				err = probeWithSetupBudget(context.Background(), cfg, "example.test:443", "", resultPath, 3, 64, interval, duration, 2*time.Second)
			} else {
				// The compatibility wrapper must retain the original total budget.
				err = probe(context.Background(), cfg, "example.test:443", "", resultPath, 3, 64, interval, duration)
			}
			result := readProbeBudgetResult(t, resultPath)
			if elapsed := result["setup_elapsed_ms"].(float64); elapsed < float64(setupDelay.Milliseconds()) {
				t.Fatalf("setup evidence missing delay: %.0fms", elapsed)
			}
			if separate {
				if err != nil || result["pass"] != true || result["budget_mode"] != "separate_setup" || result["tcp_completed"] != float64(3) || result["last_iteration_started"] != float64(2) || result["failure_phase"] != "" {
					t.Fatalf("explicit setup did not finish final iteration: err=%v result=%v", err, result)
				}
			} else {
				if err == nil || result["pass"] != false || result["budget_mode"] != "absolute_total" || result["failure"] != "probe deadline" || result["failure_phase"] != "interval" || result["tcp_completed"] != float64(2) || result["last_iteration_started"] != float64(1) {
					t.Fatalf("default total deadline was changed: err=%v result=%v", err, result)
				}
			}
		})
	}
}

func TestProbeSeparateSetupCannotExtendParentDeadline(t *testing.T) {
	cfg := probeBudgetFixture(t, 100*time.Millisecond)
	resultPath := filepath.Join(t.TempDir(), "result.json")
	parent, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	err := probeWithSetupBudget(parent, cfg, "example.test:443", "", resultPath, 3, 64, 450*time.Millisecond, 2*time.Second, 2*time.Second)
	result := readProbeBudgetResult(t, resultPath)
	if err == nil || result["pass"] != false || result["failure"] != "probe deadline" || result["last_iteration_started"] == float64(2) || result["total_elapsed_ms"].(float64) > 1200 {
		t.Fatalf("separate phase extended parent deadline: err=%v result=%v", err, result)
	}
}

func TestProbeBudgetRejectsNegativeSetupBeforeNetwork(t *testing.T) {
	err := probeWithSetupBudget(context.Background(), "missing-private-config", "", "", "", 1, 1, 0, time.Second, -time.Nanosecond)
	if err == nil || err.Error() != "invalid probe budget" {
		t.Fatalf("negative setup budget accepted: %v", err)
	}
}

func TestProbeBudgetResultOmitsSecrets(t *testing.T) {
	// This also exercises the full result artifact path with a live Session,
	// so setup evidence cannot accidentally copy the private configuration.
	cfg := probeBudgetFixture(t, 0)
	var private clientConfig
	if err := readConfig(cfg, &private); err != nil {
		t.Fatal(err)
	}
	resultPath := filepath.Join(t.TempDir(), "result.json")
	if err := probeWithSetupBudget(context.Background(), cfg, "example.test:443", "", resultPath, 1, 64, 0, time.Second, time.Second); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{private.Credentials.Admission, private.Credentials.Private} {
		if bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(secret))) {
			t.Fatal("probe artifact exposed credentials")
		}
	}
}

func TestProbeCancellationInterruptsInProgressTCPRead(t *testing.T) {
	received := make(chan string, 4)
	cfg := probeBudgetFixtureWithBackend(t, probeBudgetBackend{holdNetwork: "tcp", received: received})
	resultPath := filepath.Join(t.TempDir(), "result.json")
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- probeWithSetupBudget(parent, cfg, "example.test:443", "", resultPath, 1, 64, 0, 10*time.Second, time.Second)
	}()
	select {
	case network := <-received:
		if network != "tcp" {
			t.Fatalf("unexpected target network: %s", network)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("probe never entered its actual TCP business exchange")
	}
	cancelledAt := time.Now()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled, echo-blocked TCP probe passed")
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("TCP read waited for its future operation deadline after cancellation")
	}
	result := readProbeBudgetResult(t, resultPath)
	if result["failure_phase"] != "tcp_exchange" || result["last_iteration_started"] != float64(0) || result["tcp_completed"] != float64(0) || result["business_elapsed_ms"].(float64) > 1000 || time.Since(cancelledAt) > 1500*time.Millisecond {
		t.Fatalf("in-progress TCP cancellation evidence invalid: %v", result)
	}
}

func TestProbeDeadlineInsideUDPReadKeepsExchangePhase(t *testing.T) {
	received := make(chan string, 4)
	cfg := probeBudgetFixtureWithBackend(t, probeBudgetBackend{holdNetwork: "udp", received: received})
	resultPath := filepath.Join(t.TempDir(), "result.json")
	err := probeWithSetupBudget(context.Background(), cfg, "example.test:443", "example.test:53", resultPath, 1, 64, 0, 300*time.Millisecond, time.Second)
	if err == nil {
		t.Fatal("UDP echo-blocked probe passed")
	}
	result := readProbeBudgetResult(t, resultPath)
	if result["failure"] != "probe deadline" || result["failure_phase"] != "udp_exchange" || result["tcp_completed"] != float64(1) || result["udp_completed"] != float64(0) || result["udp_failed"] != float64(1) || result["last_iteration_started"] != float64(0) {
		t.Fatalf("UDP failure phase was replaced by interval: %v", result)
	}
	seenUDP := false
	for len(received) > 0 {
		seenUDP = seenUDP || <-received == "udp"
	}
	if !seenUDP {
		t.Fatal("probe did not actually reach its UDP business read")
	}
}

func TestProbeSetupFailuresProduceSanitizedResult(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network+"-open", func(t *testing.T) {
			cfg := probeBudgetFixtureWithBackend(t, probeBudgetBackend{rejectNetwork: network})
			resultPath := filepath.Join(t.TempDir(), "result.json")
			err := probeWithSetupBudget(context.Background(), cfg, "example.test:443", "example.test:53", resultPath, 1, 64, 0, time.Second, time.Second)
			if err == nil {
				t.Fatal("rejected target open succeeded")
			}
			result := readProbeBudgetResult(t, resultPath)
			if result["failure"] != "probe setup failed" || result["failure_phase"] != network+"_open" || result["last_iteration_started"] != float64(-1) || result["business_elapsed_ms"] != float64(0) || result["tcp_completed"] != float64(0) {
				t.Fatalf("setup phase evidence invalid: %v", result)
			}
			data, _ := os.ReadFile(resultPath)
			if bytes.Contains(data, []byte("private-backend-setup-error")) || bytes.Contains(data, []byte("example.test")) {
				t.Fatal("setup result echoed private cause or target")
			}
		})
	}
	t.Run("connect", func(t *testing.T) {
		cfgPath := probeBudgetFixture(t, 0)
		var cfg clientConfig
		if err := readConfig(cfgPath, &cfg); err != nil {
			t.Fatal(err)
		}
		// A bound TCP-only blackhole makes the real UDP-first establishment
		// time out and prevents any successful application handshake.
		blackhole, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer blackhole.Close()
		cfg.Server, cfg.TCPServer = blackhole.Addr().String(), blackhole.Addr().String()
		data, _ := json.Marshal(cfg)
		if err := os.WriteFile(cfgPath, data, 0600); err != nil {
			t.Fatal(err)
		}
		resultPath := filepath.Join(t.TempDir(), "result.json")
		err = probeWithSetupBudget(context.Background(), cfgPath, "example.test:443", "", resultPath, 1, 64, 0, time.Second, 100*time.Millisecond)
		if err == nil {
			t.Fatal("blackhole connect succeeded")
		}
		result := readProbeBudgetResult(t, resultPath)
		if result["failure_phase"] != "setup_connect" || result["pass"] != false || result["last_iteration_started"] != float64(-1) {
			t.Fatalf("connect result not recorded: %v", result)
		}
	})
}
