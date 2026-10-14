package main

import (
	"bfp/classification"
	"bfp/internal/securefile"
	"bfp/protocol"
	"bfp/security"
	"bfp/session"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func classProbeTestPolicy() classification.Config {
	policy := classification.DefaultConfig()
	policy.Behavior = classification.BehaviorConfig{Enabled: true, Window: 400 * time.Millisecond, Bucket: 50 * time.Millisecond, MinTotalBytes: 1024, BulkBytesPerSecond: 1024, BulkSustain: 250 * time.Millisecond, ActivityGap: 150 * time.Millisecond, Restore: true, RestoreBytesPerSecond: 100, RestoreSustain: 150 * time.Millisecond}
	return policy
}

func classProbeTestFixture(t *testing.T, kind string) (session.ClientConfig, string, *atomic.Uint64) {
	t.Helper()
	serverKey, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	admission := bytes.Repeat([]byte{0x71}, 32)
	policy := classProbeTestPolicy()
	opts := session.Options{HandshakeTimeout: 200 * time.Millisecond, ProbeInterval: 100 * time.Millisecond, FailureTimeout: 3 * time.Second}
	server, err := session.NewServer(session.ServerConfig{Listen: "127.0.0.1:0", Credentials: session.Credentials{Admission: admission, Private: serverKey.Private, Public: serverKey.Public, AllowedClients: [][]byte{clientKey.Public}}, Options: opts, Backend: &net.Dialer{}, Classification: &policy})
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background()) }()
	t.Cleanup(func() {
		server.Close()
		if err := <-serveDone; err != nil {
			t.Error(err)
		}
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var opened atomic.Uint64
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			opened.Add(1)
			mu.Lock()
			connections[conn] = true
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
				_, _ = io.Copy(conn, conn)
				mu.Lock()
				delete(connections, conn)
				mu.Unlock()
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		for conn := range connections {
			conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	udp := server.Addr().String()
	if kind == "tcp" {
		unused, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		udp = unused.LocalAddr().String()
		unused.Close()
	}
	cfg := session.ClientConfig{Server: udp, TCPServer: server.Addr().String(), Credentials: session.Credentials{Admission: admission, Private: clientKey.Private, Public: clientKey.Public, ServerPublic: serverKey.Public}, Options: opts, Classification: &policy}
	return cfg, listener.Addr().String(), &opened
}

func TestClassProbeEncryptedUDPAndTCPBulkRestore(t *testing.T) {
	for _, kind := range []string{"udp", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			cfg, target, opened := classProbeTestFixture(t, kind)
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			result := newClassProbeResult(24, 2048)
			emitted := 0
			if err := executeClassProbe(ctx, cfg, target, 24, 2048, 50*time.Millisecond, &result, func(snapshot session.FlowClassification, stats session.Stats, iteration int) { emitted++ }); err != nil {
				t.Fatalf("real %s class probe: %v; failure=%s completed=%d checkpoints=%+v/%+v", kind, err, result.Failure, result.TCPCompleted, result.InitialClass, result.BulkClass)
			}
			if !result.Pass || result.Initial.Carrier != kind || result.Final.Carrier != kind || opened.Load() != 1 || result.TCPCompleted != 24 || result.ExpectedUniqueBytes != 49152 || emitted != 26 {
				t.Fatalf("class probe evidence incomplete: %+v target opens=%d samples=%d", result, opened.Load(), emitted)
			}
			if result.Final.Flows != 1 || result.FinalStatsPhase != "before_flow_close" {
				t.Fatalf("successful live final state overwritten by deferred cleanup: %+v", result.Final)
			}
			if result.Timing.Phase != "complete" || result.Timing.AttemptedOperations != 24 || result.Timing.CompletedOperations != 24 || result.Timing.AcceptedBytes != 49152 || result.Timing.EchoBytes != 49152 || result.Timing.IdleRemainingMS <= 0 || result.Timing.BusinessCompletedMS > result.Timing.IdleStartedMS || result.Timing.IdleStartedMS > result.Timing.IdleRestoredMS || result.Timing.IdleRestoredMS > result.Timing.EvidenceCompletedMS {
				t.Fatalf("phase and application acceptance timing incomplete: %+v", result.Timing)
			}
			for name, passed := range result.CheckedGates {
				if !passed {
					t.Fatalf("checked gate %s failed", name)
				}
			}
			for name, claimed := range result.UncheckedGates {
				if claimed {
					t.Fatalf("unchecked gate %s was claimed", name)
				}
			}
			body, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{base64.StdEncoding.EncodeToString(cfg.Credentials.Admission), base64.StdEncoding.EncodeToString(cfg.Credentials.Private), `"credentials"`, `"admission"`, `"private"`} {
				if bytes.Contains(body, []byte(secret)) {
					t.Fatal("class probe result exposed credentials")
				}
			}
		})
	}
}

func TestClassProbeObservedExchangePreservesPartialEchoFailure(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	data := []byte("unlogged-payload-marker-123456")
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		buffer := make([]byte, len(data))
		if _, err := io.ReadFull(server, buffer); err != nil {
			return
		}
		_, _ = server.Write(buffer[:7])
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	echo, observation, err := exchangeClassTCPObserved(ctx, client, data, 4, time.Now())
	<-done
	if err == nil || echo != nil || observation.Iteration != 4 || observation.AcceptedBytes != len(data) || observation.EchoBytes != 7 || observation.FailureStage != "read" || observation.ErrorKind != "closed" || observation.DeadlineBudgetMS > 1000 || observation.DeadlineBudgetMS < 1 || observation.EndMS < observation.StartMS {
		t.Fatalf("partial exchange failure hidden or budget renewed: err=%v observation=%+v", err, observation)
	}
	encoded, _ := json.Marshal(observation)
	if bytes.Contains(encoded, data) {
		t.Fatal("operation diagnostics emitted application payload")
	}
}

func TestClassProbeObservedExchangeClampsDeadlineAndRecordsFailure(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, observation, err := exchangeClassTCPObserved(ctx, client, []byte("unconsumed"), 0, started)
	if err == nil || observation.ErrorKind != "deadline" || observation.AcceptedBytes != 0 || observation.EchoBytes != 0 || observation.DeadlineBudgetMS > 40 || observation.DeadlineBudgetMS < 1 || observation.TotalMS < observation.DeadlineBudgetMS || time.Since(started) > time.Second {
		t.Fatalf("original enclosing deadline not preserved: err=%v observation=%+v", err, observation)
	}
}

func TestClassProbeExactAckAndKnownPeerGates(t *testing.T) {
	valid := session.FlowClassification{TXVersion: 2, TXPublishedVersion: 2, TXAckedVersion: 2, LocalTX: classification.Snapshot{Class: protocol.Bulk}, PeerTX: session.PeerTXClassification{Known: true, Version: 2, Class: protocol.Bulk}}
	if !classProbeBoth(valid, protocol.Bulk) {
		t.Fatal("valid class checkpoint rejected")
	}
	for name, mutate := range map[string]func(*session.FlowClassification){
		"pending":          func(s *session.FlowClassification) { s.TXPending = true },
		"unpublished":      func(s *session.FlowClassification) { s.TXPublishedVersion = 1 },
		"old-ack":          func(s *session.FlowClassification) { s.TXAckedVersion = 1 },
		"future-ack":       func(s *session.FlowClassification) { s.TXAckedVersion = 3 },
		"version-zero":     func(s *session.FlowClassification) { s.TXVersion = 0 },
		"unknown-peer":     func(s *session.FlowClassification) { s.PeerTX.Known = false },
		"peer-other-class": func(s *session.FlowClassification) { s.PeerTX.Class = protocol.Normal },
		"terminal":         func(s *session.FlowClassification) { s.Terminal = true },
	} {
		t.Run(name, func(t *testing.T) {
			s := valid
			mutate(&s)
			if classProbeBoth(s, protocol.Bulk) {
				t.Fatal("incomplete checkpoint accepted")
			}
		})
	}
}

func TestClassProbePolicyFailuresBeforeNetwork(t *testing.T) {
	for name, mutate := range map[string]func(*classification.Config){
		"disabled":     func(p *classification.Config) { p.Behavior.Enabled = false },
		"no-restore":   func(p *classification.Config) { p.Behavior.Restore = false },
		"initial-bulk": func(p *classification.Config) { p.DefaultClass = protocol.Bulk },
		"locked-rule": func(p *classification.Config) {
			p.Rules = []classification.Rule{{Name: "test", Network: "tcp", Class: protocol.Normal, Locked: true}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := classProbeTestPolicy()
			mutate(&policy)
			result := newClassProbeResult(2, 64)
			err := executeClassProbe(context.Background(), session.ClientConfig{Classification: &policy}, "127.0.0.1:1", 2, 64, time.Millisecond, &result, nil)
			if err == nil || result.Pass || result.Failure == "client" {
				t.Fatalf("unsupported policy reached networking: %v %+v", err, result)
			}
		})
	}
}

func TestClassProbeInsufficientTrafficPreservesFailure(t *testing.T) {
	cfg, target, _ := classProbeTestFixture(t, "udp")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := newClassProbeResult(1, 64)
	if err := executeClassProbe(ctx, cfg, target, 1, 64, 10*time.Millisecond, &result, nil); err == nil || result.Pass || result.Failure != "bulk_state_missing" || result.TCPCompleted != 1 {
		t.Fatalf("insufficient sustained traffic rewritten as pass: %v %+v", err, result)
	}
}

func TestClassProbeConfigurationFailureArtifactSanitized(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := securefile.MakePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "client.json")
	if err := securefile.WriteExclusive(config, []byte(`{"private-invalid-secret-marker":true}`)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "failed.json")
	err := classProbe(context.Background(), config, "127.0.0.1:1", path, 1, 64, time.Millisecond, time.Second)
	if err == nil {
		t.Fatal("invalid config accepted")
	}
	body, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var result classProbeResult
	if json.Unmarshal(body, &result) != nil || result.Pass || result.Failure != "configuration" || bytes.Contains(body, []byte("private-invalid-secret-marker")) || bytes.Contains([]byte(err.Error()), []byte("private-invalid-secret-marker")) {
		t.Fatal("failure artifact missing or exposes config data")
	}
}

func TestClassProbeBudgetBounds(t *testing.T) {
	for _, b := range []struct {
		count, size        int
		interval, duration time.Duration
	}{
		{0, 1, time.Millisecond, time.Second}, {10001, 1, time.Millisecond, time.Second}, {1, 0, time.Millisecond, time.Second}, {1, 1<<20 + 1, time.Millisecond, time.Second}, {1, 1, 0, time.Second}, {1, 1, time.Millisecond, 0}, {1, 1, time.Millisecond, 5*time.Minute + 1},
	} {
		if validClassProbeBudget(b.count, b.size, b.interval, b.duration) {
			t.Fatal("unbounded probe budget accepted")
		}
	}
	if !validClassProbeBudget(50, 4096, 100*time.Millisecond, 35*time.Second) {
		t.Fatal("frozen WAN budget rejected")
	}
}
