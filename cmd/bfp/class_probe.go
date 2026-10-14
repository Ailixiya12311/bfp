package main

import (
	"bfp/classification"
	"bfp/protocol"
	"bfp/session"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

// This is a bounded experiment, not an outbound adapter or a public carrier
// switching API. An external run-owned UDP relay supplies failure scenarios.
type classProbeResult struct {
	Pass                bool                        `json:"pass"`
	Failure             string                      `json:"failure"`
	Scope               string                      `json:"scope"`
	WireVersion         int                         `json:"wire_version"`
	Profile             string                      `json:"profile"`
	Capabilities        session.Capabilities        `json:"capabilities"`
	TCPCompleted        int                         `json:"tcp_completed"`
	ExpectedTCP         int                         `json:"expected_tcp"`
	BytesPerOperation   int                         `json:"bytes_per_operation"`
	ExpectedUniqueBytes uint64                      `json:"expected_unique_bytes"`
	EchoSHA256          string                      `json:"echo_sha256"`
	ElapsedMS           int64                       `json:"elapsed_ms"`
	MaxTCPOperationMS   int64                       `json:"max_tcp_operation_ms"`
	EvidenceSettleMS    int64                       `json:"evidence_settle_ms"`
	SameSession         bool                        `json:"same_session"`
	FinalStatsPhase     string                      `json:"final_stats_phase"`
	Timing              classProbeTiming            `json:"timing"`
	FlowID              uint64                      `json:"flow_id"`
	Initial             session.Stats               `json:"initial"`
	Final               session.Stats               `json:"final"`
	InitialClass        *session.FlowClassification `json:"initial_class"`
	BulkClass           *session.FlowClassification `json:"bulk_class"`
	RestoredClass       *session.FlowClassification `json:"restored_class"`
	FinalClass          *session.FlowClassification `json:"final_class"`
	CheckedGates        map[string]bool             `json:"checked_gates"`
	UncheckedGates      map[string]bool             `json:"unchecked_gates"`
}

// Durations are local monotonic elapsed observations. Write completion means
// Flow accepted bytes, not that those bytes reached the peer or left a socket.
// Concurrent read and write times overlap and must not be added as packet RTT.
type classProbeOperation struct {
	Iteration        int    `json:"iteration"`
	StartMS          int64  `json:"start_ms"`
	EndMS            int64  `json:"end_ms"`
	RemainingStartMS int64  `json:"remaining_start_ms"`
	DeadlineBudgetMS int64  `json:"deadline_budget_ms"`
	WriteMS          int64  `json:"write_ms"`
	ReadMS           int64  `json:"read_ms"`
	TotalMS          int64  `json:"total_ms"`
	AcceptedBytes    int    `json:"accepted_bytes"`
	EchoBytes        int    `json:"echo_bytes"`
	FailureStage     string `json:"failure_stage,omitempty"`
	ErrorKind        string `json:"error_kind,omitempty"`
}

type classProbeTiming struct {
	Phase               string               `json:"phase"`
	InitialReadyMS      int64                `json:"initial_ready_ms"`
	BusinessCompletedMS int64                `json:"business_completed_ms"`
	IdleStartedMS       int64                `json:"idle_started_ms"`
	IdleRemainingMS     int64                `json:"idle_remaining_ms"`
	IdleRestoredMS      int64                `json:"idle_restored_ms"`
	EvidenceCompletedMS int64                `json:"evidence_completed_ms"`
	AttemptedOperations int                  `json:"attempted_operations"`
	CompletedOperations int                  `json:"completed_operations"`
	AcceptedBytes       uint64               `json:"accepted_bytes"`
	EchoBytes           uint64               `json:"echo_bytes"`
	TotalExchangeMS     int64                `json:"total_exchange_ms"`
	MaxWriteMS          int64                `json:"max_write_ms"`
	MaxReadMS           int64                `json:"max_read_ms"`
	LastOperation       *classProbeOperation `json:"last_operation,omitempty"`
}

func classProbeRemainingMS(ctx context.Context, now time.Time) int64 {
	if deadline, ok := ctx.Deadline(); ok {
		return max(0, deadline.Sub(now).Milliseconds())
	}
	return -1 // no enclosing deadline; the fixed per-operation deadline still applies
}

func classProbeErrorKind(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, session.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "closed"
	}
	if errors.Is(err, io.ErrShortWrite) {
		return "short_write"
	}
	return "io" // never include peer strings, targets, credentials or payload bytes
}

func newClassProbeResult(count, size int) classProbeResult {
	return classProbeResult{
		Scope:       "bounded echo flow: local TX publication/ACK and read-only announced peer TX; external runner must verify full peer state and target continuity",
		WireVersion: 3, EvidenceSettleMS: 1000,
		Timing:      classProbeTiming{Phase: "configuration"},
		ExpectedTCP: count, BytesPerOperation: size, ExpectedUniqueBytes: uint64(count) * uint64(size),
		CheckedGates: map[string]bool{
			"initial_both_normal": false, "initial_local_exact_ack": false, "both_bulk_seen": false, "both_restored_normal": false,
			"local_final_exact_ack": false, "versions_advance": false, "local_unique_bytes_exact": false, "echo_bytes_exact": false,
			"same_session": false, "same_local_flow": false, "no_terminal_flow": false, "idle_adds_no_business_bytes": false, "deadline_met": false,
		},
		UncheckedGates: map[string]bool{"peer_exact_publication_ack": false, "peer_unique_counter": false, "target_connection_count": false, "missing_ack_injection": false, "retry_exhaustion": false, "carrier_matrix": false},
	}
}

func validClassProbeBudget(count, size int, interval, duration time.Duration) bool {
	return count >= 1 && count <= 10000 && size >= 1 && size <= 1<<20 && interval > 0 && duration > 0 && duration <= 5*time.Minute
}

func classProbe(parent context.Context, path, target, resultPath string, count, size int, interval, duration time.Duration) error {
	if !validClassProbeBudget(count, size, interval, duration) {
		return errors.New("invalid class probe budget")
	}
	result := newClassProbeResult(count, size)
	ctx, cancel := context.WithTimeout(parent, duration)
	defer cancel()
	var cfg clientConfig
	var runErr error
	if err := readConfig(path, &cfg); err != nil {
		result.Failure = "configuration"
		runErr = errors.New("class probe configuration failed")
	} else {
		sessionCfg, err := cfg.sessionConfig()
		if err != nil {
			result.Failure = "configuration"
			runErr = errors.New("class probe configuration failed")
		} else {
			runErr = executeClassProbe(ctx, sessionCfg, target, count, size, interval, &result, func(snapshot session.FlowClassification, stats session.Stats, iteration int) {
				emit(map[string]any{"event": "class_progress", "iteration": iteration, "class": snapshot, "session": stats})
			}, func(observation classProbeOperation) {
				emit(map[string]any{"event": "class_operation", "operation": observation})
			})
		}
	}
	emit(result)
	if resultPath != "" {
		body, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return errors.New("class probe result encoding failed")
		}
		if err = os.WriteFile(resultPath, body, 0600); err != nil {
			return errors.New("class probe result write failed")
		}
	}
	return runErr
}

func classProbeExactACK(snapshot session.FlowClassification) bool {
	return snapshot.TXVersion != 0 && snapshot.TXPublishedVersion == snapshot.TXVersion && snapshot.TXAckedVersion == snapshot.TXVersion && !snapshot.TXPending
}

func classProbeBoth(snapshot session.FlowClassification, class protocol.Class) bool {
	return !snapshot.Terminal && snapshot.LocalTX.Class == class && snapshot.PeerTX.Known && snapshot.PeerTX.Class == class && classProbeExactACK(snapshot)
}

func classProbeQuery(ctx context.Context, flow *session.Flow, predicate func(session.FlowClassification) bool) (session.FlowClassification, error) {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		snapshot, err := flow.Classification(ctx)
		if err != nil {
			return snapshot, err
		}
		if predicate(snapshot) {
			return snapshot, nil
		}
		select {
		case <-ctx.Done():
			return snapshot, ctx.Err()
		case <-ticker.C:
		}
	}
}

// exchangeClassTCP preserves the pre-existing eight-second operation deadline.
// The enclosing absolute probe deadline may shorten it, never extend it.
func exchangeClassTCP(ctx context.Context, flow *session.Flow, data []byte) ([]byte, error) {
	echo, _, err := exchangeClassTCPObserved(ctx, flow, data, 0, time.Now())
	return echo, err
}

type classProbeStream interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	SetDeadline(time.Time) error
}

func exchangeClassTCPObserved(ctx context.Context, flow classProbeStream, data []byte, iteration int, probeStarted time.Time) (echo []byte, observation classProbeOperation, runErr error) {
	started := time.Now()
	observation.Iteration = iteration
	observation.StartMS = started.Sub(probeStarted).Milliseconds()
	observation.RemainingStartMS = classProbeRemainingMS(ctx, started)
	defer func() {
		now := time.Now()
		observation.EndMS = now.Sub(probeStarted).Milliseconds()
		observation.TotalMS = now.Sub(started).Milliseconds()
	}()
	deadline := started.Add(8 * time.Second)
	if probeDeadline, ok := ctx.Deadline(); ok && probeDeadline.Before(deadline) {
		deadline = probeDeadline
	}
	observation.DeadlineBudgetMS = max(0, deadline.Sub(started).Milliseconds())
	if !time.Now().Before(deadline) {
		observation.FailureStage, observation.ErrorKind = "deadline", "deadline"
		return nil, observation, context.DeadlineExceeded
	}
	if err := flow.SetDeadline(deadline); err != nil {
		observation.FailureStage, observation.ErrorKind = "set_deadline", classProbeErrorKind(err)
		return nil, observation, err
	}
	type writeObservation struct {
		bytes   int
		elapsed time.Duration
		err     error
	}
	written := make(chan writeObservation, 1)
	go func() {
		n, err := flow.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		written <- writeObservation{n, time.Since(started), err}
	}()
	echo = make([]byte, len(data))
	readStarted := time.Now()
	n, err := io.ReadFull(flow, echo)
	observation.EchoBytes, observation.ReadMS = n, time.Since(readStarted).Milliseconds()
	write := <-written
	observation.AcceptedBytes, observation.WriteMS = write.bytes, write.elapsed.Milliseconds()
	if err != nil {
		observation.FailureStage, observation.ErrorKind = "read", classProbeErrorKind(err)
	} else if write.err != nil {
		err = write.err
		observation.FailureStage, observation.ErrorKind = "write", classProbeErrorKind(err)
	}
	if err != nil {
		return nil, observation, err
	}
	if !bytes.Equal(data, echo) {
		observation.FailureStage, observation.ErrorKind = "verify", "echo_mismatch"
		return nil, observation, errors.New("echo mismatch")
	}
	return echo, observation, nil
}

func executeClassProbe(ctx context.Context, cfg session.ClientConfig, target string, count, size int, interval time.Duration, result *classProbeResult, progress func(session.FlowClassification, session.Stats, int), observations ...func(classProbeOperation)) (runErr error) {
	started := time.Now()
	result.Timing.Phase = "policy"
	fail := func(kind string) error { result.Failure = kind; return errors.New("class probe " + kind + " failed") }
	defer func() { result.ElapsedMS = time.Since(started).Milliseconds() }()
	policy := classification.DefaultConfig()
	if cfg.Classification != nil {
		policy = *cfg.Classification
	}
	compiler, err := classification.New(policy)
	if err != nil || !policy.Behavior.Enabled || !policy.Behavior.Restore {
		return fail("behavior_policy")
	}
	decision, err := compiler.Decide(classification.Metadata{Target: protocol.Target{Network: "tcp", Address: target}})
	if err != nil || decision.Class != protocol.Normal || decision.Locked {
		return fail("normal_baseline_policy")
	}
	client, err := session.NewClient(cfg)
	if err != nil {
		return fail("client")
	}
	defer client.Close()
	result.Timing.Phase = "connect"
	owner, err := client.Connect(ctx)
	if err != nil {
		return fail("connect")
	}
	result.Initial = owner.Stats()
	// Successful construction and handshake enforce this fixed selection.
	// Artifacts that fail before connecting make no negotiated-selection claim.
	result.Profile, result.Capabilities = session.ProfileClassAnnouncementV1, session.CapabilityClassAnnouncementV1
	defer func() {
		// Keep the explicitly captured pre-close sample on successful completion.
		// Failure cleanup may already have removed the flow; label that sample.
		if result.FinalStatsPhase == "" {
			result.Final = owner.Stats()
			result.FinalStatsPhase = "deferred_cleanup"
		}
		result.SameSession = result.Initial.ID != "" && result.Initial.ID == result.Final.ID
	}()
	result.Timing.Phase = "dial"
	conn, err := client.DialContext(ctx, "tcp", target)
	if err != nil {
		return fail("dial")
	}
	defer conn.Close()
	flow, ok := conn.(*session.Flow)
	if !ok {
		return fail("flow_type")
	}
	stopCancel := context.AfterFunc(ctx, func() { flow.Close() })
	defer stopCancel()
	result.Timing.Phase = "initial_classification"
	initial, err := classProbeQuery(ctx, flow, func(snapshot session.FlowClassification) bool {
		return classProbeBoth(snapshot, protocol.Normal) && snapshot.TXVersion == 1 && snapshot.PeerTX.Version == 1
	})
	if err != nil {
		return fail("initial_state")
	}
	result.InitialClass, result.FlowID = &initial, initial.ID
	result.Timing.InitialReadyMS = time.Since(started).Milliseconds()
	result.CheckedGates["initial_both_normal"], result.CheckedGates["initial_local_exact_ack"] = true, true
	if progress != nil {
		progress(initial, owner.Stats(), -1)
	}
	echoHash := sha256.New()
	result.Timing.Phase = "business"
	for iteration := 0; iteration < count; iteration++ {
		begin := time.Now()
		data := make([]byte, size)
		if _, err = io.ReadFull(rand.Reader, data); err != nil {
			return fail("entropy")
		}
		echo, observation, exchangeErr := exchangeClassTCPObserved(ctx, flow, data, iteration, started)
		result.Timing.AttemptedOperations++
		result.Timing.AcceptedBytes += uint64(observation.AcceptedBytes)
		result.Timing.EchoBytes += uint64(observation.EchoBytes)
		result.Timing.TotalExchangeMS += observation.TotalMS
		result.Timing.MaxWriteMS = max(result.Timing.MaxWriteMS, observation.WriteMS)
		result.Timing.MaxReadMS = max(result.Timing.MaxReadMS, observation.ReadMS)
		result.Timing.LastOperation = &observation
		for _, observe := range observations {
			if observe != nil {
				observe(observation)
			}
		}
		if exchangeErr != nil {
			return fail("tcp_exchange")
		}
		result.TCPCompleted++
		result.Timing.CompletedOperations++
		result.Timing.BusinessCompletedMS = time.Since(started).Milliseconds()
		_, _ = echoHash.Write(echo)
		result.MaxTCPOperationMS = max(result.MaxTCPOperationMS, time.Since(begin).Milliseconds())
		snapshot, err := flow.Classification(ctx)
		if err != nil {
			return fail("snapshot")
		}
		if snapshot.ID != result.FlowID || snapshot.Terminal {
			return fail("flow_continuity")
		}
		if result.BulkClass == nil && classProbeBoth(snapshot, protocol.Bulk) && snapshot.TXVersion > initial.TXVersion && snapshot.PeerTX.Version > initial.PeerTX.Version {
			result.BulkClass = &snapshot
			result.CheckedGates["both_bulk_seen"] = true
		}
		if progress != nil {
			progress(snapshot, owner.Stats(), iteration)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fail("deadline")
		case <-timer.C:
		}
	}
	result.EchoSHA256 = hex.EncodeToString(echoHash.Sum(nil))
	if result.BulkClass == nil {
		return fail("bulk_state_missing")
	}
	// The idle phase queries without sending business bytes. Carrier recovery
	// remains driven by the ordinary watchdog and an external relay failure.
	result.Timing.Phase = "idle_restore"
	result.Timing.IdleStartedMS = time.Since(started).Milliseconds()
	result.Timing.IdleRemainingMS = classProbeRemainingMS(ctx, time.Now())
	restored, err := classProbeQuery(ctx, flow, func(snapshot session.FlowClassification) bool {
		return classProbeBoth(snapshot, protocol.Normal) && snapshot.TXVersion > result.BulkClass.TXVersion && snapshot.PeerTX.Version > result.BulkClass.PeerTX.Version
	})
	if err != nil {
		return fail("idle_restore")
	}
	result.RestoredClass = &restored
	result.Timing.IdleRestoredMS = time.Since(started).Milliseconds()
	result.Timing.Phase = "evidence_settle"
	// Leave the live idle flow observable for one fixed server-statistics period.
	// This sends no business bytes and cannot extend the absolute probe deadline.
	settle := time.NewTimer(time.Duration(result.EvidenceSettleMS) * time.Millisecond)
	select {
	case <-ctx.Done():
		settle.Stop()
		return fail("evidence_deadline")
	case <-settle.C:
	}
	finalClass, err := flow.Classification(ctx)
	if err != nil {
		return fail("final_snapshot")
	}
	result.FinalClass = &finalClass
	result.Final = owner.Stats()
	result.FinalStatsPhase = "before_flow_close"
	result.Timing.EvidenceCompletedMS = time.Since(started).Milliseconds()
	result.Timing.Phase = "gates"
	result.SameSession = result.Initial.ID != "" && result.Initial.ID == result.Final.ID
	result.CheckedGates["both_restored_normal"] = classProbeBoth(restored, protocol.Normal)
	result.CheckedGates["local_final_exact_ack"] = classProbeExactACK(finalClass)
	result.CheckedGates["versions_advance"] = restored.TXVersion > result.BulkClass.TXVersion && restored.PeerTX.Version > result.BulkClass.PeerTX.Version
	result.CheckedGates["local_unique_bytes_exact"] = finalClass.LocalTX.TotalBytes == result.ExpectedUniqueBytes
	result.CheckedGates["echo_bytes_exact"] = result.TCPCompleted == count && len(result.EchoSHA256) == 64
	result.CheckedGates["same_session"] = result.SameSession
	result.CheckedGates["same_local_flow"] = initial.ID == finalClass.ID && result.Final.Opened == 1 && result.Final.Flows == 1
	result.CheckedGates["no_terminal_flow"] = !finalClass.Terminal
	result.CheckedGates["idle_adds_no_business_bytes"] = restored.LocalTX.TotalBytes == result.ExpectedUniqueBytes && finalClass.LocalTX.TotalBytes == result.ExpectedUniqueBytes
	result.CheckedGates["deadline_met"] = ctx.Err() == nil
	for _, passed := range result.CheckedGates {
		if !passed {
			return fail("gate")
		}
	}
	result.Pass = true
	result.Timing.Phase = "complete"
	if progress != nil {
		progress(finalClass, result.Final, count)
	}
	return nil
}
