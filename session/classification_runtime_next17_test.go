package session

import (
	"context"
	"testing"

	"bfp/classification"
	"bfp/protocol"
)

func TestClassificationRuntimeLocalMetadataBridge(t *testing.T) {
	local, peer := classification.DefaultConfig(), classification.DefaultConfig()
	local.Behavior.Enabled, peer.Behavior.Enabled = false, false
	local.HighestAllowed = protocol.Normal
	local.Rules = []classification.Rule{{Name: "terminal-app", Application: "terminal", Class: protocol.Interactive, Locked: true}}
	peer.DefaultClass = protocol.Bulk
	f := newClassFixture(t, "tcp", &local, &peer)
	wireTarget := protocol.Target{Network: "tcp", Address: f.address, Domain: "wire.example.test", RuleTag: "app:terminal", Class: protocol.Interactive}
	bridge := classification.NewLocalMetadataBridge(wireTarget)
	plain, _ := f.dial(t, "metadata", bridge.Metadata())
	if snap := classSnapshot(t, f.local, plain.id); snap.LocalTX.Baseline.Source != classification.SourceDefault || snap.LocalTX.Class != protocol.Normal {
		t.Fatalf("wire fields crossed bridge: %+v", snap)
	}
	trustedBridge, err := bridge.WithTrustedApplication("terminal")
	if err != nil {
		t.Fatal(err)
	}
	trusted, _ := f.dial(t, "metadata", trustedBridge.Metadata())
	snap := classSnapshot(t, f.local, trusted.id)
	if snap.LocalTX.Baseline.Source != classification.SourceMetadata || snap.LocalTX.Baseline.Rule != "terminal-app" || snap.LocalTX.Class != protocol.Normal || !snap.LocalTX.Baseline.Locked {
		t.Fatalf("local application policy not bridged: %+v", snap)
	}
	if peerSnap := classSnapshot(t, f.peer, trusted.id); peerSnap.LocalTX.Baseline.Source != classification.SourceDefault || peerSnap.LocalTX.Class != protocol.Bulk {
		t.Fatalf("peer inherited local application trust: %+v", peerSnap)
	}
	var opened protocol.Target
	if err := f.peer.call(context.Background(), func() {
		opened = f.peer.streams[trusted.id].target
	}); err != nil {
		t.Fatal(err)
	}
	if opened.RuleTag != "" || opened.Domain != "" || opened.Class != protocol.Normal {
		t.Fatalf("local-only application metadata leaked into OPEN target: %+v", opened)
	}
}
