package main

import (
	"bfp/classification"
	"bfp/clientconfig"
	"bfp/protocol"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestKeygenLowBandwidthPolicyWorksInBothClientEntries(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "credentials")
	if err := keygenWithClassificationProfile(directory, "127.0.0.1:51880", "127.0.0.1:51880", "", "127.0.0.1:1080", "low-bandwidth"); err != nil {
		t.Fatal(err)
	}
	var client clientConfig
	var server serverConfig
	if err := readConfig(filepath.Join(directory, "client.json"), &client); err != nil {
		t.Fatal(err)
	}
	if err := readConfig(filepath.Join(directory, "server.json"), &server); err != nil {
		t.Fatal(err)
	}
	standalone, err := client.sessionConfig()
	if err != nil {
		t.Fatal(err)
	}
	native, err := clientconfig.Load(filepath.Join(directory, "client.json"))
	if err != nil {
		t.Fatal(err)
	}
	serverPolicy, err := configClassification(server.Classification)
	if err != nil || !reflect.DeepEqual(standalone.Classification, native.Session.Classification) || !reflect.DeepEqual(serverPolicy, standalone.Classification) {
		t.Fatal("standalone, native and server policy decoding disagree")
	}
	classifier, err := classification.New(*native.Session.Classification)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := classifier.NewFlow(classification.Metadata{Target: protocol.Target{Network: "tcp", Address: "203.0.113.1:443"}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for elapsed := time.Duration(0); elapsed <= 9*time.Second; elapsed += 250 * time.Millisecond {
		if _, err := flow.Observe(elapsed, 4096); err != nil {
			t.Fatal(err)
		}
	}
	if flow.Snapshot().Class != protocol.Bulk {
		t.Fatal("sustained 16 KiB/s download did not enter bulk on the slow-link profile")
	}
	locked, err := classifier.NewFlow(classification.Metadata{Target: protocol.Target{Network: "tcp", Address: "203.0.113.1:22"}}, 0)
	if err != nil || locked.Snapshot().Class != protocol.Interactive || !locked.Snapshot().Baseline.Locked {
		t.Fatal("SSH did not retain interactive policy")
	}
}

func TestUnknownClassificationProfileCreatesNoCredentials(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "credentials")
	if err := keygenWithClassificationProfile(directory, "127.0.0.1:1", "127.0.0.1:1", "", "127.0.0.1:2", "unknown"); err == nil {
		t.Fatal("unknown profile accepted")
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("invalid profile created credential state")
	}
}
