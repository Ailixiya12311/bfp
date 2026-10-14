package main

import (
	"bfp/protocol"
	"bfp/security"
	"bfp/session"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDatagramFECCLIDefaultsAndNegotiationModes(t *testing.T) {
	for _, item := range []struct {
		name, body string
		want       *session.NegotiationConfig
	}{
		{"omitted", `{}`, nil},
		{"empty", `{"datagram_fec":{}}`, nil},
		{"off", `{"datagram_fec":{"mode":"off"}}`, nil},
		{"optional", `{"datagram_fec":{"mode":"optional"}}`, &session.NegotiationConfig{Profile: session.ProfileClassAnnouncementV1, OfferedCapabilities: 5, RequiredCapabilities: 1}},
		{"required", `{"datagram_fec":{"mode":"required"}}`, &session.NegotiationConfig{Profile: session.ProfileClassAnnouncementV1, OfferedCapabilities: 5, RequiredCapabilities: 5}},
	} {
		t.Run(item.name, func(t *testing.T) {
			path := writePrivateOptionsConfig(t, item.body)
			var client clientConfig
			var server serverConfig
			if err := readConfig(path, &client); err != nil {
				t.Fatal(err)
			}
			if err := readConfig(path, &server); err != nil {
				t.Fatal(err)
			}
			cc, err := client.sessionConfig()
			if err != nil {
				t.Fatal(err)
			}
			sc, err := server.sessionConfig(&net.Dialer{})
			if err != nil {
				t.Fatal(err)
			}
			if cc.DatagramFEC != nil || !reflect.DeepEqual(cc.Negotiation, item.want) || !reflect.DeepEqual(sc.Negotiation, item.want) {
				t.Fatalf("capability-only mode changed default repair or offer: client=%+v server=%+v policy=%+v", cc.Negotiation, sc.Negotiation, cc.DatagramFEC)
			}
			if cc.Classification != nil || sc.Classification != nil {
				t.Fatal("FEC mode enabled classification policy implicitly")
			}
			socksCfg, err := client.socksConfig(nil)
			if err != nil || socksCfg.DomainSource != "ignore" {
				t.Fatal("FEC mode changed default SOCKS metadata trust")
			}
		})
	}
}

func TestDatagramFECCLIProfilesAndClassSelections(t *testing.T) {
	for _, item := range []struct {
		name, settings string
		classes        []protocol.Class
		shards         uint8
		size           uint16
	}{
		{"default-profile", `{"mode":"optional","by_class":{"interactive":"xor1","normal":"off","bulk":"xor1"}}`, []protocol.Class{protocol.Interactive, protocol.Bulk}, 32, 900},
		{"empty-profile", `{"mode":"required","by_class":{"normal":"xor1"},"profile":{}}`, []protocol.Class{protocol.Normal}, 32, 900},
		{"minimum", `{"mode":"optional","by_class":{"normal":"xor1"},"profile":{"max_data_shards":1,"shard_size":1}}`, []protocol.Class{protocol.Normal}, 1, 1},
		{"custom", `{"mode":"required","by_class":{"bulk":"xor1"},"profile":{"max_data_shards":4,"shard_size":600}}`, []protocol.Class{protocol.Bulk}, 4, 600},
		{"one-field-default", `{"mode":"optional","by_class":{"normal":"xor1"},"profile":{"shard_size":800}}`, []protocol.Class{protocol.Normal}, 32, 800},
		{"empty-classes", `{"mode":"optional","by_class":{}}`, nil, 0, 0},
		{"all-disabled", `{"mode":"required","by_class":{"interactive":"off","normal":"off","bulk":"off"}}`, nil, 0, 0},
	} {
		t.Run(item.name, func(t *testing.T) {
			var cfg clientConfig
			if err := readConfig(writePrivateOptionsConfig(t, `{"datagram_fec":`+item.settings+`}`), &cfg); err != nil {
				t.Fatal(err)
			}
			cc, err := cfg.sessionConfig()
			if err != nil || cc.Negotiation == nil {
				t.Fatalf("client constructor bridge rejected valid config: %v", err)
			}
			if len(item.classes) == 0 {
				if cc.DatagramFEC != nil {
					t.Fatal("empty or all-disabled classes installed an automatic FEC policy")
				}
				return
			}
			want := make(map[protocol.Class]protocol.FECProfile)
			for _, class := range item.classes {
				want[class] = protocol.FECProfile{Version: 1, Algorithm: protocol.FECXOR1, MaxDataShards: item.shards, ParityShards: 1, ShardSize: item.size, MaxBlockSize: uint32(item.shards) * uint32(item.size)}
			}
			if cc.DatagramFEC == nil || !reflect.DeepEqual(cc.DatagramFEC.ByClass, want) {
				t.Fatalf("per-class profile or derived block bound lost: got=%+v want=%+v", cc.DatagramFEC, want)
			}
			for _, profile := range cc.DatagramFEC.ByClass {
				if err := profile.Validate(); err != nil {
					t.Fatal("CLI profile did not satisfy canonical wire bounds")
				}
			}
		})
	}
}

func TestDatagramFECCLIRejectsMalformedAndAmbiguousConfiguration(t *testing.T) {
	cases := []string{
		`{"datagram_fec":null}`,
		`{"datagram_fec":[]}`,
		`{"datagram_fec":"private-invalid-fec-marker"}`,
		`{"datagram_fec":{"private-invalid-fec-marker":true}}`,
		`{"datagram_fec":{"mode":null}}`,
		`{"datagram_fec":{"mode":true}}`,
		`{"datagram_fec":{"mode":5}}`,
		`{"datagram_fec":{"mode":"private-invalid-fec-marker"}}`,
		`{"datagram_fec":{"mode":"OPTIONAL"}}`,
		`{"datagram_fec":{"mode":"\ud800"}}`,
		`{"datagram_fec":{"mode":"\udc00"}}`,
		`{"datagram_fec":{"mode":"off","by_class":{}}}`,
		`{"datagram_fec":{"profile":{}}}`,
		`{"datagram_fec":{"by_class":{"normal":"xor1"}}}`,
		`{"datagram_fec":{"mode":"optional","by_class":null}}`,
		`{"datagram_fec":{"mode":"optional","by_class":[]}}`,
		`{"datagram_fec":{"mode":"optional","by_class":{"Normal":"xor1"}}}`,
		`{"datagram_fec":{"mode":"optional","by_class":{"private-invalid-fec-marker":"xor1"}}}`,
		`{"datagram_fec":{"mode":"optional","by_class":{"normal":null}}}`,
		`{"datagram_fec":{"mode":"optional","by_class":{"normal":1}}}`,
		`{"datagram_fec":{"mode":"optional","by_class":{"normal":true}}}`,
		`{"datagram_fec":{"mode":"optional","by_class":{"normal":"private-invalid-fec-marker"}}}`,
		`{"datagram_fec":{"mode":"optional","by_class":{"normal":"XOR1"}}}`,
		`{"datagram_fec":{"mode":"optional","by_class":{"normal":"\ud800"}}}`,
		`{"datagram_fec":{"mode":"optional","by_class":{"normal":"xor1","normal":"off"}}}`,
		`{"datagram_fec":{"mode":"optional","profile":{}}}`,
		`{"datagram_fec":{"mode":"optional","by_class":{"normal":"off"},"profile":{}}}`,
		`{"datagram_fec":{},"datagram_fec":{}}`,
		`{"datagram_fec":{},"DATAGRAM_FEC":{}}`,
		`{"Datagram_FEC":{}}`,
		`{"datagram_fec":{"mode":"off","mode":"optional"}}`,
		`{"datagram_fec":{"Mode":"optional"}}`,
		`{"datagram_fec":{"mode":"optional","by_class":{"normal":"xor1"},"profile":null}}`,
		`{"datagram_fec":{"mode":"optional","by_class":{"normal":"xor1"},"profile":[]}}`,
		`{"datagram_fec":{"mode":"optional","by_class":{"normal":"xor1"},"profile":{"private-invalid-fec-marker":1}}}`,
		`{"datagram_fec":{"mode":"optional","by_class":{"normal":"xor1"},"profile":{"shard_size":900,"shard_size":800}}}`,
	}
	for _, field := range []string{"max_data_shards", "shard_size"} {
		for _, value := range []string{"null", "0", "-1", "true", `"12"`, "1.0", "1e2", "18446744073709551616"} {
			cases = append(cases, `{"datagram_fec":{"mode":"optional","by_class":{"normal":"xor1"},"profile":{"`+field+`":`+value+`}}}`)
		}
	}
	cases = append(cases,
		`{"datagram_fec":{"mode":"optional","by_class":{"normal":"xor1"},"profile":{"max_data_shards":33}}}`,
		`{"datagram_fec":{"mode":"optional","by_class":{"normal":"xor1"},"profile":{"shard_size":901}}}`)
	for _, body := range cases {
		err := readConfig(writePrivateOptionsConfig(t, body), &clientConfig{})
		if err == nil || !strings.Contains(err.Error(), "datagram_fec") || strings.Contains(err.Error(), "private-invalid-fec-marker") {
			t.Fatalf("malformed FEC config accepted or user data echoed: %v", err)
		}
	}
	invalidUTF8 := `{"datagram_fec":{"mode":"` + string([]byte{0xff}) + `"}}`
	if err := readConfig(writePrivateOptionsConfig(t, invalidUTF8), &clientConfig{}); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatal("invalid configuration bytes replaced silently")
	}
}

func TestDatagramFECCLIServerRejectsLocalFlowPolicy(t *testing.T) {
	for _, body := range []string{
		`{"datagram_fec":{"mode":"optional","by_class":{}}}`,
		`{"datagram_fec":{"mode":"required","by_class":{"normal":"xor1"}}}`,
		`{"datagram_fec":{"mode":"optional","profile":{}}}`,
		`{"datagram_fec":{"mode":"off","profile":null}}`,
		`{"datagram_fec":{"mode":"optional","by_class":"private-invalid-fec-marker"}}`,
	} {
		err := readConfig(writePrivateOptionsConfig(t, body), &serverConfig{})
		if err == nil || !strings.Contains(err.Error(), "datagram_fec") || strings.Contains(err.Error(), "private-invalid-fec-marker") {
			t.Fatalf("server accepted local per-flow FEC or echoed input: %v", err)
		}
	}
}

func TestDatagramFECCLIInvalidSettingsStopCommandBeforeNetwork(t *testing.T) {
	original := os.Args
	t.Cleanup(func() { os.Args = original })
	for _, command := range []string{"server", "client", "probe"} {
		t.Run(command, func(t *testing.T) {
			path := writePrivateOptionsConfig(t, `{"datagram_fec":{"mode":"private-invalid-fec-marker"}}`)
			os.Args = []string{"bfp", command, "-config", path}
			err := run()
			if err == nil || !strings.Contains(err.Error(), "datagram_fec.mode") || strings.Contains(err.Error(), "private-invalid-fec-marker") {
				t.Fatalf("CLI entered credentials/network/target pipeline before validation: %v", err)
			}
		})
	}
	t.Run("class-probe", func(t *testing.T) {
		path := writePrivateOptionsConfig(t, `{"datagram_fec":{"mode":"private-invalid-fec-marker"}}`)
		resultPath := filepath.Join(t.TempDir(), "failure.json")
		os.Args = []string{"bfp", "class-probe", "-config", path, "-result", resultPath}
		err := run()
		// class-probe deliberately replaces field errors with a fixed public
		// failure and publishes its phase, preserving the existing log contract.
		if err == nil || err.Error() != "class probe configuration failed" {
			t.Fatalf("class-probe did not stop at configuration: %v", err)
		}
		body, err := os.ReadFile(resultPath)
		if err != nil {
			t.Fatal(err)
		}
		var result classProbeResult
		if err := json.Unmarshal(body, &result); err != nil || result.Pass || result.Failure != "configuration" || result.Timing.Phase != "configuration" || result.Initial.ID != "" || result.TCPCompleted != 0 || bytes.Contains(body, []byte("private-invalid-fec-marker")) {
			t.Fatal("class-probe entered networking or exposed malformed configuration")
		}
	})
}

func TestDatagramFECCLIConstructorBridgeOwnsParsedConfiguration(t *testing.T) {
	var client clientConfig
	if err := readConfig(writePrivateOptionsConfig(t, `{"datagram_fec":{"mode":"optional","by_class":{"normal":"xor1"},"profile":{"max_data_shards":4,"shard_size":600}}}`), &client); err != nil {
		t.Fatal(err)
	}
	first, err := client.sessionConfig()
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.sessionConfig()
	if err != nil {
		t.Fatal(err)
	}
	first.DatagramFEC.ByClass[protocol.Normal] = protocol.DisabledFECProfile()
	first.Negotiation.OfferedCapabilities = session.CapabilityClassAnnouncementV1
	if second.DatagramFEC.ByClass[protocol.Normal].Algorithm != protocol.FECXOR1 || second.Negotiation.OfferedCapabilities != 5 {
		t.Fatal("constructor bridge shared caller-mutable maps or negotiation pointers")
	}
	client.DatagramFEC[0] = '['
	if _, err := client.sessionConfig(); err == nil || second.DatagramFEC.ByClass[protocol.Normal].ShardSize != 600 {
		t.Fatal("parser retained mutable source JSON or accepted later malformed input")
	}
	var server serverConfig
	if err := readConfig(writePrivateOptionsConfig(t, `{"datagram_fec":{"mode":"required"}}`), &server); err != nil {
		t.Fatal(err)
	}
	sc1, err := server.sessionConfig(&net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	sc2, err := server.sessionConfig(&net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	sc1.Negotiation.RequiredCapabilities = 1
	if sc2.Negotiation.RequiredCapabilities != 5 {
		t.Fatal("server constructor bridge shared negotiation ownership")
	}
}

func TestDatagramFECCLIRequiredPeerRejectedByRealHandshake(t *testing.T) {
	for _, item := range []struct {
		name, clientMode, serverMode string
	}{
		{"client-required-server-default", "required", ""},
		{"server-required-client-default", "", "required"},
	} {
		t.Run(item.name, func(t *testing.T) {
			serverKey, err := security.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			clientKey, err := security.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			admission := bytes.Repeat([]byte{0x5f}, 32)
			serverJSON := serverConfig{Listen: "127.0.0.1:0", Credentials: session.Credentials{Admission: admission, Private: serverKey.Private, Public: serverKey.Public, AllowedClients: [][]byte{clientKey.Public}}}
			if item.serverMode != "" {
				serverJSON.DatagramFEC = json.RawMessage(`{"mode":"` + item.serverMode + `"}`)
			}
			body, err := json.Marshal(serverJSON)
			if err != nil {
				t.Fatal(err)
			}
			var serverCLI serverConfig
			if err := readConfig(writePrivateOptionsConfig(t, string(body)), &serverCLI); err != nil {
				t.Fatal(err)
			}
			sc, err := serverCLI.sessionConfig(&net.Dialer{})
			if err != nil {
				t.Fatal(err)
			}
			sc.Options.HandshakeTimeout = 80 * time.Millisecond
			server, err := session.NewServer(sc)
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
			clientJSON := clientConfig{Server: server.Addr().String(), TCPServer: server.Addr().String(), Credentials: session.Credentials{Admission: admission, Private: clientKey.Private, Public: clientKey.Public, ServerPublic: serverKey.Public}}
			if item.clientMode != "" {
				clientJSON.DatagramFEC = json.RawMessage(`{"mode":"` + item.clientMode + `"}`)
			}
			body, err = json.Marshal(clientJSON)
			if err != nil {
				t.Fatal(err)
			}
			var clientCLI clientConfig
			if err := readConfig(writePrivateOptionsConfig(t, string(body)), &clientCLI); err != nil {
				t.Fatal(err)
			}
			cc, err := clientCLI.sessionConfig()
			if err != nil {
				t.Fatal(err)
			}
			cc.Options.HandshakeTimeout = 80 * time.Millisecond
			client, err := session.NewClient(cc)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Abort()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if current, err := client.Connect(ctx); err == nil || current != nil || client.Session() != nil {
				t.Fatal("required CLI capability silently downgraded to a default peer")
			}
			for _, snapshot := range server.Snapshot() {
				if snapshot.Opened != 0 {
					t.Fatal("required negotiation rejection opened a business target")
				}
			}
		})
	}
}
