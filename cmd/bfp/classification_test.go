package main

import (
	"bfp/adapter/socks"
	"bfp/classification"
	"bfp/protocol"
	"bfp/session"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestClassificationCLIConfigPresenceDefaultsAndBothRoles(t *testing.T) {
	for _, tc := range []struct {
		body string
		want *classification.Config
	}{
		{`{}`, nil},
		{`{"classification":{}}`, classDefaultPointer()},
		{`{"classification":{"rules":[],"behavior":{}}}`, classDefaultPointer()},
		{`{"classification":{"default_class":"bulk","highest_allowed":"normal","behavior":{"enabled":false,"restore":false,"cooldown":"0s"}}}`, func() *classification.Config {
			c := classification.DefaultConfig()
			c.DefaultClass, c.HighestAllowed = protocol.Bulk, protocol.Normal
			c.Behavior.Enabled, c.Behavior.Restore, c.Behavior.Cooldown = false, false, 0
			return &c
		}()},
	} {
		path := writePrivateOptionsConfig(t, tc.body)
		var client clientConfig
		var server serverConfig
		if e := readConfig(path, &client); e != nil {
			t.Fatal(e)
		}
		if e := readConfig(path, &server); e != nil {
			t.Fatal(e)
		}
		cc, e := client.sessionConfig()
		if e != nil {
			t.Fatal(e)
		}
		sc, e := server.sessionConfig(&net.Dialer{})
		if e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(cc.Classification, tc.want) || !reflect.DeepEqual(sc.Classification, tc.want) {
			t.Fatalf("CLI default/presence: client=%+v server=%+v want=%+v", cc.Classification, sc.Classification, tc.want)
		}
	}
}

func classDefaultPointer() *classification.Config { c := classification.DefaultConfig(); return &c }

func TestClassificationCLIRejectsMalformedWithoutEchoing(t *testing.T) {
	for _, body := range []string{
		`{"classification":null}`,
		`{"classification":[]}`,
		`{"classification":{"default_class":0}}`,
		`{"classification":{"default_class":"private-invalid-value"}}`,
		`{"classification":{"highest_allowed":null}}`,
		`{"classification":{"rules":null}}`,
		`{"classification":{"private-invalid-value":true}}`,
		`{"classification":{"behavior":null}}`,
		`{"classification":{"behavior":{"enabled":null}}}`,
		`{"classification":{"behavior":{"enabled":"private-invalid-value"}}}`,
		`{"classification":{"behavior":{"bucket":0}}}`,
		`{"classification":{"behavior":{"window":"private-invalid-value"}}}`,
		`{"classification":{"behavior":{"bulk_sustain":"0s"}}}`,
		`{"classification":{"behavior":{"cooldown":"-1ns"}}}`,
		`{"classification":{"behavior":{"window":"999999999999999h"}}}`,
		`{"classification":{"behavior":{"min_total_bytes":1.0}}}`,
		`{"classification":{"behavior":{"min_total_bytes":1e2}}}`,
		`{"classification":{"behavior":{"min_total_bytes":"12"}}}`,
		`{"classification":{"behavior":{"min_total_bytes":0}}}`,
		`{"classification":{"behavior":{"min_total_bytes":18446744073709551616}}}`,
		`{"classification":{"behavior":{"enabled":false,"restore":false,"window":"1s","bucket":"700ms"}}}`,
		`{"classification":{"behavior":{"enabled":false,"restore":false,"restore_bytes_per_second":262144}}}`,
		`{"classification":{"behavior":{"bulk_bytes_per_second":18446744073709551615}}}`,
		`{"classification":{"rules":[null]}}`,
		`{"classification":{"rules":[{"class":"normal","network":"tcp"}]}}`,
		`{"classification":{"rules":[{"name":"rule","network":"tcp"}]}}`,
		`{"classification":{"rules":[{"name":"rule","class":"normal"}]}}`,
		`{"classification":{"rules":[{"name":"rule","class":"normal","priority":2147483648,"network":"tcp"}]}}`,
		`{"classification":{"rules":[{"name":"rule","class":"normal","network":""}]}}`,
		`{"classification":{"rules":[{"name":"rule","class":"normal","domain":"bad..test"}]}}`,
		`{"classification":{"rules":[{"name":"rule","class":"normal","domain":"127.0.0.1"}]}}`,
		`{"classification":{"rules":[{"name":"rule","class":"normal","domain":"example.test","domain_suffix":"example.test"}]}}`,
		`{"classification":{"rules":[{"name":"rule","class":"normal","rule_tag":"bad\n"}]}}`,
		`{"classification":{"rules":[{"name":"rule","class":"normal","ports":[]}]}}`,
		`{"classification":{"rules":[{"name":"rule","class":"normal","ports":[{"first":2,"last":1}]}]}}`,
		`{"classification":{"rules":[{"name":"rule","class":"normal","ports":[{"first":1}]}]}}`,
		`{"classification":{"rules":[{"name":"rule","class":"normal","ports":[{"first":0,"last":65536}]}]}}`,
		`{"classification":{"rules":[{"name":"rule","class":"normal","network":"tcp"},{"name":"rule","class":"bulk","network":"udp"}]}}`,
		`{"classification":{"rules":[{"name":"\ud800","class":"normal","network":"tcp"}]}}`,
		`{"classification":{"rules":[{"name":"\udc00","class":"normal","network":"tcp"}]}}`,
		`{"classification":{},"classification":{"default_class":"bulk"}}`,
		`{"classification":{},"Classification":{}}`,
		`{"classification":{},"claſſification":{}}`,
		`{"classification":{"default_class":"normal","default_class":"bulk"}}`,
		`{"classification":{"behavior":{"enabled":true,"enabled":false}}}`,
		`{"classification":{"rules":[{"name":"rule","class":"normal","network":"tcp","ports":[{"first":1,"first":2,"last":2}]}]}}`,
	} {
		path := writePrivateOptionsConfig(t, body)
		for _, cfg := range []any{&clientConfig{}, &serverConfig{}} {
			e := readConfig(path, cfg)
			if e == nil || !strings.Contains(e.Error(), "classification") || strings.Contains(e.Error(), "private-invalid-value") {
				t.Fatalf("malformed classification accepted or echoed: error=%v case=%s", e, body)
			}
		}
	}
	invalidUTF8 := "{\"classification\":{\"rules\":[{\"name\":\"" + string([]byte{0xff}) + "\",\"class\":\"bulk\",\"network\":\"tcp\"}]}}"
	if e := readConfig(writePrivateOptionsConfig(t, invalidUTF8), &clientConfig{}); e == nil || !strings.Contains(e.Error(), "UTF-8") {
		t.Fatal("invalid byte sequence replaced silently")
	}
}

func TestClassificationCLIFieldBoundsAndStablePrecedence(t *testing.T) {
	body := `{"classification":{"default_class":"normal","rules":[{"name":"target-max-priority","priority":2147483647,"class":"bulk","network":"tcp"},{"name":"metadata-low-priority","priority":-2147483648,"class":"interactive","domain_suffix":"EXAMPLE.TEST."},{"name":"same-priority-later","priority":2147483647,"class":"normal","network":"tcp"}],"behavior":{"min_total_bytes":18446744073709551615}}}`
	var cfg clientConfig
	if e := readConfig(writePrivateOptionsConfig(t, body), &cfg); e != nil {
		t.Fatal(e)
	}
	cc, e := cfg.sessionConfig()
	if e != nil {
		t.Fatal(e)
	}
	if cc.Classification.Behavior.MinTotalBytes != math.MaxUint64 {
		t.Fatal("uint64 went through float64")
	}
	c, e := classification.New(*cc.Classification)
	if e != nil {
		t.Fatal(e)
	}
	meta := classification.Metadata{Target: protocol.Target{Network: "tcp", Address: "127.0.0.1:443", Domain: "chat.example.test"}}
	d, e := c.Decide(meta)
	if e != nil || d.Rule != "target-max-priority" || d.Class != protocol.Bulk {
		t.Fatalf("untrusted domain/same-priority: %+v %v", d, e)
	}
	meta.DomainTrusted = true
	d, e = c.Decide(meta)
	if e != nil || d.Rule != "metadata-low-priority" || d.Class != protocol.Interactive {
		t.Fatalf("groups globally sorted: %+v %v", d, e)
	}
	for _, count := range []int{128, 129} {
		rules := make([]string, count)
		for i := range rules {
			rules[i] = fmt.Sprintf(`{"name":"r%d","class":"normal","network":"tcp"}`, i)
		}
		_, e := configClassification(json.RawMessage(`{"rules":[` + strings.Join(rules, ",") + `]}`))
		if (e == nil) != (count == 128) {
			t.Fatalf("rule count=%d: %v", count, e)
		}
	}
	for _, count := range []int{64, 65} {
		ranges := make([]string, count)
		for i := range ranges {
			ranges[i] = `{"first":1,"last":65535}`
		}
		_, e := configClassification(json.RawMessage(`{"rules":[{"name":"ports","class":"bulk","ports":[` + strings.Join(ranges, ",") + `]}]}`))
		if (e == nil) != (count == 64) {
			t.Fatalf("range count=%d: %v", count, e)
		}
	}
	for _, name := range []string{strings.Repeat("x", 128), strings.Repeat("x", 129), strings.Repeat("界", 43)} {
		raw, _ := json.Marshal(map[string]any{"rules": []any{map[string]any{"name": name, "class": "normal", "network": "tcp"}}})
		_, e := configClassification(raw)
		if (e == nil) != (len(name) <= 128) {
			t.Fatal("name cap used runes instead of UTF-8 bytes")
		}
	}
}

func TestClassificationCLISOCKSMetadataStrictAndClientOnly(t *testing.T) {
	for _, body := range []string{`{}`, `{"socks_metadata":{}}`, `{"socks_metadata":{"domain_source":"ignore"}}`, `{"socks_metadata":{"domain_source":"socks_address"}}`} {
		var c clientConfig
		if e := readConfig(writePrivateOptionsConfig(t, body), &c); e != nil {
			t.Fatal(e)
		}
		value, e := configSOCKSDomainSource(c.SOCKSMetadata)
		want := "ignore"
		if strings.Contains(body, "socks_address") {
			want = "socks_address"
		}
		if e != nil || value != want {
			t.Fatalf("SOCKS source: %s %v", value, e)
		}
	}
	for _, body := range []string{
		`{"socks_metadata":null}`,
		`{"socks_metadata":{"domain_source":null}}`,
		`{"socks_metadata":{"domain_source":"private-invalid-value"}}`,
		`{"socks_metadata":{"domain_source":true}}`,
		`{"socks_metadata":{"domain_source":"ignore","domain_source":"socks_address"}}`,
		`{"socks_metadata":{},"socks_metadata":{}}`,
		`{"SOCKS_METADATA":{}}`,
		`{"socKs_metadata":{}}`,
		`{"socks_metadata":{"domain_source":"ignore","hint":"private-invalid-value"}}`,
	} {
		if e := readConfig(writePrivateOptionsConfig(t, body), &clientConfig{}); e == nil || strings.Contains(e.Error(), "private-invalid-value") {
			t.Fatalf("invalid SOCKS source: %v", e)
		}
	}
	if e := readConfig(writePrivateOptionsConfig(t, `{"socks_metadata":{}}`), &serverConfig{}); e == nil {
		t.Fatal("server accepted local client source")
	}
}

func TestClassificationCLIInvalidConfigurationStopsCommandPipeline(t *testing.T) {
	// run must reject new configuration before credentials/Connect/Listen; no
	// remote endpoints or side effects are needed to detect this ordering.
	path := writePrivateOptionsConfig(t, `{"classification":{"behavior":{"enabled":null}}}`)
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	for _, mode := range []string{"client", "server", "probe"} {
		os.Args = []string{"bfp", mode, "-config", path}
		if e := run(); e == nil || !strings.Contains(e.Error(), "classification.behavior.enabled") {
			t.Fatalf("%s did not stop at config validation: %v", mode, e)
		}
	}
}

func TestClassificationCLIRejectsNullEachProvidedLeaf(t *testing.T) {
	for _, name := range []string{"enabled", "window", "bucket", "min_total_bytes", "bulk_bytes_per_second", "bulk_sustain", "activity_gap", "restore", "restore_bytes_per_second", "restore_sustain", "cooldown"} {
		if _, e := configClassification(json.RawMessage(fmt.Sprintf("{\"behavior\":{\"%s\":null}}", name))); e == nil {
			t.Fatalf("behavior null accepted: %s", name)
		}
	}
	for _, name := range []string{"name", "class", "priority", "locked", "network", "ports", "domain", "domain_suffix", "rule_tag"} {
		body := map[string]any{"name": "r", "class": "normal", "network": "tcp"}
		body[name] = nil
		raw, _ := json.Marshal(map[string]any{"rules": []any{body}})
		if _, e := configClassification(raw); e == nil {
			t.Fatalf("rule null accepted: %s", name)
		}
	}
	// Valid paired Unicode escapes are not confused with the malformed
	// UTF-16 escape cases; configured labels remain UTF-8 byte bounded.
	if _, e := configClassification(json.RawMessage("{\"rules\":[{\"name\":\"\\ud83d\\ude80\",\"class\":\"bulk\",\"network\":\"tcp\"}]}")); e != nil {
		t.Fatal(e)
	}
}

func TestClassificationCLISOCKSMappingChecksCapabilityBeforeListen(t *testing.T) {
	c := clientConfig{SOCKS: "127.0.0.1:0", SOCKSMetadata: json.RawMessage("{\"domain_source\":\"socks_address\"}")}
	sc, e := c.socksConfig(&net.Dialer{})
	if e != nil {
		t.Fatal(e)
	}
	if sc.DomainSource != socks.DomainSourceSOCKSAddress {
		t.Fatal("CLI dropped opt-in")
	}
	busy, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer busy.Close()
	sc.Listen = busy.Addr().String()
	if srv, e := socks.New(sc); srv != nil || e != socks.ErrMetadataBackend {
		if srv != nil {
			srv.Close()
		}
		t.Fatalf("capability checked after occupied Listen: %v", e)
	}
	c.SOCKSMetadata = nil
	sc, e = c.socksConfig(&net.Dialer{})
	if e != nil || sc.DomainSource != socks.DomainSourceIgnore {
		t.Fatal("old CLI source default changed")
	}
	srv, e := socks.New(sc)
	if e != nil {
		t.Fatal(e)
	}
	srv.Close()
}

func TestClassificationCLIRealConstructorsUseIndependentPoliciesWithoutNormalHint(t *testing.T) {
	keydir := filepath.Join(t.TempDir(), "keys")
	if e := keygen(keydir); e != nil {
		t.Fatal(e)
	}
	var client clientConfig
	var server serverConfig
	if e := readConfig(filepath.Join(keydir, "client.json"), &client); e != nil {
		t.Fatal(e)
	}
	if e := readConfig(filepath.Join(keydir, "server.json"), &server); e != nil {
		t.Fatal(e)
	}
	server.Listen = "127.0.0.1:0"
	client.Classification = json.RawMessage(`{"rules":[{"name":"domain-only","domain":"localhost","class":"interactive"},{"name":"plain-tcp","network":"tcp","class":"bulk"}],"behavior":{"enabled":false}}`)
	server.Classification = json.RawMessage(`{"default_class":"interactive","highest_allowed":"normal","behavior":{"enabled":false}}`)
	sc, e := server.sessionConfig(&net.Dialer{})
	if e != nil {
		t.Fatal(e)
	}
	if sc.Classification.DefaultClass != protocol.Interactive || sc.Classification.HighestAllowed != protocol.Normal {
		t.Fatal("server reused client policy")
	}
	srv, e := session.NewServer(sc)
	if e != nil {
		t.Fatal(e)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(context.Background()) }()
	t.Cleanup(func() { srv.Close(); <-serveDone })
	target, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { target.Close() })
	targetDone := make(chan error, 1)
	go func() {
		for n := 0; n < 2; n++ {
			c, e := target.Accept()
			if e != nil {
				targetDone <- e
				return
			}
			c.SetDeadline(time.Now().Add(3 * time.Second))
			_, e = io.Copy(c, c)
			c.Close()
			if e != nil {
				targetDone <- e
				return
			}
		}
		targetDone <- nil
	}()
	client.Server = srv.Addr().String()
	cc, e := client.sessionConfig()
	if e != nil {
		t.Fatal(e)
	}
	cl, e := session.NewClient(cc)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { cl.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, port, _ := net.SplitHostPort(target.Addr().String())
	conn, e := cl.DialContext(ctx, "tcp", net.JoinHostPort("localhost", port))
	if e != nil {
		t.Fatal(e)
	}
	flow := conn.(*session.Flow)
	flow.SetDeadline(time.Now().Add(2 * time.Second))
	if _, e := flow.Write([]byte("plain-client-policy")); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len("plain-client-policy"))
	if _, e := io.ReadFull(flow, got); e != nil || string(got) != "plain-client-policy" {
		t.Fatalf("real CLI-configured flow: %v", e)
	}
	snap, e := flow.Classification(ctx)
	if e != nil || snap.LocalTX.Class != protocol.Bulk || snap.LocalTX.Baseline.Rule != "plain-tcp" || snap.LocalTX.Baseline.Source != classification.SourceTarget {
		t.Fatalf("implicit NormalHint/domain trust defeated plain rules: %+v %v", snap, e)
	}
	flow.Close()
	// The actual CLI source DTO must also reach socks.New and the real
	// metadata path; a domain-looking DialContext alone did not qualify.
	client.SOCKS = "127.0.0.1:0"
	client.SOCKSMetadata = json.RawMessage("{\"domain_source\":\"socks_address\"}")
	tap := &cliClassBackend{client: cl, flows: make(chan *session.Flow, 2)}
	socksCfg, e := client.socksConfig(tap)
	if e != nil {
		t.Fatal(e)
	}
	socksServer, e := socks.New(socksCfg)
	if e != nil {
		t.Fatal(e)
	}
	socksDone := make(chan error, 1)
	go func() { socksDone <- socksServer.Serve(context.Background()) }()
	t.Cleanup(func() { socksServer.Close(); <-socksDone })
	local, e := net.DialTimeout("tcp", socksServer.Addr().String(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { local.Close() })
	local.SetDeadline(time.Now().Add(2 * time.Second))
	local.Write([]byte{5, 1, 0})
	var greeting [2]byte
	if _, e := io.ReadFull(local, greeting[:]); e != nil || greeting != [2]byte{5, 0} {
		t.Fatalf("SOCKS greeting: %v", e)
	}
	destPort, _ := strconv.Atoi(port)
	request := append([]byte{5, 1, 0, 3, 9}, []byte("localhost")...)
	request = binary.BigEndian.AppendUint16(request, uint16(destPort))
	if _, e := local.Write(request); e != nil {
		t.Fatal(e)
	}
	var reply [4]byte
	if _, e := io.ReadFull(local, reply[:]); e != nil || reply[1] != 0 {
		t.Fatalf("SOCKS CONNECT reply: %v %v", reply, e)
	}
	size := 0
	switch reply[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var length [1]byte
		if _, e := io.ReadFull(local, length[:]); e != nil {
			t.Fatal(e)
		}
		size = int(length[0])
	default:
		t.Fatal("invalid SOCKS reply ATYP")
	}
	if _, e := io.ReadFull(local, make([]byte, size+2)); e != nil {
		t.Fatal(e)
	}
	local.Write([]byte("cli-source"))
	echo := make([]byte, 10)
	if _, e := io.ReadFull(local, echo); e != nil || string(echo) != "cli-source" {
		t.Fatalf("CLI→SOCKS→Session pipeline: %v", e)
	}
	var metadataFlow *session.Flow
	select {
	case metadataFlow = <-tap.flows:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	metaSnap, e := metadataFlow.Classification(ctx)
	if e != nil || metaSnap.LocalTX.Class != protocol.Interactive || metaSnap.LocalTX.Baseline.Source != classification.SourceMetadata || metaSnap.LocalTX.Baseline.Rule != "domain-only" {
		t.Fatalf("CLI source did not reach local metadata rules: %+v %v", metaSnap, e)
	}
	local.Close()
	select {
	case <-targetDone:
	case <-ctx.Done():
		t.Fatal("target worker did not retire")
	}
}

type cliClassBackend struct {
	client *session.Client
	flows  chan *session.Flow
}

func (b *cliClassBackend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, e := b.client.DialContext(ctx, network, address)
	if e == nil {
		b.flows <- c.(*session.Flow)
	}
	return c, e
}
func (b *cliClassBackend) DialMetadata(ctx context.Context, meta classification.Metadata) (net.Conn, error) {
	c, e := b.client.DialMetadata(ctx, meta)
	if e == nil {
		b.flows <- c.(*session.Flow)
	}
	return c, e
}

func FuzzClassificationCLIParser(f *testing.F) {
	for _, raw := range []string{
		"{}", "null", "{\"behavior\":{\"enabled\":false}}",
		"{\"rules\":[{\"name\":\"\\ud800\",\"class\":\"bulk\",\"network\":\"tcp\"}]}",
		"{\"default_class\":\"normal\",\"default_class\":\"bulk\"}",
		"{\"rules\":[{\"name\":\"\\ud83d\\ude80\",\"class\":\"bulk\",\"network\":\"tcp\"}]}",
	} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			return
		}
		cfg, e := configClassification(raw)
		if e == nil && cfg != nil {
			// Every accepted DTO must compile as an immutable policy; the
			// input parser is not allowed to manufacture invalid core state.
			if _, e := classification.New(*cfg); e != nil {
				t.Fatal("accepted configuration failed core validation")
			}
		}
	})
}
