package config

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

// Use real keygen with runtime-only keys in t.TempDir. Command output and
// configuration contents are never printed; the temporary tree is removed.
func bfpGraphNext26PrivateFixture(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate graph fixture source")
	}
	checkout := filepath.Dir(filepath.Dir(source))
	base := t.TempDir()
	binary := filepath.Join(base, "bfp-graph-keygen")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	offlineEnv := append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly")
	locate := exec.CommandContext(ctx, "go", "list", "-mod=readonly", "-m", "-f", "{{.Dir}}", "bfp")
	locate.Dir = checkout
	locate.Env = offlineEnv
	location, err := locate.Output()
	if err != nil {
		t.Fatal("locate pinned actual BFP module")
	}
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-o", binary, "./cmd/bfp")
	build.Dir = strings.TrimSpace(string(location))
	build.Env = offlineEnv
	if err := build.Run(); err != nil {
		t.Fatal("build real keygen from pinned BFP module")
	}
	privateDir := filepath.Join(base, "private")
	if err := exec.CommandContext(ctx, binary, "keygen", "-out", privateDir).Run(); err != nil {
		t.Fatal("generate protected synthetic credentials")
	}
	return filepath.Join(privateDir, "client.json")
}

func TestBFPNext26ActualProxyParserAndDialerGraph(t *testing.T) {
	path := bfpGraphNext26PrivateFixture(t)
	bfp := func(name, detour string) map[string]any {
		mapping := map[string]any{
			"name": name, "type": "bfp", "client-config-file": path, "udp": true,
			"interface-name": "fixture-interface", "routing-mark": 123, "tfo": true, "mptcp": true,
		}
		if detour != "" {
			mapping["dialer-proxy"] = detour
		}
		return mapping
	}
	socks := func(name, detour string) map[string]any {
		mapping := map[string]any{"name": name, "type": "socks5", "server": "127.0.0.1", "port": 1080}
		if detour != "" {
			mapping["dialer-proxy"] = detour
		}
		return mapping
	}
	cases := []struct {
		name        string
		mappings    []map[string]any
		errContains string
	}{
		{"missing_reference", []map[string]any{bfp("a", "absent")}, "dialer-proxy [absent] not found"},
		{"self_reference", []map[string]any{bfp("a", "a")}, "circular dialer-proxy dependency"},
		{"two_bfp_cycle", []map[string]any{bfp("a", "b"), bfp("b", "a")}, "circular dialer-proxy dependency"},
		{"three_bfp_cycle", []map[string]any{bfp("a", "b"), bfp("b", "c"), bfp("c", "a")}, "circular dialer-proxy dependency"},
		{"mixed_bfp_socks_cycle", []map[string]any{bfp("a", "b"), socks("b", "a")}, "circular dialer-proxy dependency"},
		{"ordinary_bfp_no_detour", []map[string]any{bfp("a", "")}, ""},
		{"builtin_direct_detour", []map[string]any{bfp("a", "DIRECT")}, ""},
		{"named_socks_detour", []map[string]any{bfp("a", "b"), socks("b", "")}, ""},
		{"acyclic_bfp_chain", []map[string]any{bfp("a", "b"), bfp("b", "DIRECT")}, ""},
		{"acyclic_mixed_chain", []map[string]any{bfp("a", "b"), socks("b", "DIRECT")}, ""},
		{"ordinary_socks_no_detour", []map[string]any{socks("b", "")}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// This path uses actual parsed adapters and wrappers, never a
			// mock that substitutes the ProxyInfo used by graph validation.
			proxies := map[string]C.Proxy{"DIRECT": adapter.NewProxy(outbound.NewDirect())}
			for _, mapping := range tc.mappings {
				proxy, err := adapter.ParseProxy(mapping, adapter.WithProviderName("graph-fixture"))
				if err != nil {
					t.Fatal("parse actual adapter before graph validation")
				}
				proxies[proxy.Name()] = proxy
				t.Cleanup(func() {
					if err := proxy.Close(); err != nil {
						t.Error("close parsed graph adapter")
					}
				})
				if mapping["type"] == "bfp" {
					// ParseProxy adds the real native AutoClose wrapper around BFP.
					if proxy.Type() != C.BFP {
						t.Fatal("parser did not produce the actual BFP adapter")
					}
					info := proxy.ProxyInfo()
					if info.Interface != "fixture-interface" || info.RoutingMark != 123 || !info.TFO || !info.MPTCP || info.ProviderName != "graph-fixture" {
						t.Fatal("BFP override dropped native base proxy information")
					}
				}
				wantDetour, _ := mapping["dialer-proxy"].(string)
				if proxy.ProxyInfo().DialerProxy != wantDetour {
					t.Fatal("real adapter omitted its configured dependency")
				}
				body, err := proxy.MarshalJSON()
				if err != nil {
					t.Fatal("marshal actual proxy wrapper")
				}
				var info map[string]any
				if json.Unmarshal(body, &info) != nil || info["dialer-proxy"] != wantDetour {
					t.Fatal("wrapper did not publish the configured dependency")
				}
				if mapping["type"] == "bfp" && (info["interface"] != "fixture-interface" || info["routing-mark"] != float64(123) || info["tfo"] != true || info["mptcp"] != true || info["provider-name"] != "graph-fixture") {
					t.Fatal("wrapper JSON dropped native base proxy information")
				}
			}
			checkError := func(err error) {
				t.Helper()
				if tc.errContains == "" {
					if err != nil {
						t.Fatalf("valid dependency graph rejected: %v", err)
					}
				} else if err == nil || !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected graph rejection containing %q, got %v", tc.errContains, err)
				}
			}
			checkError(validateDialerProxies(proxies))
			// Also traverse the production config parser's own graph boundary.
			parsed, providers, err := parseProxies(&RawConfig{Proxy: tc.mappings})
			checkError(err)
			if err == nil {
				t.Cleanup(func() {
					for _, provider := range providers {
						if closer, ok := provider.(interface{ Close() error }); ok {
							if err := closer.Close(); err != nil {
								t.Error("close config parser provider")
							}
						}
					}
					for _, proxy := range parsed {
						if err := proxy.Close(); err != nil {
							t.Error("close config parser proxy")
						}
					}
				})
				for _, mapping := range tc.mappings {
					name := mapping["name"].(string)
					wantDetour, _ := mapping["dialer-proxy"].(string)
					if parsed[name].ProxyInfo().DialerProxy != wantDetour {
						t.Fatal("config parser omitted the configured dependency")
					}
				}
				if parsed["DIRECT"].Type() != C.Direct || parsed["DIRECT"].ProxyInfo().DialerProxy != "" {
					t.Fatal("ordinary DIRECT path changed")
				}
			}
		})
	}
}
