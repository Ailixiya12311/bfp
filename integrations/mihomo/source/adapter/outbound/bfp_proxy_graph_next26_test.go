package outbound

import (
	"testing"

	"bfp/clientconfig"
)

func TestBFPNext26ProxyInfoPreservesConfiguredDetour(t *testing.T) {
	path, _ := bfpPrivateFixture(t)
	loaded, err := clientconfig.Load(path)
	if err != nil {
		t.Fatal("load protected synthetic client configuration")
	}
	for _, name := range []string{"", "DIRECT", "carrier-detour"} {
		label := name
		if label == "" {
			label = "ordinary_no_detour"
		}
		t.Run(label, func(t *testing.T) {
			physical := new(bfpNativePhysical)
			option := BFPOption{
				Name: "graph-test", ClientConfigFile: path, UDP: true,
				BasicOption: BasicOption{
					DialerProxy: name, DialerForAPI: physical,
					ProviderName: "fixture-provider", Interface: "fixture-interface",
					RoutingMark: 123, TFO: true, MPTCP: true,
				},
			}
			h, err := NewBFP(option)
			if err != nil {
				t.Fatal("construct actual BFP adapter")
			}
			t.Cleanup(func() {
				if err := h.Close(); err != nil {
					t.Error("close actual BFP adapter")
				}
			})
			// Match the native adapter convention: report the configured edge
			// even when an API-injected dialer takes precedence for actual I/O.
			want := h.Base.ProxyInfo()
			want.DialerProxy = name
			if got := h.ProxyInfo(); got != want {
				t.Fatalf("proxy information mismatch: got %+v, want %+v", got, want)
			}
			option.DialerProxy = "changed-after-construction"
			if h.ProxyInfo().DialerProxy != name {
				t.Fatal("adapter did not retain its own configured detour")
			}
			if h.Addr() != loaded.Session.Server || h.client.Session() != nil || physical.tcp.Load() != 0 || physical.udp.Load() != 0 {
				t.Fatal("proxy information altered endpoint or caused carrier I/O")
			}
		})
	}
}
