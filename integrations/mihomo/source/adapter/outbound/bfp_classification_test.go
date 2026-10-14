package outbound

import (
	"strings"
	"testing"
	"time"

	"bfp/protocol"
)

func TestParseBFPClassificationRulesAndBehavior(t *testing.T) {
	cfg, err := parseBFPClassification(map[string]any{
		"default-class":   "normal",
		"highest-allowed": "interactive",
		"rules": []any{
			map[string]any{
				"name":     "interactive-dns",
				"network":  "udp",
				"ports":    []any{map[string]any{"first": float64(53), "last": float64(53)}},
				"class":    "interactive",
				"priority": float64(10),
			},
			map[string]any{
				"name":          "trusted-domain",
				"domain-suffix": "example.test",
				"class":         "bulk",
				"locked":        true,
			},
		},
		"behavior": map[string]any{
			"enabled":                  true,
			"window":                   "4s",
			"bucket":                   "250ms",
			"min-total-bytes":          float64(1048576),
			"bulk-bytes-per-second":    float64(262144),
			"bulk-sustain":             "3s",
			"activity-gap":             "1s",
			"restore":                  true,
			"restore-bytes-per-second": float64(65536),
			"restore-sustain":          "8s",
			"cooldown":                 "5s",
		},
	})
	if err != nil {
		t.Fatalf("parse classification: %v", err)
	}
	if cfg.DefaultClass != protocol.Normal || cfg.HighestAllowed != protocol.Interactive {
		t.Fatalf("unexpected classes: default=%v highest=%v", cfg.DefaultClass, cfg.HighestAllowed)
	}
	if len(cfg.Rules) != 2 {
		t.Fatalf("rule count = %d, want 2", len(cfg.Rules))
	}
	if cfg.Rules[0].Network != "udp" || len(cfg.Rules[0].Ports) != 1 || cfg.Rules[0].Ports[0].First != 53 || cfg.Rules[0].Priority != 10 {
		t.Fatalf("unexpected port rule: %+v", cfg.Rules[0])
	}
	if cfg.Rules[1].DomainSuffix != "example.test" || !cfg.Rules[1].Locked || cfg.Rules[1].Class != protocol.Bulk {
		t.Fatalf("unexpected domain rule: %+v", cfg.Rules[1])
	}
	if !cfg.Behavior.Enabled || cfg.Behavior.Window != 4*time.Second || cfg.Behavior.Bucket != 250*time.Millisecond || cfg.Behavior.MinTotalBytes != 1<<20 || cfg.Behavior.BulkBytesPerSecond != 262144 {
		t.Fatalf("unexpected behavior: %+v", cfg.Behavior)
	}
}

func TestParseBFPClassificationUsesValidatedDefaults(t *testing.T) {
	cfg, err := parseBFPClassification(map[string]any{})
	if err != nil {
		t.Fatalf("empty classification should use defaults: %v", err)
	}
	if cfg.DefaultClass != protocol.Normal || !cfg.Behavior.Enabled {
		t.Fatalf("defaults were not retained: %+v", cfg)
	}
}

func TestParseBFPClassificationRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]any
		want string
	}{
		{
			name: "unknown top-level field",
			raw:  map[string]any{"clasification": map[string]any{}},
			want: "unsupported classification field",
		},
		{
			name: "invalid class",
			raw:  map[string]any{"default-class": "latency"},
			want: "unknown class",
		},
		{
			name: "invalid port",
			raw: map[string]any{"rules": []any{map[string]any{
				"name": "bad-port", "network": "tcp", "ports": []any{map[string]any{"first": float64(0), "last": float64(80)}}, "class": "normal",
			}}},
			want: "port range",
		},
		{
			name: "invalid behavior window",
			raw: map[string]any{"behavior": map[string]any{
				"window": "1s", "bucket": "1s",
			}},
			want: "window/bucket",
		},
		{
			name: "unknown behavior field",
			raw:  map[string]any{"behavior": map[string]any{"windows": "4s"}},
			want: "unsupported classification.behavior field",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseBFPClassification(test.raw)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}
