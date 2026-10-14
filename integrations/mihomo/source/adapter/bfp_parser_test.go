package adapter_test

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter"
)

func TestBFPParserRejectsInvalidNativeFieldsBeforeFileRead(t *testing.T) {
	for _, field := range []struct {
		name, key string
		value     any
	}{
		{"unknown", "credentials", "no-inline-private-data"},
		{"case", "UDP", true},
		{"null", "udp", nil},
		{"string_boolean", "udp", "true"},
		{"string_limit", "max-packet-conns", "16"},
		{"fraction_limit", "max-packet-conns", 1.5},
		{"negative_limit", "max-packet-conns", -1},
		{"numeric_file", "client-config-file", 42},
		{"unsupported_policy", "classification", map[string]any{}},
	} {
		t.Run(field.name, func(t *testing.T) {
			mapping := map[string]any{"type": "bfp", "name": "parser-test", "client-config-file": "must-not-be-read.json"}
			mapping[field.key] = field.value
			proxy, err := adapter.ParseProxy(mapping)
			if proxy != nil || err == nil || !strings.Contains(err.Error(), "invalid or unsupported outbound option") || strings.Contains(err.Error(), "must-not-be-read") {
				t.Fatalf("invalid option reached file loading or was ignored: proxy=%T err=%v", proxy, err)
			}
		})
	}
}
