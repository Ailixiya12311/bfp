// Package configjson shares strict runtime-policy decoding between the CLI and
// native application adapters. It never reads credentials or starts networking.
package configjson

import (
	"bfp/classification"
	"bfp/protocol"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

func FieldError(path, reason string) error { return fmt.Errorf("%s: %s", path, reason) }

// New subtrees have independent strict decoding: RawMessage does not inherit
// the outer Decoder's unknown-field rules. No user-supplied key/value is echoed.
func Object(raw json.RawMessage, path string, allowed ...string) (map[string]json.RawMessage, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return nil, FieldError(path, "must be an object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := CheckValue(dec, 0); err != nil {
		return nil, FieldError(path, "invalid JSON or duplicate field")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, FieldError(path, "invalid JSON")
	}
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil {
		return nil, FieldError(path, "must be an object")
	}
	for key := range values {
		found := false
		for _, candidate := range allowed {
			found = found || key == candidate
		}
		if !found {
			return nil, FieldError(path, "unknown field")
		}
	}
	return values, nil
}

func CheckValue(dec *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("depth")
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			token, err := dec.Token()
			key, ok := token.(string)
			if err != nil || !ok || seen[key] {
				return errors.New("key")
			}
			seen[key] = true
			if err := CheckValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("object")
		}
	case '[':
		for dec.More() {
			if err := CheckValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("array")
		}
	default:
		return errors.New("delimiter")
	}
	return nil
}

// Check only the newly added root names, preserving unrelated legacy semantics.
// Case-insensitive matching prevents encoding/json's field folding from hiding
// a duplicate or accepting an undocumented spelling of a new field.
func CheckEntryKeys(body []byte) error {
	if !utf8.Valid(body) {
		return errors.New("invalid configuration: invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("invalid configuration")
	}
	seen := map[string]bool{}
	for dec.More() {
		token, err := dec.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return errors.New("invalid configuration")
		}
		for _, name := range []string{"classification", "socks_metadata", "datagram_fec", "dns"} {
			if strings.EqualFold(key, name) {
				if key != name || seen[name] {
					return FieldError(name, "duplicate field or invalid field spelling")
				}
				seen[name] = true
			}
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return errors.New("invalid configuration")
		}
	}
	if _, err := dec.Token(); err != nil {
		return errors.New("invalid configuration")
	}
	return nil
}

func String(raw json.RawMessage, path string) (string, error) {
	raw = bytes.TrimSpace(raw)
	var value string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil || !utf8.Valid(raw) || !ValidSurrogates(raw) {
		return "", FieldError(path, "must be a valid UTF-8 string")
	}
	return value, nil
}

// encoding/json replaces unpaired UTF-16 escapes with U+FFFD. Refuse the
// malformed escape instead of silently changing a selector or trust option.
func ValidSurrogates(raw []byte) bool {
	for at := 1; at < len(raw)-1; at++ {
		if raw[at] != '\\' {
			continue
		}
		at++
		if raw[at] != 'u' {
			continue
		}
		first, err := strconv.ParseUint(string(raw[at+1:at+5]), 16, 16)
		if err != nil {
			return false
		}
		at += 4
		if first >= 0xDC00 && first <= 0xDFFF {
			return false
		}
		if first >= 0xD800 && first <= 0xDBFF {
			if at+6 >= len(raw) || raw[at+1] != '\\' || raw[at+2] != 'u' {
				return false
			}
			second, err := strconv.ParseUint(string(raw[at+3:at+7]), 16, 16)
			if err != nil || second < 0xDC00 || second > 0xDFFF {
				return false
			}
			at += 6
		}
	}
	return true
}

func Class(raw json.RawMessage, path string) (protocol.Class, error) {
	value, err := String(raw, path)
	if err != nil {
		return 0, err
	}
	switch value {
	case "interactive":
		return protocol.Interactive, nil
	case "normal":
		return protocol.Normal, nil
	case "bulk":
		return protocol.Bulk, nil
	default:
		return 0, FieldError(path, "must be interactive, normal or bulk")
	}
}

func Bool(raw json.RawMessage, path string) (bool, error) {
	switch string(bytes.TrimSpace(raw)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, FieldError(path, "must be a boolean")
	}
}

func Uint(raw json.RawMessage, path string, maximum uint64) (uint64, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return 0, FieldError(path, "must be a positive decimal integer")
	}
	for _, digit := range raw {
		if digit < '0' || digit > '9' {
			return 0, FieldError(path, "must be a positive decimal integer")
		}
	}
	value, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil || value == 0 || value > maximum {
		return 0, FieldError(path, "integer outside permitted range")
	}
	return value, nil
}

func Array(raw json.RawMessage, path string, limit int, nonempty bool) ([]json.RawMessage, error) {
	raw = bytes.TrimSpace(raw)
	var values []json.RawMessage
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &values) != nil {
		return nil, FieldError(path, "must be an array")
	}
	if len(values) > limit || nonempty && len(values) == 0 {
		return nil, FieldError(path, "array length outside permitted range")
	}
	return values, nil
}

func Domain(value, path string) error {
	// Reuse the immutable compiler's domain normalization and structural
	// validation without trusting any request or duplicating DNS grammar.
	cfg := classification.DefaultConfig()
	cfg.Rules = []classification.Rule{{Domain: value, Class: protocol.Normal}}
	if _, err := classification.New(cfg); err != nil {
		return FieldError(path, "must be an ASCII DNS name")
	}
	return nil
}

func Rule(raw json.RawMessage, index int) (classification.Rule, error) {
	path := fmt.Sprintf("classification.rules[%d]", index)
	fields, err := Object(raw, path, "name", "class", "priority", "locked", "network", "ports", "domain", "domain_suffix", "rule_tag")
	if err != nil {
		return classification.Rule{}, err
	}
	var rule classification.Rule
	rule.Name, err = String(fields["name"], path+".name")
	if err != nil || len(rule.Name) == 0 || len(rule.Name) > 128 || strings.IndexFunc(rule.Name, unicode.IsControl) >= 0 {
		return rule, FieldError(path+".name", "must be 1..128 UTF-8 bytes without control characters")
	}
	rule.Class, err = Class(fields["class"], path+".class")
	if err != nil {
		return rule, err
	}
	if raw, present := fields["priority"]; present {
		var value int32
		if json.Unmarshal(raw, &value) != nil || string(bytes.TrimSpace(raw)) == "null" {
			return rule, FieldError(path+".priority", "must be a signed 32-bit integer")
		}
		rule.Priority = int(value)
	}
	if raw, present := fields["locked"]; present {
		rule.Locked, err = Bool(raw, path+".locked")
		if err != nil {
			return rule, err
		}
	}
	for _, field := range []struct {
		name string
		out  *string
	}{{"network", &rule.Network}, {"domain", &rule.Domain}, {"domain_suffix", &rule.DomainSuffix}, {"rule_tag", &rule.RuleTag}} {
		if raw, present := fields[field.name]; present {
			*field.out, err = String(raw, path+"."+field.name)
			if err != nil {
				return rule, err
			}
			if *field.out == "" {
				return rule, FieldError(path+"."+field.name, "must be nonempty")
			}
		}
	}
	if rule.Network != "" && rule.Network != "tcp" && rule.Network != "udp" {
		return rule, FieldError(path+".network", "must be tcp or udp")
	}
	if rule.Domain != "" && rule.DomainSuffix != "" {
		return rule, FieldError(path, "domain and domain_suffix are mutually exclusive")
	}
	for _, field := range []struct{ name, value string }{{"domain", rule.Domain}, {"domain_suffix", rule.DomainSuffix}} {
		if field.value != "" {
			if err := Domain(field.value, path+"."+field.name); err != nil {
				return rule, err
			}
		}
	}
	if len(rule.RuleTag) > 256 || strings.IndexFunc(rule.RuleTag, unicode.IsControl) >= 0 {
		return rule, FieldError(path+".rule_tag", "must be at most 256 UTF-8 bytes without control characters")
	}
	if raw, present := fields["ports"]; present {
		ports, err := Array(raw, path+".ports", 64, true)
		if err != nil {
			return rule, err
		}
		for i, port := range ports {
			portPath := fmt.Sprintf("%s.ports[%d]", path, i)
			fields, err := Object(port, portPath, "first", "last")
			if err != nil {
				return rule, err
			}
			first, err := Uint(fields["first"], portPath+".first", 65535)
			if err != nil {
				return rule, err
			}
			last, err := Uint(fields["last"], portPath+".last", 65535)
			if err != nil {
				return rule, err
			}
			if last < first {
				return rule, FieldError(portPath+".last", "must be >= first")
			}
			rule.Ports = append(rule.Ports, classification.PortRange{First: uint16(first), Last: uint16(last)})
		}
	}
	if rule.Network == "" && rule.Domain == "" && rule.DomainSuffix == "" && rule.RuleTag == "" && len(rule.Ports) == 0 {
		return rule, FieldError(path, "requires at least one selector")
	}
	return rule, nil
}

func Behavior(raw json.RawMessage, out *classification.BehaviorConfig) error {
	path := "classification.behavior"
	fields, err := Object(raw, path, "enabled", "window", "bucket", "min_total_bytes", "bulk_bytes_per_second", "bulk_sustain", "activity_gap", "restore", "restore_bytes_per_second", "restore_sustain", "cooldown")
	if err != nil {
		return err
	}
	for _, field := range []struct {
		name string
		out  *bool
	}{{"enabled", &out.Enabled}, {"restore", &out.Restore}} {
		if raw, present := fields[field.name]; present {
			*field.out, err = Bool(raw, path+"."+field.name)
			if err != nil {
				return err
			}
		}
	}
	for _, field := range []struct {
		name string
		out  *uint64
	}{{"min_total_bytes", &out.MinTotalBytes}, {"bulk_bytes_per_second", &out.BulkBytesPerSecond}, {"restore_bytes_per_second", &out.RestoreBytesPerSecond}} {
		if raw, present := fields[field.name]; present {
			*field.out, err = Uint(raw, path+"."+field.name, ^uint64(0))
			if err != nil {
				return err
			}
		}
	}
	for _, field := range []struct {
		name string
		out  *time.Duration
	}{{"window", &out.Window}, {"bucket", &out.Bucket}, {"bulk_sustain", &out.BulkSustain}, {"activity_gap", &out.ActivityGap}, {"restore_sustain", &out.RestoreSustain}, {"cooldown", &out.Cooldown}} {
		if raw, present := fields[field.name]; present {
			value, err := String(raw, path+"."+field.name)
			if err != nil {
				return err
			}
			duration, err := time.ParseDuration(value)
			if err != nil || duration < 0 || duration == 0 && field.name != "cooldown" {
				return FieldError(path+"."+field.name, "must be a valid positive duration (cooldown permits zero)")
			}
			*field.out = duration
		}
	}
	return nil
}

func Classification(raw json.RawMessage) (*classification.Config, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	fields, err := Object(raw, "classification", "default_class", "highest_allowed", "rules", "behavior")
	if err != nil {
		return nil, err
	}
	cfg := classification.DefaultConfig()
	for _, field := range []struct {
		name string
		out  *protocol.Class
	}{{"default_class", &cfg.DefaultClass}, {"highest_allowed", &cfg.HighestAllowed}} {
		if raw, present := fields[field.name]; present {
			*field.out, err = Class(raw, "classification."+field.name)
			if err != nil {
				return nil, err
			}
		}
	}
	if raw, present := fields["rules"]; present {
		rules, err := Array(raw, "classification.rules", 128, false)
		if err != nil {
			return nil, err
		}
		names := map[string]bool{}
		for i, raw := range rules {
			rule, err := Rule(raw, i)
			if err != nil {
				return nil, err
			}
			if names[rule.Name] {
				return nil, FieldError(fmt.Sprintf("classification.rules[%d].name", i), "must be unique")
			}
			names[rule.Name] = true
			cfg.Rules = append(cfg.Rules, rule)
		}
	}
	if raw, present := fields["behavior"]; present {
		if err := Behavior(raw, &cfg.Behavior); err != nil {
			return nil, err
		}
	}
	// Validate dormant fields as well; retain the user's actual enable flags.
	check := cfg
	check.Behavior.Enabled, check.Behavior.Restore = true, true
	if _, err := classification.New(check); err != nil {
		return nil, FieldError("classification.behavior", "inconsistent window, thresholds, hysteresis or rate overflow")
	}
	return &cfg, nil
}

func SOCKSDomainSource(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "ignore", nil
	}
	fields, err := Object(raw, "socks_metadata", "domain_source")
	if err != nil {
		return "", err
	}
	if raw, present := fields["domain_source"]; present {
		value, err := String(raw, "socks_metadata.domain_source")
		if err != nil {
			return "", err
		}
		if value != "ignore" && value != "socks_address" {
			return "", FieldError("socks_metadata.domain_source", "must be ignore or socks_address")
		}
		return value, nil
	}
	return "ignore", nil
}
