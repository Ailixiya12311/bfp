package outbound

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"bfp/classification"
	"bfp/protocol"
)

// parseBFPClassification is deliberately independent of Mihomo's weak
// decoder. The adapter accepts a small, documented map and converts it to the
// root protocol's validated classifier before any Session is opened.
func parseBFPClassification(raw map[string]any) (*classification.Config, error) {
	cfg := classification.DefaultConfig()
	for key, value := range raw {
		switch canonicalClassKey(key) {
		case "default_class":
			class, err := parseBFPClass(value)
			if err != nil {
				return nil, fmt.Errorf("bfp: classification.default-class: %w", err)
			}
			cfg.DefaultClass = class
		case "highest_allowed":
			class, err := parseBFPClass(value)
			if err != nil {
				return nil, fmt.Errorf("bfp: classification.highest-allowed: %w", err)
			}
			cfg.HighestAllowed = class
		case "rules":
			rules, err := parseBFPClassRules(value)
			if err != nil {
				return nil, err
			}
			cfg.Rules = rules
		case "behavior":
			behavior, err := parseBFPBehavior(value)
			if err != nil {
				return nil, err
			}
			cfg.Behavior = behavior
		default:
			return nil, fmt.Errorf("bfp: unsupported classification field %q", key)
		}
	}
	// Validate disabled/dormant behavior fields too. This prevents a later
	// runtime toggle from accepting a malformed threshold that startup ignored.
	check := cfg
	check.Behavior.Enabled, check.Behavior.Restore = true, true
	if _, err := classification.New(check); err != nil {
		return nil, fmt.Errorf("bfp: classification: %w", err)
	}
	return &cfg, nil
}

func canonicalClassKey(key string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(key)), "-", "_")
}

func parseBFPClass(value any) (protocol.Class, error) {
	text, ok := value.(string)
	if !ok {
		return 0, fmt.Errorf("class must be interactive, normal, or bulk")
	}
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "interactive":
		return protocol.Interactive, nil
	case "normal":
		return protocol.Normal, nil
	case "bulk":
		return protocol.Bulk, nil
	default:
		return 0, fmt.Errorf("unknown class %q", text)
	}
}

func asBFPMap(value any, path string) (map[string]any, error) {
	if value == nil {
		return nil, fmt.Errorf("bfp: %s must be an object", path)
	}
	if typed, ok := value.(map[string]any); ok {
		return typed, nil
	}
	if typed, ok := value.(map[any]any); ok {
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			name, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("bfp: %s has a non-string field", path)
			}
			out[name] = item
		}
		return out, nil
	}
	return nil, fmt.Errorf("bfp: %s must be an object", path)
}

func asBFPList(value any, path string) ([]any, error) {
	if typed, ok := value.([]any); ok {
		return typed, nil
	}
	return nil, fmt.Errorf("bfp: %s must be an array", path)
}

func parseBFPClassRules(value any) ([]classification.Rule, error) {
	items, err := asBFPList(value, "classification.rules")
	if err != nil {
		return nil, err
	}
	if len(items) > 128 {
		return nil, fmt.Errorf("bfp: classification.rules exceeds 128 entries")
	}
	rules := make([]classification.Rule, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for index, item := range items {
		fields, err := asBFPMap(item, fmt.Sprintf("classification.rules[%d]", index))
		if err != nil {
			return nil, err
		}
		rule := classification.Rule{}
		for key, raw := range fields {
			switch canonicalClassKey(key) {
			case "name":
				rule.Name, err = bfpString(raw, "name")
			case "priority":
				rule.Priority, err = bfpInt(raw, "priority")
			case "network":
				rule.Network, err = bfpString(raw, "network")
			case "ports":
				rule.Ports, err = parseBFPPorts(raw, index)
			case "domain":
				rule.Domain, err = bfpString(raw, "domain")
			case "domain_suffix":
				rule.DomainSuffix, err = bfpString(raw, "domain-suffix")
			case "rule_tag":
				rule.RuleTag, err = bfpString(raw, "rule-tag")
			case "application":
				rule.Application, err = bfpString(raw, "application")
			case "class":
				rule.Class, err = parseBFPClass(raw)
			case "locked":
				rule.Locked, err = bfpBool(raw, "locked")
			default:
				return nil, fmt.Errorf("bfp: unsupported classification.rules[%d] field %q", index, key)
			}
			if err != nil {
				return nil, fmt.Errorf("bfp: classification.rules[%d].%s: %w", index, key, err)
			}
		}
		if rule.Name == "" {
			return nil, fmt.Errorf("bfp: classification.rules[%d].name is required", index)
		}
		if _, exists := seen[rule.Name]; exists {
			return nil, fmt.Errorf("bfp: duplicate classification rule %q", rule.Name)
		}
		seen[rule.Name] = struct{}{}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parseBFPPorts(value any, ruleIndex int) ([]classification.PortRange, error) {
	items, err := asBFPList(value, fmt.Sprintf("classification.rules[%d].ports", ruleIndex))
	if err != nil {
		return nil, err
	}
	if len(items) > 64 {
		return nil, fmt.Errorf("bfp: classification.rules[%d].ports exceeds 64 entries", ruleIndex)
	}
	ports := make([]classification.PortRange, 0, len(items))
	for index, item := range items {
		fields, err := asBFPMap(item, fmt.Sprintf("classification.rules[%d].ports[%d]", ruleIndex, index))
		if err != nil {
			return nil, err
		}
		var port classification.PortRange
		for key, raw := range fields {
			switch canonicalClassKey(key) {
			case "first":
				port.First, err = bfpUint16(raw, "first")
			case "last":
				port.Last, err = bfpUint16(raw, "last")
			default:
				return nil, fmt.Errorf("bfp: unsupported port field %q", key)
			}
			if err != nil {
				return nil, fmt.Errorf("bfp: port field %q: %w", key, err)
			}
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func parseBFPBehavior(value any) (classification.BehaviorConfig, error) {
	fields, err := asBFPMap(value, "classification.behavior")
	if err != nil {
		return classification.BehaviorConfig{}, err
	}
	behavior := classification.DefaultBehaviorConfig()
	for key, raw := range fields {
		var fieldErr error
		switch canonicalClassKey(key) {
		case "enabled":
			behavior.Enabled, fieldErr = bfpBool(raw, "enabled")
		case "window":
			behavior.Window, fieldErr = bfpDuration(raw, "window")
		case "bucket":
			behavior.Bucket, fieldErr = bfpDuration(raw, "bucket")
		case "min_total_bytes":
			behavior.MinTotalBytes, fieldErr = bfpUint64(raw, "min-total-bytes")
		case "bulk_bytes_per_second":
			behavior.BulkBytesPerSecond, fieldErr = bfpUint64(raw, "bulk-bytes-per-second")
		case "bulk_sustain":
			behavior.BulkSustain, fieldErr = bfpDuration(raw, "bulk-sustain")
		case "activity_gap":
			behavior.ActivityGap, fieldErr = bfpDuration(raw, "activity-gap")
		case "restore":
			behavior.Restore, fieldErr = bfpBool(raw, "restore")
		case "restore_bytes_per_second":
			behavior.RestoreBytesPerSecond, fieldErr = bfpUint64(raw, "restore-bytes-per-second")
		case "restore_sustain":
			behavior.RestoreSustain, fieldErr = bfpDuration(raw, "restore-sustain")
		case "cooldown":
			behavior.Cooldown, fieldErr = bfpDuration(raw, "cooldown")
		default:
			return classification.BehaviorConfig{}, fmt.Errorf("bfp: unsupported classification.behavior field %q", key)
		}
		if fieldErr != nil {
			return classification.BehaviorConfig{}, fmt.Errorf("bfp: classification.behavior.%s: %w", key, fieldErr)
		}
	}
	return behavior, nil
}

func bfpString(value any, field string) (string, error) {
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", field)
	}
	return text, nil
}

func bfpBool(value any, field string) (bool, error) {
	parsed, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be boolean", field)
	}
	return parsed, nil
}

func bfpUint64(value any, field string) (uint64, error) {
	switch number := value.(type) {
	case uint64:
		return number, nil
	case uint:
		return uint64(number), nil
	case int:
		if number >= 0 {
			return uint64(number), nil
		}
	case int64:
		if number >= 0 {
			return uint64(number), nil
		}
	case float64:
		if number >= 0 && number == float64(uint64(number)) {
			return uint64(number), nil
		}
	case string:
		parsed, err := strconv.ParseUint(strings.TrimSpace(number), 10, 64)
		if err == nil {
			return parsed, nil
		}
	}
	return 0, fmt.Errorf("%s must be a non-negative integer", field)
}

func bfpUint16(value any, field string) (uint16, error) {
	parsed, err := bfpUint64(value, field)
	if err != nil || parsed > 65535 {
		return 0, fmt.Errorf("%s must be between 0 and 65535", field)
	}
	return uint16(parsed), nil
}

func bfpInt(value any, field string) (int, error) {
	switch number := value.(type) {
	case int:
		return number, nil
	case int64:
		if int64(int(number)) == number {
			return int(number), nil
		}
	case uint64:
		if number <= uint64(^uint(0)>>1) {
			return int(number), nil
		}
	case float64:
		if number == float64(int(number)) {
			return int(number), nil
		}
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(number))
		if err == nil {
			return parsed, nil
		}
	}
	return 0, fmt.Errorf("%s must be an integer", field)
}

func bfpDuration(value any, field string) (time.Duration, error) {
	text, ok := value.(string)
	if !ok {
		return 0, fmt.Errorf("%s must be a duration string", field)
	}
	duration, err := time.ParseDuration(strings.TrimSpace(text))
	if err != nil || duration < 0 {
		return 0, fmt.Errorf("%s must be a non-negative duration", field)
	}
	return duration, nil
}
