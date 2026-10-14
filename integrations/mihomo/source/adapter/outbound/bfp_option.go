package outbound

import (
	"errors"
	"math"
)

// ValidateBFPMapping rejects misspelled, null and weakly coerced BFP options
// before Mihomo's ordinary structure decoder. Duplicate YAML/JSON root keys
// must be handled by the host parser before it creates this map; private BFP
// credential files have their own raw strict parser.
func ValidateBFPMapping(mapping map[string]any) error {
	invalid := errors.New("bfp: invalid or unsupported outbound option")
	for key, value := range mapping {
		if value == nil {
			return invalid
		}
		switch key {
		case "type", "name", "client-config-file", "interface-name", "dialer-proxy", "ip-version":
			if _, ok := value.(string); !ok {
				return invalid
			}
		case "udp", "tfo", "mptcp":
			if _, ok := value.(bool); !ok {
				return invalid
			}
		case "max-packet-conns", "routing-mark":
			switch number := value.(type) {
			case int:
				if number < 0 {
					return invalid
				}
			case int64:
				if number < 0 {
					return invalid
				}
			case uint64, uint: // valid integer input; decoder checks host int bounds
			case float64:
				if math.IsNaN(number) || math.IsInf(number, 0) || number < 0 || math.Trunc(number) != number {
					return invalid
				}
			default:
				return invalid
			}
		case "classification":
			switch value.(type) {
			case map[string]any, map[any]any:
			default:
				return invalid
			}
		default:
			return invalid
		}
	}
	return nil
}
