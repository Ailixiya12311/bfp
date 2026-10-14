package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
)

// A rule journal stores the complete fib_rule_hdr and its attributes. The
// dependency's RuleList loses the action and other selectors, so rebuilding a
// delete request from its Rule can turn a goto into a lookup or omit a NOP.
type nativeRoutingRule struct {
	nativeRuleSelectors `json:"-"`
	Payload             []byte `json:"payload"`
}

// Keep the journal decoder platform-independent; importing the Linux netlink
// implementation here would prevent building the Windows client/server.
type nativeRuleSelectors struct {
	Priority, Family, Table, Goto, SuppressPrefixlen int
	Type                                             uint8
	IifName, OifName                                 string
	Invert                                           bool
	Dport                                            *nativeRulePorts
}

type nativeRulePorts struct{ Start, End uint16 }

const nativeRuleHeaderSize = 12 // Linux struct fib_rule_hdr, UAPI fib_rules.h.

func decodeNativeRule(payload []byte) (nativeRoutingRule, error) {
	if len(payload) < nativeRuleHeaderSize || len(payload) > 65536 {
		return nativeRoutingRule{}, errors.New("invalid native routing rule size")
	}
	if payload[0] != 2 && payload[0] != 10 { // AF_INET and AF_INET6.
		return nativeRoutingRule{}, errors.New("invalid native routing rule family")
	}
	rule := nativeRoutingRule{nativeRuleSelectors: nativeRuleSelectors{Goto: -1, SuppressPrefixlen: -1}, Payload: append([]byte(nil), payload...)}
	rule.Family, rule.Type, rule.Table = int(payload[0]), payload[7], int(payload[4])
	rule.Priority = 0
	flags := binary.NativeEndian.Uint32(payload[8:12])
	rule.Invert = flags&2 != 0
	// These kernel status flags change when an interface or goto target
	// disappears. They are not rule selectors and must not break recovery.
	flags &^= 4 | 8 | 16 // UNRESOLVED, IIF_DETACHED, OIF_DETACHED.
	binary.NativeEndian.PutUint32(rule.Payload[8:12], flags)
	for offset := nativeRuleHeaderSize; offset < len(payload); {
		if len(payload)-offset < 4 {
			return nativeRoutingRule{}, errors.New("truncated native routing rule attribute")
		}
		length := int(binary.NativeEndian.Uint16(payload[offset : offset+2]))
		kind := binary.NativeEndian.Uint16(payload[offset+2:offset+4]) & 0x3fff
		aligned := (length + 3) &^ 3
		if length < 4 || aligned > len(payload)-offset {
			return nativeRoutingRule{}, errors.New("invalid native routing rule attribute size")
		}
		value := payload[offset+4 : offset+length]
		switch kind {
		case 4, 6, 14, 15: // FRA_GOTO, PRIORITY, SUPPRESS_PREFIXLEN, TABLE.
			if len(value) != 4 {
				return nativeRoutingRule{}, errors.New("invalid native routing rule integer")
			}
			number := int(binary.NativeEndian.Uint32(value))
			switch kind {
			case 4:
				rule.Goto = number
			case 6:
				rule.Priority = number
			case 14:
				if number != 0xffffffff {
					rule.SuppressPrefixlen = number
				}
			case 15:
				rule.Table = number
			}
		case 3, 17: // FRA_IIFNAME, OIFNAME.
			if len(value) < 2 || value[len(value)-1] != 0 || strings.IndexByte(string(value[:len(value)-1]), 0) >= 0 {
				return nativeRoutingRule{}, errors.New("invalid native routing rule interface")
			}
			if kind == 3 {
				rule.IifName = string(value[:len(value)-1])
			} else {
				rule.OifName = string(value[:len(value)-1])
			}
		case 24: // FRA_DPORT_RANGE.
			if len(value) != 4 {
				return nativeRoutingRule{}, errors.New("invalid native routing rule port range")
			}
			rule.Dport = &nativeRulePorts{binary.NativeEndian.Uint16(value[:2]), binary.NativeEndian.Uint16(value[2:])}
		}
		offset += aligned
	}
	return rule, nil
}

func (r *nativeRoutingRule) UnmarshalJSON(raw []byte) error {
	var record struct {
		Payload []byte `json:"payload"`
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return err
	}
	decoded, err := decodeNativeRule(record.Payload)
	if err != nil {
		return err
	}
	*r = decoded
	return nil
}
