package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func nativeRuleFixture(family, action byte, flags uint32, attrs ...[]byte) []byte {
	message := make([]byte, nativeRuleHeaderSize)
	message[0], message[7] = family, action
	binary.NativeEndian.PutUint32(message[8:12], flags)
	for _, attr := range attrs {
		message = append(message, attr...)
	}
	return message
}

func nativeRuleFixtureAttr(kind uint16, value []byte) []byte {
	length := 4 + len(value)
	attr := make([]byte, (length+3)&^3)
	binary.NativeEndian.PutUint16(attr[:2], uint16(length))
	binary.NativeEndian.PutUint16(attr[2:4], kind)
	copy(attr[4:], value)
	return attr
}

func nativeRuleFixtureInt(kind uint16, value uint32) []byte {
	data := make([]byte, 4)
	binary.NativeEndian.PutUint32(data, value)
	return nativeRuleFixtureAttr(kind, data)
}

func TestNativeRuleJournalPreservesActionsAndSelectors(t *testing.T) {
	for _, test := range []struct {
		name   string
		family byte
		action byte
		gotoID int
		attrs  [][]byte
	}{
		{"IPv4 goto", 2, 2, 9042, [][]byte{nativeRuleFixtureInt(4, 9042), nativeRuleFixtureAttr(3, []byte("bfp-tun-2886e79\x00"))}},
		{"IPv4 nop", 2, 3, -1, nil},
		{"IPv6 unreachable", 10, 7, -1, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			attrs := append([][]byte{nativeRuleFixtureInt(6, 9033), nativeRuleFixtureAttr(21, []byte{4})}, test.attrs...)
			payload := nativeRuleFixture(test.family, test.action, 0, attrs...)
			rule, err := decodeNativeRule(payload)
			if err != nil {
				t.Fatal(err)
			}
			if rule.Type != test.action || rule.Goto != test.gotoID || rule.Priority != 9033 || !bytes.Equal(rule.Payload, payload) {
				t.Fatalf("kernel rule changed: %+v", rule)
			}
			raw, err := json.Marshal(rule)
			if err != nil {
				t.Fatal(err)
			}
			var restored nativeRoutingRule
			if err := json.Unmarshal(raw, &restored); err != nil {
				t.Fatal(err)
			}
			if restored.Type != test.action || restored.Goto != test.gotoID || !bytes.Equal(restored.Payload, payload) {
				t.Fatalf("journal changed the rule: %+v", restored)
			}
		})
	}
}

func TestNativeRuleDetachedStatusDoesNotChangeIdentity(t *testing.T) {
	attrs := [][]byte{nativeRuleFixtureInt(6, 9033), nativeRuleFixtureInt(4, 9042)}
	before, err := decodeNativeRule(nativeRuleFixture(2, 2, 2, attrs...))
	if err != nil {
		t.Fatal(err)
	}
	after, err := decodeNativeRule(nativeRuleFixture(2, 2, 2|4|8|16, attrs...))
	if err != nil {
		t.Fatal(err)
	}
	if !before.Invert || !after.Invert || !bytes.Equal(before.Payload, after.Payload) {
		t.Fatal("detached kernel status broke rule ownership")
	}
	foreign, err := decodeNativeRule(nativeRuleFixture(2, 2, 0, attrs...))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before.Payload, foreign.Payload) {
		t.Fatal("different inversion selectors matched")
	}
	foreignPayload := nativeRuleFixture(2, 2, 2, append(attrs, nativeRuleFixtureAttr(21, []byte{99}))...)
	foreign, err = decodeNativeRule(foreignPayload)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before.Payload, foreign.Payload) {
		t.Fatal("opaque rule origin selector was lost")
	}
}

func TestNativeRuleJournalRejectsMalformedPayload(t *testing.T) {
	for _, payload := range [][]byte{
		{2},
		nativeRuleFixture(0, 2, 0),
		nativeRuleFixture(2, 2, 0, []byte{3, 0, 6, 0}),
		nativeRuleFixture(2, 2, 0, nativeRuleFixtureAttr(4, []byte{1})),
		nativeRuleFixture(2, 2, 0, nativeRuleFixtureAttr(3, []byte("no-terminator"))),
	} {
		raw, err := json.Marshal(map[string][]byte{"payload": payload})
		if err != nil {
			t.Fatal(err)
		}
		var rule nativeRoutingRule
		if err := json.Unmarshal(raw, &rule); err == nil {
			t.Fatalf("accepted malformed journal: %x", payload)
		}
	}
}
