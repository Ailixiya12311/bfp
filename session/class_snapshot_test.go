package session

import (
	"bfp/internal/classcontrol"
	"bfp/protocol"
	"testing"
)

func TestClassSnapshotStrictPresenceAndFullWidth(t *testing.T) {
	for _, raw := range []string{`{"i":1,"r":0,"m":16,"o":"ok","tc":null}`, `{"i":1,"r":0,"m":16,"o":"ok","TC":{"v":1,"c":0}}`, `{"i":1,"r":0,"m":16,"o":"ok","tc":{"v":1,"c":0},"tc":{"v":2,"c":2}}`, `{"i":1,"r":null,"m":16,"o":"ok"}`} {
		var snap flowSnapshot
		if err := decodeJSON([]byte(raw), &snap); err == nil {
			t.Errorf("accepted malformed flow snapshot %s", raw)
		}
	}
	for _, raw := range []string{`{}`, `{"v":1}`, `{"c":0}`, `{"v":null,"c":0}`, `{"v":1,"c":null}`, `{"v":1,"c":0,"C":2}`, `{"v":1,"v":2,"c":0}`, `{"v":1,"c":0,"extra":1}`} {
		var state classWireSnapshot
		if err := decodeJSON([]byte(raw), &state); err == nil {
			t.Errorf("accepted malformed class snapshot %s", raw)
		}
	}
	table, _ := classcontrol.New(classcontrol.DefaultConfig())
	s := &Session{classTable: table}
	for _, class := range []uint64{3, 256, ^uint64(0)} {
		if s.validClassSnapshot(flowSnapshot{TXClass: &classWireSnapshot{Version: 1, Class: class}, Result: "ok"}) {
			t.Errorf("accepted class %d", class)
		}
	}
	if s.validClassSnapshot(flowSnapshot{Result: "ok"}) || s.validClassSnapshot(flowSnapshot{Result: ""}) || s.validClassSnapshot(flowSnapshot{TXClass: &classWireSnapshot{Class: 0}, Result: "ok"}) {
		t.Fatal("accepted absent/nonversioned successful class state")
	}
	if !s.validClassSnapshot(flowSnapshot{TXClass: &classWireSnapshot{Version: 1, Class: uint64(protocol.Interactive)}, Result: "ok"}) {
		t.Fatal("Interactive zero class treated as absent")
	}
	if !s.validClassSnapshot(flowSnapshot{Reset: true}) || !s.validClassSnapshot(flowSnapshot{Result: "failed"}) {
		t.Fatal("terminal unsuccessful snapshot requires TX allocation")
	}
}
