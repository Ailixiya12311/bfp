package session

import (
	"bfp/internal/classcontrol"
	"bfp/protocol"
	"bytes"
	"errors"
	"time"
)

var ErrClassControl = errors.New("session: class announcement budget exhausted")

// The nested snapshot has explicit presence. Interactive is the valid zero
// class; missing or null fields must not silently acquire that meaning.
type classWireSnapshot struct {
	Version uint64 `json:"v"`
	Class   uint64 `json:"c"`
}

func (snap *flowSnapshot) UnmarshalJSON(data []byte) error {
	fields, err := objectFields(data)
	if err != nil || capabilityFieldsPresent(data, "i", "r", "m", "o") != nil {
		return ErrState
	}
	for key, raw := range fields {
		switch key {
		case "i", "r", "m", "o", "f", "x", "ar", "mr", "or", "tc":
		default:
			return ErrState
		}
		if key != "f" && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return ErrState
		}
	}
	type plain flowSnapshot
	var out plain
	if err := decodeJSON(data, &out); err != nil {
		return err
	}
	*snap = flowSnapshot(out)
	return nil
}

func (c *classWireSnapshot) UnmarshalJSON(data []byte) error {
	fields, err := objectFields(data)
	if err != nil || len(fields) != 2 {
		return ErrState
	}
	if capabilityFieldsPresent(data, "v", "c") != nil {
		return ErrState
	}
	type plain classWireSnapshot
	var out plain
	if err := decodeJSON(data, &out); err != nil {
		return err
	}
	*c = classWireSnapshot(out)
	return nil
}

func (s *Session) classStamp() time.Duration { return s.controlStamp(s.transportTime()) }

func (s *Session) startClassControl(st *streamState) bool {
	if s.classTable == nil {
		return true
	}
	state, err := s.classTable.Start(st.flow.id, st.effectiveClass, s.classStamp())
	if err != nil {
		s.reset(st, err, true)
		return false
	}
	st.classTX = state
	return true
}

func (s *Session) enableClassControl(st *streamState) {
	if s.classTable == nil || st.terminal() || st.openResult != "ok" {
		return
	}
	if err := s.classTable.Enable(st.flow.id, s.classStamp()); err != nil {
		s.cancel()
	}
}

func (s *Session) updateClassControl(st *streamState) {
	if s.classTable == nil || st.terminal() {
		return
	}
	state, _, err := s.classTable.Update(st.flow.id, st.effectiveClass, s.classStamp())
	if err != nil {
		s.reset(st, err, true)
		return
	}
	st.classTX = state
}

// Fixed pending lifetimes survive version changes, starvation, suspension and
// rebind. Exhaustion ends the Flow through the existing bounded RESET path.
func (s *Session) maintainClassControls() {
	if s.classTable == nil {
		return
	}
	for id, st := range s.streams {
		if st.terminal() {
			s.classTable.Forget(id)
		}
	}
	_, exhausted, err := s.classTable.Ready(s.classStamp(), 0)
	if err != nil {
		s.cancel()
		return
	}
	for _, id := range exhausted {
		if st := s.streams[id]; st != nil && !st.terminal() {
			s.reset(st, ErrClassControl, true)
		}
	}
}

func classFrame(state classcontrol.State, flags uint8) protocol.Frame {
	return protocol.Frame{Kind: protocol.ClassUpdate, Flags: flags, Flow: state.Flow, Offset: state.Version, Value: uint64(state.Class)}
}

// Round robin is independent of business FIFO identity. At most two of the
// existing four send slots select class controls; ACK and TX alternate. These
// frames still pay the full record/pacer/cwnd cost in udpSend.
func nextClassState(states []classcontrol.State, cursor *uint64) (classcontrol.State, bool) {
	if len(states) == 0 {
		return classcontrol.State{}, false
	}
	chosen := states[0]
	for _, state := range states {
		if state.Flow > *cursor {
			chosen = state
			break
		}
	}
	*cursor = chosen.Flow
	return chosen, true
}

func (s *Session) nextClassFrame() (protocol.Frame, bool) {
	if s.classTable == nil || !s.peerDone || !s.localDoneAck {
		return protocol.Frame{}, false
	}
	ready, _, err := s.classTable.Ready(s.classStamp(), classcontrol.MaxEntries)
	if err != nil {
		s.cancel()
		return protocol.Frame{}, false
	}
	acks, err := s.classTable.ReadyAcks(classcontrol.MaxEntries)
	if err != nil {
		s.cancel()
		return protocol.Frame{}, false
	}
	for pass := 0; pass < 2; pass++ {
		ack := s.classAckTurn
		s.classAckTurn = !s.classAckTurn
		if ack {
			if state, ok := nextClassState(acks, &s.classACKCursor); ok {
				return classFrame(state, 1), true
			}
		} else if state, ok := nextClassState(ready, &s.classTXCursor); ok {
			return classFrame(state, 0), true
		}
	}
	return protocol.Frame{}, false
}

func (s *Session) nextSendFrame(slot int) (protocol.Frame, bool) {
	if slot < 2 {
		if f, ok := s.nextClassFrame(); ok {
			return f, true
		}
	}
	var f protocol.Frame
	var ok bool
	if s.oldUDPBusinessPaused() {
		f, ok = s.queue.PopMatching(func(f protocol.Frame) bool { return !isBusinessFrame(f) && f.Kind != protocol.DatagramRepairFrame })
	} else {
		f, ok = s.queue.Pop()
	}
	if ok {
		s.datagramPopped(f)
	}
	return f, ok
}

func validClassFrame(f protocol.Frame) bool {
	return f.Kind == protocol.ClassUpdate && f.Flow != 0 && f.Offset != 0 && f.Value <= uint64(protocol.Bulk) && f.Flags <= 1 && len(f.Data) == 0
}

func (s *Session) prepareClassControl(f protocol.Frame) (*classcontrol.Publication, bool, error) {
	if f.Kind != protocol.ClassUpdate || s.classTable == nil {
		return nil, false, nil
	}
	if !validClassFrame(f) {
		return nil, false, ErrState
	}
	st := s.streams[f.Flow]
	if st == nil || st.terminal() {
		return nil, true, nil
	}
	if !s.peerDone || !s.localDoneAck {
		return nil, true, nil
	}
	if f.Flags == 1 {
		view, err := s.classTable.Snapshot(f.Flow)
		if err != nil {
			return nil, false, err
		}
		want := classcontrol.State{Flow: f.Flow, Version: f.Offset, Class: protocol.Class(f.Value)}
		return nil, !view.AckPending || view.Ack != want, nil
	}
	p, err := s.classTable.Prepare(f.Flow, f.Offset, protocol.Class(f.Value), s.classStamp())
	if err == classcontrol.ErrStale || err == classcontrol.ErrNotDue || err == classcontrol.ErrExhausted {
		return nil, true, nil
	}
	return p, false, err
}

func (s *Session) publishClassControl(f protocol.Frame, p *classcontrol.Publication, base time.Duration) error {
	if f.Kind != protocol.ClassUpdate || s.classTable == nil {
		return nil
	}
	if f.Flags == 1 {
		return s.classTable.AckSent(classcontrol.State{Flow: f.Flow, Version: f.Offset, Class: protocol.Class(f.Value)})
	}
	return s.classTable.Publish(p, s.classStamp(), base)
}

func (s *Session) handleClassControl(f protocol.Frame) {
	// Capability-zero states are only legacy synthetic transport fixtures. The
	// authenticated wire3 handshake requires this capability on actual Sessions.
	if s.classTable == nil {
		return
	}
	if !validClassFrame(f) {
		s.cancel()
		return
	}
	st := s.streams[f.Flow]
	if st == nil || st.terminal() || st.opening || st.openResult != "ok" {
		return
	}
	state := classcontrol.State{Flow: f.Flow, Version: f.Offset, Class: protocol.Class(f.Value)}
	if f.Flags == 1 {
		if _, err := s.classTable.Ack(f.Flow, f.Offset, state.Class, s.classStamp()); err != nil {
			s.cancel()
		}
		return
	}
	if _, err := s.classTable.MergePeer(state); err != nil {
		s.cancel()
		return
	}
	if err := s.classTable.QueueAck(state); err != nil {
		s.cancel()
	}
}

func (s *Session) validClassSnapshot(snap flowSnapshot) bool {
	if s.classTable == nil {
		return snap.TXClass == nil
	}
	if snap.TXClass == nil {
		return snap.Reset || snap.Result == "failed" || snap.Result == "limit"
	}
	return snap.TXClass.Version != 0 && snap.TXClass.Class <= uint64(protocol.Bulk)
}

func (s *Session) mergeClassSnapshot(st *streamState, snap flowSnapshot) bool {
	if s.classTable == nil || st.terminal() || snap.TXClass == nil {
		return true
	}
	_, err := s.classTable.MergePeer(classcontrol.State{Flow: st.flow.id, Version: snap.TXClass.Version, Class: protocol.Class(snap.TXClass.Class)})
	return err == nil
}
