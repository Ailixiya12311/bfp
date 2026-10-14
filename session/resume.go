package session

import (
	"bfp/internal/latestcontrol"
	"bfp/protocol"
	"bfp/security"
	"errors"
	"sort"
)

// resumeDoneVersion identifies the bounded Session-level recovery payload.
// It is carried inside the authenticated frame so adding these fields cannot
// make them visible to an unauthenticated observer.
const resumeDoneVersion = 1

const (
	maxResumeDirtyControls = 128
	maxResumeDonePayload   = 8 << 10
)

// resumeDoneControl is a semantic latest-control value that changed after the
// Flow snapshots were frozen. The receiver applies it as peer state and the
// ResumeDone acknowledgement echoes the exact value as a snapshot receipt.
// It is deliberately not a wire Frame: the JSON payload has an independent
// bounded schema and cannot accidentally carry target or carrier fields.
type resumeDoneControl struct {
	Kind     protocol.Kind `json:"k"`
	Flow     uint64        `json:"f"`
	Revision uint64        `json:"r"`
	Value    uint64        `json:"v,omitempty"`
	Data     []byte        `json:"d,omitempty"`
}

type resumeDoneState struct {
	Version         uint8               `json:"v"`
	Generation      uint64              `json:"g"`
	SnapshotID      uint64              `json:"s"`
	SnapshotCount   uint64              `json:"n"`
	SessionRevision uint64              `json:"sr"`
	SessionValue    uint64              `json:"sv"`
	Dirty           []resumeDoneControl `json:"d,omitempty"`
}

func resumeControlLess(a, b resumeDoneControl) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return a.Flow < b.Flow
}

func validateResumeDoneState(st resumeDoneState) error {
	if st.Version != resumeDoneVersion || st.Generation == 0 || st.SnapshotID == 0 || st.SnapshotCount > 4096 {
		return errors.New("session: invalid resume done version or scope")
	}
	if st.SessionRevision == 0 || st.SessionValue == 0 {
		return errors.New("session: invalid resume session credit")
	}
	if len(st.Dirty) > maxResumeDirtyControls {
		return errors.New("session: resume dirty-control budget exceeded")
	}
	if len(st.Dirty) > 1 {
		if !sort.SliceIsSorted(st.Dirty, func(i, j int) bool { return resumeControlLess(st.Dirty[i], st.Dirty[j]) }) {
			return errors.New("session: resume dirty controls not ordered")
		}
	}
	for i, c := range st.Dirty {
		if c.Revision == 0 || !c.Kind.Valid() {
			return errors.New("session: invalid resume dirty control")
		}
		if i > 0 && st.Dirty[i-1].Kind == c.Kind && st.Dirty[i-1].Flow == c.Flow {
			return errors.New("session: duplicate resume dirty control")
		}
		switch c.Kind {
		case protocol.StreamAck, protocol.MaxFlowData:
			if c.Flow == 0 || len(c.Data) != 0 {
				return errors.New("session: invalid flow resume control")
			}
		case protocol.MaxSessionData:
			if c.Flow != 0 || len(c.Data) != 0 {
				return errors.New("session: invalid session resume control")
			}
		case protocol.OpenResult:
			if c.Flow == 0 || c.Value != 0 || len(c.Data) == 0 || len(c.Data) > security.MaxRecordSize/2 {
				return errors.New("session: invalid open-result resume control")
			}
		default:
			return errors.New("session: unsupported resume dirty control")
		}
	}
	return nil
}

func encodeResumeDoneState(st resumeDoneState) []byte {
	b := encodeJSON(st)
	if len(b) > maxResumeDonePayload {
		return nil
	}
	return b
}

func decodeResumeDoneState(data []byte) (resumeDoneState, error) {
	if len(data) == 0 || len(data) > maxResumeDonePayload {
		return resumeDoneState{}, errors.New("session: invalid resume done payload size")
	}
	var st resumeDoneState
	if err := decodeJSON(data, &st); err != nil {
		return resumeDoneState{}, err
	}
	if err := validateResumeDoneState(st); err != nil {
		return resumeDoneState{}, err
	}
	return st, nil
}

func (s *Session) resumeControlState(key latestcontrol.Key) (latestcontrol.State, bool) {
	if s.controlTable == nil {
		return latestcontrol.State{}, false
	}
	snap, err := s.controlTable.Snapshot(key)
	if err != nil {
		return latestcontrol.State{}, false
	}
	return snap.State, true
}

func resumeControlFromState(st latestcontrol.State) resumeDoneControl {
	c := resumeDoneControl{Kind: st.Key.Kind, Flow: st.Key.Flow, Revision: st.Revision}
	switch st.Key.Kind {
	case protocol.StreamAck, protocol.MaxFlowData, protocol.MaxSessionData:
		c.Value = st.Value
	case protocol.OpenResult:
		c.Data = append([]byte(nil), st.Data...)
	}
	return c
}

func (s *Session) captureResumeBaseline() {
	s.resumeBaseline = make(map[latestcontrol.Key]uint64)
	if s.controlTable == nil {
		return
	}
	for id := range s.streams {
		for _, kind := range []protocol.Kind{protocol.StreamAck, protocol.MaxFlowData, protocol.OpenResult} {
			if st, ok := s.resumeControlState(latestcontrol.Key{Kind: kind, Flow: id}); ok {
				s.resumeBaseline[st.Key] = st.Revision
			}
		}
	}
	if st, ok := s.resumeControlState(latestcontrol.Key{Kind: protocol.MaxSessionData}); ok {
		s.resumeBaseline[st.Key] = st.Revision
	}
}

func (s *Session) resumeDoneState() (resumeDoneState, bool, error) {
	if s.current == nil || s.resumeID == 0 || s.resumeSessionRevision == 0 {
		return resumeDoneState{}, false, nil
	}
	st := resumeDoneState{Version: resumeDoneVersion, Generation: s.current.generation,
		SnapshotID: s.resumeID, SnapshotCount: uint64(len(s.syncFrames)),
		SessionRevision: s.maxSessionRevision, SessionValue: s.maxSessionValue}
	if st.SessionRevision == 0 || st.SessionValue == 0 {
		return resumeDoneState{}, false, nil
	}
	if s.controlTable != nil {
		keys := make([]latestcontrol.Key, 0, len(s.streams)*3+1)
		for id := range s.streams {
			keys = append(keys,
				latestcontrol.Key{Kind: protocol.StreamAck, Flow: id},
				latestcontrol.Key{Kind: protocol.MaxFlowData, Flow: id},
				latestcontrol.Key{Kind: protocol.OpenResult, Flow: id})
		}
		keys = append(keys, latestcontrol.Key{Kind: protocol.MaxSessionData})
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].Kind != keys[j].Kind {
				return keys[i].Kind < keys[j].Kind
			}
			return keys[i].Flow < keys[j].Flow
		})
		for _, key := range keys {
			state, ok := s.resumeControlState(key)
			if !ok || state.Revision <= s.resumeBaseline[key] {
				continue
			}
			st.Dirty = append(st.Dirty, resumeControlFromState(state))
			if len(st.Dirty) > maxResumeDirtyControls {
				// A recovery barrier with an incomplete dirty set would let the
				// peer open the Session with an unacknowledged control state. The
				// caller must fail closed instead of silently waiting forever.
				return resumeDoneState{}, false, errors.New("session: resume dirty-control budget exceeded")
			}
		}
	}
	if len(st.Dirty) > 1 && !sort.SliceIsSorted(st.Dirty, func(i, j int) bool { return resumeControlLess(st.Dirty[i], st.Dirty[j]) }) {
		sort.Slice(st.Dirty, func(i, j int) bool { return resumeControlLess(st.Dirty[i], st.Dirty[j]) })
	}
	return st, true, nil
}

func (s *Session) resumeDoneFrame(flags uint8) (protocol.Frame, bool) {
	if s.current == nil {
		return protocol.Frame{}, false
	}
	if flags == 0 {
		st, ok, err := s.resumeDoneState()
		if err != nil {
			s.cancel()
			return protocol.Frame{}, false
		}
		if !ok {
			return protocol.Frame{}, false
		}
		data := encodeResumeDoneState(st)
		if data == nil {
			// The bounded JSON envelope is part of the recovery contract. A
			// state that cannot fit cannot be retried as an empty barrier.
			s.cancel()
			return protocol.Frame{}, false
		}
		return protocol.Frame{Kind: protocol.ResumeDone, Flow: st.SnapshotCount, Offset: st.Generation,
			Value: st.SessionValue, Data: data}, true
	}
	if s.peerResumeDone == nil {
		return protocol.Frame{}, false
	}
	ack := *s.peerResumeDone
	ack.Dirty = append([]resumeDoneControl(nil), ack.Dirty...)
	data := encodeResumeDoneState(ack)
	if data == nil {
		s.cancel()
		return protocol.Frame{}, false
	}
	return protocol.Frame{Kind: protocol.ResumeDone, Flags: 1, Flow: ack.SnapshotCount,
		Offset: ack.Generation, Data: data}, true
}

func decodeResumeDoneFrame(f protocol.Frame) (resumeDoneState, bool, error) {
	if f.Flags > 1 || f.Offset == 0 || f.Flow > 4096 {
		return resumeDoneState{}, false, errors.New("session: invalid resume done frame scope")
	}
	if f.Flags == 1 && f.Value != 0 {
		return resumeDoneState{}, false, errors.New("session: invalid resume done acknowledgement")
	}
	if len(f.Data) == 0 {
		// Legacy in-process fixtures are accepted only as a compatibility input;
		// all next4 send paths use the versioned payload above.
		return resumeDoneState{Generation: f.Offset, SnapshotCount: f.Flow, SessionValue: f.Value}, true, nil
	}
	st, err := decodeResumeDoneState(f.Data)
	if err != nil {
		return resumeDoneState{}, false, err
	}
	if st.Generation != f.Offset || st.SnapshotCount != f.Flow {
		return resumeDoneState{}, false, errors.New("session: resume done payload disagrees with frame")
	}
	if f.Flags == 0 && st.SessionValue != f.Value {
		return resumeDoneState{}, false, errors.New("session: resume done credit disagrees with frame")
	}
	return st, false, nil
}

func resumeControlEqual(a, b resumeDoneControl) bool {
	if a.Kind != b.Kind || a.Flow != b.Flow || a.Revision != b.Revision || a.Value != b.Value {
		return false
	}
	if len(a.Data) != len(b.Data) {
		return false
	}
	for i := range a.Data {
		if a.Data[i] != b.Data[i] {
			return false
		}
	}
	return true
}

func resumeStateCovers(want, got resumeDoneState) bool {
	if want.Version != got.Version || want.Generation != got.Generation || want.SnapshotID != got.SnapshotID ||
		want.SnapshotCount != got.SnapshotCount || want.SessionRevision != got.SessionRevision || want.SessionValue != got.SessionValue ||
		len(want.Dirty) != len(got.Dirty) {
		return false
	}
	for i := range want.Dirty {
		if !resumeControlEqual(want.Dirty[i], got.Dirty[i]) {
			return false
		}
	}
	return true
}

// resumeStateSupersedes distinguishes a stale receipt from a malformed or
// future receipt. It is only used after generation, snapshot id, and count
// have already matched. A stale receipt can be ignored and retried; an
// unrelated value is an authenticated protocol error.
func resumeStateSupersedes(want, got resumeDoneState) bool {
	if want.Version != got.Version || want.Generation != got.Generation || want.SnapshotID != got.SnapshotID ||
		want.SnapshotCount != got.SnapshotCount {
		return false
	}
	if want.SessionRevision > got.SessionRevision {
		return true
	}
	if want.SessionRevision < got.SessionRevision || want.SessionValue != got.SessionValue {
		return false
	}
	for _, have := range got.Dirty {
		found := false
		for _, current := range want.Dirty {
			if current.Kind != have.Kind || current.Flow != have.Flow {
				continue
			}
			found = true
			if current.Revision > have.Revision {
				return true
			}
			if current.Revision < have.Revision || !resumeControlEqual(current, have) {
				return false
			}
			break
		}
		if !found {
			return false
		}
	}
	return len(want.Dirty) > len(got.Dirty)
}

func (s *Session) applyPeerSessionCredit(revision, value uint64) bool {
	if revision == 0 || value == 0 {
		return false
	}
	if revision < s.peerMaxSessionRevision {
		return value <= s.peerMaxSessionValue
	}
	if revision == s.peerMaxSessionRevision {
		return s.peerMaxSessionRevision == 0 || value == s.peerMaxSessionValue
	}
	if value < s.peerMaxSessionValue {
		return false
	}
	s.peerMaxSessionRevision, s.peerMaxSessionValue = revision, value
	s.peerSessionMax = max(s.peerSessionMax, value)
	return true
}

func (s *Session) applyResumeDirtyControl(c resumeDoneControl) bool {
	switch c.Kind {
	case protocol.StreamAck:
		st := s.streams[c.Flow]
		if st == nil || st.reset || c.Flow == 0 {
			return false
		}
		if c.Revision < st.peerStreamAckRevision {
			return c.Value <= st.peerStreamAckValue
		}
		if c.Revision == st.peerStreamAckRevision {
			return st.peerStreamAckRevision == 0 || c.Value == st.peerStreamAckValue
		}
		if c.Value < st.peerStreamAckValue || !s.ack(st, c.Value) {
			return false
		}
		st.peerStreamAckRevision, st.peerStreamAckValue = c.Revision, c.Value
		return true
	case protocol.MaxFlowData:
		st := s.streams[c.Flow]
		if st == nil || st.reset || c.Flow == 0 {
			return false
		}
		if c.Revision < st.peerMaxFlowRevision {
			return c.Value <= st.peerMaxFlowValue
		}
		if c.Revision == st.peerMaxFlowRevision {
			return st.peerMaxFlowRevision == 0 || c.Value == st.peerMaxFlowValue
		}
		if c.Value < st.peerMaxFlowValue {
			return false
		}
		st.peerMaxFlowRevision, st.peerMaxFlowValue = c.Revision, c.Value
		st.maxRemote = max(st.maxRemote, c.Value)
		return true
	case protocol.MaxSessionData:
		return s.applyPeerSessionCredit(c.Revision, c.Value)
	case protocol.OpenResult:
		if !s.client || c.Flow == 0 || c.Value != 0 || len(c.Data) == 0 {
			return false
		}
		st := s.streams[c.Flow]
		if st == nil || st.reset {
			return false
		}
		result := string(c.Data)
		if c.Revision < st.peerOpenResultRevision {
			return result == st.peerOpenResultValue
		}
		if c.Revision == st.peerOpenResultRevision {
			return st.peerOpenResultRevision == 0 || result == st.peerOpenResultValue
		}
		if st.peerOpenResultRevision != 0 && result != st.peerOpenResultValue {
			return false
		}
		st.peerOpenResultRevision, st.peerOpenResultValue = c.Revision, result
		if st.opening {
			s.result(st, result)
		}
		return true
	default:
		return false
	}
}

func (s *Session) applyResumeDoneState(st resumeDoneState) bool {
	if s.current == nil || st.Generation != s.current.generation {
		return false
	}
	if st.Version == 0 {
		if st.SessionValue != 0 {
			s.peerSessionMax = max(s.peerSessionMax, st.SessionValue)
		}
		return true
	}
	if err := validateResumeDoneState(st); err != nil {
		return false
	}
	if !s.applyPeerSessionCredit(st.SessionRevision, st.SessionValue) {
		return false
	}
	for _, c := range st.Dirty {
		if !s.applyResumeDirtyControl(c) {
			return false
		}
	}
	return true
}
