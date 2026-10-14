package session

import (
	"bfp/classification"
	"bfp/protocol"
	"context"
	"errors"
	"sort"
	"time"
)

var ErrFlowUnknown = errors.New("session: unknown flow")

// FlowClassification separates local sending policy from the read-only peer
// TX view. Querying it does not advance time or classify control traffic.
type FlowClassification struct {
	TXVersion, TXPublishedVersion, TXAckedVersion uint64
	TXPending                                     bool
	PeerTX                                        PeerTXClassification
	ID                                            uint64
	Network                                       string
	LocalTX                                       classification.Snapshot
	Terminal                                      bool
}

type PeerTXClassification struct {
	Known   bool
	Version uint64
	Class   protocol.Class
}

func compileClassification(cfg *classification.Config) (*classification.Classifier, error) {
	if cfg == nil {
		defaults := classification.DefaultConfig()
		cfg = &defaults
	}
	return classification.New(*cfg)
}

// FlowClassification obtains an actor-owned snapshot without Tick or mutation.
func (s *Session) FlowClassification(ctx context.Context, id uint64) (FlowClassification, error) {
	var out FlowClassification
	var queryErr error
	if s.terminating() {
		return out, ErrClosed
	}
	err := s.call(ctx, func() {
		if s.terminating() {
			queryErr = ErrClosed
			return
		}
		st := s.streams[id]
		if st == nil {
			queryErr = ErrFlowUnknown
			return
		}
		if st.txClassifier == nil {
			queryErr = ErrState
			return
		}
		out = s.classificationSnapshot(st)
	})
	if err != nil {
		return FlowClassification{}, err
	}
	return out, queryErr
}

func (s *Session) classificationSnapshot(st *streamState) FlowClassification {
	out := FlowClassification{ID: st.flow.id, Network: st.target.Network, LocalTX: st.txClassifier.Snapshot(), Terminal: st.terminal(), TXVersion: st.classTX.Version}
	if s.classTable != nil {
		if view, err := s.classTable.Snapshot(st.flow.id); err == nil {
			out.TXVersion, out.TXPublishedVersion, out.TXAckedVersion = view.Local.Version, view.Published.Version, view.Acked.Version
			out.TXPending = view.Pending
			out.PeerTX = PeerTXClassification{Known: view.Peer.Known, Version: view.Peer.State.Version, Class: view.Peer.State.Class}
		}
	}
	return out
}

// FlowClassifications returns bounded, ordered copies of live flow diagnostics.
// It includes no target addresses or credentials and never advances a clock.
func (s *Session) FlowClassifications(ctx context.Context) ([]FlowClassification, error) {
	var out []FlowClassification
	if s.terminating() {
		return nil, ErrClosed
	}
	err := s.call(ctx, func() {
		if s.terminating() {
			return
		}
		for _, st := range s.streams {
			if st.txClassifier != nil && !st.terminal() {
				out = append(out, s.classificationSnapshot(st))
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	})
	return out, err
}

func (f *Flow) Classification(ctx context.Context) (FlowClassification, error) {
	return f.s.FlowClassification(ctx, f.id)
}

// classTime is sampled at actual actor processing time, never from a buffered
// ticker value. classNow is a package-private clock seam used only by tests.
func (s *Session) classTime() time.Duration { return s.classNow().Sub(s.classOrigin) }

func (s *Session) observeTX(st *streamState, bytes uint64) {
	if st.txClassifier == nil {
		return
	} // Only synthetic/failed states lack it.
	update, err := st.txClassifier.Observe(s.classTime(), bytes)
	if err != nil {
		s.cancel()
		return
	}
	st.effectiveClass = update.Snapshot.Class
	if update.Changed {
		s.updateClassControl(st)
	}
	// Queued control/data retain FIFO and their original item classes. Do not
	// ReclassifyFlow: that would downgrade already queued control messages too.
}

func (s *Session) tickClassification() {
	if s.classNow == nil {
		return
	} // Raw transition fixtures have no clock.
	elapsed := s.classTime()
	for _, st := range s.streams {
		if st.txClassifier == nil || st.terminal() {
			continue
		}
		update, err := st.txClassifier.Tick(elapsed)
		if err != nil {
			s.cancel()
			return
		}
		st.effectiveClass = update.Snapshot.Class
		if update.Changed {
			s.updateClassControl(st)
		}
	}
}
