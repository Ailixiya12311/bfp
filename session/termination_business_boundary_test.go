package session

import (
	"context"
	"regexp"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the cancellation boundary independently of graceful intent and
// Client parent cancellation. These observations diagnose a stop; they do not
// establish why a production caller chose to stop its business context.
func TestBusinessStopBoundaryDiagnostic(t *testing.T) {
	newOwner := func(t *testing.T) *Session {
		t.Helper()
		owner := newSession(context.Background(), sessionInfo{ID: "business-boundary", lifetimeUntil: time.Now().Add(time.Minute)}, Options{}, true, nil)
		t.Cleanup(func() { owner.cancel(); <-owner.Done() })
		return owner
	}
	checkSource := func(t *testing.T, owner *Session, pattern string) string {
		t.Helper()
		source, recorded := owner.TerminationSource()
		if !recorded || !regexp.MustCompile(pattern).MatchString(source) {
			t.Fatalf("termination source=%q recorded=%t want pattern=%q", source, recorded, pattern)
		}
		return source
	}
	for _, withScope := range []bool{false, true} {
		name := "direct-business-stop"
		if withScope {
			name = "client-scope-wrapper"
		}
		t.Run(name, func(t *testing.T) {
			var owner *Session
			var scope *testClientAddressScope
			pattern := `^raw_business_stop@termination_business_boundary_test\.go:[1-9][0-9]*$`
			if withScope {
				scope = &testClientAddressScope{}
				var err error
				owner, err = newSessionWithAddressScope(context.Background(), sessionInfo{ID: "business-scope-boundary", lifetimeUntil: time.Now().Add(time.Minute)}, Options{}, true, nil, datagramFECPolicy{}, &testClientScopeFactory{scope: scope})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { owner.cancel(); <-owner.Done() })
				pattern = `^raw_business_stop@client_address_scope\.go:[1-9][0-9]*$`
			} else {
				owner = newOwner(t)
			}
			if state := owner.TerminationState(); state != (TerminationState{}) {
				t.Fatalf("live owner already ended: %+v", state)
			}
			// A BusinessDone observer must see the boundary caller on its first
			// read, even if scope retirement has not finished running yet.
			type observation struct {
				source   string
				recorded bool
				state    TerminationState
			}
			observed := make(chan observation, 1)
			go func() {
				<-owner.BusinessDone()
				source, recorded := owner.TerminationSource()
				observed <- observation{source, recorded, owner.TerminationState()}
			}()
			owner.stopBusiness()
			select {
			case got := <-observed:
				if !got.recorded || !regexp.MustCompile(pattern).MatchString(got.source) {
					t.Fatalf("first BusinessDone observation source=%q recorded=%t", got.source, got.recorded)
				}
				want := TerminationState{BusinessEnded: true}
				if got.state != want {
					t.Fatalf("business-only stop state=%+v want=%+v", got.state, want)
				}
			case <-time.After(time.Second):
				t.Fatal("business-only stop did not notify observer")
			}
			first := checkSource(t, owner, pattern)
			owner.stopBusiness()
			if after := checkSource(t, owner, pattern); after != first {
				t.Fatalf("repeated stop replaced boundary caller: first=%q after=%q", first, after)
			}
			if scope != nil && (!scope.closed.Load() || scope.closes.Load() != 1) {
				t.Fatal("business-only scope stop did not retire its map exactly once")
			}
		})
	}
	t.Run("explicit-cancel-source-priority", func(t *testing.T) {
		owner := newOwner(t)
		owner.stopBusiness()
		checkSource(t, owner, `^raw_business_stop@termination_business_boundary_test\.go:[1-9][0-9]*$`)
		owner.cancel()
		checkSource(t, owner, `^termination_business_boundary_test\.go:[1-9][0-9]*$`)
		<-owner.Done()
	})
	t.Run("graceful-source-priority", func(t *testing.T) {
		owner := newOwner(t)
		owner.requestClose(true, owner.closeTime())
		first := checkSource(t, owner, `^local_close@termination_business_boundary_test\.go:[1-9][0-9]*$`)
		owner.cancel()
		if after := checkSource(t, owner, `^local_close@termination_business_boundary_test\.go:[1-9][0-9]*$`); after != first {
			t.Fatalf("cancel replaced first graceful source: first=%q after=%q", first, after)
		}
		<-owner.Done()
	})
	t.Run("parent-source-survives-actor-retirement", func(t *testing.T) {
		parent, stopParent := context.WithCancel(context.Background())
		defer stopParent()
		owner := newSession(parent, sessionInfo{ID: "parent-boundary"}, Options{}, true, nil)
		t.Cleanup(func() { owner.cancel(); <-owner.Done() })
		metadata := &atomic.Pointer[string]{}
		owner.parentTerminationSource = metadata
		source := "client.go:227"
		metadata.Store(&source)
		stopParent()
		<-owner.Done()
		checkSource(t, owner, `^parent_context_end@client\.go:227$`)
		if owner.businessStopSource.Load() != nil {
			t.Fatal("actor retirement recorded raw stop after parent had already canceled business")
		}
	})
	t.Run("legacy-parent-remains-unrecorded", func(t *testing.T) {
		parent, stopParent := context.WithCancel(context.Background())
		defer stopParent()
		owner := newSession(parent, sessionInfo{ID: "legacy-parent-boundary"}, Options{}, true, nil)
		t.Cleanup(func() { owner.cancel(); <-owner.Done() })
		stopParent()
		<-owner.Done()
		if source, recorded := owner.TerminationSource(); recorded || source != "" {
			t.Fatalf("legacy parent cancellation invented raw source: %q recorded=%t", source, recorded)
		}
		if owner.businessStopSource.Load() != nil {
			t.Fatal("retirement polluted legacy parent diagnostic")
		}
	})
}
