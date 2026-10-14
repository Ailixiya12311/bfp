package session

import (
	"context"
	"regexp"
	"testing"
	"time"
)

func TestClientParentTerminationDiagnostic(t *testing.T) {
	for _, action := range []string{"Abort", "Close"} {
		t.Run(action+"-isolated-owner", func(t *testing.T) {
			server, credentials := clientCreationServer(t)
			client, _ := clientCreationClient(t, server, credentials, nil)
			// A parent-owned actor outside current/owners isolates propagation:
			// Abort cannot overwrite it with its explicit per-owner s.cancel.
			owner := newSession(client.sessionCtx, sessionInfo{ID: "parent-diagnostic"}, Options{}, true, nil)
			owner.parentTerminationSource = client.sessionParentSource
			t.Cleanup(func() { owner.cancel(); <-owner.Done() })
			if state := owner.TerminationState(); state != (TerminationState{}) {
				t.Fatalf("live owner reports termination: %+v", state)
			}
			observed := make(chan string, 1)
			go func() {
				<-owner.BusinessDone()
				source, recorded := owner.TerminationSource()
				if !recorded {
					source = "unrecorded"
				}
				observed <- source
			}()
			var err error
			if action == "Abort" {
				err = client.Abort()
			} else {
				err = client.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case source := <-observed:
				if !regexp.MustCompile(`^parent_context_end@client\.go:[1-9][0-9]*$`).MatchString(source) {
					t.Fatalf("BusinessDone did not expose Client parent caller immediately: %q", source)
				}
			case <-time.After(time.Second):
				t.Fatal("parent did not end isolated Session business")
			}
			state := owner.TerminationState()
			if !state.BusinessEnded || !state.ControlEnded || state.CloseIntent || state.LocalClose {
				t.Fatalf("parent-only termination state: %+v", state)
			}
		})
	}
	// Genuine Connect must install the shared pointer before returning a Session.
	// Replace a gracefully draining actor while it is blocked, then Abort both;
	// neither its graceful source nor the fresh actor's explicit cancel source
	// may be replaced by the later parent marker.
	t.Run("published-and-replaced-owner-priority", func(t *testing.T) {
		f, _ := newClassRecoveryFixture(t, false, false)
		old := f.local
		if old.parentTerminationSource == nil || old.parentTerminationSource != f.client.sessionParentSource {
			t.Fatal("Connect published a Session without its independent parent marker")
		}
		unblock := next10BlockActor(t, old)
		oldClose := next10BeginCloseAtBarrier(t, old)
		t.Cleanup(unblock)
		oldSource, recorded := old.TerminationSource()
		if !recorded || !regexp.MustCompile(`^local_close@session\.go:[1-9][0-9]*$`).MatchString(oldSource) {
			t.Fatalf("old graceful source missing: %q", oldSource)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		fresh, err := f.client.Connect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if fresh == old || fresh.parentTerminationSource != f.client.sessionParentSource {
			t.Fatal("replacement owner did not receive the shared parent marker")
		}
		fresh.cancel()
		<-fresh.BusinessDone()
		freshSource, recorded := fresh.TerminationSource()
		if !recorded || !regexp.MustCompile(`^termination_parent_diagnostic_test\.go:[1-9][0-9]*$`).MatchString(freshSource) {
			t.Fatalf("explicit cancel source missing: %q", freshSource)
		}
		result := make(chan error, 1)
		go func() { result <- f.client.Abort() }()
		select {
		case <-f.client.sessionCtx.Done():
		case <-time.After(time.Second):
			t.Fatal("Abort did not cancel parent")
		}
		if source, recorded := old.TerminationSource(); !recorded || source != oldSource {
			t.Fatalf("parent replaced graceful origin: %q", source)
		}
		if source, recorded := fresh.TerminationSource(); !recorded || source != freshSource {
			t.Fatalf("parent replaced explicit cancel origin: %q", source)
		}
		unblock()
		_ = next11AbortResult(t, result)
		_ = next11AbortResult(t, oldClose)
	})
	t.Run("legacy-without-parent-metadata", func(t *testing.T) {
		parent, cancel := context.WithCancel(context.Background())
		owner := newSession(parent, sessionInfo{ID: "legacy-parent-diagnostic"}, Options{}, true, nil)
		t.Cleanup(func() { owner.cancel(); <-owner.Done() })
		cancel()
		<-owner.BusinessDone()
		if source, recorded := owner.TerminationSource(); recorded || source != "" {
			t.Fatalf("legacy constructor invented parent metadata: %q %t", source, recorded)
		}
		var absent *Session
		if absent.TerminationState() != (TerminationState{}) {
			t.Fatal("nil state is not zero")
		}
	})
}
