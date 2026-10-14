package session

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"bfp/protocol"
)

func TestSessionTerminationSourceBeforeGracefulBusinessDone(t *testing.T) {
	for _, kind := range []string{"udp", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			f := newCloseTestFixture(t, kind, 450*time.Millisecond, nil)
			f.flow(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			type observation struct {
				source   string
				recorded bool
			}
			observations := [2]chan observation{make(chan observation, 1), make(chan observation, 1)}
			for index, owner := range f.sessions {
				go func() {
					select {
					case <-owner.BusinessDone():
						source, recorded := owner.TerminationSource()
						observations[index] <- observation{source, recorded}
					case <-ctx.Done():
					}
				}()
			}
			result := make(chan error, 1)
			go func() { result <- f.sessions[0].Close() }()
			want := [2]string{`^local_close@session\.go:[1-9][0-9]*$`, `^peer_close@close_control\.go:[1-9][0-9]*$`}
			var sources [2]string
			for index := range observations {
				select {
				case got := <-observations[index]:
					if !got.recorded || !regexp.MustCompile(want[index]).MatchString(got.source) {
						t.Fatalf("owner %d BusinessDone exposed no valid graceful origin: %+v", index, got)
					}
					sources[index] = got.source
				case <-time.After(time.Second):
					t.Fatalf("owner %d did not end business after authenticated close", index)
				}
			}
			if len(f.relay.selected(0, protocol.SessionClose)) == 0 {
				t.Fatal("peer origin was not preceded by a real authenticated SessionClose record")
			}
			select {
			case err := <-result:
				if err != nil && !errors.Is(err, ErrCloseUnconfirmed) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("diagnostic observation changed bounded close completion")
			}
			for index, owner := range f.sessions {
				// A later abort must not replace the first intent origin.
				owner.cancel()
				if source, recorded := owner.TerminationSource(); !recorded || source != sources[index] {
					t.Fatalf("later cancel replaced first graceful origin: %q", source)
				}
			}
		})
	}
	t.Run("cancel-first", func(t *testing.T) {
		owner := newSession(context.Background(), sessionInfo{ID: "termination-source"}, Options{}, true, nil)
		t.Cleanup(func() { owner.cancel(); <-owner.Done() })
		owner.cancel()
		<-owner.BusinessDone()
		source, recorded := owner.TerminationSource()
		if !recorded || !regexp.MustCompile(`^termination_source_close_test\.go:[1-9][0-9]*$`).MatchString(source) {
			t.Fatalf("abort source was unavailable immediately after BusinessDone: %q %t", source, recorded)
		}
		owner.requestClose(true, time.Now())
		if got, recorded := owner.TerminationSource(); !recorded || got != source {
			t.Fatalf("later graceful intent replaced first abort source: %q", got)
		}
	})
}
