package main

import (
	"bfp/internal/securefile"
	"bfp/session"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writePrivateOptionsConfig(t *testing.T, body string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if e := securefile.MakePrivateDir(dir); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "config.json")
	if e := securefile.WriteExclusive(path, []byte(body)); e != nil {
		t.Fatal(e)
	}
	return path
}

func TestLifecycleConfigReadsPrivateDurationStringsAndMapsBothRoles(t *testing.T) {
	path := writePrivateOptionsConfig(t, `{"options":{"ticket_ttl":"12m","ticket_refresh_lead":"90s","ticket_overlap":"2.5s","max_session_lifetime":"36h"}}`)
	var client clientConfig
	if e := readConfig(path, &client); e != nil {
		t.Fatal(e)
	}
	var server serverConfig
	if e := readConfig(path, &server); e != nil {
		t.Fatal(e)
	}
	cc, e := client.sessionConfig()
	if e != nil {
		t.Fatal(e)
	}
	sc, e := server.sessionConfig(&net.Dialer{})
	if e != nil {
		t.Fatal(e)
	}
	want := session.Options{TicketTTL: 12 * time.Minute, TicketRefreshLead: 90 * time.Second, TicketOverlap: 2500 * time.Millisecond, MaxSessionLifetime: 36 * time.Hour}
	if cc.Options != want || sc.Options != want {
		t.Fatalf("lifecycle mappings differ: client=%+v server=%+v", cc.Options, sc.Options)
	}
}

func TestOmittedLifecycleConfigPreservesSessionDefaults(t *testing.T) {
	for _, body := range []string{`{}`, `{"options":{}}`, `{"options":{"ticket_ttl":"8m"}}`} {
		t.Run(body, func(t *testing.T) {
			path := writePrivateOptionsConfig(t, body)
			var cfg clientConfig
			if e := readConfig(path, &cfg); e != nil {
				t.Fatal(e)
			}
			cc, e := cfg.sessionConfig()
			if e != nil {
				t.Fatal(e)
			}
			if cc.Options.TicketRefreshLead != 0 || cc.Options.TicketOverlap != 0 || cc.Options.MaxSessionLifetime != 0 {
				t.Fatal("omitted lifecycle fields did not retain default sentinels")
			}
			if strings.Contains(body, "ticket_ttl") {
				if cc.Options.TicketTTL != 8*time.Minute {
					t.Fatal("explicit TTL was lost")
				}
			} else if cc.Options != (session.Options{}) {
				t.Fatal("absent options did not retain Session defaults")
			}
		})
	}
}

func TestLifecycleConfigRejectsMalformedDurationWithSafeFieldErrors(t *testing.T) {
	for _, field := range []string{"ticket_ttl", "ticket_refresh_lead", "ticket_overlap", "max_session_lifetime"} {
		for _, raw := range []string{`"private-invalid-value"`, `""`, `"-1s"`, `"0s"`, `null`, `123`, `true`, `{}`, `[]`, `"1d"`, `"999999999999999999999h"`} {
			t.Run(field+"/"+raw, func(t *testing.T) {
				path := writePrivateOptionsConfig(t, `{"options":{"`+field+`":`+raw+`}}`)
				for _, cfg := range []any{&clientConfig{}, &serverConfig{}} {
					e := readConfig(path, cfg)
					if e == nil || !strings.Contains(e.Error(), "options."+field) {
						t.Fatalf("expected named field error, got %v", e)
					}
					if strings.Contains(e.Error(), "private-invalid-value") {
						t.Fatal("duration diagnostic echoed invalid input")
					}
				}
			})
		}
	}
}

func TestLifecycleConfigRejectsBoundsAndUnknownOptions(t *testing.T) {
	cases := []struct {
		body  string
		field string
	}{
		{`{"ticket_ttl":"39ms"}`, "ticket_ttl"},
		{`{"ticket_ttl":"721h"}`, "ticket_ttl"},
		{`{"max_session_lifetime":"39ms"}`, "max_session_lifetime"},
		{`{"max_session_lifetime":"721h"}`, "max_session_lifetime"},
		{`{"ticket_refresh_lead":"500us"}`, "ticket_refresh_lead"},
		{`{"ticket_ttl":"1s","ticket_refresh_lead":"1s"}`, "ticket_refresh_lead"},
		{`{"ticket_refresh_lead":"21m"}`, "ticket_refresh_lead"},
		{`{"ticket_overlap":"500us"}`, "ticket_overlap"},
		{`{"ticket_ttl":"1s","ticket_overlap":"2s"}`, "ticket_overlap"},
		{`{"ticket_overlap":"21m"}`, "ticket_overlap"},
	}
	for _, tc := range cases {
		path := writePrivateOptionsConfig(t, `{"options":`+tc.body+`}`)
		var cfg clientConfig
		e := readConfig(path, &cfg)
		if e == nil || !strings.Contains(e.Error(), "options."+tc.field) {
			t.Fatalf("expected %s bound error, got %v", tc.field, e)
		}
	}
	for _, body := range []string{`{"options":{"unknown_lifecycle":"private-invalid-value"}}`, `{"options":123}`, `{"options":"private-invalid-value"}`} {
		path := writePrivateOptionsConfig(t, body)
		var cfg clientConfig
		if e := readConfig(path, &cfg); e == nil || strings.Contains(e.Error(), "private-invalid-value") {
			t.Fatalf("malformed options accepted or input leaked: %v", e)
		}
	}
}

func TestLifecycleConfigBoundaryAcceptedByRealSessionConstructors(t *testing.T) {
	keydir := filepath.Join(t.TempDir(), "keys")
	if e := keygen(keydir); e != nil {
		t.Fatal(e)
	}
	var client clientConfig
	if e := readConfig(filepath.Join(keydir, "client.json"), &client); e != nil {
		t.Fatal(e)
	}
	var server serverConfig
	if e := readConfig(filepath.Join(keydir, "server.json"), &server); e != nil {
		t.Fatal(e)
	}
	for _, body := range []string{`{"ticket_ttl":"40ms","ticket_refresh_lead":"1ms","ticket_overlap":"40ms","max_session_lifetime":"40ms"}`, `{"ticket_ttl":"720h","max_session_lifetime":"720h"}`} {
		var options configOptions
		if e := json.Unmarshal([]byte(body), &options); e != nil {
			t.Fatal(e)
		}
		client.Options, server.Options = &options, &options
		cc, e := client.sessionConfig()
		if e != nil {
			t.Fatal(e)
		}
		c, e := session.NewClient(cc)
		if e != nil {
			t.Fatalf("client rejected documented CLI bounds: %v", e)
		}
		c.Close()
		server.Listen = "127.0.0.1:0"
		sc, e := server.sessionConfig(&net.Dialer{})
		if e != nil {
			t.Fatal(e)
		}
		s, e := session.NewServer(sc)
		if e != nil {
			t.Fatalf("server rejected documented CLI bounds: %v", e)
		}
		s.Close()
	}
}

func TestCLICommandsRejectLifecycleDurationBeforeNetwork(t *testing.T) {
	original := os.Args
	t.Cleanup(func() { os.Args = original })
	for _, command := range []string{"server", "client", "probe"} {
		for _, field := range []string{"ticket_ttl", "ticket_refresh_lead", "ticket_overlap", "max_session_lifetime"} {
			t.Run(command+"/"+field, func(t *testing.T) {
				path := writePrivateOptionsConfig(t, `{"options":{"`+field+`":"invalid-private-duration"}}`)
				os.Args = []string{"bfp", command, "-config", path}
				e := run()
				if e == nil || !strings.Contains(e.Error(), "options."+field) || strings.Contains(e.Error(), "invalid-private-duration") {
					t.Fatalf("command did not reject duration safely before credentials/network: %v", e)
				}
			})
		}
	}
}
