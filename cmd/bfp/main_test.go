package main

import (
	"bfp/internal/securefile"
	"bfp/session"
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigReaderRejectsOversizeAndExtraJSON(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if e := securefile.MakePrivateDir(dir); e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name string
		body []byte
		pass bool
	}{
		{"valid", []byte(`{"server":"127.0.0.1:1"}`), true},
		{"unknown", []byte(`{"server":"127.0.0.1:1","secret_unknown":"do-not-echo"}`), false},
		{"second", []byte(`{"server":"127.0.0.1:1"} {}`), false},
		{"garbage", []byte(`{"server":"127.0.0.1:1"} trailing`), false},
		{"oversize", bytes.Repeat([]byte(" "), 65537), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name+".json")
			if e := securefile.WriteExclusive(p, tc.body); e != nil {
				t.Fatal(e)
			}
			var cfg clientConfig
			e := readConfig(p, &cfg)
			if (e == nil) != tc.pass {
				t.Fatalf("accept=%t want=%t", e == nil, tc.pass)
			}
		})
	}
}

func TestKeygenCreatesReadableProtectedCredentialsWithoutOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "credentials")
	if e := keygen(dir); e != nil {
		t.Fatal(e)
	}
	var cfg clientConfig
	if e := readConfig(filepath.Join(dir, "client.json"), &cfg); e != nil {
		t.Fatal(e)
	}
	if cfg.Options != nil {
		t.Fatal("keygen changed the compatible no-options default")
	}
	cc, e := cfg.sessionConfig()
	if e != nil {
		t.Fatal(e)
	}
	c, e := session.NewClient(cc)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	var sc serverConfig
	if e = readConfig(filepath.Join(dir, "server.json"), &sc); e != nil {
		t.Fatal(e)
	}
	if sc.Options != nil {
		t.Fatal("keygen changed the compatible no-options server default")
	}
	sc.Listen = "127.0.0.1:0"
	sessionCfg, e := sc.sessionConfig(&net.Dialer{})
	if e != nil {
		t.Fatal(e)
	}
	s, e := session.NewServer(sessionCfg)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	before, e := securefile.Read(filepath.Join(dir, "server.json"), 65536)
	if e != nil {
		t.Fatal(e)
	}
	if e = keygen(dir); !errors.Is(e, os.ErrExist) {
		t.Fatalf("existing directory was not refused: %v", e)
	}
	after, e := securefile.Read(filepath.Join(dir, "server.json"), 65536)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("existing credentials changed")
	}
}
