package clientconfig_test

import (
	"bfp/clientconfig"
	"bfp/internal/securefile"
	"bfp/security"
	"bfp/session"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func credentialsFixture(t *testing.T) session.Credentials {
	t.Helper()
	client, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal("generate client fixture")
	}
	server, err := security.GenerateKeyPair()
	if err != nil {
		t.Fatal("generate server fixture")
	}
	admission := make([]byte, 32)
	if _, err := rand.Read(admission); err != nil {
		t.Fatal("generate admission fixture")
	}
	return session.Credentials{Admission: admission, Private: client.Private, Public: client.Public, ServerPublic: server.Public}
}

func credentialBody(t *testing.T, credentials session.Credentials) []byte {
	t.Helper()
	body, err := json.Marshal(credentials)
	if err != nil {
		t.Fatal("encode credential fixture")
	}
	return body
}

func clientBody(t *testing.T, credentials session.Credentials) []byte {
	t.Helper()
	body, err := json.Marshal(struct {
		Server      string              `json:"server"`
		TCPServer   string              `json:"tcp_server"`
		SOCKS       string              `json:"socks"`
		Credentials session.Credentials `json:"credentials"`
	}{"127.0.0.1:51880", "", "127.0.0.1:1080", credentials})
	if err != nil {
		t.Fatal("encode client fixture")
	}
	return body
}

func privateFixture(t *testing.T, body []byte) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "private")
	if securefile.MakePrivateDir(directory) != nil {
		t.Fatal("create private fixture directory")
	}
	path := filepath.Join(directory, "client.json")
	if securefile.WriteExclusive(path, body) != nil {
		t.Fatal("write private fixture")
	}
	return path
}

func appendField(body []byte, field string) []byte {
	return []byte(string(body[:len(body)-1]) + "," + field + "}")
}

func sameCredentials(a, b session.Credentials) bool {
	return bytes.Equal(a.Admission, b.Admission) && bytes.Equal(a.Private, b.Private) && bytes.Equal(a.Public, b.Public) && bytes.Equal(a.ServerPublic, b.ServerPublic)
}

func safeError(t *testing.T, err error, credentials session.Credentials) {
	t.Helper()
	if err == nil {
		t.Fatal("expected rejection")
	}
	for _, value := range [][]byte{credentials.Admission, credentials.Private, credentials.Public, credentials.ServerPublic} {
		if strings.Contains(err.Error(), base64.StdEncoding.EncodeToString(value)) {
			t.Fatal("error contains fixture credential")
		}
	}
	if strings.Contains(err.Error(), "do-not-echo") {
		t.Fatal("error echoed supplied field or value")
	}
}

func TestLoadProtectedClientAndStandaloneCredentials(t *testing.T) {
	credentials := credentialsFixture(t)
	file, err := clientconfig.Load(privateFixture(t, clientBody(t, credentials)))
	if err != nil {
		t.Fatal("load protected client fixture")
	}
	if file.Session.Server != "127.0.0.1:51880" || file.Session.TCPServer != "" || file.SOCKSListen != "127.0.0.1:1080" || !sameCredentials(file.Session.Credentials, credentials) {
		t.Fatal("base client fields were changed")
	}
	client, err := session.NewClient(file.Session)
	if err != nil {
		t.Fatal("ordinary constructor rejected loaded credentials")
	}
	if err := client.Close(); err != nil {
		t.Fatal("close unconnected client")
	}
	standalone, err := clientconfig.LoadCredentials(privateFixture(t, credentialBody(t, credentials)))
	if err != nil || !sameCredentials(standalone, credentials) {
		t.Fatal("standalone credentials changed")
	}
	minimal := []byte(`{"server":"127.0.0.1:1","credentials":` + string(credentialBody(t, credentials)) + `}`)
	file, err = clientconfig.Load(privateFixture(t, minimal))
	if err != nil || file.Session.TCPServer != "" || file.SOCKSListen != "" {
		t.Fatal("omitted optional endpoints did not retain zero values")
	}
}

func TestLoadRejectsMalformedExactAndDuplicateFieldsWithoutEcho(t *testing.T) {
	credentials := credentialsFixture(t)
	valid := clientBody(t, credentials)
	privateJSON := `"private":"` + base64.StdEncoding.EncodeToString(credentials.Private) + `"`
	cases := map[string][]byte{
		"unknown":        appendField(valid, `"do-not-echo-name":"do-not-echo-value"`),
		"case-root":      []byte(strings.Replace(string(valid), `"server":`, `"Server":`, 1)),
		"case-key":       []byte(strings.Replace(string(valid), `"private":`, `"Private":`, 1)),
		"duplicate":      appendField(valid, `"server":"do-not-echo"`),
		"escaped-dupe":   appendField(valid, `"\u0073erver":"do-not-echo"`),
		"key-duplicate":  []byte(strings.Replace(string(valid), `"private":`, `"admission":"do-not-echo","private":`, 1)),
		"key-unknown":    []byte(strings.Replace(string(valid), `"private":`, `"do-not-echo":"do-not-echo","private":`, 1)),
		"key-missing":    []byte(strings.Replace(string(valid), `"server_public":`, `"do-not-echo":`, 1)),
		"key-null":       []byte(strings.Replace(string(valid), privateJSON, `"private":null`, 1)),
		"key-base64":     []byte(strings.Replace(string(valid), privateJSON, `"private":"do-not-echo!"`, 1)),
		"trailing":       append(append([]byte(nil), valid...), []byte(" {}")...),
		"garbage":        append(append([]byte(nil), valid...), []byte(" do-not-echo")...),
		"array":          []byte("[]"),
		"null":           []byte("null"),
		"empty":          nil,
		"missing":        []byte(`{"server":"127.0.0.1:1"}`),
		"empty-server":   []byte(strings.Replace(string(valid), `"127.0.0.1:51880"`, `""`, 1)),
		"null-server":    []byte(strings.Replace(string(valid), `"127.0.0.1:51880"`, `null`, 1)),
		"null-tcp":       []byte(strings.Replace(string(valid), `"tcp_server":""`, `"tcp_server":null`, 1)),
		"null-socks":     []byte(strings.Replace(string(valid), `"socks":"127.0.0.1:1080"`, `"socks":null`, 1)),
		"null-keys":      []byte(`{"server":"127.0.0.1:1","credentials":null}`),
		"high-surrogate": []byte(strings.Replace(string(valid), `"127.0.0.1:51880"`, `"\ud800:51880"`, 1)),
		"low-surrogate":  []byte(strings.Replace(string(valid), `"127.0.0.1:51880"`, `"\udc00:51880"`, 1)),
		"invalid-utf8":   append([]byte{'{', '"', 0xff, '"', ':', '1', '}'}, '\n'),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			file, err := clientconfig.Load(privateFixture(t, body))
			if !errors.Is(err, clientconfig.ErrInvalid) || file.Session.Server != "" || len(file.Session.Credentials.Private) != 0 {
				t.Fatal("malformed configuration did not fail closed")
			}
			safeError(t, err, credentials)
		})
	}
}

func TestLoadRejectsEveryUnsupportedFieldEvenEmpty(t *testing.T) {
	credentials := credentialsFixture(t)
	valid := clientBody(t, credentials)
	for _, field := range []string{"options", "socks_metadata", "datagram_fec", "dns"} {
		for _, value := range []string{"null", "{}", "[]", `""`, "false"} {
			t.Run(field+"/"+value, func(t *testing.T) {
				_, err := clientconfig.Load(privateFixture(t, appendField(valid, `"`+field+`":`+value)))
				if !errors.Is(err, clientconfig.ErrUnsupported) {
					t.Fatal("unsupported configuration selected a silent default")
				}
				safeError(t, err, credentials)
			})
		}
	}
}

func TestLoadClassificationPolicyAndRejectMalformedPolicy(t *testing.T) {
	credentials := credentialsFixture(t)
	valid := clientBody(t, credentials)
	policy := `"classification":{"default_class":"bulk","behavior":{"enabled":false},"rules":[{"name":"dns","network":"udp","ports":[{"first":53,"last":53}],"class":"interactive","locked":true}]}`
	loaded, err := clientconfig.Load(privateFixture(t, appendField(valid, policy)))
	if err != nil || loaded.Session.Classification == nil || len(loaded.Session.Classification.Rules) != 1 || !sameCredentials(loaded.Session.Credentials, credentials) {
		t.Fatal("runtime classification policy was not loaded with the original credentials")
	}
	client, err := session.NewClient(loaded.Session)
	if err != nil {
		t.Fatal("ordinary Session constructor rejected the loaded policy")
	}
	client.Close()
	for _, value := range []string{
		`null`, `[]`, `false`,
		`{"default_class":"do-not-echo"}`,
		`{"default_class":"normal","default_class":"bulk"}`,
		`{"behavior":{"window":"do-not-echo"}}`,
		`{"rules":[{"name":"bad","class":"interactive","ports":[{"first":0,"last":53}]}]}`,
		`{"do-not-echo":"do-not-echo"}`,
	} {
		loaded, err := clientconfig.Load(privateFixture(t, appendField(valid, `"classification":`+value)))
		if !errors.Is(err, clientconfig.ErrInvalid) || len(loaded.Session.Credentials.Private) != 0 || loaded.Session.Classification != nil {
			t.Fatal("malformed policy was accepted or returned partial credentials")
		}
		safeError(t, err, credentials)
	}
}

func TestStandaloneCredentialSchemaIsStrict(t *testing.T) {
	credentials := credentialsFixture(t)
	valid := credentialBody(t, credentials)
	for name, body := range map[string][]byte{
		"duplicate":      appendField(valid, `"private":"do-not-echo"`),
		"server-only":    appendField(valid, `"allowed_clients":[]`),
		"unknown":        appendField(valid, `"do-not-echo":"do-not-echo"`),
		"case":           []byte(strings.Replace(string(valid), `"private":`, `"Private":`, 1)),
		"missing":        []byte(`{"admission":"","private":"","public":""}`),
		"null-field":     []byte(`{"admission":"","private":null,"public":"","server_public":""}`),
		"invalid-base64": []byte(`{"admission":"","private":"do-not-echo!","public":"","server_public":""}`),
		"trailing":       append(append([]byte(nil), valid...), []byte(" {}")...),
		"utf8":           []byte{'{', '"', 0xff, '"', ':', '0', '}'},
	} {
		t.Run(name, func(t *testing.T) {
			loaded, err := clientconfig.LoadCredentials(privateFixture(t, body))
			if !errors.Is(err, clientconfig.ErrInvalid) || len(loaded.Private) != 0 {
				t.Fatal("standalone credential schema did not fail closed")
			}
			safeError(t, err, credentials)
		})
	}
}

func TestNormalConstructorRejectsDecodedInvalidKeys(t *testing.T) {
	for _, kind := range []string{"admission-length", "private-length", "public-mismatch", "pin-length", "pin-low-order"} {
		t.Run(kind, func(t *testing.T) {
			credentials := credentialsFixture(t)
			switch kind {
			case "admission-length":
				credentials.Admission = credentials.Admission[:31]
			case "private-length":
				credentials.Private = credentials.Private[:31]
			case "public-mismatch":
				credentials.Public[0] ^= 0x80
			case "pin-length":
				credentials.ServerPublic = credentials.ServerPublic[:31]
			case "pin-low-order":
				credentials.ServerPublic = make([]byte, 32)
			}
			file, err := clientconfig.Load(privateFixture(t, clientBody(t, credentials)))
			if err != nil {
				t.Fatal("loader replaced the constructor's cryptographic validation")
			}
			client, err := session.NewClient(file.Session)
			if err == nil || client != nil {
				if client != nil {
					client.Close()
				}
				t.Fatal("normal constructor accepted invalid decoded credentials")
			}
			safeError(t, err, credentials)
		})
	}
}

func TestBothLoadersRejectOversizedUnsafeAndLinkedFiles(t *testing.T) {
	loaders := map[string]func(string) error{
		"client":      func(path string) error { _, err := clientconfig.Load(path); return err },
		"credentials": func(path string) error { _, err := clientconfig.LoadCredentials(path); return err },
	}
	for name, load := range loaders {
		t.Run(name, func(t *testing.T) {
			if err := load(privateFixture(t, bytes.Repeat([]byte{' '}, clientconfig.MaxFileBytes+1))); !errors.Is(err, clientconfig.ErrFileSize) {
				t.Fatal("oversized private file accepted")
			}
			path := privateFixture(t, []byte("non-secret permissions fixture"))
			makePubliclyReadable(t, path)
			if err := load(path); !errors.Is(err, clientconfig.ErrUnsafeFile) {
				t.Fatal("unsafe file permissions accepted")
			}
			path = privateFixture(t, []byte("non-secret link fixture"))
			linked := linkedParent(t, path)
			if err := load(linked); !errors.Is(err, clientconfig.ErrUnsafeFile) {
				t.Fatal("linked parent accepted")
			}
			if err := load(filepath.Dir(path)); err == nil {
				t.Fatal("directory accepted as a regular credential file")
			}
			if err := load(filepath.Join(t.TempDir(), "missing.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("missing file error not preserved")
			}
		})
	}
}

func TestExactFileLimitAndValidUnicodeEscapes(t *testing.T) {
	credentials := credentialsFixture(t)
	clientJSON := clientBody(t, credentials)
	clientJSON = append(clientJSON, bytes.Repeat([]byte{' '}, clientconfig.MaxFileBytes-len(clientJSON))...)
	if _, err := clientconfig.Load(privateFixture(t, clientJSON)); err != nil {
		t.Fatal("exact maximum file length rejected")
	}
	credentialJSON := credentialBody(t, credentials)
	credentialJSON = append(credentialJSON, bytes.Repeat([]byte{' '}, clientconfig.MaxFileBytes-len(credentialJSON))...)
	if _, err := clientconfig.LoadCredentials(privateFixture(t, credentialJSON)); err != nil {
		t.Fatal("exact maximum credentials file length rejected")
	}
	for _, host := range []string{`"\ud83d\ude00:443"`, `"\ufffd:443"`, `"literal\\ud800:443"`} {
		body := []byte(strings.Replace(string(clientBody(t, credentials)), `"127.0.0.1:51880"`, host, 1))
		if _, err := clientconfig.Load(privateFixture(t, body)); err != nil {
			t.Fatal("valid Unicode endpoint string was changed or rejected")
		}
	}
}
