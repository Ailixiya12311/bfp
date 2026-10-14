// Package clientconfig loads bounded private credential files for applications
// outside the bfp module. It never starts a listener, dials a carrier, or logs
// configuration contents.
package clientconfig

import (
	"bfp/internal/configjson"
	"bfp/internal/securefile"
	"bfp/session"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"
)

// MaxFileBytes matches the CLI's private configuration file limit.
const MaxFileBytes = 65536

var (
	ErrInvalid     = errors.New("clientconfig: invalid configuration")
	ErrUnsupported = errors.New("clientconfig: unsupported configuration field")
	ErrUnsafeFile  = securefile.ErrUnsafe
	ErrFileSize    = securefile.ErrSize
)

// Config is a keygen-compatible client configuration. SOCKSListen is
// merely an adapter setting; Load does not bind it. Call session.NewClient with
// Session to perform the ordinary keypair, pinned-key and policy validation.
type Config struct {
	Session     session.ClientConfig
	SOCKSListen string
}

// Load reads the base client.json format emitted by bfp keygen. Supported root
// fields are server, tcp_server, socks, credentials and classification. Classification
// uses the same strict policy decoder as the standalone CLI. Advanced CLI options,
// socks_metadata, datagram_fec and dns are deliberately unsupported:
// their presence is an error even when the value is null or an empty object.
// Hosts configure supported runtime policies explicitly on the returned Session.
// All names are exact, duplicate/unknown fields and trailing JSON are rejected,
// and parser errors never include supplied keys, values or credential contents.
// Existing path symlinks/reparse points and unsafe native file permissions are
// rejected. As with securefile, parents must be trusted against replacement
// during the check/open sequence; this is not a race-proof ancestor traversal.
func Load(path string) (Config, error) {
	body, err := securefile.Read(path, MaxFileBytes)
	if err != nil {
		return Config{}, err
	}
	defer clear(body)
	values, err := object(body, "server", "tcp_server", "socks", "credentials", "options", "classification", "socks_metadata", "datagram_fec", "dns")
	if err != nil {
		return Config{}, err
	}
	defer clearValues(values)
	for _, key := range []string{"options", "socks_metadata", "datagram_fec", "dns"} {
		if _, exists := values[key]; exists {
			return Config{}, ErrUnsupported
		}
	}
	server, err := stringValue(values["server"])
	if err != nil || server == "" {
		return Config{}, ErrInvalid
	}
	var tcpServer, socks string
	if raw, exists := values["tcp_server"]; exists {
		tcpServer, err = stringValue(raw)
		if err != nil {
			return Config{}, err
		}
	}
	if raw, exists := values["socks"]; exists {
		socks, err = stringValue(raw)
		if err != nil {
			return Config{}, err
		}
	}
	credentials, err := decodeCredentials(values["credentials"])
	if err != nil {
		return Config{}, err
	}
	classifier, err := configjson.Classification(values["classification"])
	if err != nil {
		return Config{}, ErrInvalid
	}
	return Config{Session: session.ClientConfig{Server: server, TCPServer: tcpServer, Credentials: credentials, Classification: classifier}, SOCKSListen: socks}, nil
}

// LoadCredentials reads a standalone object with the same four base64 string
// fields as client.json's credentials: admission, private, public, server_public.
// It uses the same private-file checks and limit as Load. The cryptographic
// validity of the resulting credentials is checked by session.NewClient; this
// loader does not substitute a different credential validator or constructor.
func LoadCredentials(path string) (session.Credentials, error) {
	body, err := securefile.Read(path, MaxFileBytes)
	if err != nil {
		return session.Credentials{}, err
	}
	defer clear(body)
	return decodeCredentials(body)
}

func decodeCredentials(body []byte) (session.Credentials, error) {
	values, err := object(body, "admission", "private", "public", "server_public")
	if err != nil {
		return session.Credentials{}, err
	}
	defer clearValues(values)
	credentials := session.Credentials{}
	for _, field := range []struct {
		name string
		out  *[]byte
	}{
		{"admission", &credentials.Admission},
		{"private", &credentials.Private},
		{"public", &credentials.Public},
		{"server_public", &credentials.ServerPublic},
	} {
		raw := bytes.TrimSpace(values[field.name])
		if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, field.out) != nil {
			return session.Credentials{}, ErrInvalid
		}
	}
	return credentials, nil
}

func stringValue(raw []byte) (string, error) {
	raw = bytes.TrimSpace(raw)
	var value string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil || !validStringEscapes(raw) {
		return "", ErrInvalid
	}
	return value, nil
}

// encoding/json replaces unpaired UTF-16 escapes. Endpoint strings must not be
// changed silently. This runs only after ordinary JSON string decoding succeeds.
func validStringEscapes(raw []byte) bool {
	for at := 1; at < len(raw)-1; at++ {
		if raw[at] != '\\' {
			continue
		}
		at++
		if raw[at] != 'u' {
			continue
		}
		first, err := strconv.ParseUint(string(raw[at+1:at+5]), 16, 16)
		if err != nil {
			return false
		}
		at += 4
		if first >= 0xdc00 && first <= 0xdfff {
			return false
		}
		if first >= 0xd800 && first <= 0xdbff {
			if at+6 >= len(raw)-1 || raw[at+1] != '\\' || raw[at+2] != 'u' {
				return false
			}
			second, err := strconv.ParseUint(string(raw[at+3:at+7]), 16, 16)
			if err != nil || second < 0xdc00 || second > 0xdfff {
				return false
			}
			at += 6
		}
	}
	return true
}

// object avoids encoding/json's case folding and last-duplicate-wins behavior.
// Nested credentials are checked by another call; unsupported subtrees are not
// interpreted and never converted into defaults.
func object(body []byte, allowed ...string) (map[string]json.RawMessage, error) {
	if !utf8.Valid(body) {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, ErrInvalid
	}
	values := make(map[string]json.RawMessage, len(allowed))
	valid := false
	defer func() {
		if !valid {
			clearValues(values)
		}
	}()
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, ErrInvalid
		}
		if _, duplicate := values[key]; duplicate {
			return nil, ErrInvalid
		}
		known := false
		for _, name := range allowed {
			known = known || key == name
		}
		if !known {
			return nil, ErrInvalid
		}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return nil, ErrInvalid
		}
		values[key] = raw
	}
	if last, err := decoder.Token(); err != nil || last != json.Delim('}') {
		return nil, ErrInvalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	valid = true
	return values, nil
}

func clearValues(values map[string]json.RawMessage) {
	for _, raw := range values {
		clear(raw)
	}
}
