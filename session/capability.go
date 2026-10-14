package session

import (
	"bfp/security"
	"bytes"
	"encoding/json"
	"io"
)

// Capabilities is the authenticated feature set fixed for one Session.
type Capabilities uint64

const (
	CapabilityClassAnnouncementV1 Capabilities = 1 << iota
	// Bit 1 remains reserved for an unknown optional offer used by v3 tests.
	// XOR v1 selects the fixed bounded datagram-repair contract; it is optional
	// and never changes reliable StreamData semantics.
	CapabilityDatagramXORV1    Capabilities = 1 << 2
	ProfileClassAnnouncementV1              = "class-announcement-v1"
	knownCapabilities                       = CapabilityClassAnnouncementV1 | CapabilityDatagramXORV1
	maxCapabilityOfferSize                  = 256
)

// NegotiationConfig describes an initial authenticated capability offer. On a
// server OfferedCapabilities denotes its supported set. This experimental
// profile requires class announcement v1; an explicit zero config is invalid.
// A nil config selects the frozen profile and its mandatory capability.
type NegotiationConfig struct {
	Profile              string
	OfferedCapabilities  Capabilities
	RequiredCapabilities Capabilities
}

type capabilityOffer struct {
	Profile  string       `json:"p"`
	Offered  Capabilities `json:"o"`
	Required Capabilities `json:"r"`
}

func defaultCapabilityOffer() capabilityOffer {
	return capabilityOffer{ProfileClassAnnouncementV1, CapabilityClassAnnouncementV1, CapabilityClassAnnouncementV1}
}

func normalizeNegotiation(cfg *NegotiationConfig) (*NegotiationConfig, error) {
	offer := defaultCapabilityOffer()
	if cfg != nil {
		offer = capabilityOffer{cfg.Profile, cfg.OfferedCapabilities, cfg.RequiredCapabilities}
	}
	if err := validateCapabilityOffer(offer); err != nil {
		return nil, err
	}
	return &NegotiationConfig{offer.Profile, offer.Offered, offer.Required}, nil
}

func validateCapabilityOffer(offer capabilityOffer) error {
	if offer.Profile != ProfileClassAnnouncementV1 || offer.Required&^knownCapabilities != 0 || offer.Required&^offer.Offered != 0 || offer.Required&CapabilityClassAnnouncementV1 == 0 {
		return security.ErrAuthentication
	}
	return nil
}

// objectFields rejects duplicate keys and non-object JSON before ordinary
// strict struct decoding. Capability fields must be present, never null.
func objectFields(data []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, security.ErrAuthentication
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		tok, err = d.Token()
		key, ok := tok.(string)
		if err != nil || !ok {
			return nil, security.ErrAuthentication
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, security.ErrAuthentication
		}
		var raw json.RawMessage
		if err = d.Decode(&raw); err != nil {
			return nil, security.ErrAuthentication
		}
		fields[key] = raw
	}
	if tok, err = d.Token(); err != nil || tok != json.Delim('}') {
		return nil, security.ErrAuthentication
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, security.ErrAuthentication
	}
	return fields, nil
}

func capabilityFieldsPresent(data []byte, names ...string) error {
	fields, err := objectFields(data)
	if err != nil {
		return err
	}
	for _, name := range names {
		raw, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return security.ErrAuthentication
		}
	}
	return nil
}

func decodeCapabilityOffer(data []byte) (capabilityOffer, error) {
	var offer capabilityOffer
	if len(data) > maxCapabilityOfferSize {
		return offer, security.ErrAuthentication
	}
	fields, err := objectFields(data)
	if err != nil || len(fields) != 3 || capabilityFieldsPresent(data, "p", "o", "r") != nil || decodeJSON(data, &offer) != nil || validateCapabilityOffer(offer) != nil {
		return offer, security.ErrAuthentication
	}
	return offer, nil
}

func validCapabilitySelection(profile string, selected Capabilities) bool {
	return profile == ProfileClassAnnouncementV1 && selected&CapabilityClassAnnouncementV1 != 0 && selected&^knownCapabilities == 0
}

func selectCapabilities(offer capabilityOffer, cfg *NegotiationConfig, previous *sessionInfo) (string, Capabilities, error) {
	local, err := normalizeNegotiation(cfg)
	if err != nil || validateCapabilityOffer(offer) != nil || offer.Profile != local.Profile {
		return "", 0, security.ErrAuthentication
	}
	selected := offer.Offered & local.OfferedCapabilities & knownCapabilities
	if !validCapabilitySelection(offer.Profile, selected) || offer.Required&^selected != 0 || local.RequiredCapabilities&^selected != 0 {
		return "", 0, security.ErrAuthentication
	}
	if previous != nil && (!validCapabilitySelection(previous.Profile, previous.Capabilities) || offer.Profile != previous.Profile || offer.Offered != previous.Capabilities || offer.Required != previous.Capabilities || selected != previous.Capabilities) {
		return "", 0, security.ErrAuthentication
	}
	return offer.Profile, selected, nil
}

func clientCapabilityOffer(cfg ClientConfig, previous *sessionInfo) (capabilityOffer, error) {
	if previous != nil {
		if !validCapabilitySelection(previous.Profile, previous.Capabilities) {
			return capabilityOffer{}, security.ErrAuthentication
		}
		return capabilityOffer{previous.Profile, previous.Capabilities, previous.Capabilities}, nil
	}
	local, err := normalizeNegotiation(cfg.Negotiation)
	if err != nil {
		return capabilityOffer{}, err
	}
	return capabilityOffer{local.Profile, local.OfferedCapabilities, local.RequiredCapabilities}, nil
}

func validateServerSelection(payload []byte, offer capabilityOffer, info sessionInfo, previous *sessionInfo) error {
	fields, err := objectFields(payload)
	if err != nil {
		return err
	}
	// encoding/json treats field names case-insensitively; the wire schema does
	// not. Reject aliases such as P/Z as well as all unrecognized exact keys.
	for key := range fields {
		switch key {
		case "s", "c", "r", "t", "k", "g", "h", "q", "u", "e", "l", "p", "z":
		default:
			return security.ErrAuthentication
		}
	}
	if capabilityFieldsPresent(payload, "p", "z") != nil || !validCapabilitySelection(info.Profile, info.Capabilities) || info.Profile != offer.Profile || info.Capabilities&^offer.Offered != 0 || offer.Required&^info.Capabilities != 0 {
		return security.ErrAuthentication
	}
	if previous != nil && (info.Profile != previous.Profile || info.Capabilities != previous.Capabilities) {
		return security.ErrAuthentication
	}
	return nil
}
