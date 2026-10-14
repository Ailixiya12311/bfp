package main

import (
	"bfp/adapter/socks"
	"bfp/session"
	"encoding/json"
	"fmt"
	"time"
)

// RawMessage distinguishes an omitted field from null, numbers and an empty
// string, so malformed lifecycle settings cannot silently select defaults.
type configOptions struct {
	TicketTTL          json.RawMessage `json:"ticket_ttl,omitempty"`
	TicketRefreshLead  json.RawMessage `json:"ticket_refresh_lead,omitempty"`
	TicketOverlap      json.RawMessage `json:"ticket_overlap,omitempty"`
	MaxSessionLifetime json.RawMessage `json:"max_session_lifetime,omitempty"`
}

func parseConfigDuration(name string, raw json.RawMessage) (time.Duration, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	var value string
	if raw[0] != '"' || json.Unmarshal(raw, &value) != nil {
		return 0, fmt.Errorf("options.%s: must be a duration string", name)
	}
	duration, e := time.ParseDuration(value)
	if e != nil {
		return 0, fmt.Errorf("options.%s: must be a valid duration string", name)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("options.%s: must be positive", name)
	}
	return duration, nil
}

func (o *configOptions) sessionOptions() (session.Options, error) {
	var parsed session.Options
	if o == nil {
		return parsed, nil
	}
	fields := []struct {
		name string
		raw  json.RawMessage
		out  *time.Duration
	}{
		{"ticket_ttl", o.TicketTTL, &parsed.TicketTTL},
		{"ticket_refresh_lead", o.TicketRefreshLead, &parsed.TicketRefreshLead},
		{"ticket_overlap", o.TicketOverlap, &parsed.TicketOverlap},
		{"max_session_lifetime", o.MaxSessionLifetime, &parsed.MaxSessionLifetime},
	}
	for _, field := range fields {
		duration, e := parseConfigDuration(field.name, field.raw)
		if e != nil {
			return session.Options{}, e
		}
		*field.out = duration
	}
	// Match the Session constructor's bounds while retaining zero values in the
	// returned Options for omitted settings. Only effective defaults are used
	// here to give the user the relevant JSON field in an error.
	ttl := parsed.TicketTTL
	if ttl == 0 {
		ttl = 20 * time.Minute
	}
	if ttl < 40*time.Millisecond || ttl > 30*24*time.Hour {
		return session.Options{}, fmt.Errorf("options.ticket_ttl: must be between 40ms and 720h")
	}
	lead := parsed.TicketRefreshLead
	if lead == 0 {
		lead = ttl / 4
	}
	if lead < time.Millisecond || lead >= ttl {
		return session.Options{}, fmt.Errorf("options.ticket_refresh_lead: must be at least 1ms and less than options.ticket_ttl")
	}
	overlap := parsed.TicketOverlap
	if overlap == 0 {
		overlap = min(30*time.Second, ttl/4)
	}
	if overlap < time.Millisecond || overlap > ttl {
		return session.Options{}, fmt.Errorf("options.ticket_overlap: must be at least 1ms and no greater than options.ticket_ttl")
	}
	lifetime := parsed.MaxSessionLifetime
	if lifetime == 0 {
		lifetime = 24 * time.Hour
	}
	if lifetime < 40*time.Millisecond || lifetime > 30*24*time.Hour {
		return session.Options{}, fmt.Errorf("options.max_session_lifetime: must be between 40ms and 720h")
	}
	return parsed, nil
}

func (c *serverConfig) validateOptions() error {
	if _, e := c.Options.sessionOptions(); e != nil {
		return e
	}
	if _, e := configClassification(c.Classification); e != nil {
		return e
	}
	_, e := parseServerDatagramFEC(c.DatagramFEC)
	return e
}

func (c *clientConfig) validateOptions() error {
	if _, e := parseClientDNS(c.DNS); e != nil {
		return e
	}
	if _, e := c.Options.sessionOptions(); e != nil {
		return e
	}
	if _, e := configClassification(c.Classification); e != nil {
		return e
	}
	if _, e := configSOCKSDomainSource(c.SOCKSMetadata); e != nil {
		return e
	}
	_, _, e := parseClientDatagramFEC(c.DatagramFEC)
	return e
}

func (c serverConfig) sessionConfig(backend session.Backend) (session.ServerConfig, error) {
	options, e := c.Options.sessionOptions()
	if e != nil {
		return session.ServerConfig{}, e
	}
	classifier, e := configClassification(c.Classification)
	if e != nil {
		return session.ServerConfig{}, e
	}
	negotiation, e := parseServerDatagramFEC(c.DatagramFEC)
	if e != nil {
		return session.ServerConfig{}, e
	}
	return session.ServerConfig{Listen: c.Listen, Credentials: c.Credentials, Backend: backend, MaxSessions: c.MaxSessions, Options: options, Classification: classifier, Negotiation: negotiation}, nil
}

func (c clientConfig) sessionConfig() (session.ClientConfig, error) {
	dns, e := parseClientDNS(c.DNS)
	if e != nil {
		return session.ClientConfig{}, e
	}
	options, e := c.Options.sessionOptions()
	if e != nil {
		return session.ClientConfig{}, e
	}
	classifier, e := configClassification(c.Classification)
	if e != nil {
		return session.ClientConfig{}, e
	}
	if _, e := configSOCKSDomainSource(c.SOCKSMetadata); e != nil {
		return session.ClientConfig{}, e
	}
	fecPolicy, negotiation, e := parseClientDatagramFEC(c.DatagramFEC)
	if e != nil {
		return session.ClientConfig{}, e
	}
	result := session.ClientConfig{Server: c.Server, TCPServer: c.TCPServer, Credentials: c.Credentials, Options: options, Classification: classifier, DatagramFEC: fecPolicy, Negotiation: negotiation}
	if dns != nil {
		result.AddressScopeFactory, e = dns.addressFactory()
		if e != nil {
			return session.ClientConfig{}, e
		}
	}
	return result, nil
}

func (c clientConfig) socksConfig(backend socks.Backend) (socks.Config, error) {
	domainSource, e := configSOCKSDomainSource(c.SOCKSMetadata)
	if e != nil {
		return socks.Config{}, e
	}
	return socks.Config{Listen: c.SOCKS, Backend: backend, DomainSource: socks.DomainSource(domainSource)}, nil
}
