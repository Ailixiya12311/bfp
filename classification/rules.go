// Package classification assigns scheduling classes using trusted local policy
// and bounded application-byte observations. It never changes delivery semantics,
// target authorization, flow credit, or congestion accounting.
//
// Classifier is immutable after construction. Each Flow is owner-confined and is
// not safe for concurrent use. No network I/O, goroutines, or wall-clock reads are
// performed by this package.
package classification

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"bfp/protocol"
)

var (
	ErrConfig   = errors.New("classification: invalid configuration")
	ErrMetadata = errors.New("classification: invalid metadata")
	ErrTime     = errors.New("classification: elapsed time must not decrease")
)

// Metadata carries OPEN metadata with trust supplied independently by the local
// adapter/owner. An authenticated peer is not automatically a trusted policy
// source. Target.Class is deliberately ignored; use Hint for a trusted local
// decision. The target address must be host:port, including brackets for IPv6.
type Metadata struct {
	Target             protocol.Target
	DomainTrusted      bool
	RuleTagTrusted     bool
	Application        string
	ApplicationTrusted bool
	Hint               *ClassHint
}

type ClassHint struct {
	Class   protocol.Class
	Trusted bool
	Locked  bool
}

type PortRange struct {
	First uint16
	Last  uint16
}

// Rule matches the conjunction of its nonempty selectors. Ports are alternatives
// within that selector. DomainSuffix matches the suffix itself or a subdomain,
// never an unrelated hostname that merely ends with the same characters.
// Domain selectors require DomainTrusted, RuleTag requires RuleTagTrusted,
// and Application requires ApplicationTrusted. Application is local-only and
// is never serialized in protocol.Target.
// Domains must be ASCII DNS names; callers perform IDNA conversion if needed.
type Rule struct {
	Name         string
	Priority     int
	Network      string
	Ports        []PortRange
	Domain       string
	DomainSuffix string
	RuleTag      string
	Application  string
	Class        protocol.Class
	Locked       bool
}

type Config struct {
	DefaultClass protocol.Class
	// HighestAllowed caps priority: Normal permits Normal/Bulk but not
	// Interactive. The zero value permits all three classes.
	HighestAllowed protocol.Class
	Rules          []Rule
	Behavior       BehaviorConfig
}

func DefaultConfig() Config {
	return Config{DefaultClass: protocol.Normal, HighestAllowed: protocol.Interactive, Behavior: DefaultBehaviorConfig()}
}

type Source string

const (
	SourceHint     Source = "trusted_hint"
	SourceMetadata Source = "metadata_rule"
	SourceTarget   Source = "target_rule"
	SourceDefault  Source = "default"
)

type Decision struct {
	Class  protocol.Class
	Locked bool
	Source Source
	Rule   string
}

type Classifier struct {
	cfg           Config
	metadataRules []Rule
	targetRules   []Rule
	bulkThreshold uint64
	lowThreshold  uint64
}

// New validates and copies configuration. Precedence is trusted Hint, then
// metadata rules, target/network/port rules, and the default. Within either rule
// group higher Priority wins; equal priorities retain configuration order.
// Locked decisions disable behavior adjustment; all decisions obey the local
// HighestAllowed cap, including trusted hints.
func New(cfg Config) (*Classifier, error) {
	if !cfg.DefaultClass.Valid() || !cfg.HighestAllowed.Valid() {
		return nil, fmt.Errorf("%w: class", ErrConfig)
	}
	c := &Classifier{cfg: cfg}
	c.cfg.Rules = nil // Only the immutable compiled copies are retained.
	for i, rule := range cfg.Rules {
		r, err := validateRule(rule)
		if err != nil {
			return nil, fmt.Errorf("%w: rule %d: %v", ErrConfig, i, err)
		}
		if r.Domain != "" || r.DomainSuffix != "" || r.RuleTag != "" || r.Application != "" {
			c.metadataRules = append(c.metadataRules, r)
		} else {
			c.targetRules = append(c.targetRules, r)
		}
	}
	for _, rules := range [][]Rule{c.metadataRules, c.targetRules} {
		sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority > rules[j].Priority })
	}
	if cfg.Behavior.Enabled {
		var err error
		c.bulkThreshold, c.lowThreshold, err = validateBehavior(cfg.Behavior)
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func validateRule(r Rule) (Rule, error) {
	if !r.Class.Valid() || (r.Network != "" && r.Network != "tcp" && r.Network != "udp") {
		return Rule{}, errors.New("class or network")
	}
	if r.Domain != "" && r.DomainSuffix != "" {
		return Rule{}, errors.New("domain and domain suffix are mutually exclusive")
	}
	var err error
	if r.Domain != "" {
		r.Domain, err = normalizeDomain(r.Domain)
		if err != nil {
			return Rule{}, err
		}
	}
	if r.DomainSuffix != "" {
		r.DomainSuffix, err = normalizeDomain(r.DomainSuffix)
		if err != nil {
			return Rule{}, err
		}
	}
	if !validTag(r.RuleTag) || (r.Application != "" && !validApplication(r.Application)) {
		return Rule{}, errors.New("rule tag or application")
	}
	if r.Network == "" && len(r.Ports) == 0 && r.Domain == "" && r.DomainSuffix == "" && r.RuleTag == "" && r.Application == "" {
		return Rule{}, errors.New("empty selector; use DefaultClass")
	}
	r.Ports = append([]PortRange(nil), r.Ports...)
	for _, p := range r.Ports {
		if p.First == 0 || p.Last < p.First {
			return Rule{}, errors.New("port range")
		}
	}
	return r, nil
}

func validTag(tag string) bool {
	return len(tag) <= 256 && strings.IndexFunc(tag, unicode.IsControl) == -1
}

func validApplication(identity string) bool {
	if identity == "" || len(identity) > 128 {
		return false
	}
	for _, ch := range identity {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '.' || ch == '_' || ch == '-') {
			return false
		}
	}
	return true
}

func normalizeDomain(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if len(domain) == 0 || len(domain) > 253 || net.ParseIP(domain) != nil {
		return "", errors.New("domain must be an ASCII DNS name")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid domain label")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", errors.New("domain must be an ASCII DNS name")
			}
		}
	}
	return domain, nil
}

func (c *Classifier) cap(class protocol.Class) protocol.Class {
	if class < c.cfg.HighestAllowed {
		return c.cfg.HighestAllowed
	}
	return class
}

// Decide validates structural target metadata. Untrusted domain/tag/hint fields
// are ignored, including invalid values in them. A domain in Target.Address is
// not silently promoted to a trusted Domain hint.
func (c *Classifier) Decide(meta Metadata) (Decision, error) {
	if meta.Target.Network != "tcp" && meta.Target.Network != "udp" {
		return Decision{}, fmt.Errorf("%w: network", ErrMetadata)
	}
	host, portText, err := net.SplitHostPort(meta.Target.Address)
	if err != nil || host == "" {
		return Decision{}, fmt.Errorf("%w: target address", ErrMetadata)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return Decision{}, fmt.Errorf("%w: target port", ErrMetadata)
	}
	var domain, tag string
	if meta.DomainTrusted && meta.Target.Domain != "" {
		domain, err = normalizeDomain(meta.Target.Domain)
		if err != nil {
			return Decision{}, fmt.Errorf("%w: domain", ErrMetadata)
		}
	}
	if meta.RuleTagTrusted {
		if !validTag(meta.Target.RuleTag) {
			return Decision{}, fmt.Errorf("%w: rule tag", ErrMetadata)
		}
		tag = meta.Target.RuleTag
	}
	var application string
	if meta.ApplicationTrusted {
		if !validApplication(meta.Application) {
			return Decision{}, fmt.Errorf("%w: application", ErrMetadata)
		}
		application = meta.Application
	}
	if meta.Hint != nil && meta.Hint.Trusted {
		if !meta.Hint.Class.Valid() {
			return Decision{}, fmt.Errorf("%w: hint class", ErrMetadata)
		}
		return Decision{Class: c.cap(meta.Hint.Class), Locked: meta.Hint.Locked, Source: SourceHint}, nil
	}
	for _, group := range []struct {
		rules  []Rule
		source Source
	}{{c.metadataRules, SourceMetadata}, {c.targetRules, SourceTarget}} {
		for _, r := range group.rules {
			if r.matches(meta.Target.Network, uint16(port), domain, tag, application) {
				return Decision{Class: c.cap(r.Class), Locked: r.Locked, Source: group.source, Rule: r.Name}, nil
			}
		}
	}
	return Decision{Class: c.cap(c.cfg.DefaultClass), Source: SourceDefault}, nil
}

func (r Rule) matches(network string, port uint16, domain, tag, application string) bool {
	if r.Network != "" && r.Network != network || r.RuleTag != "" && r.RuleTag != tag || r.Application != "" && r.Application != application {
		return false
	}
	if r.Domain != "" && r.Domain != domain {
		return false
	}
	if r.DomainSuffix != "" && domain != r.DomainSuffix && !strings.HasSuffix(domain, "."+r.DomainSuffix) {
		return false
	}
	if len(r.Ports) != 0 {
		for _, p := range r.Ports {
			if port >= p.First && port <= p.Last {
				return true
			}
		}
		return false
	}
	return true
}

// NewFlow fixes the initial trusted-rule baseline. elapsed is caller-provided
// time since an arbitrary monotonic origin, not Unix time. Separate Flow objects
// should be used per sending direction; do not mix retransmissions into Observe.
func (c *Classifier) NewFlow(meta Metadata, elapsed time.Duration) (*Flow, error) {
	if elapsed < 0 {
		return nil, ErrTime
	}
	d, err := c.Decide(meta)
	if err != nil {
		return nil, err
	}
	f := &Flow{decision: d, behavior: c.cfg.Behavior, class: d.Class, opened: elapsed, now: elapsed, lastChange: elapsed, bulkThreshold: c.bulkThreshold, lowThreshold: c.lowThreshold}
	if f.behavior.Enabled && !d.Locked && d.Class != protocol.Bulk {
		f.buckets = make([]uint64, int(f.behavior.Window/f.behavior.Bucket))
		f.tick = int64(elapsed / f.behavior.Bucket)
	}
	return f, nil
}
