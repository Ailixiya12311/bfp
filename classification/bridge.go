package classification

import (
	"fmt"

	"bfp/protocol"
)

// LocalMetadataBridge constructs classification metadata at a local adapter
// boundary. It deliberately starts from an untrusted view of Target: Domain,
// RuleTag, and Class supplied by a wire/JSON target are discarded. A caller
// must explicitly invoke one of the WithTrusted* methods for a locally
// established policy fact to become eligible for a metadata rule.
//
// This is an adapter contract, not an authorization mechanism against code in
// the same process. Callers must only use WithTrusted* for values obtained from
// a local policy source they control. In particular, decoding an authenticated
// OPEN frame never calls this type and never upgrades peer metadata to trusted.
type LocalMetadataBridge struct {
	meta Metadata
}

// NewLocalMetadataBridge copies the structural target and strips policy-bearing
// fields that may have originated outside the local adapter. The returned
// metadata defaults to Normal so callers cannot accidentally use a wire Class
// as a local scheduling decision. Delivery and FEC contracts are copied because
// they are explicit flow contracts, not classification trust signals.
func NewLocalMetadataBridge(target protocol.Target) LocalMetadataBridge {
	target.Domain = ""
	target.RuleTag = ""
	target.Class = protocol.Normal
	if target.Delivery != nil {
		contract := *target.Delivery
		target.Delivery = &contract
	}
	if target.FEC != nil {
		profile := *target.FEC
		target.FEC = &profile
	}
	return LocalMetadataBridge{meta: Metadata{Target: target}}
}

// Metadata returns a copy suitable for DialMetadata. Optional hint pointers
// are copied so a caller cannot mutate the bridge through the returned value.
func (b LocalMetadataBridge) Metadata() Metadata {
	out := b.meta
	target := b.meta.Target
	if b.meta.Target.Delivery != nil {
		contract := *b.meta.Target.Delivery
		target.Delivery = &contract
	}
	if b.meta.Target.FEC != nil {
		profile := *b.meta.Target.FEC
		target.FEC = &profile
	}
	out.Target = target
	if b.meta.Hint != nil {
		hint := *b.meta.Hint
		out.Hint = &hint
	}
	return out
}

// WithTrustedDomain marks a locally resolved/selected domain as eligible for
// domain rules. The input is validated and bounded before it is retained; the
// classifier canonicalizes it during rule matching.
func (b LocalMetadataBridge) WithTrustedDomain(domain string) (LocalMetadataBridge, error) {
	if _, err := normalizeDomain(domain); err != nil {
		return b, fmt.Errorf("%w: trusted domain", ErrMetadata)
	}
	out := b
	// Preserve the adapter's original spelling in the envelope. The classifier
	// performs its own canonical comparison, while recording the source value
	// remains useful to adapter diagnostics and does not weaken validation.
	out.meta.Target.Domain = domain
	out.meta.DomainTrusted = true
	return out, nil
}

// WithTrustedRuleTag marks a locally selected rule tag as eligible for tag
// rules. A tag arriving only in a wire Target remains ignored by default.
func (b LocalMetadataBridge) WithTrustedRuleTag(tag string) (LocalMetadataBridge, error) {
	if !validTag(tag) || tag == "" {
		return b, fmt.Errorf("%w: trusted rule tag", ErrMetadata)
	}
	out := b
	out.meta.Target.RuleTag = tag
	out.meta.RuleTagTrusted = true
	return out, nil
}

// WithTrustedApplication marks a local application identity as eligible for
// Application rules. The identity is deliberately kept outside protocol.Target
// and therefore cannot appear in an OPEN frame. The caller must supply it from
// a local process/policy source; peer-provided strings are not trusted here.
func (b LocalMetadataBridge) WithTrustedApplication(identity string) (LocalMetadataBridge, error) {
	if !validApplication(identity) {
		return b, fmt.Errorf("%w: trusted application", ErrMetadata)
	}
	out := b
	out.meta.Application = identity
	out.meta.ApplicationTrusted = true
	return out, nil
}
