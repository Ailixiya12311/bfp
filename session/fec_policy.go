package session

import (
	"bfp/protocol"
	"errors"
	"fmt"
)

// DatagramFECPolicyConfig selects optional UDP repair at initial OPEN admission.
// The keys refer to the final local initial classification after rules, trusted
// hints and the local priority cap. A missing class (or a disabled profile)
// keeps the default best-effort Datagram contract without repair. Behavior
// reclassification, peer announcements and recovery do not reselect a profile.
// Explicit Target.FEC always takes precedence over this policy.
//
// NewClient validates and copies the map; later caller mutations have no effect.
type DatagramFECPolicyConfig struct {
	ByClass map[protocol.Class]protocol.FECProfile
}

var ErrDatagramFECPolicy = errors.New("session: invalid datagram FEC policy")

// Values, rather than a caller-owned map or profile pointers, are published to
// the Session before its actor starts. Zero entries select no automatic repair.
type datagramFECPolicy struct {
	byClass [protocol.Bulk + 1]protocol.FECProfile
}

func compileDatagramFECPolicy(cfg *DatagramFECPolicyConfig, negotiation *NegotiationConfig) (datagramFECPolicy, error) {
	var out datagramFECPolicy
	if cfg == nil {
		return out, nil
	}
	for class, profile := range cfg.ByClass {
		if !class.Valid() {
			return datagramFECPolicy{}, fmt.Errorf("%w: class %d", ErrDatagramFECPolicy, class)
		}
		if err := profile.Validate(); err != nil {
			return datagramFECPolicy{}, fmt.Errorf("%w: class %d: %w", ErrDatagramFECPolicy, class, err)
		}
		if profile.Enabled() {
			if !datagramFECCapability().Supports(profile) {
				return datagramFECPolicy{}, fmt.Errorf("%w: class %d profile exceeds datagram XOR v1 bounds", ErrDatagramFECPolicy, class)
			}
			if negotiation == nil || negotiation.OfferedCapabilities&CapabilityDatagramXORV1 == 0 {
				return datagramFECPolicy{}, fmt.Errorf("%w: enabled class %d requires offered datagram XOR v1 capability", ErrDatagramFECPolicy, class)
			}
		}
		out.byClass[class] = profile
	}
	return out, nil
}

// selectDatagramFEC changes only a nil UDP FEC field and owns the selected copy.
// Optional negotiation can omit repair; an explicit FEC field is subsequently
// resolved by the strict existing admission path and never silently downgraded.
func (s *Session) selectDatagramFEC(target protocol.Target) protocol.Target {
	if target.Network != "udp" || target.FEC != nil || !target.Class.Valid() {
		return target
	}
	profile := s.datagramFEC.byClass[target.Class]
	if profile.Enabled() && s.fecPermitted(profile) {
		target.FEC = &profile
	}
	return target
}
