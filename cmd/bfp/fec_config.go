package main

import (
	"bfp/protocol"
	"bfp/session"
	"encoding/json"
)

// A nil negotiation retains the existing class-announcement-only offer. FEC
// mode controls authenticated capability negotiation, separately from the
// per-class policy that selects a frozen profile when a Datagram flow opens.
func datagramFECNegotiation(fields map[string]json.RawMessage) (*session.NegotiationConfig, error) {
	mode := "off"
	if raw, present := fields["mode"]; present {
		value, err := configString(raw, "datagram_fec.mode")
		if err != nil {
			return nil, err
		}
		mode = value
	}
	switch mode {
	case "off":
		if _, present := fields["by_class"]; present {
			return nil, configFieldError("datagram_fec.by_class", "requires optional or required mode")
		}
		if _, present := fields["profile"]; present {
			return nil, configFieldError("datagram_fec.profile", "requires optional or required mode")
		}
		return nil, nil
	case "optional", "required":
		required := session.CapabilityClassAnnouncementV1
		if mode == "required" {
			required |= session.CapabilityDatagramXORV1
		}
		return &session.NegotiationConfig{
			Profile:              session.ProfileClassAnnouncementV1,
			OfferedCapabilities:  session.CapabilityClassAnnouncementV1 | session.CapabilityDatagramXORV1,
			RequiredCapabilities: required,
		}, nil
	default:
		return nil, configFieldError("datagram_fec.mode", "must be off, optional or required")
	}
}

func configDatagramFECProfile(raw json.RawMessage) (protocol.FECProfile, error) {
	maxDataShards, shardSize := uint64(32), uint64(900)
	if len(raw) != 0 {
		fields, err := configObject(raw, "datagram_fec.profile", "max_data_shards", "shard_size")
		if err != nil {
			return protocol.FECProfile{}, err
		}
		for _, field := range []struct {
			name    string
			maximum uint64
			out     *uint64
		}{{"max_data_shards", 32, &maxDataShards}, {"shard_size", 900, &shardSize}} {
			if value, present := fields[field.name]; present {
				parsed, err := configUint(value, "datagram_fec.profile."+field.name, field.maximum)
				if err != nil {
					return protocol.FECProfile{}, err
				}
				*field.out = parsed
			}
		}
	}
	return protocol.FECProfile{
		Version:       protocol.FECWireVersion,
		Algorithm:     protocol.FECXOR1,
		MaxDataShards: uint8(maxDataShards),
		ParityShards:  1,
		ShardSize:     uint16(shardSize),
		MaxBlockSize:  uint32(maxDataShards * shardSize),
	}, nil
}

func parseClientDatagramFEC(raw json.RawMessage) (*session.DatagramFECPolicyConfig, *session.NegotiationConfig, error) {
	if len(raw) == 0 {
		return nil, nil, nil
	}
	fields, err := configObject(raw, "datagram_fec", "mode", "by_class", "profile")
	if err != nil {
		return nil, nil, err
	}
	negotiation, err := datagramFECNegotiation(fields)
	if err != nil || negotiation == nil {
		return nil, negotiation, err
	}
	classes := make(map[protocol.Class]protocol.FECProfile)
	if raw, present := fields["by_class"]; present {
		byClass, err := configObject(raw, "datagram_fec.by_class", "interactive", "normal", "bulk")
		if err != nil {
			return nil, nil, err
		}
		for _, item := range []struct {
			name  string
			class protocol.Class
		}{{"interactive", protocol.Interactive}, {"normal", protocol.Normal}, {"bulk", protocol.Bulk}} {
			if raw, present := byClass[item.name]; present {
				value, err := configString(raw, "datagram_fec.by_class."+item.name)
				if err != nil {
					return nil, nil, err
				}
				switch value {
				case "off":
				case "xor1":
					classes[item.class] = protocol.FECProfile{}
				default:
					return nil, nil, configFieldError("datagram_fec.by_class."+item.name, "must be off or xor1")
				}
			}
		}
	}
	profileRaw, profilePresent := fields["profile"]
	if len(classes) == 0 {
		if profilePresent {
			return nil, nil, configFieldError("datagram_fec.profile", "requires at least one xor1 class")
		}
		return nil, negotiation, nil
	}
	profile, err := configDatagramFECProfile(profileRaw)
	if err != nil {
		return nil, nil, err
	}
	for class := range classes {
		classes[class] = profile
	}
	return &session.DatagramFECPolicyConfig{ByClass: classes}, negotiation, nil
}

func parseServerDatagramFEC(raw json.RawMessage) (*session.NegotiationConfig, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	// The server uses the authenticated OPEN profile for both directions; local
	// class rules cannot renegotiate the flow or choose a reply-only profile.
	fields, err := configObject(raw, "datagram_fec", "mode")
	if err != nil {
		return nil, err
	}
	return datagramFECNegotiation(fields)
}
