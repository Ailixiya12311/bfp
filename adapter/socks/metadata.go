package socks

import (
	"context"
	"errors"
	"net"

	"bfp/classification"
	"bfp/protocol"
)

// DomainSource identifies the administrator-selected local scheduling source.
// It does not establish DNS ownership, application identity, or authorization.
type DomainSource string

const (
	DomainSourceIgnore       DomainSource = "ignore"
	DomainSourceSOCKSAddress DomainSource = "socks_address"
)

var (
	ErrDomainSource           = errors.New("socks: invalid domain source")
	ErrMetadataBackend        = errors.New("socks: domain source requires metadata backend")
	ErrTargetRestorer         = errors.New("socks: target restorer returned an invalid target")
	ErrTargetRestorerConflict = errors.New("socks: Session backend already owns target restoration")
)

// MetadataBackend optionally accepts local classification metadata. The backend
// must validate trusted metadata before allocating a flow or dialing its target.
// Its returned connection retains the original deadline and half-close methods.
type MetadataBackend interface {
	DialMetadata(context.Context, classification.Metadata) (net.Conn, error)
}

func configureDomainSource(cfg *Config) (MetadataBackend, error) {
	if cfg.DomainSource == "" {
		cfg.DomainSource = DomainSourceIgnore
	}
	switch cfg.DomainSource {
	case DomainSourceIgnore:
		return nil, nil
	case DomainSourceSOCKSAddress:
		backend, ok := cfg.Backend.(MetadataBackend)
		if !ok {
			return nil, ErrMetadataBackend
		}
		return backend, nil
	default:
		return nil, ErrDomainSource
	}
}

// dialTarget only receives the address type of the actual target request. For
// UDP that is the business datagram, never the UDP ASSOCIATE control request.
func (s *Server) dialTarget(ctx context.Context, network, address string, atyp byte) (net.Conn, error) {
	target, restored, err := s.restoreTarget(network, address)
	if err != nil {
		return nil, err
	}
	if s.cfg.DomainSource == DomainSourceIgnore {
		return s.cfg.Backend.DialContext(ctx, target.Network, target.Address)
	}
	// Build metadata through the local bridge. It strips any policy-bearing
	// fields before this adapter explicitly marks a SOCKS-resolved domain as a
	// local policy input. The wire Target is never treated as trusted here.
	bridge := classification.NewLocalMetadataBridge(target)
	if atyp == 3 || restored {
		host, _, err := net.SplitHostPort(target.Address)
		if err != nil {
			return nil, classification.ErrMetadata
		}
		if net.ParseIP(host) == nil {
			var bridgeErr error
			bridge, bridgeErr = bridge.WithTrustedDomain(host)
			if bridgeErr != nil {
				return nil, bridgeErr
			}
		}
	}
	// Normal is only the existing structural wire value, not a trusted Hint.
	// The backend's local rules/cap validate and classify the original address.
	return s.metadata.DialMetadata(ctx, bridge.Metadata())
}

// restoreTarget applies the configured local fake-IP reverse map before the
// destination reaches either the legacy backend or the metadata bridge.  The
// network is intentionally immutable at this boundary: a restorer maps an
// address, it cannot turn a SOCKS TCP request into UDP (or vice versa).
func (s *Server) restoreTarget(network, address string) (protocol.Target, bool, error) {
	target := protocol.Target{Network: network, Address: address, Class: protocol.Normal}
	if s.cfg.TargetRestorer == nil {
		return target, false, nil
	}
	restored, err := s.cfg.TargetRestorer.RestoreTarget(target)
	if err != nil {
		return protocol.Target{}, false, err
	}
	if restored.Network != network || restored.Address == "" {
		return protocol.Target{}, false, ErrTargetRestorer
	}
	if _, _, err := net.SplitHostPort(restored.Address); err != nil {
		return protocol.Target{}, false, ErrTargetRestorer
	}
	return restored, restored.Address != address, nil
}
