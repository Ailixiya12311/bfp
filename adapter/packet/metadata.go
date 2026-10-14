package packet

import (
	"bfp/classification"
	"context"
)

func copyMetadata(meta classification.Metadata) classification.Metadata {
	if meta.Hint != nil {
		hint := *meta.Hint
		meta.Hint = &hint
	}
	if meta.Target.Delivery != nil {
		delivery := *meta.Target.Delivery
		meta.Target.Delivery = &delivery
	}
	if meta.Target.FEC != nil {
		fec := *meta.Target.FEC
		meta.Target.FEC = &fec
	}
	return meta
}

func (p *Conn) targetMetadata(ctx context.Context, target TargetToken, domain string) (classification.Metadata, error) {
	address := target.Address
	base := copyMetadata(p.cfg.Metadata)
	base.Target.Network, base.Target.Address, base.Target.Domain = "udp", address.String(), domain
	if p.cfg.MetadataForTarget == nil && p.cfg.MetadataForTargetToken == nil {
		return base, ctx.Err()
	}
	var selected classification.Metadata
	var err error
	if p.cfg.MetadataForTargetToken != nil {
		selected, err = p.cfg.MetadataForTargetToken(ctx, target, copyMetadata(base))
	} else {
		selected, err = p.cfg.MetadataForTarget(ctx, address, copyMetadata(base))
	}
	if err != nil {
		return classification.Metadata{}, err
	}
	if err := ctx.Err(); err != nil {
		return classification.Metadata{}, err
	}
	if selected.Target.Network != "udp" || selected.Target.Address != address.String() {
		return classification.Metadata{}, classification.ErrMetadata
	}
	return copyMetadata(selected), nil
}
