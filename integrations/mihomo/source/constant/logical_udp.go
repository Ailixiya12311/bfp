package constant

import (
	"context"
	"net"
	"net/netip"
)

// LogicalUDPPacketConn is an optional outbound capability. It keeps restored
// domains and original inbound destinations across a multi-target packet
// association without client-side business DNS. Payload I/O still goes through
// PacketConn.WriteTo and WaitReadFrom, including the normal traffic trackers.
type LogicalUDPPacketConn interface {
	// PrepareUDPMetadata receives preprocessed metadata before Pure discards
	// Host. origin is the packet's original destination, when it was numeric.
	// The implementation must bind the returned address to its fixed owner
	// and retain only bounded source restoration state.
	PrepareUDPMetadata(ctx context.Context, metadata *Metadata, origin netip.AddrPort) (net.Addr, error)
	// RestoreUDPSource validates and restores a reply's logical source. An
	// error rejects it; the tunnel never substitutes the first destination.
	RestoreUDPSource(source net.Addr) (net.Addr, error)
}

// LogicalUDPPacketConnTransaction is implemented by logical packet adapters
// that reserve destination metadata before the underlying PacketConn write.
// Prepare may create provisional state; Commit publishes it after a
// successful WriteTo and Abort releases it when WriteTo fails or is canceled.
// The address is the exact value returned by Prepare and must satisfy the
// normal UDP PacketConn address contract.
// Implementations must also release provisional state when Prepare's context
// is canceled, even if a caller omits Abort. Source restoration may wait for
// Commit while holding a fast reply; Abort and retirement must wake and reject
// those unpublished replies. Successful payload accounting remains WriteTo's
// normal PacketConn path.
type LogicalUDPPacketConnTransaction interface {
	LogicalUDPPacketConn
	CommitUDPMetadata(address net.Addr) error
	AbortUDPMetadata(address net.Addr)
}

type logicalDestinationMetadataKey struct{}

// WithLogicalDestinationMetadata preserves local, restored destination metadata
// across outbound setup. Existing protocols still receive Metadata.Pure. An
// opting-in outbound may recover the trusted Host for classification without
// replacing Pure's numeric destination with a sniffed or unrelated hostname.
func WithLogicalDestinationMetadata(ctx context.Context, metadata *Metadata) context.Context {
	if metadata == nil {
		return ctx
	}
	return context.WithValue(ctx, logicalDestinationMetadataKey{}, metadata.Clone())
}

// LogicalDestinationMetadataFromContext returns a fresh copy so setup cannot
// mutate the snapshot seen by another retry or wrapper.
func LogicalDestinationMetadataFromContext(ctx context.Context) (*Metadata, bool) {
	metadata, ok := ctx.Value(logicalDestinationMetadataKey{}).(*Metadata)
	if !ok || metadata == nil {
		return nil, false
	}
	return metadata.Clone(), true
}

// WithLogicalUDPMetadata retains the UDP-specific name for packet adapters.
func WithLogicalUDPMetadata(ctx context.Context, metadata *Metadata) context.Context {
	return WithLogicalDestinationMetadata(ctx, metadata)
}

func LogicalUDPMetadataFromContext(ctx context.Context) (*Metadata, bool) {
	return LogicalDestinationMetadataFromContext(ctx)
}
