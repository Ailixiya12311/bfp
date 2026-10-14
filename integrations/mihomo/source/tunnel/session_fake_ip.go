package tunnel

import (
	"context"
	"net/netip"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

func bindSessionFakeIPMetadata(metadata *C.Metadata, lease C.SessionFakeIPLease) error {
	if metadata.SpecialProxy != "" && metadata.SpecialProxy != lease.ProxyName() {
		return C.ErrSessionFakeIP
	}
	ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
	defer cancel()
	if _, err := lease.Remaining(ctx); err != nil {
		return err
	}
	metadata.SessionFakeIP = lease
	metadata.SpecialProxy = lease.ProxyName()
	metadata.Host = lease.Host()
	metadata.DstIP = netip.Addr{}
	metadata.DNSMode = C.DNSFakeIP
	return nil
}
