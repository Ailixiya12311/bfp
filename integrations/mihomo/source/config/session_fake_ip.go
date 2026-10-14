package config

import (
	"fmt"
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
)

func bindSessionFakeIP(raw *RawConfig, dns *DNS, proxies map[string]C.Proxy) error {
	name := raw.DNS.FakeIPSessionProxy
	if name == "" {
		return nil
	}
	if !dns.Enable || dns.EnhancedMode != C.DNSFakeIP {
		return fmt.Errorf("dns.fake-ip-session-proxy requires enabled fake-ip DNS")
	}
	if raw.Profile.StoreFakeIP {
		return fmt.Errorf("session fake-IP addresses cannot use profile.store-fake-ip")
	}
	proxy, ok := proxies[name]
	if !ok {
		return fmt.Errorf("dns.fake-ip-session-proxy [%s] not found", name)
	}
	owner, ok := proxy.Adapter().(C.SessionFakeIPOwner)
	if !ok {
		return fmt.Errorf("dns.fake-ip-session-proxy [%s] must be a concrete session-owned outbound", name)
	}
	v4, v6 := owner.SessionFakeIPPrefixes()
	if !v4.IsValid() || !v6.IsValid() {
		return fmt.Errorf("dns.fake-ip-session-proxy [%s] must be a concrete session-owned outbound", name)
	}
	if dns.FakeIPRange.IsValid() && dns.FakeIPRange.Masked() != v4 && dns.FakeIPRange.Masked() != netip.MustParsePrefix("198.18.0.0/16") {
		return fmt.Errorf("session fake-IP requires IPv4 range %s", v4)
	}
	if dns.FakeIPRange6.IsValid() && dns.FakeIPRange6.Masked() != v6 {
		return fmt.Errorf("session fake-IP requires IPv6 range %s", v6)
	}
	dns.SessionFakeIPOwner = owner
	dns.FakeIPPool, dns.FakeIPPool6 = nil, nil
	// Keep the TUN's gateway address while routing the complete session pool.
	dns.FakeIPRange = netip.PrefixFrom(v4.Addr().Next(), v4.Bits())
	if dns.IPv6 {
		dns.FakeIPRange6 = v6
	}
	return nil
}
