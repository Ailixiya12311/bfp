package addressscope

import "net/netip"

// AddressFamily selects the local synthetic DNS address, not the exit's family.
type AddressFamily uint8

const (
	IPv4 AddressFamily = 4
	IPv6 AddressFamily = 6
)

var (
	fakeIPv4Prefix = netip.MustParsePrefix("198.18.0.0/15")
	fakeIPv6Prefix = netip.MustParsePrefix("fd42:6266:7000::/96")
)

func FakeIPv4Prefix() netip.Prefix { return fakeIPv4Prefix }
func FakeIPv6Prefix() netip.Prefix { return fakeIPv6Prefix }

// IsFakeAddress reserves both complete pools, including unknown and zoned
// input. An address from either pool must never be dialed without restoration.
func IsFakeAddress(ip netip.Addr) bool {
	ip = ip.WithZone("").Unmap()
	return fakeIPv4Prefix.Contains(ip) || fakeIPv6Prefix.Contains(ip)
}

// MappingAddress converts a supported alias into the one IPv4 mapping key.
// Zones and IPv6 aliases whose suffix is outside the IPv4 pool are invalid.
func MappingAddress(ip netip.Addr) (netip.Addr, bool) {
	if !ip.IsValid() || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	if fakeIPv4Prefix.Contains(ip) {
		return ip, true
	}
	if !fakeIPv6Prefix.Contains(ip) {
		return netip.Addr{}, false
	}
	bytes := ip.As16()
	mapping := netip.AddrFrom4([4]byte(bytes[12:16]))
	return mapping, fakeIPv4Prefix.Contains(mapping)
}

func IPv6Address(ip netip.Addr) (netip.Addr, bool) {
	if !ip.IsValid() || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	if !fakeIPv4Prefix.Contains(ip) {
		return netip.Addr{}, false
	}
	bytes := fakeIPv6Prefix.Addr().As16()
	v4 := ip.As4()
	copy(bytes[12:], v4[:])
	return netip.AddrFrom16(bytes), true
}
