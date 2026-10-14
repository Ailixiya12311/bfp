//go:build linux

package main

import (
	"github.com/sagernet/netlink/nl"
	"golang.org/x/sys/unix"
)

func nativeRoutingRules() ([]nativeRoutingRule, error) {
	var rules []nativeRoutingRule
	// An AF_UNSPEC dump also includes multicast-routing families 128/129.
	// TUN leases own unicast IPv4/IPv6 rules, so query those families directly.
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		request := nl.NewNetlinkRequest(unix.RTM_GETRULE, unix.NLM_F_DUMP)
		header := make([]byte, nativeRuleHeaderSize)
		header[0] = family
		request.AddRawData(header)
		messages, err := request.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWRULE)
		if err != nil {
			return nil, err
		}
		for _, payload := range messages {
			rule, err := decodeNativeRule(payload)
			if err != nil {
				return nil, err
			}
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func deleteNativeRoutingRule(rule nativeRoutingRule) error {
	request := nl.NewNetlinkRequest(unix.RTM_DELRULE, unix.NLM_F_ACK)
	request.AddRawData(rule.Payload)
	_, err := request.Execute(unix.NETLINK_ROUTE, 0)
	return err
}
