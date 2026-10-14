package main

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"time"

	dnsfront "bfp/adapter/dns"
	"bfp/adapter/socks"
	"bfp/gateway"
	"bfp/session"
)

// A CLI DNS entry shares Client's selected Session with SOCKS. It synthesizes
// A/AAAA records and does not change system DNS, a TUN interface or OS routes.
type clientDNSConfig struct {
	Listen          string
	MappingTTL      time.Duration
	MappingCapacity int
}

func parseClientDNS(raw json.RawMessage) (*clientDNSConfig, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	values, err := configObject(raw, "dns", "listen", "mapping_ttl", "mapping_capacity")
	if err != nil {
		return nil, err
	}
	listen, err := configString(values["listen"], "dns.listen")
	if err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, configFieldError("dns.listen", "must be a literal loopback host and numeric port")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() || ip.Zone() != "" {
		return nil, configFieldError("dns.listen", "must be a literal loopback host without a zone")
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || port != strconv.FormatUint(number, 10) {
		return nil, configFieldError("dns.listen", "must use a numeric port from 0 to 65535")
	}
	result := &clientDNSConfig{Listen: listen, MappingTTL: 10 * time.Minute, MappingCapacity: 64}
	if value, exists := values["mapping_ttl"]; exists {
		text, err := configString(value, "dns.mapping_ttl")
		if err != nil {
			return nil, err
		}
		ttl, err := time.ParseDuration(text)
		if err != nil || ttl <= 0 || ttl > 30*24*time.Hour {
			return nil, configFieldError("dns.mapping_ttl", "must be a positive duration no greater than 720h")
		}
		result.MappingTTL = ttl
	}
	if value, exists := values["mapping_capacity"]; exists {
		capacity, err := configUint(value, "dns.mapping_capacity", 128)
		if err != nil {
			return nil, err
		}
		if capacity != 64 && capacity != 128 {
			return nil, configFieldError("dns.mapping_capacity", "must be 64 or 128")
		}
		result.MappingCapacity = int(capacity)
	}
	return result, nil
}

func (c clientDNSConfig) addressFactory() (session.ClientAddressScopeFactory, error) {
	return gateway.NewFakeIPScopeFactory(c.MappingTTL, c.MappingCapacity)
}

// serveClientEntries owns and joins the entry servers only. Client owns the
// mapping factory and Session; stopping one listener cancels the other entry.
func serveClientEntries(ctx context.Context, cfg clientConfig, client *session.Client) error {
	dnsConfig, err := parseClientDNS(cfg.DNS)
	if err != nil {
		return err
	}
	// Capture readiness from the Session selected before entry requests can
	// retire it or trigger a new Connect. The current pointer can be nil while
	// a replacement handshake is pending; logging must never dereference it.
	owner := client.Session()
	if owner == nil {
		return session.ErrClosed
	}
	initialStats := owner.Stats()
	socksConfig, err := cfg.socksConfig(client)
	if err != nil {
		return err
	}
	socksServer, err := socks.New(socksConfig)
	if err != nil {
		return err
	}
	defer socksServer.Close()
	var dnsServer *dnsfront.Server
	if dnsConfig != nil {
		dnsServer, err = dnsfront.New(dnsfront.Config{Listen: dnsConfig.Listen, Client: client})
		if err != nil {
			return err
		}
		defer dnsServer.Close()
	}
	entryCtx, stop := context.WithCancel(ctx)
	defer stop()
	completed := make(chan error, 2)
	count := 1
	go func() { completed <- socksServer.Serve(entryCtx) }()
	if dnsServer != nil {
		count++
		go func() { completed <- dnsServer.Serve(entryCtx) }()
		emit(map[string]any{"event": "dns_listening", "address": dnsServer.Addr().String(), "record_types": []string{"A", "AAAA"}})
	}
	emit(map[string]any{"event": "socks_listening", "address": socksServer.Addr().String(), "session": initialStats})
	first := <-completed
	stop()
	_ = socksServer.Close()
	if dnsServer != nil {
		_ = dnsServer.Close()
	}
	for i := 1; i < count; i++ {
		if err := <-completed; first == nil {
			first = err
		}
	}
	return first
}
