//go:build linux

package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"syscall"

	"bfp/internal/securefile"
	"github.com/sagernet/netlink"
	"go.yaml.in/yaml/v3"
)

const nativeJournalName = "bfp-native-network.json"

// The package reserves a free routing table and rule interval before letting
// Mihomo create any network state. Recovery is bound to the boot and netns;
// it never flushes the system routing tables or restores a global snapshot.
type nativeNetworkLease struct {
	Version      int                 `json:"version"`
	BootID       string              `json:"boot_id"`
	Namespace    string              `json:"namespace"`
	Device       string              `json:"device"`
	DeviceIndex  int                 `json:"device_index"`
	Table        int                 `json:"table"`
	RuleStart    int                 `json:"rule_start"`
	FallbackRule int                 `json:"fallback_rule"`
	Captured     bool                `json:"captured"`
	Rules        []nativeRoutingRule `json:"rules,omitempty"`
	journal      string
}

func nativeNetworkIdentity() (string, string, error) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", "", err
	}
	namespace, err := os.Readlink("/proc/self/ns/net")
	return strings.TrimSpace(string(boot)), namespace, err
}

func nativeInstanceLock(runtimePath string) (*os.File, error) {
	root, err := os.Getwd()
	if err != nil || runtimePath != filepath.Join(root, "runtime") {
		return nil, errors.New("native supervisor requires this package's runtime")
	}
	lock := os.NewFile(9, "native.lock")
	if lock == nil {
		return nil, errors.New("native supervisor has no inherited instance lock")
	}
	info, err := lock.Stat()
	pathInfo, pathErr := os.Lstat(filepath.Join(runtimePath, "native.lock"))
	if err != nil || pathErr != nil || !pathInfo.Mode().IsRegular() || !os.SameFile(info, pathInfo) {
		lock.Close()
		return nil, errors.New("native supervisor instance lock does not match")
	}
	probe, err := os.OpenFile(filepath.Join(runtimePath, "native.lock"), os.O_RDWR, 0)
	if err != nil {
		lock.Close()
		return nil, err
	}
	err = syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	probe.Close()
	if !errors.Is(err, syscall.EWOULDBLOCK) {
		lock.Close()
		return nil, errors.New("native supervisor requires an already held instance lock")
	}
	syscall.CloseOnExec(9)
	return lock, nil
}

func nativeRecover(args []string) (int, error) {
	f := flag.NewFlagSet("native-recover", flag.ContinueOnError)
	runtimePath := f.String("runtime", "", "owned runtime directory")
	if err := f.Parse(args); err != nil {
		return 1, err
	}
	if f.NArg() != 0 {
		return 1, errors.New("unexpected native recovery arguments")
	}
	lock, err := nativeInstanceLock(*runtimePath)
	if err != nil {
		return 1, err
	}
	defer lock.Close()
	journal := filepath.Join(*runtimePath, nativeJournalName)
	if _, err := os.Lstat(journal); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	} else if err != nil {
		return 1, err
	}
	raw, err := securefile.Read(journal, 256*1024)
	if err != nil {
		return 1, errors.New("native recovery journal must be a private regular file")
	}
	var lease nativeNetworkLease
	if err := json.Unmarshal(raw, &lease); err != nil {
		return 1, errors.New("invalid native recovery journal")
	}
	lease.journal = journal
	if err := lease.cleanup(); err != nil {
		return 1, err
	}
	marker := filepath.Join(*runtimePath, "bfp-tun-supervisor.env")
	record, err := os.ReadFile(marker)
	if err == nil && string(record) == "version=1\nmode=tun\ndevice="+lease.Device+"\n" {
		if err := os.Remove(marker); err != nil {
			return 1, err
		}
		if err := os.Remove(filepath.Join(*runtimePath, "native-tun.generated.yaml")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return 1, err
		}
	}
	fmt.Println("BFP owned network state recovered")
	return 0, nil
}

func (l *nativeNetworkLease) save() error {
	raw, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	if info, err := os.Lstat(l.journal); err == nil && !info.Mode().IsRegular() {
		return errors.New("native journal must not be a link or special file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(l.journal), ".native-network-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(raw); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp.Name(), l.journal)
}

func nativeYAMLField(mapping *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func nativeSetYAMLInt(mapping *yaml.Node, key string, value int) {
	node := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprint(value)}
	if old := nativeYAMLField(mapping, key); old != nil {
		*old = *node
		return
	}
	mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, node)
}

func prepareNativeNetwork(runtimePath, config, device string) (*nativeNetworkLease, error) {
	if _, err := netlink.LinkByName(device); err == nil {
		return nil, errors.New("allocated TUN device already exists")
	} else {
		var absent netlink.LinkNotFoundError
		if !errors.As(err, &absent) {
			return nil, err
		}
	}
	raw, err := os.ReadFile(config)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("invalid native TUN configuration")
	}
	// Decode once for duplicate-key and alias validation before changing fields.
	var validated map[string]any
	if err := doc.Decode(&validated); err != nil {
		return nil, errors.New("invalid native TUN configuration")
	}
	tun := nativeYAMLField(doc.Content[0], "tun")
	if tun == nil || tun.Kind != yaml.MappingNode {
		return nil, errors.New("native supervisor requires a TUN mapping")
	}
	dev := nativeYAMLField(tun, "device")
	if dev == nil || dev.Value != device {
		return nil, errors.New("native TUN device does not match its marker")
	}
	rules, err := nativeRoutingRules()
	if err != nil {
		return nil, err
	}
	lease := &nativeNetworkLease{Version: 2, Device: device, journal: filepath.Join(runtimePath, nativeJournalName)}
	lease.BootID, lease.Namespace, err = nativeNetworkIdentity()
	if err != nil {
		return nil, err
	}
	// Sing-tun uses ruleStart..ruleStart+10. Reserve a wider free interval
	// without deleting any preexisting rule, including a default-9000 conflict.
	for start := 9000; start <= 32000; start += 32 {
		free := true
		for _, rule := range rules {
			if rule.Priority >= start && rule.Priority < start+32 {
				free = false
				break
			}
		}
		if free {
			lease.RuleStart = start
			break
		}
	}
	for priority := 32768; priority < 60000; priority++ {
		free := true
		for _, rule := range rules {
			if rule.Priority == priority {
				free = false
				break
			}
		}
		if free {
			lease.FallbackRule = priority
			break
		}
	}
	if lease.RuleStart == 0 || lease.FallbackRule == 0 {
		return nil, errors.New("no free native routing rule interval")
	}
	for attempt := 0; attempt < 64; attempt++ {
		var random [4]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, err
		}
		candidate := int(binary.BigEndian.Uint32(random[:])&0x3fffffff) + 65536
		free := true
		for _, rule := range rules {
			if rule.Table == candidate {
				free = false
				break
			}
		}
		if !free {
			continue
		}
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: candidate}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return nil, err
		}
		if len(routes) == 0 {
			lease.Table = candidate
			break
		}
	}
	if lease.Table == 0 {
		return nil, errors.New("no free native routing table")
	}
	nativeSetYAMLInt(tun, "iproute2-table-index", lease.Table)
	nativeSetYAMLInt(tun, "iproute2-rule-index", lease.RuleStart)
	nativeSetYAMLInt(tun, "auto-redirect-iproute2-fallback-rule-index", lease.FallbackRule)
	updated, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, err
	}
	// The plan is durable before the child can create even its first rule.
	if err := lease.save(); err != nil {
		return nil, err
	}
	if err := os.WriteFile(config, updated, 0o600); err != nil {
		return lease, err
	}
	return lease, nil
}

func (l *nativeNetworkLease) ownsRule(rule nativeRoutingRule) bool {
	if rule.Table == l.Table || rule.IifName == l.Device || rule.OifName == l.Device {
		return true
	}
	if rule.Priority < l.RuleStart || rule.Priority > l.RuleStart+10 {
		return false
	}
	// Auxiliary rules are tied to the reserved interval: goto its NOP, the
	// DNS-excluding main lookup, and the trailing NOP/unreachable rule. A
	// foreign lookup to another private table in the interval is not owned.
	return (rule.Goto >= l.RuleStart && rule.Goto <= l.RuleStart+10) ||
		(rule.Table == 254 && rule.Invert && rule.Dport != nil && rule.Dport.Start == 53 && rule.Dport.End == 53 && rule.SuppressPrefixlen == 0) ||
		(rule.Table <= 0 && rule.Goto < 0 && (rule.Type == 3 || rule.Type == 7 || rule.Type == 8))
}

func (l *nativeNetworkLease) capture() error {
	link, err := netlink.LinkByName(l.Device)
	if err != nil {
		return err
	}
	l.DeviceIndex = link.Attrs().Index
	rules, err := nativeRoutingRules()
	if err != nil {
		return err
	}
	l.Rules = nil
	for _, rule := range rules {
		if l.ownsRule(rule) {
			l.Rules = append(l.Rules, rule)
		}
	}
	l.Captured = true
	return l.save()
}

func (l *nativeNetworkLease) cleanup() error {
	boot, namespace, err := nativeNetworkIdentity()
	if err != nil {
		return err
	}
	if l.Version != 2 || l.BootID != boot || l.Namespace != namespace || !regexp.MustCompile(`^bfp-tun-[0-9a-f]{7}$`).MatchString(l.Device) ||
		l.Table < 65536 || l.Table > 0x4000ffff || l.RuleStart < 9000 || l.RuleStart > 32000 || l.FallbackRule < 32768 || l.FallbackRule >= 60000 {
		return errors.New("native journal identity or resource allocation does not match this boot and network namespace")
	}
	for _, rule := range l.Rules {
		if !l.ownsRule(rule) {
			return errors.New("native journal contains a rule outside its owned resources")
		}
	}
	rules, err := nativeRoutingRules()
	if err != nil {
		return err
	}
	for _, rule := range rules {
		owned := l.ownsRule(rule)
		if l.Captured {
			owned = false
			for _, expected := range l.Rules {
				if reflect.DeepEqual(rule, expected) {
					owned = true
					break
				}
			}
		}
		if owned {
			if err := deleteNativeRoutingRule(rule); err != nil && !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) {
				return fmt.Errorf("remove owned native rule family=%d priority=%d action=%d: %w", rule.Family, rule.Priority, rule.Type, err)
			}
		}
	}
	link, err := netlink.LinkByName(l.Device)
	if err == nil {
		if l.DeviceIndex != 0 && link.Attrs().Index != l.DeviceIndex {
			return errors.New("native TUN name now belongs to a different interface; retaining journal")
		}
		if err := netlink.LinkDel(link); err != nil {
			return fmt.Errorf("remove owned native TUN: %w", err)
		}
	} else {
		var absent netlink.LinkNotFoundError
		if !errors.As(err, &absent) {
			return err
		}
	}
	if err := os.Remove(l.journal); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
