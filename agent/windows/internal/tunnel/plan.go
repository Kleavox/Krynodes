package tunnel

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

const Inside uint64 = 0

var (
	halves = map[netip.Prefix][]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"): {netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")},
		netip.MustParsePrefix("::/0"):      {netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")},
	}
	private = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("fc00::/7"),
	}
	broadcast = netip.MustParseAddr("255.255.255.255")
)

type Peer struct {
	Key          string
	PresharedKey string
	Endpoint     string
	Pin          string
	Relay        bool
	AllowedIPs   []string
	Keepalive    int
}

type Config struct {
	Key     []byte
	Address string
	MTU     int
	Peers   []Peer
	DNS     []string
	Exit    bool
	Local   bool
}

type Gateway struct {
	Interface uint64
	Via       netip.Addr
}

type Link struct {
	Interface uint64
	Prefix    netip.Prefix
}

type System struct {
	Default4 Gateway
	Default6 Gateway
	Links    []Link
	Routes   []Route
	Routed   []uint64
	Virtual  []uint64
	NoIPv6   bool
}

type Route struct {
	Prefix    netip.Prefix
	Interface uint64
	Via       netip.Addr
}

type Plan struct {
	Addresses   []netip.Prefix
	Routes      []Route
	DNS         []netip.Addr
	ExitRefused bool
}

type Policy struct {
	Name          []string
	Servers       string
	ConfigOptions uint32
	Version       uint32
}

func Virtual(luid uint64) bool {
	return luid>>48 == 53
}

func inside(prefix netip.Prefix, ranges []netip.Prefix) bool {
	return slices.ContainsFunc(ranges, func(outer netip.Prefix) bool {
		return outer.Bits() <= prefix.Bits() && outer.Contains(prefix.Addr())
	})
}

func Build(config Config, system System) Plan {
	address, err := netip.ParseAddr(config.Address)
	if err != nil || !address.Is4() {
		return Plan{}
	}
	plan := Plan{Addresses: []netip.Prefix{netip.PrefixFrom(address, 32)}}
	if six, err := netip.ParseAddr(network.Address6(config.Address)); err == nil && !system.NoIPv6 {
		plan.Addresses = append(plan.Addresses, netip.PrefixFrom(six, 128))
	}
	if config.Exit && system.NoIPv6 && system.Default6.Interface != Inside {
		config.Exit, plan.ExitRefused = false, true
	}
	usable := func(prefix netip.Prefix) bool { return prefix.Addr().Is4() || !system.NoIPv6 }
	add := func(route Route) {
		if usable(route.Prefix) && !slices.Contains(plan.Routes, route) {
			plan.Routes = append(plan.Routes, route)
		}
	}
	for _, peer := range config.Peers {
		for _, text := range peer.AllowedIPs {
			prefix, err := netip.ParsePrefix(text)
			if err != nil {
				continue
			}
			prefix = prefix.Masked()
			if prefix.Bits() > 0 {
				add(Route{Prefix: prefix})
				continue
			}
			if config.Exit {
				for _, half := range halves[prefix] {
					add(Route{Prefix: half})
				}
			}
		}
	}
	if !config.Exit {
		return plan
	}
	var pins []netip.Prefix
	for _, peer := range config.Peers {
		endpoint, err := netip.ParseAddrPort(peer.Pin)
		if err != nil {
			continue
		}
		host := endpoint.Addr().Unmap()
		pin := netip.PrefixFrom(host, host.BitLen())
		pins = append(pins, pin)
		if link := slices.IndexFunc(system.Links, func(link Link) bool { return link.Prefix.Contains(host) }); link >= 0 {
			add(Route{Prefix: pin, Interface: system.Links[link].Interface})
			continue
		}
		gateway := system.Default6
		if host.Is4() {
			gateway = system.Default4
		}
		if gateway.Interface != Inside {
			add(Route{Prefix: pin, Interface: gateway.Interface, Via: gateway.Via})
		}
	}
	var kept []netip.Prefix
	for _, link := range system.Links {
		if slices.Contains(system.Virtual, link.Interface) {
			continue
		}
		if config.Local && inside(link.Prefix, private) {
			kept = append(kept, link.Prefix)
			continue
		}
		add(Route{Prefix: link.Prefix})
	}
	for _, route := range system.Routes {
		if !slices.Contains(system.Virtual, route.Interface) && shadow(route, slices.Contains(system.Routed, route.Interface), pins, kept) {
			add(Route{Prefix: route.Prefix.Masked()})
		}
	}
	for _, text := range config.DNS {
		if server, err := netip.ParseAddr(text); err == nil {
			plan.DNS = append(plan.DNS, server.Unmap())
		}
	}
	return plan
}

func shadow(route Route, routed bool, pins, kept []netip.Prefix) bool {
	prefix := route.Prefix.Masked()
	target := prefix.Addr()
	switch {
	case prefix.Bits() <= 1, target.IsMulticast(), target.IsLoopback(), target.IsLinkLocalUnicast(), target == broadcast, slices.Contains(pins, prefix):
		return false
	case !routed:
		return !inside(prefix, private)
	}
	return !inside(prefix, kept)
}

func hexKey(text string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil || len(raw) != 32 {
		return "", errors.New("a WireGuard key is not 32 bytes of base64")
	}
	return hex.EncodeToString(raw), nil
}

func settings(config Config, before *Config) (string, error) {
	if len(config.Key) != 32 {
		return "", errors.New("this laptop's WireGuard key is missing")
	}
	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\n", hex.EncodeToString(config.Key))
	var had []Peer
	if before != nil {
		had = before.Peers
	}
	for _, peer := range config.Peers {
		key, err := hexKey(peer.Key)
		if err != nil {
			return "", err
		}
		if peer.Endpoint == "" && slices.ContainsFunc(had, func(was Peer) bool { return was.Key == peer.Key && was.Endpoint != "" }) {
			fmt.Fprintf(&uapi, "public_key=%s\nremove=true\n", key)
		}
		fmt.Fprintf(&uapi, "public_key=%s\n", key)
		if peer.PresharedKey != "" {
			psk, err := hexKey(peer.PresharedKey)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&uapi, "preshared_key=%s\n", psk)
		}
		if peer.Endpoint != "" {
			fmt.Fprintf(&uapi, "endpoint=%s\n", peer.Endpoint)
		}
		fmt.Fprintf(&uapi, "persistent_keepalive_interval=%d\nreplace_allowed_ips=true\n", peer.Keepalive)
		for _, allowed := range peer.AllowedIPs {
			fmt.Fprintf(&uapi, "allowed_ip=%s\n", allowed)
		}
	}
	for _, was := range had {
		if slices.ContainsFunc(config.Peers, func(peer Peer) bool { return peer.Key == was.Key }) {
			continue
		}
		if key, err := hexKey(was.Key); err == nil {
			fmt.Fprintf(&uapi, "public_key=%s\nremove=true\n", key)
		}
	}
	return uapi.String(), nil
}

func reassert(peers []Peer, dump string) string {
	current := map[string]string{}
	key := ""
	for line := range strings.SplitSeq(dump, "\n") {
		name, value, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch name {
		case "public_key":
			key = value
		case "endpoint":
			current[key] = value
		}
	}
	var uapi strings.Builder
	for _, peer := range peers {
		key, err := hexKey(peer.Key)
		if err != nil || !peer.Relay || peer.Endpoint == "" || network.SameEndpoint(current[key], peer.Endpoint) {
			continue
		}
		fmt.Fprintf(&uapi, "public_key=%s\nupdate_only=true\nendpoint=%s\n", key, peer.Endpoint)
	}
	return uapi.String()
}

func NRPT(plan Plan) (Policy, bool) {
	if len(plan.DNS) == 0 {
		return Policy{}, false
	}
	servers := make([]string, len(plan.DNS))
	for index, server := range plan.DNS {
		servers[index] = server.String()
	}
	return Policy{Name: []string{"."}, Servers: strings.Join(servers, ";"), ConfigOptions: 8, Version: 2}, true
}

const (
	nrptName   = "Krynodes"
	nrptPrefix = "Krynodes for "
)

var vpnSuffixes = map[string]string{
	"100.100.100.100":    ".ts.net",
	"fd7a:115c:a1e0::53": ".ts.net",
}

type nrptRule struct {
	Key string
	Policy
}

func ours(rule nrptRule) bool {
	return rule.Key == nrptName || strings.HasPrefix(rule.Key, nrptPrefix)
}

func otherVPNRules(existing []nrptRule) []nrptRule {
	var rules []nrptRule
	for _, rule := range existing {
		if ours(rule) || !slices.Contains(rule.Name, ".") {
			continue
		}
		var names, servers []string
		for server := range strings.SplitSeq(rule.Servers, ";") {
			server = strings.TrimSpace(server)
			suffix, known := vpnSuffixes[server]
			if !known {
				continue
			}
			servers = append(servers, server)
			if !slices.Contains(names, suffix) {
				names = append(names, suffix)
			}
		}
		if len(names) > 0 {
			rules = append(rules, nrptRule{Key: nrptPrefix + rule.Key, Policy: Policy{Name: names, Servers: strings.Join(servers, ";"), ConfigOptions: 8, Version: 2}})
		}
	}
	return rules
}

func nrptChanges(exit bool, existing []nrptRule) (write []nrptRule, remove []string) {
	var want []nrptRule
	if exit {
		want = otherVPNRules(existing)
	}
	for _, rule := range existing {
		if strings.HasPrefix(rule.Key, nrptPrefix) && !slices.ContainsFunc(want, func(wanted nrptRule) bool { return wanted.Key == rule.Key }) {
			remove = append(remove, rule.Key)
		}
	}
	for _, rule := range want {
		if !slices.ContainsFunc(existing, func(had nrptRule) bool {
			return had.Key == rule.Key && slices.Equal(had.Name, rule.Name) && had.Servers == rule.Servers
		}) {
			write = append(write, rule)
		}
	}
	return write, remove
}
