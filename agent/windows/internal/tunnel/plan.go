package tunnel

import (
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
