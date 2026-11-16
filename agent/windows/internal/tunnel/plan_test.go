package tunnel

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"
)

const wifi uint64 = 7

var (
	home = System{
		Default4: Gateway{Interface: wifi, Via: netip.MustParseAddr("192.168.1.1")},
		Default6: Gateway{Interface: wifi, Via: netip.MustParseAddr("fe80::1")},
		Links: []Link{
			{Interface: wifi, Prefix: netip.MustParsePrefix("192.168.1.0/24")},
			{Interface: wifi, Prefix: netip.MustParsePrefix("2001:db8:1::/64")},
			{Interface: wifi, Prefix: netip.MustParsePrefix("fd12:3456:789a:1::/64")},
		},
	}
	systemDefaults = []Route{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Interface: wifi, Via: netip.MustParseAddr("192.168.1.1")},
		{Prefix: netip.MustParsePrefix("::/0"), Interface: wifi, Via: netip.MustParseAddr("fe80::1")},
		{Prefix: netip.MustParsePrefix("192.168.1.0/24"), Interface: wifi},
		{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), Interface: wifi},
		{Prefix: netip.MustParsePrefix("fd12:3456:789a:1::/64"), Interface: wifi},
	}
)

func laptop(exit, local bool) Config {
	server1 := Peer{Endpoint: "203.0.113.1:51820", Pin: "203.0.113.1:51820", AllowedIPs: []string{"10.88.0.1/32", "10.88.0.3/32"}}
	server2 := Peer{Endpoint: "203.0.113.2:51820", Pin: "203.0.113.2:51820", AllowedIPs: []string{"10.88.0.2/32"}}
	server4 := Peer{Endpoint: "[2001:db8:ffff::4]:51820", Pin: "[2001:db8:ffff::4]:51820", AllowedIPs: []string{"10.88.0.4/32"}}
	if exit {
		server2.AllowedIPs = append(server2.AllowedIPs, "0.0.0.0/0", "::/0")
	}
	return Config{Address: "10.88.0.10", Peers: []Peer{server1, server2, server4}, DNS: []string{"10.88.0.1", "1.1.1.1"}, Exit: exit, Local: local}
}

func lookup(routes []Route, destination string) Route {
	address := netip.MustParseAddr(destination)
	best := Route{Prefix: netip.PrefixFrom(address, 0), Interface: 999}
	found := false
	for _, route := range routes {
		if route.Prefix.Contains(address) && (!found || route.Prefix.Bits() >= best.Prefix.Bits()) {
			best, found = route, true
		}
	}
	return best
}

func table(system System, plan Plan) []Route {
	routes := slices.Clone(systemDefaults)
	routes = append(routes, system.Routes...)
	for _, link := range system.Links {
		routes = append(routes, Route{Prefix: link.Prefix, Interface: link.Interface})
	}
	return append(routes, plan.Routes...)
}

func tunnelPrefixes(plan Plan) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, route := range plan.Routes {
		if route.Interface == Inside {
			prefixes = append(prefixes, route.Prefix)
		}
	}
	return prefixes
}

func TestIPv6IsCapturedAndDroppedWhileAnExitIsOn(t *testing.T) {
	for _, local := range []bool{false, true} {
		for _, system := range []System{home, {Default4: home.Default4, Links: home.Links[:1]}} {
			plan := Build(laptop(true, local), system)
			if !slices.Contains(plan.Addresses, netip.MustParsePrefix("fd88:88::a/128")) || !slices.Contains(plan.Addresses, netip.MustParsePrefix("10.88.0.10/32")) {
				t.Fatalf("addresses %v", plan.Addresses)
			}
			tunnel := tunnelPrefixes(plan)
			for _, half := range []string{"::/1", "8000::/1", "0.0.0.0/1", "128.0.0.0/1"} {
				if !slices.Contains(tunnel, netip.MustParsePrefix(half)) {
					t.Fatalf("local %v: %s is not on the tunnel: %v", local, half, plan.Routes)
				}
			}
			for _, route := range plan.Routes {
				if route.Interface != Inside && route.Prefix.Bits() != route.Prefix.Addr().BitLen() {
					t.Fatalf("only endpoint pins may leave the tunnel: %+v", route)
				}
			}
			everything := table(system, plan)
			for _, destination := range []string{"2606:4700:4700::1111", "2a00:1450:4001::1", "fd00::1", "1.1.1.1", "8.8.8.8"} {
				if route := lookup(everything, destination); route.Interface != Inside {
					t.Fatalf("local %v: %s leaves through %+v", local, destination, route)
				}
			}
			for _, endpoint := range []string{"203.0.113.1", "203.0.113.2"} {
				if route := lookup(everything, endpoint); route.Interface != wifi || route.Via != home.Default4.Via {
					t.Fatalf("endpoint %s goes through %+v, want the original gateway", endpoint, route)
				}
			}
			six := slices.Contains(plan.Routes, Route{Prefix: netip.MustParsePrefix("2001:db8:ffff::4/128"), Interface: wifi, Via: home.Default6.Via})
			if six != (system.Default6.Interface == wifi) {
				t.Fatalf("the IPv6 endpoint is pinned %v with IPv6 gateway %+v", six, system.Default6)
			}
			if !slices.Equal(plan.DNS, []netip.Addr{netip.MustParseAddr("10.88.0.1"), netip.MustParseAddr("1.1.1.1")}) {
				t.Fatalf("DNS %v", plan.DNS)
			}
		}
	}
}

func TestWithoutAnExitOnlyMembersAreRouted(t *testing.T) {
	plan := Build(laptop(false, false), home)
	want := []Route{
		{Prefix: netip.MustParsePrefix("10.88.0.1/32")},
		{Prefix: netip.MustParsePrefix("10.88.0.3/32")},
		{Prefix: netip.MustParsePrefix("10.88.0.2/32")},
		{Prefix: netip.MustParsePrefix("10.88.0.4/32")},
	}
	if !slices.Equal(plan.Routes, want) || len(plan.DNS) != 0 {
		t.Fatalf("plan %+v", plan)
	}
	stray := laptop(false, false)
	stray.Peers[1].AllowedIPs = append(stray.Peers[1].AllowedIPs, "0.0.0.0/0", "::/0")
	if plan := Build(stray, home); !slices.Equal(plan.Routes, want) {
		t.Fatalf("a default route without an exit: %+v", plan.Routes)
	}
	if plan := Build(Config{}, home); len(plan.Addresses) != 0 || len(plan.Routes) != 0 {
		t.Fatalf("a tunnel that is down has %+v", plan)
	}
}

func TestAllowLocalNetworkKeepsTheLaptopsSubnets(t *testing.T) {
	inside := table(home, Build(laptop(true, false), home))
	outside := table(home, Build(laptop(true, true), home))
	for _, neighbour := range []string{"192.168.1.50", "fd12:3456:789a:1::50"} {
		if route := lookup(inside, neighbour); route.Interface != Inside {
			t.Fatalf("%s stays outside with Allow Local Network off: %+v", neighbour, route)
		}
		if route := lookup(outside, neighbour); route.Interface != wifi {
			t.Fatalf("%s goes into the tunnel with Allow Local Network on: %+v", neighbour, route)
		}
	}
	if route := lookup(outside, "2001:db8:1::50"); route.Interface != Inside {
		t.Fatalf("a public subnet stays outside with Allow Local Network on: %+v", route)
	}
	onLink := laptop(true, false)
	onLink.Peers[0].Pin = "192.168.1.20:51820"
	pins := Build(onLink, home).Routes
	if !slices.Contains(pins, Route{Prefix: netip.MustParsePrefix("192.168.1.20/32"), Interface: wifi}) {
		t.Fatalf("an endpoint on the local network is not pinned on its link: %+v", pins)
	}
}

func TestAHostileNetworkCannotPullTrafficOutOfTheExit(t *testing.T) {
	gateway := home.Default4.Via
	hostile := home
	hostile.Links = append(slices.Clone(home.Links), Link{Interface: wifi, Prefix: netip.MustParsePrefix("128.0.0.0/1")})
	hostile.Routed = []uint64{wifi}
	hostile.Routes = []Route{
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Interface: wifi, Via: gateway},
		{Prefix: netip.MustParsePrefix("0.0.0.0/2"), Interface: wifi, Via: gateway},
		{Prefix: netip.MustParsePrefix("64.0.0.0/2"), Interface: wifi, Via: gateway},
		{Prefix: netip.MustParsePrefix("2000::/3"), Interface: wifi, Via: home.Default6.Via},
		{Prefix: netip.MustParsePrefix("203.0.113.1/32"), Interface: wifi, Via: gateway},
		{Prefix: netip.MustParsePrefix("192.168.1.0/24"), Interface: wifi},
		{Prefix: netip.MustParsePrefix("224.0.0.0/4"), Interface: wifi},
	}
	for _, local := range []bool{false, true} {
		plan := Build(laptop(true, local), hostile)
		everything := table(hostile, plan)
		for _, destination := range []string{"203.0.113.50", "8.8.8.8", "100.64.0.1", "198.51.100.1", "2606:4700:4700::1111"} {
			if route := lookup(everything, destination); route.Interface != Inside {
				t.Fatalf("local %v: %s leaves through %+v", local, destination, route)
			}
		}
		if route := lookup(everything, "203.0.113.1"); route.Interface != wifi {
			t.Fatalf("local %v: the signed endpoint was shadowed: %+v", local, route)
		}
		if slices.Contains(tunnelPrefixes(plan), netip.MustParsePrefix("224.0.0.0/4")) {
			t.Fatalf("multicast was shadowed: %v", plan.Routes)
		}
		if route := lookup(everything, "192.168.1.50"); (route.Interface == wifi) != local {
			t.Fatalf("local %v: the LAN goes through %+v", local, route)
		}
	}
}

func TestRoutesOnAnInterfaceWithoutADefaultAreShadowedUnlessPrivate(t *testing.T) {
	const otherWifi, wsl uint64 = 8, 9
	hostile := home
	hostile.Routed = []uint64{wifi}
	hostile.Routes = []Route{
		{Prefix: netip.MustParsePrefix("0.0.0.0/2"), Interface: otherWifi, Via: netip.MustParseAddr("10.0.0.1")},
		{Prefix: netip.MustParsePrefix("64.0.0.0/2"), Interface: otherWifi, Via: netip.MustParseAddr("10.0.0.1")},
		{Prefix: netip.MustParsePrefix("128.0.0.0/2"), Interface: otherWifi, Via: netip.MustParseAddr("10.0.0.1")},
		{Prefix: netip.MustParsePrefix("192.0.0.0/2"), Interface: otherWifi, Via: netip.MustParseAddr("10.0.0.1")},
		{Prefix: netip.MustParsePrefix("2000::/3"), Interface: otherWifi, Via: netip.MustParseAddr("fe80::2")},
		{Prefix: netip.MustParsePrefix("10.0.0.0/24"), Interface: otherWifi},
		{Prefix: netip.MustParsePrefix("172.20.0.0/16"), Interface: wsl},
	}
	for _, local := range []bool{false, true} {
		plan := Build(laptop(true, local), hostile)
		everything := table(hostile, plan)
		for _, destination := range []string{"8.8.8.8", "100.64.0.1", "198.51.100.1", "203.0.113.50", "2606:4700:4700::1111"} {
			if route := lookup(everything, destination); route.Interface != Inside {
				t.Fatalf("local %v: %s leaves through %+v", local, destination, route)
			}
		}
		for destination, want := range map[string]uint64{"172.20.0.5": wsl, "10.0.0.7": otherWifi, "203.0.113.1": wifi} {
			if route := lookup(everything, destination); route.Interface != want {
				t.Fatalf("local %v: %s goes through %+v, want interface %d", local, destination, route, want)
			}
		}
	}
}

func TestAnotherVPNKeepsItsRoutesWhileAnExitIsOn(t *testing.T) {
	const other = 53<<48 | 4
	if !Virtual(other) || Virtual(131<<48|5) || Virtual(6<<48|1) || Virtual(71<<48|2) || Virtual(243<<48|3) {
		t.Fatal("the adapter types are read wrongly")
	}
	routes := func(adapter uint64) []Route {
		return []Route{
			{Prefix: netip.MustParsePrefix("100.64.0.0/10"), Interface: adapter},
			{Prefix: netip.MustParsePrefix("fd7a:115c:a1e0::/48"), Interface: adapter},
			{Prefix: netip.MustParsePrefix("0.0.0.0/2"), Interface: adapter},
			{Prefix: netip.MustParsePrefix("64.0.0.0/2"), Interface: adapter},
			{Prefix: netip.MustParsePrefix("128.0.0.0/2"), Interface: adapter},
			{Prefix: netip.MustParsePrefix("192.0.0.0/2"), Interface: adapter},
		}
	}
	vpn := home
	vpn.Routed, vpn.Virtual, vpn.Routes = []uint64{wifi}, []uint64{other}, routes(other)
	vpn.Links = append(slices.Clone(home.Links), Link{Interface: other, Prefix: netip.MustParsePrefix("100.100.0.0/16")})
	for _, local := range []bool{false, true} {
		plan := Build(laptop(true, local), vpn)
		everything := table(vpn, plan)
		for _, destination := range []string{"100.101.102.103", "fd7a:115c:a1e0::1", "8.8.8.8", "100.100.1.1", "203.0.113.50"} {
			if route := lookup(everything, destination); route.Interface != other {
				t.Fatalf("local %v: %s goes through %+v, want the other VPN", local, destination, route)
			}
		}
		if route := lookup(everything, "2606:4700:4700::1111"); route.Interface != Inside {
			t.Fatalf("local %v: IPv6 leaves through %+v", local, route)
		}
	}
	const transition uint64 = 131<<48 | 5
	isatap := home
	isatap.Routed = []uint64{wifi}
	isatap.Virtual = nil
	isatap.Routes = []Route{
		{Prefix: netip.MustParsePrefix("0.0.0.0/2"), Interface: transition},
		{Prefix: netip.MustParsePrefix("2000::/3"), Interface: transition, Via: netip.MustParseAddr("fe80::2")},
	}
	for _, local := range []bool{false, true} {
		everything := table(isatap, Build(laptop(true, local), isatap))
		for _, destination := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
			if route := lookup(everything, destination); route.Interface != Inside {
				t.Fatalf("local %v: %s leaves through the transition tunnel %+v", local, destination, route)
			}
		}
	}
	const otherWifi uint64 = 8
	physical := home
	physical.Routed, physical.Routes = []uint64{wifi}, routes(otherWifi)
	plan := Build(laptop(true, true), physical)
	everything := table(physical, plan)
	for _, destination := range []string{"100.101.102.103", "8.8.8.8", "203.0.113.50"} {
		if route := lookup(everything, destination); route.Interface != Inside {
			t.Fatalf("on a Wi-Fi adapter %s leaves through %+v", destination, route)
		}
	}
	if route := lookup(everything, "fd7a:115c:a1e0::1"); route.Interface != otherWifi {
		t.Fatalf("a private prefix on a Wi-Fi adapter without a default goes through %+v", route)
	}
}

func TestAHintedEndpointIsNeverPinned(t *testing.T) {
	hinted := laptop(true, false)
	hinted.Peers[0].Endpoint = "198.51.100.7:51820"
	plan := Build(hinted, home)
	for _, route := range plan.Routes {
		if route.Interface != Inside && route.Prefix == netip.MustParsePrefix("198.51.100.7/32") {
			t.Fatalf("a hinted endpoint was pinned outside the exit: %+v", route)
		}
	}
	if !slices.Contains(plan.Routes, Route{Prefix: netip.MustParsePrefix("203.0.113.1/32"), Interface: wifi, Via: home.Default4.Via}) {
		t.Fatalf("the signed endpoint is not pinned: %+v", plan.Routes)
	}
	if route := lookup(table(home, plan), "198.51.100.7"); route.Interface != Inside {
		t.Fatalf("the hinted address leaves through %+v", route)
	}
}

func TestWithIPv6OffTheLaptopRunsIPv4Only(t *testing.T) {
	off := System{Default4: home.Default4, Links: home.Links[:1], NoIPv6: true}
	plan := Build(laptop(true, false), off)
	if plan.ExitRefused || !slices.Equal(plan.Addresses, []netip.Prefix{netip.MustParsePrefix("10.88.0.10/32")}) {
		t.Fatalf("plan %+v", plan)
	}
	for _, route := range plan.Routes {
		if route.Prefix.Addr().Is6() {
			t.Fatalf("an IPv6 route with IPv6 off: %+v", route)
		}
	}
	if tunnel := tunnelPrefixes(plan); !slices.Contains(tunnel, netip.MustParsePrefix("0.0.0.0/1")) || !slices.Contains(tunnel, netip.MustParsePrefix("128.0.0.0/1")) {
		t.Fatalf("the exit is not on the tunnel: %v", tunnel)
	}

	leaky := home
	leaky.NoIPv6 = true
	refused := Build(laptop(true, false), leaky)
	members := Build(laptop(false, false), leaky)
	if !refused.ExitRefused || !reflect.DeepEqual(refused.Routes, members.Routes) || len(refused.DNS) != 0 {
		t.Fatalf("an exit with IPv6 on another interface: %+v", refused)
	}
}

func TestNRPTSendsEveryNameToTheDocumentsDNS(t *testing.T) {
	policy, on := NRPT(Build(laptop(true, false), home))
	if want := (Policy{Name: []string{"."}, Servers: "10.88.0.1;1.1.1.1", ConfigOptions: 8, Version: 2}); !on || !reflect.DeepEqual(policy, want) {
		t.Fatalf("policy %+v %v", policy, on)
	}
	if _, on := NRPT(Build(laptop(false, false), home)); on {
		t.Fatal("a policy without an exit")
	}
	refused := home
	refused.NoIPv6 = true
	if _, on := NRPT(Build(laptop(true, false), refused)); on {
		t.Fatal("a policy for a refused exit")
	}
}
