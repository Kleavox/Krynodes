package tunnel

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"reflect"
	"slices"
	"strings"
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

func TestARelayEndpointLeavesThroughItsPinNotTheTunnel(t *testing.T) {
	relayed := func(local bool, host string) Config {
		config := laptop(true, local)
		config.Peers = append(config.Peers[1:2], Peer{Endpoint: host + ":51920", Pin: host + ":51920", Relay: true, AllowedIPs: []string{"10.88.0.3/32"}})
		return config
	}
	gateway := home.Default4.Via
	routed := home
	routed.Routed = []uint64{wifi}
	routed.Routes = []Route{
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Interface: wifi, Via: gateway},
		{Prefix: netip.MustParsePrefix("203.0.113.3/32"), Interface: wifi, Via: gateway},
	}
	for _, local := range []bool{false, true} {
		for _, system := range []System{home, routed} {
			plan := Build(relayed(local, "203.0.113.3"), system)
			if !slices.Contains(plan.Routes, Route{Prefix: netip.MustParsePrefix("203.0.113.3/32"), Interface: wifi, Via: gateway}) {
				t.Fatalf("local %v: the meeting point's host is not pinned: %+v", local, plan.Routes)
			}
			everything := table(system, plan)
			if route := lookup(everything, "203.0.113.3"); route.Interface != wifi {
				t.Fatalf("local %v: the pair port's datagrams go through %+v", local, route)
			}
			if route := lookup(everything, "203.0.113.50"); route.Interface != Inside {
				t.Fatalf("local %v: a route covering the relay host pulled %+v out of the exit", local, route)
			}
			if route := lookup(everything, "10.88.0.3"); route.Interface != Inside {
				t.Fatalf("local %v: the member behind NAT is reached through %+v", local, route)
			}
		}
		onLink := Build(relayed(local, "192.168.1.30"), home)
		if !slices.Contains(onLink.Routes, Route{Prefix: netip.MustParsePrefix("192.168.1.30/32"), Interface: wifi}) {
			t.Fatalf("local %v: a relay host on the local network is not pinned on its link: %+v", local, onLink.Routes)
		}
		if route := lookup(table(home, onLink), "192.168.1.30"); route.Interface != wifi {
			t.Fatalf("local %v: a relay host on the local network goes through %+v", local, route)
		}
	}
}

func key(seed byte) (string, string) {
	raw := make([]byte, 32)
	for index := range raw {
		raw[index] = seed
	}
	return base64.StdEncoding.EncodeToString(raw), hex.EncodeToString(raw)
}

func TestARelayPeerThatLosesItsEndpointIsMadeAgain(t *testing.T) {
	public, publicHex := key(1)
	behind, behindHex := key(2)
	gone, goneHex := key(3)
	before := Config{Key: make([]byte, 32), Peers: []Peer{
		{Key: public, Endpoint: "203.0.113.1:51820", Keepalive: 25, AllowedIPs: []string{"10.88.0.1/32"}},
		{Key: behind, Endpoint: "203.0.113.1:51920", Relay: true, Keepalive: 25, AllowedIPs: []string{"10.88.0.2/32"}},
		{Key: gone, Endpoint: "203.0.113.4:51820", Keepalive: 25, AllowedIPs: []string{"10.88.0.4/32"}},
	}}
	after := Config{Key: before.Key, Peers: []Peer{before.Peers[0], before.Peers[1]}}
	after.Peers[1].Endpoint = ""
	uapi, err := settings(after, &before)
	if err != nil {
		t.Fatal(err)
	}
	want := "private_key=" + hex.EncodeToString(before.Key) + "\n" +
		"public_key=" + publicHex + "\nendpoint=203.0.113.1:51820\npersistent_keepalive_interval=25\nreplace_allowed_ips=true\nallowed_ip=10.88.0.1/32\n" +
		"public_key=" + behindHex + "\nremove=true\n" +
		"public_key=" + behindHex + "\npersistent_keepalive_interval=25\nreplace_allowed_ips=true\nallowed_ip=10.88.0.2/32\n" +
		"public_key=" + goneHex + "\nremove=true\n"
	if uapi != want {
		t.Fatalf("got\n%s\nwant\n%s", uapi, want)
	}
	if again, err := settings(after, &after); err != nil || strings.Contains(again, "remove=true") {
		t.Fatalf("a peer without an endpoint is made again on every change: %v\n%s", err, again)
	}
	if _, err := settings(Config{Peers: after.Peers}, nil); err == nil {
		t.Fatal("no private key is no tunnel")
	}
}

func TestRoamingNeverMovesARelayPeerOffTheChosenMeetingPoint(t *testing.T) {
	public, publicHex := key(1)
	behind, behindHex := key(2)
	other, otherHex := key(3)
	waiting, waitingHex := key(4)
	peers := []Peer{
		{Key: public, Endpoint: "203.0.113.1:51820"},
		{Key: behind, Endpoint: "203.0.113.3:51920", Relay: true},
		{Key: other, Endpoint: "203.0.113.3:51921", Relay: true},
		{Key: waiting, Relay: true},
	}
	dump := "private_key=" + publicHex + "\nlisten_port=51820\n" +
		"public_key=" + publicHex + "\nendpoint=198.51.100.1:51820\nlast_handshake_time_sec=1\n" +
		"public_key=" + behindHex + "\nendpoint=203.0.113.1:51920\ntx_bytes=10\n" +
		"public_key=" + otherHex + "\nendpoint=[::ffff:203.0.113.3]:51921\n" +
		"public_key=" + waitingHex + "\nendpoint=203.0.113.1:51922\n"
	if got, want := reassert(peers, dump), "public_key="+behindHex+"\nupdate_only=true\nendpoint=203.0.113.3:51920\n"; got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if got := reassert(peers[2:], "public_key="+otherHex+"\nendpoint=203.0.113.3:51921\n"); got != "" {
		t.Fatalf("an endpoint in place is set again:\n%s", got)
	}
	if got := reassert(peers[1:2], ""); got != "public_key="+behindHex+"\nupdate_only=true\nendpoint=203.0.113.3:51920\n" {
		t.Fatalf("a relay peer with no endpoint yet:\n%s", got)
	}
}
