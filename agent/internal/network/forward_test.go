package network

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
)

type packet struct {
	src, dst, in, out, proto string
	port                     int
	states                   []string
}

type tables map[string][][]string

func portIn(port int, list string) bool {
	for entry := range strings.SplitSeq(list, ",") {
		first, last, ranged := strings.Cut(entry, ":")
		low, _ := strconv.Atoi(first)
		high := low
		if ranged {
			high, _ = strconv.Atoi(last)
		}
		if port >= low && port <= high {
			return true
		}
	}
	return false
}

func inPrefix(text, prefix string) bool {
	network, err := netip.ParsePrefix(prefix)
	address, other := netip.ParseAddr(text)
	return err == nil && other == nil && network.Contains(address)
}

func matches(t *testing.T, args []string, p packet) (bool, string) {
	t.Helper()
	negate, target := false, ""
	for i := 0; i < len(args); i++ {
		ok := true
		switch args[i] {
		case "!":
			negate = true
			continue
		case "-m", "--icmp-type", "--icmpv6-type":
			i++
			continue
		case "-j":
			target = args[i+1]
			i++
			continue
		case "-s":
			ok = inPrefix(p.src, args[i+1])
		case "-d":
			ok = inPrefix(p.dst, args[i+1])
		case "-i":
			prefix, wildcard := strings.CutSuffix(args[i+1], "+")
			ok = p.in == args[i+1] || wildcard && strings.HasPrefix(p.in, prefix)
		case "-o":
			ok = p.out == args[i+1]
		case "-p":
			ok = p.proto == args[i+1]
		case "--ctstate":
			ok = slices.ContainsFunc(strings.Split(args[i+1], ","), func(state string) bool { return slices.Contains(p.states, state) })
		case "--ctorigdstport", "--dports":
			ok = portIn(p.port, args[i+1])
		default:
			t.Fatalf("the walker does not know %q in %q", args[i], args)
		}
		i++
		if ok == negate {
			return false, ""
		}
		negate = false
	}
	return true, target
}

func (chains tables) walk(t *testing.T, chain string, p packet) string {
	t.Helper()
	for _, rule := range chains[chain] {
		ok, target := matches(t, rule, p)
		switch {
		case !ok || target == "":
		case target == "ACCEPT" || target == "DROP" || target == "RETURN":
			return target
		default:
			if verdict := chains.walk(t, target, p); verdict != "RETURN" {
				return verdict
			}
		}
	}
	return "RETURN"
}

var dockerForward = [][]string{
	{"-j", "DOCKER-USER"},
	{"-o", "docker0", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	{"-o", "docker0", "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"},
}

func loaded(body string, exit, exitFirst, docker bool) tables {
	chains := tables{}
	for _, line := range lines(body) {
		if fields := strings.Fields(line); len(fields) > 2 && fields[0] == "-A" {
			chains[fields[1]] = append(chains[fields[1]], fields[2:])
		}
	}
	jumps := Jumps()
	if exit && exitFirst {
		jumps = append(slices.Clone(ExitJumps), jumps...)
	} else if exit {
		jumps = append(jumps, ExitJumps...)
	}
	for _, jump := range jumps {
		chains[jump[0]] = append([][]string{jump[1:]}, chains[jump[0]]...)
	}
	if docker {
		chains["FORWARD"] = append(slices.Clone(dockerForward), chains["FORWARD"]...)
	}
	return chains
}

func verdicts(t *testing.T, body string, exit bool, p packet) (string, string) {
	t.Helper()
	var docker, plain string
	for _, exitFirst := range []bool{false, true} {
		withDocker := loaded(body, exit, exitFirst, true).walk(t, "FORWARD", p)
		without := loaded(body, exit, exitFirst, false).walk(t, "FORWARD", p)
		if exitFirst && (withDocker != docker || without != plain) {
			t.Fatalf("%+v: the verdict depends on the order the jumps went in: %s/%s then %s/%s", p, docker, plain, withDocker, without)
		}
		docker, plain = withDocker, without
	}
	return docker, plain
}

func forwardDocument() Document {
	document := ruleDocument(everyPort(laptops, servers), some(node(nodeB), node(nodeA), "81/tcp"))
	document.Members[0].Exit = true
	return document
}

func TestANewConnectionToABridgeAddressIsDropped(t *testing.T) {
	body := RenderRules(forwardDocument(), nodeA, nil, 4, "eth0")
	for _, p := range []packet{
		{src: "10.88.0.9", in: Interface, out: "docker0", proto: "tcp", port: 80, states: []string{"NEW"}},
		{src: "10.88.0.2", in: Interface, out: "docker0", proto: "tcp", port: 81, states: []string{"NEW"}},
		{src: "10.88.0.2", in: Interface, out: "eth1", proto: "tcp", port: 81, states: []string{"NEW"}},
	} {
		if docker, plain := verdicts(t, body, true, p); docker != "DROP" || plain != "DROP" {
			t.Errorf("%+v: with Docker %s without %s", p, docker, plain)
		}
	}
}

func TestAReplyToAContainersConnectionPasses(t *testing.T) {
	body := RenderRules(forwardDocument(), nodeA, nil, 4, "eth0")
	for _, state := range []string{"ESTABLISHED", "RELATED"} {
		p := packet{src: "10.88.0.3", in: Interface, out: "docker0", proto: "tcp", port: 41000, states: []string{state}}
		if docker, plain := verdicts(t, body, true, p); docker != "ACCEPT" || plain != "RETURN" {
			t.Errorf("%s reply: with Docker %s without %s", state, docker, plain)
		}
	}
}

func TestADNATedPortPassesOnlyWhenGranted(t *testing.T) {
	body := RenderRules(forwardDocument(), nodeA, nil, 4, "eth0")
	dnat := []string{"NEW", "DNAT"}
	for _, p := range []packet{
		{src: "10.88.0.2", in: Interface, out: "docker0", proto: "tcp", port: 81, states: dnat},
		{src: "10.88.0.9", in: Interface, out: "docker0", proto: "udp", port: 5353, states: dnat},
	} {
		if docker, plain := verdicts(t, body, true, p); docker != "ACCEPT" || plain != "RETURN" {
			t.Errorf("granted %+v: with Docker %s without %s", p, docker, plain)
		}
	}
	for _, p := range []packet{
		{src: "10.88.0.2", in: Interface, out: "docker0", proto: "tcp", port: 82, states: dnat},
		{src: "10.88.0.2", in: Interface, out: "docker0", proto: "udp", port: 81, states: dnat},
		{src: "10.88.0.3", in: Interface, out: "docker0", proto: "tcp", port: 81, states: dnat},
	} {
		if docker, plain := verdicts(t, body, true, p); docker != "DROP" || plain != "DROP" {
			t.Errorf("ungranted %+v: with Docker %s without %s", p, docker, plain)
		}
	}
	dropped := RenderRules(forwardDocument(), nodeA, []string{"10.88.0.2"}, 4, "eth0")
	if docker, plain := verdicts(t, dropped, true, packet{src: "10.88.0.2", in: Interface, out: "docker0", proto: "tcp", port: 81, states: dnat}); docker != "DROP" || plain != "DROP" {
		t.Errorf("a dropped member: with Docker %s without %s", docker, plain)
	}
}

func TestOnTheExitNodeOnlyLaptopsGoOutTheUplink(t *testing.T) {
	for _, family := range []int{4, 6} {
		laptop, server := "10.88.0.9", "10.88.0.2"
		if family == 6 {
			laptop, server = Address6(laptop), Address6(server)
		}
		body := RenderRules(forwardDocument(), nodeA, nil, family, "eth0")
		if docker, plain := verdicts(t, body, true, packet{src: laptop, in: Interface, out: "eth0", proto: "tcp", port: 443, states: []string{"NEW"}}); docker != "ACCEPT" || plain != "ACCEPT" {
			t.Errorf("family %d laptop: with Docker %s without %s", family, docker, plain)
		}
		if docker, plain := verdicts(t, body, true, packet{src: server, in: Interface, out: "eth0", proto: "tcp", port: 443, states: []string{"NEW"}}); docker != "DROP" || plain != "DROP" {
			t.Errorf("family %d server: with Docker %s without %s", family, docker, plain)
		}
		if docker, plain := verdicts(t, body, true, packet{src: "198.51.100.7", in: "eth0", out: Interface, proto: "tcp", port: 52000, states: []string{"ESTABLISHED"}}); docker != "ACCEPT" || plain != "ACCEPT" {
			t.Errorf("family %d reply from the uplink: with Docker %s without %s", family, docker, plain)
		}
	}
}

func TestOnTheExitNodeOnlyRepliesComeIntoKry0FromAnotherInterface(t *testing.T) {
	for _, family := range []int{4, 6} {
		lan, laptop := "192.0.2.5", "10.88.0.9"
		if family == 6 {
			lan, laptop = "2001:db8::5", Address6(laptop)
		}
		body := RenderRules(forwardDocument(), nodeA, nil, family, "eth0")
		for _, in := range []string{"eth1", "wlan0", "eth0"} {
			for _, states := range [][]string{{"NEW"}, {"INVALID"}, {"NEW", "DNAT"}} {
				if docker, plain := verdicts(t, body, true, packet{src: lan, dst: laptop, in: in, out: Interface, proto: "tcp", port: 22, states: states}); docker != "DROP" || plain != "DROP" {
					t.Errorf("family %d %s %q into kry0: with Docker %s without %s", family, in, states, docker, plain)
				}
			}
		}
		for _, states := range [][]string{{"ESTABLISHED"}, {"RELATED"}} {
			if docker, plain := verdicts(t, body, true, packet{src: lan, dst: laptop, in: "eth1", out: Interface, proto: "tcp", port: 52000, states: states}); docker == "DROP" || plain == "DROP" {
				t.Errorf("family %d a %q reply from eth1: with Docker %s without %s", family, states, docker, plain)
			}
		}
		for _, in := range []string{"docker0", "br-1a2b3c"} {
			if docker, plain := verdicts(t, body, true, packet{src: "172.17.0.2", dst: laptop, in: in, out: Interface, proto: "tcp", port: 5432, states: []string{"NEW"}}); docker != "RETURN" || plain != "RETURN" {
				t.Errorf("family %d a container on %s: with Docker %s without %s", family, in, docker, plain)
			}
		}
	}
}

func TestADroppedLaptopNeverGoesOutTheUplink(t *testing.T) {
	for _, family := range []int{4, 6} {
		laptop := "10.88.0.9"
		if family == 6 {
			laptop = Address6(laptop)
		}
		body := RenderRules(forwardDocument(), nodeA, []string{"10.88.0.9"}, family, "eth0")
		for _, states := range [][]string{{"NEW"}, {"ESTABLISHED"}} {
			if docker, plain := verdicts(t, body, true, packet{src: laptop, in: Interface, out: "eth0", proto: "tcp", port: 443, states: states}); docker != "DROP" || plain != "DROP" {
				t.Errorf("family %d %q: with Docker %s without %s", family, states, docker, plain)
			}
		}
	}
}

func TestOffTheExitNodeALaptopsWanTrafficDrops(t *testing.T) {
	document := forwardDocument()
	for _, self := range []string{nodeB, nodeA} {
		uplink := "eth0"
		if self == nodeA {
			uplink = ""
		}
		body := RenderRules(document, self, nil, 4, uplink)
		if docker, plain := verdicts(t, body, false, packet{src: "10.88.0.9", in: Interface, out: "eth0", proto: "tcp", port: 443, states: []string{"NEW"}}); docker != "DROP" || plain != "DROP" {
			t.Errorf("%s uplink %q: with Docker %s without %s", self, uplink, docker, plain)
		}
	}
}

func TestKry0ToKry0IsDroppedEvenWhenEstablished(t *testing.T) {
	body := RenderRules(forwardDocument(), nodeA, nil, 4, "eth0")
	for _, states := range [][]string{{"NEW"}, {"ESTABLISHED"}, {"NEW", "DNAT"}} {
		if docker, plain := verdicts(t, body, true, packet{src: "10.88.0.9", in: Interface, out: Interface, proto: "tcp", port: 81, states: states}); docker != "DROP" || plain != "DROP" {
			t.Errorf("%q: with Docker %s without %s", states, docker, plain)
		}
	}
}

func TestThePoolIsReachableOnlyFromInside(t *testing.T) {
	for _, family := range []int{4, 6} {
		own, lan := "10.88.0.1", "192.0.2.5"
		if family == 6 {
			own, lan = Address6(own), "2001:db8::5"
		}
		for _, uplink := range []string{"eth0", ""} {
			chains := loaded(RenderRules(forwardDocument(), nodeB, nil, family, uplink), false, false, false)
			for _, in := range []string{"eth0", "eth1", "wlan0"} {
				if verdict := chains.walk(t, "INPUT", packet{src: lan, dst: own, in: in, proto: "tcp", port: 22, states: []string{"NEW"}}); verdict != "DROP" {
					t.Errorf("family %d uplink %q: a neighbour on %s reaches the network address: %s", family, uplink, in, verdict)
				}
			}
			for _, in := range []string{"lo", "docker0", "br-1a2b3c"} {
				if verdict := chains.walk(t, "INPUT", packet{src: lan, dst: own, in: in, proto: "tcp", port: 22, states: []string{"NEW"}}); verdict != "RETURN" {
					t.Errorf("family %d uplink %q: %s cannot reach the network address: %s", family, uplink, in, verdict)
				}
			}
			if verdict := chains.walk(t, "INPUT", packet{src: lan, dst: "203.0.113.21", in: "eth0", proto: "tcp", port: 22, states: []string{"NEW"}}); family == 4 && verdict != "RETURN" {
				t.Errorf("uplink %q: the public address is dropped: %s", uplink, verdict)
			}
		}
	}
}

func TestAnUplinkThatIsNotAnInterfaceNameRendersNothing(t *testing.T) {
	want := RenderRules(forwardDocument(), nodeA, nil, 4, "")
	for _, uplink := range []string{"eth0\n-A INPUT -j ACCEPT", "eth0 -j ACCEPT", "a-name-longer-than-15", "eth0;", ""} {
		got := RenderRules(forwardDocument(), nodeA, nil, 4, uplink)
		if got != want || strings.Contains(got, "-A INPUT") {
			t.Errorf("%q renders\n%s", uplink, got)
		}
	}
	if got := RenderRules(forwardDocument(), nodeA, nil, 4, "enp3s0.100"); !strings.Contains(got, "-o enp3s0.100 -j ACCEPT\n") {
		t.Errorf("a VLAN uplink renders\n%s", got)
	}
}

func TestALaptopNeverExitsToAPrivateDestination(t *testing.T) {
	for _, want := range []struct {
		family  int
		dst     string
		verdict string
	}{
		{4, "192.168.1.1", "DROP"}, {4, "169.254.169.254", "DROP"}, {4, "10.1.2.3", "DROP"}, {4, "172.20.0.1", "DROP"},
		{4, "100.100.100.100", "DROP"}, {4, "0.0.0.1", "DROP"}, {4, "203.0.113.9", "ACCEPT"},
		{6, "fe80::1", "DROP"}, {6, "fd00::1", "DROP"}, {6, "2001:db8::9", "ACCEPT"},
	} {
		laptop := "10.88.0.9"
		if want.family == 6 {
			laptop = Address6(laptop)
		}
		body := RenderRules(forwardDocument(), nodeA, nil, want.family, "eth0")
		if docker, plain := verdicts(t, body, true, packet{src: laptop, dst: want.dst, in: Interface, out: "eth0", proto: "tcp", port: 443, states: []string{"NEW"}}); docker != want.verdict || plain != want.verdict {
			t.Errorf("a laptop to %s: with Docker %s without %s, want %s", want.dst, docker, plain, want.verdict)
		}
	}
	body := RenderRules(forwardDocument(), nodeA, nil, 4, "eth0")
	if docker, plain := verdicts(t, body, true, packet{src: "192.168.1.1", dst: "10.88.0.9", in: "eth0", out: Interface, proto: "tcp", port: 52000, states: []string{"ESTABLISHED"}}); docker != "ACCEPT" || plain != "ACCEPT" {
		t.Errorf("a reply from a private address: with Docker %s without %s", docker, plain)
	}
}
