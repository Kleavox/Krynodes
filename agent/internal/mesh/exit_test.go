package mesh

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

func sysctlFile(t *testing.T, m *Mesh) (string, bool) {
	t.Helper()
	body, err := os.ReadFile(m.path(laptopExitConf))
	if errors.Is(err, os.ErrNotExist) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(body), true
}

func procValue(t *testing.T, m *Mesh, path string) string {
	t.Helper()
	return strings.TrimSpace(readRoot(t, m, path))
}

func noExit(t *testing.T, tables *fakeTables, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if len(tables.chain(tool, "filter", network.ExitChain)) != 0 || slices.ContainsFunc(tables.chain(tool, "filter", "FORWARD"), func(line string) bool { return strings.HasSuffix(line, "-j KRY-EXIT") }) {
			t.Fatalf("%s keeps the exit:\n%s", tool, tables)
		}
		if slices.ContainsFunc(tables.chain(tool, "nat", "POSTROUTING"), func(line string) bool { return strings.Contains(line, "MASQUERADE") }) {
			t.Fatalf("%s still masquerades:\n%s", tool, tables)
		}
	}
}

func onTop(t *testing.T, tables *fakeTables, tool string, jumps ...string) {
	t.Helper()
	forward := tables.chain(tool, "filter", "FORWARD")
	if len(forward) < len(jumps) || !slices.Equal(slices.Sorted(slices.Values(forward[:len(jumps)])), slices.Sorted(slices.Values(jumps))) {
		t.Fatalf("%s FORWARD does not start with %q: %q", tool, jumps, forward)
	}
}

func dockerForward(tables *fakeTables) {
	for _, tool := range []string{"iptables", "ip6tables"} {
		tables.rules[tool+" filter FORWARD"] = []string{"-A FORWARD -j DOCKER-USER", "-A FORWARD -j REJECT --reject-with icmp-host-prohibited"}
	}
}

func exits(t *testing.T, tables *fakeTables, tool, uplink, source string) {
	t.Helper()
	chain := tables.chain(tool, "filter", network.ExitChain)
	for _, line := range []string{
		"-A KRY-EXIT -i " + uplink + " -o kry0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"-A KRY-EXIT -s " + source + " -i kry0 -o " + uplink + " -j ACCEPT",
		"-A KRY-EXIT -i kry0 -o " + uplink + " -j DROP",
		"-A KRY-EXIT ! -i kry0 -o kry0 -m conntrack ! --ctstate RELATED,ESTABLISHED -j DROP",
	} {
		if !slices.Contains(chain, line) {
			t.Fatalf("%s KRY-EXIT lacks %q: %q", tool, line, chain)
		}
	}
	onTop(t, tables, tool, exitOutOf, exitInto)
}

func withIPv6(t *testing.T, n *testNet, uplink string) {
	t.Helper()
	rootFile(t, n.m, "/proc/net/ipv6_route", v6route(uplink))
	rootFile(t, n.m, "/proc/sys/net/ipv6/conf/"+uplink+"/accept_ra", "1\n")
}

func TestExitTurnsOnOnlyWhenTheDocumentSaysSo(t *testing.T) {
	n := joinedNet(t)
	dockerForward(n.tables)
	n.apply(t, exitOffPrivate)
	noExit(t, n.tables, "iptables", "ip6tables")
	if procValue(t, n.m, ipForward) != "0" {
		t.Fatal("a server that is no exit forwards nothing")
	}
	n.apply(t, exitOnPrivate)
	exits(t, n.tables, "iptables", "eth0", "10.88.0.9/32")
	if !slices.Contains(n.tables.chain("iptables", "nat", "POSTROUTING"), "-A POSTROUTING -s 10.88.0.9/32 -o eth0 -j MASQUERADE") {
		t.Fatalf("no masquerade:\n%s", n.tables)
	}
	if procValue(t, n.m, ipForward) != "1" || n.tables.policy["iptables filter FORWARD"] != "DROP" {
		t.Fatalf("forwarding %q policy %q", procValue(t, n.m, ipForward), n.tables.policy)
	}
	if _, found := sysctlFile(t, n.m); found || len(n.run.called("sysctl")) != 0 {
		t.Fatalf("an IPv4 exit persists no forwarding key: %v", n.run.calls)
	}
	n.apply(t, exitOnPrivate)
	if forward := n.tables.chain("iptables", "filter", "FORWARD"); len(forward) != 6 {
		t.Fatalf("the jumps were added twice: %q", forward)
	}
	if nat := n.tables.chain("iptables", "nat", "POSTROUTING"); len(nat) != 1 {
		t.Fatalf("the masquerade was added twice: %q", nat)
	}
}

func TestForwardingIsSwitchedOnOnlyForAnExit(t *testing.T) {
	n := joinedNet(t)
	n.apply(t, asIs)
	if procValue(t, n.m, ipForward) != "0" || slices.Contains(n.run.calls, "iptables -w -P FORWARD DROP") {
		t.Fatalf("a meeting point relays in user space, yet forwarding is %q: %v", procValue(t, n.m, ipForward), n.run.calls)
	}
	flipped := false
	n.run.effects = map[string]func(){"iptables -w -P FORWARD DROP": func() {
		flipped = procValue(t, n.m, ipForward) == "0"
	}}
	n.apply(t, exitOn)
	if !flipped || procValue(t, n.m, ipForward) != "1" || n.tables.policy["iptables filter FORWARD"] != "DROP" {
		t.Fatalf("the policy is set before forwarding: flipped %v forwarding %q policy %q", flipped, procValue(t, n.m, ipForward), n.tables.policy)
	}
	n.apply(t, asIs)
	if procValue(t, n.m, ipForward) != "1" {
		t.Fatal("forwarding is never switched back off")
	}
	other := newNet(t)
	rootFile(t, other.m, ipForward, "1\n")
	other.apply(t, exitOn)
	if slices.Contains(other.run.calls, "iptables -w -P FORWARD DROP") || other.tables.policy["iptables filter FORWARD"] != "" {
		t.Fatalf("forwarding was already on, the policy is left alone: %v", other.run.calls)
	}
}

func TestExitTurnsOffWhenHeldEvenIfTheDocumentSaysOn(t *testing.T) {
	n := joinedNet(t)
	withIPv6(t, n, "eth0")
	n.apply(t, exitOn)
	if body, _ := sysctlFile(t, n.m); body != "net.ipv6.conf.eth0.accept_ra = 2\n" {
		t.Fatalf("forwarding %q", body)
	}
	if config := readRoot(t, n.m, network.ConfigPath); !strings.Contains(config, "fd88:88::9/128") {
		t.Fatalf("the laptop's IPv6 address is not on kry0:\n%s", config)
	}
	n.m.Hints(t.Context(), reporter.Hints{Held: []string{selfNode}})
	noExit(t, n.tables, "iptables", "ip6tables")
	if _, found := sysctlFile(t, n.m); found {
		t.Fatal("held: the IPv6 exit's file stays")
	}
	if config := readRoot(t, n.m, network.ConfigPath); strings.Contains(config, "fd88:88::") {
		t.Fatalf("held: the laptop's IPv6 address stays on kry0:\n%s", config)
	}
	for _, tool := range []string{"iptables", "ip6tables"} {
		if !slices.Contains(n.tables.chain(tool, "filter", "FORWARD"), apartOf) {
			t.Fatalf("a held server still forwards nothing between peers:\n%s", n.tables)
		}
	}
	if current, _ := n.m.load(); !current.Held || len(relayPairs(n.m.view(current), member1(t, n.m.view(current)))) != 1 {
		t.Fatalf("a held meeting point still relays until the laptop moves on: %+v", current)
	}
	n.apply(t, exitOn)
	noExit(t, n.tables, "iptables", "ip6tables")
	if _, ok := n.m.keep(t.Context(), map[string]string{}); !ok {
		t.Fatal("the guard skipped a joined server")
	}
	noExit(t, n.tables, "iptables", "ip6tables")
	n.m.Hints(t.Context(), reporter.Hints{Held: []string{}})
	exits(t, n.tables, "iptables", "eth0", "10.88.0.9/32")
	exits(t, n.tables, "ip6tables", "eth0", "fd88:88::9/128")
}

func member1(t *testing.T, document network.Document) network.Member {
	t.Helper()
	me, ok := member(document, selfNode)
	if !ok {
		t.Fatal("this server is not in the document")
	}
	return me
}

func TestExitOffRemovesExactlyWhatOnAdded(t *testing.T) {
	n := joinedNet(t)
	withIPv6(t, n, "eth0")
	dockerForward(n.tables)
	n.apply(t, exitOffPrivate)
	before, config := n.tables.String(), readRoot(t, n.m, network.ConfigPath)
	n.apply(t, exitOnPrivate)
	if n.tables.String() == before || len(n.tables.chain("ip6tables", "filter", network.ExitChain)) == 0 {
		t.Fatalf("the exit added nothing:\n%s", n.tables)
	}
	if _, found := sysctlFile(t, n.m); !found {
		t.Fatal("the IPv6 exit wrote no accept_ra")
	}
	n.apply(t, exitOffPrivate)
	if after := n.tables.String(); after != before {
		t.Fatalf("off left something:\nbefore\n%s\nafter\n%s", before, after)
	}
	if _, found := sysctlFile(t, n.m); found {
		t.Fatal("off left the sysctl file")
	}
	if now := readRoot(t, n.m, network.ConfigPath); now != config {
		t.Fatalf("off changed kry0:\n%s\nwas\n%s", now, config)
	}
}

func TestAnIPv6ExitKeepsRouterAdvertisements(t *testing.T) {
	n := joinedNet(t)
	withIPv6(t, n, "eth0")
	accept := "/proc/sys/net/ipv6/conf/eth0/accept_ra"
	ready := false
	n.run.effects = map[string]func(){"ip6tables -w -P FORWARD DROP": func() {
		ready = procValue(t, n.m, accept) == "2" && procValue(t, n.m, ip6Forward) == "0"
	}}
	n.apply(t, exitOnPrivate)
	if body, _ := sysctlFile(t, n.m); body != "net.ipv6.conf.eth0.accept_ra = 2\n" {
		t.Fatalf("the file keeps only accept_ra: %q", body)
	}
	if !slices.Contains(n.run.calls, "sysctl -p "+n.m.path(laptopExitConf)) {
		t.Fatalf("the file is applied alone: %v", n.run.calls)
	}
	if !ready || procValue(t, n.m, ip6Forward) != "1" || n.tables.policy["ip6tables filter FORWARD"] != "DROP" {
		t.Fatalf("accept_ra before forwarding: ready %v forwarding %q policy %q", ready, procValue(t, n.m, ip6Forward), n.tables.policy)
	}
	exits(t, n.tables, "ip6tables", "eth0", "fd88:88::9/128")
	if !slices.Contains(n.tables.chain("ip6tables", "nat", "POSTROUTING"), "-A POSTROUTING -s fd88:88::9/128 -o eth0 -j MASQUERADE") {
		t.Fatalf("no NAT66:\n%s", n.tables)
	}
	if config := readRoot(t, n.m, network.ConfigPath); !strings.Contains(config, "AllowedIPs = 10.88.0.9/32, fd88:88::9/128") {
		t.Fatalf("the laptop's IPv6 address is not on kry0:\n%s", config)
	}
	n.apply(t, exitOnPrivate)
	if body, _ := sysctlFile(t, n.m); body != "net.ipv6.conf.eth0.accept_ra = 2\n" {
		t.Fatalf("once applied, accept_ra reads 2 and must stay in the file: %q", body)
	}
	rootFile(t, n.m, accept, "0\n")
	n.apply(t, exitOnPrivate)
	if _, found := sysctlFile(t, n.m); found || procValue(t, n.m, accept) != "0" {
		t.Fatal("a static IPv6 address keeps its own setting")
	}
}

func TestAnIPv6ExitUsesTheIPv6Uplink(t *testing.T) {
	n := joinedNet(t)
	withIPv6(t, n, "eth1")
	rootFile(t, n.m, "/proc/sys/net/ipv6/conf/eth0/accept_ra", "1\n")
	n.apply(t, exitOnPrivate)
	exits(t, n.tables, "iptables", "eth0", "10.88.0.9/32")
	exits(t, n.tables, "ip6tables", "eth1", "fd88:88::9/128")
	if !slices.Contains(n.tables.chain("ip6tables", "nat", "POSTROUTING"), "-A POSTROUTING -s fd88:88::9/128 -o eth1 -j MASQUERADE") {
		t.Fatalf("NAT66:\n%s", n.tables)
	}
	if body, _ := sysctlFile(t, n.m); body != "net.ipv6.conf.eth1.accept_ra = 2\n" || procValue(t, n.m, "/proc/sys/net/ipv6/conf/eth0/accept_ra") != "1" {
		t.Fatalf("accept_ra belongs to the IPv6 uplink: %q", body)
	}
}

func TestADottedUplinkUsesTheSlashKey(t *testing.T) {
	n := joinedNet(t)
	withIPv6(t, n, "eth0.100")
	n.apply(t, exitOnPrivate)
	if body, _ := sysctlFile(t, n.m); body != "net/ipv6/conf/eth0.100/accept_ra = 2\n" {
		t.Fatalf("%q", body)
	}
}

func TestAServerWithoutIPv6GetsNoIPv6ExitRules(t *testing.T) {
	n := joinedNet(t)
	rootFile(t, n.m, "/proc/sys/net/ipv6/conf/eth0/accept_ra", "1\n")
	n.apply(t, exitOnPrivate)
	exits(t, n.tables, "iptables", "eth0", "10.88.0.9/32")
	noExit(t, n.tables, "ip6tables")
	if slices.ContainsFunc(n.run.calls, func(call string) bool {
		return strings.HasPrefix(call, "ip6tables -w -P") || strings.HasPrefix(call, "ip6tables -w -t nat -A")
	}) {
		t.Fatalf("IPv6 exit rules were written: %v", n.run.calls)
	}
	if _, found := sysctlFile(t, n.m); found || procValue(t, n.m, ip6Forward) != "0" {
		t.Fatal("no IPv6, no IPv6 forwarding")
	}
	if config := readRoot(t, n.m, network.ConfigPath); strings.Contains(config, "fd88:88::") {
		t.Fatalf("kry0 carries an IPv6 route the server cannot use:\n%s", config)
	}
}

func TestIPv6ForwardingStaysOffWhenRouterAdvertisementsCannotBeKept(t *testing.T) {
	n := joinedNet(t)
	withIPv6(t, n, "eth0")
	accept := n.m.path("/proc/sys/net/ipv6/conf/eth0/accept_ra")
	n.run.effects = map[string]func(){"ip6tables -w -t nat -S POSTROUTING": func() {
		if info, err := os.Stat(accept); err == nil && !info.IsDir() {
			os.Remove(accept)
			os.Mkdir(accept, 0o755)
		}
	}}
	applied := n.offer(t, n.next(t, exitOnPrivate))
	if !applied.OK || !strings.Contains(applied.Message, "the exit for laptops is off: ") || !strings.Contains(applied.Message, "router advertisements on eth0") {
		t.Fatalf("%+v", applied)
	}
	if procValue(t, n.m, ip6Forward) != "0" || slices.Contains(n.run.calls, "ip6tables -w -P FORWARD DROP") {
		t.Fatalf("IPv6 forwarding was switched on without accept_ra: %v", n.run.calls)
	}
	noExit(t, n.tables, "iptables", "ip6tables")
	if _, found := sysctlFile(t, n.m); found {
		t.Fatal("an exit that is off keeps its sysctl file")
	}
	n.m.keep(t.Context(), map[string]string{})
	noExit(t, n.tables, "iptables", "ip6tables")
	withoutServer4 := func(self *network.Member, members []network.Member) []network.Member {
		return slices.DeleteFunc(exitOnPrivate(self, members), func(entry network.Member) bool { return entry.Node == behindNode })
	}
	if applied := n.offer(t, n.next(t, withoutServer4)); !applied.OK || n.applied(t).Version != 3 || strings.Contains(readRoot(t, n.m, network.HostsPath), "server-4") {
		t.Fatalf("a node whose exit cannot run refused the next document: %+v", applied)
	}
	noExit(t, n.tables, "iptables", "ip6tables")
}

func TestServersNeverForwardBetweenPeers(t *testing.T) {
	n := joinedNet(t)
	dockerForward(n.tables)
	for _, change := range []change{withoutLaptop, asIs, behindNAT, exitOn, asIs} {
		n.apply(t, change)
		for _, tool := range []string{"iptables", "ip6tables"} {
			if forward := n.tables.chain(tool, "filter", "FORWARD"); len(slices.DeleteFunc(slices.Clone(forward), func(line string) bool { return line != apartOf })) != 1 {
				t.Fatalf("%s FORWARD %q", tool, forward)
			}
		}
	}
}

func TestOnlyAMeetingPointOpensItsPairPorts(t *testing.T) {
	n := joinedNet(t)
	opened := "ufw allow 51920/udp comment krynodes-network"
	n.apply(t, withoutLaptop)
	if current, _ := n.m.load(); slices.Contains(n.run.calls, opened) || current.Relays != nil {
		t.Fatalf("no laptop, no pair port: %v", n.run.calls)
	}
	n.run.calls = nil
	n.apply(t, asIs)
	current, _ := n.m.load()
	if !slices.Contains(n.run.calls, opened) || !slices.Equal(current.Relays, []int{51920}) {
		t.Fatalf("a meeting point opens its pair port: %v", n.run.calls)
	}
	pairs := relayPairs(n.m.view(current), member1(t, n.m.view(current)))
	if len(pairs) != 1 || pairs[0].Port != 51920 || pairs[0].Sides != [2]string{n.laptop.Public, n.behind.Public} || pairs[0].Host.String() != "203.0.113.30" {
		t.Fatalf("pairs %+v", pairs)
	}
	n.run.calls = nil
	n.apply(t, asIs)
	if len(n.run.called("ufw")) != 0 {
		t.Fatalf("an open port is opened again: %v", n.run.calls)
	}
	n.run.respond["ufw status numbered"] = "[ 1] 51821/udp ALLOW IN Anywhere # krynodes-network\n[ 2] Anywhere on kry0 ALLOW IN Anywhere # krynodes-network\n[ 3] 51920/udp ALLOW IN Anywhere # krynodes-network\n[ 4] 51920/udp (v6) ALLOW IN Anywhere (v6) # krynodes-network\n"
	n.run.calls = nil
	n.apply(t, withoutLaptop)
	if current, _ := n.m.load(); !slices.Contains(n.run.calls, "ufw --force delete 4") || !slices.Contains(n.run.calls, "ufw --force delete 3") || slices.Contains(n.run.calls, "ufw --force delete 2") || slices.Contains(n.run.calls, "ufw --force delete 1") || current.Relays != nil {
		t.Fatalf("the laptop left, its pair port stays: %v", n.run.calls)
	}
	n.apply(t, asIs)
	n.run.calls = nil
	n.apply(t, behindNAT)
	if current, _ := n.m.load(); !slices.Contains(n.run.calls, "ufw --force delete 4") || current.Relays != nil || relayPairs(n.m.view(current), member1(t, n.m.view(current))) != nil {
		t.Fatalf("a member behind NAT is no meeting point: %v", n.run.calls)
	}
}

func TestAPairPortTheFirewallRefusesFailsNothingAndIsTriedAgain(t *testing.T) {
	n := joinedNet(t)
	opened := "ufw allow 51920/udp comment krynodes-network"
	n.run.failing[opened] = "ERROR: Could not get lock\n"
	n.apply(t, asIs)
	if current, _ := n.m.load(); current.Relays != nil || current.Applied.Version != 2 {
		t.Fatalf("a refused pair port applies the document and records no port: %+v", current)
	}
	delete(n.run.failing, opened)
	n.run.calls = nil
	n.m.keep(t.Context(), map[string]string{})
	if current, _ := n.m.load(); !slices.Contains(n.run.calls, opened) || !slices.Equal(current.Relays, []int{51920}) {
		t.Fatalf("the refused port is opened by the guard, with no new document: %v", n.run.calls)
	}
	n.run.calls = nil
	n.m.keep(t.Context(), map[string]string{})
	if len(n.run.called("ufw")) != 0 || len(n.run.called("firewall-cmd")) != 0 {
		t.Fatalf("a round with every port in place touches no firewall: %v", n.run.calls)
	}
	n.run.failing["ufw status numbered"] = "ERROR: Could not get lock\n"
	n.run.calls = nil
	n.apply(t, withoutLaptop)
	if current, _ := n.m.load(); len(n.run.called("ufw --force delete")) != 0 || !slices.Equal(current.Relays, []int{51920}) {
		t.Fatalf("an unread listing deletes nothing and keeps the port: %v", n.run.calls)
	}
	delete(n.run.failing, "ufw status numbered")
	n.run.respond["ufw status numbered"] = "[ 1] 51821/udp ALLOW IN Anywhere # krynodes-network\n[ 2] 51920/udp ALLOW IN Anywhere # krynodes-network\n"
	n.run.calls = nil
	n.m.keep(t.Context(), map[string]string{})
	if current, _ := n.m.load(); !slices.Contains(n.run.calls, "ufw --force delete 2") || slices.Contains(n.run.calls, "ufw --force delete 1") || current.Relays != nil {
		t.Fatalf("the kept port is closed by the guard: %v", n.run.calls)
	}
}
