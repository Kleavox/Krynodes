package actions

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/config"
	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/relay"
	"github.com/Kleavox/krynodes/agent/internal/seal"
)

const (
	laptopNode  = "99999999-9999-4999-8999-999999999999"
	thirdNode   = "33333333-3333-4333-8333-333333333333"
	behindNode  = "44444444-4444-4444-8444-444444444444"
	strangeNode = "55555555-5555-4555-8555-555555555555"
	selfPublic  = "203.0.113.30:51821"
	v4Default   = "default via 203.0.113.1 dev eth0 proto static\n"
	v6Default   = "default via fe80::1 dev eth0 proto ra metric 1024 pref medium\n"
	exitOutOf   = "-A FORWARD -i kry0 ! -o kry0 -j KRY-EXIT"
	exitInto    = "-A FORWARD ! -i kry0 -o kry0 -j KRY-EXIT"
	apartOf     = "-A FORWARD -i kry0 -o kry0 -j DROP"
	ipForward   = "/proc/sys/net/ipv4/ip_forward"
	ip6Forward  = "/proc/sys/net/ipv6/conf/all/forwarding"
)

type fakeTables struct {
	rules  map[string][]string
	policy map[string]string
	next   Runner
}

func withTables(executor *Executor) *fakeTables {
	tables := &fakeTables{rules: map[string][]string{}, policy: map[string]string{}, next: executor.Run}
	executor.Run = tables.run
	return tables
}

func builtInChain(chain string) bool {
	return slices.Contains([]string{"INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING"}, chain)
}

func (f *fakeTables) run(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	output, code, err := f.next(ctx, name, args...)
	tool, restore := strings.CutSuffix(name, "-restore")
	if tool != "iptables" && tool != "ip6tables" {
		return output, code, err
	}
	fail := func() ([]byte, int, error) {
		return []byte("iptables: No chain/target/match by that name."), 1, errors.New("exit status 1")
	}
	if restore {
		body, readErr := os.ReadFile(args[len(args)-1])
		if readErr != nil {
			return fail()
		}
		table := "filter"
		for line := range strings.SplitSeq(string(body), "\n") {
			switch {
			case strings.HasPrefix(line, "*"):
				table = line[1:]
			case strings.HasPrefix(line, ":"):
				f.rules[tool+" "+table+" "+strings.Fields(line[1:])[0]] = []string{}
			case strings.HasPrefix(line, "-A "):
				key := tool + " " + table + " " + strings.Fields(line)[1]
				f.rules[key] = append(f.rules[key], line)
			}
		}
		return nil, 0, nil
	}
	table := "filter"
	if len(args) > 2 && args[0] == "-t" {
		table, args = args[1], args[2:]
	}
	if len(args) < 2 {
		return output, code, err
	}
	verb, chain, rest := args[0], args[1], args[2:]
	key := tool + " " + table + " " + chain
	current, exists := f.rules[key]
	exists = exists || builtInChain(chain)
	if verb == "-I" && len(rest) > 0 {
		if _, numbered := strconv.Atoi(rest[0]); numbered == nil {
			rest = rest[1:]
		}
	}
	line := strings.Join(append([]string{"-A", chain}, rest...), " ")
	target := ""
	if index := slices.Index(rest, "-j"); index >= 0 && index+1 < len(rest) {
		target = rest[index+1]
	}
	switch verb {
	case "-S":
		if !exists {
			return fail()
		}
		head := "-N " + chain
		if builtInChain(chain) {
			head = "-P " + chain + " " + cmp.Or(f.policy[key], "ACCEPT")
		}
		return []byte(strings.Join(append([]string{head}, current...), "\n") + "\n"), 0, nil
	case "-P":
		if !builtInChain(chain) || len(rest) != 1 {
			return fail()
		}
		f.policy[key] = rest[0]
	case "-N":
		if exists {
			return []byte("iptables: Chain already exists."), 1, errors.New("exit status 1")
		}
		f.rules[key] = []string{}
	case "-F":
		if !exists {
			return fail()
		}
		f.rules[key] = []string{}
	case "-X":
		referenced := false
		for other, lines := range f.rules {
			referenced = referenced || (strings.HasPrefix(other, tool+" "+table+" ") && slices.ContainsFunc(lines, func(rule string) bool { return strings.HasSuffix(rule, "-j "+chain) }))
		}
		if !exists || builtInChain(chain) || len(current) > 0 || referenced {
			return fail()
		}
		delete(f.rules, key)
	case "-A", "-I":
		if _, known := f.rules[tool+" "+table+" "+target]; !exists || (strings.HasPrefix(target, "KRY-") && !known) {
			return fail()
		}
		if verb == "-A" {
			f.rules[key] = append(current, line)
		} else {
			f.rules[key] = append([]string{line}, current...)
		}
	case "-C":
		if !exists || !slices.Contains(current, line) {
			return fail()
		}
	case "-D":
		index := slices.Index(current, line)
		if index < 0 {
			return fail()
		}
		f.rules[key] = slices.Delete(slices.Clone(current), index, index+1)
	default:
		return output, code, err
	}
	return nil, 0, nil
}

func (f *fakeTables) chain(tool, table, chain string) []string {
	return f.rules[tool+" "+table+" "+chain]
}

func (f *fakeTables) has(tool, table, chain string) bool {
	_, ok := f.rules[tool+" "+table+" "+chain]
	return ok
}

func (f *fakeTables) String() string {
	var text strings.Builder
	for _, key := range slices.Sorted(maps.Keys(f.rules)) {
		if len(f.rules[key]) == 0 && builtInChain(key[strings.LastIndex(key, " ")+1:]) {
			continue
		}
		fmt.Fprintf(&text, "%s: %s\n", key, strings.Join(f.rules[key], " | "))
	}
	return text.String()
}

type laptopNet struct {
	executor Executor
	keys     network.Keys
	peer     network.Keys
	laptop   network.Keys
	third    network.Keys
	behind   network.Keys
	version  int
}

func newLaptopNet(t *testing.T) (*laptopNet, *fakeRun, *fakeTables) {
	t.Helper()
	executor, run, keys, peer, _ := joinedServer(t)
	tables := withTables(&executor)
	laptop, _ := peerKeys(t)
	third, _ := peerKeys(t)
	behind, _ := peerKeys(t)
	run.respond["ip -4 route show default"] = v4Default
	rootFile(t, executor, ipForward, "0\n")
	rootFile(t, executor, ip6Forward, "0\n")
	return &laptopNet{executor: executor, keys: keys, peer: peer, laptop: laptop, third: third, behind: behind, version: 1}, run, tables
}

func (n *laptopNet) document(t *testing.T, change func(self *network.Member, members []network.Member) []network.Member) network.Document {
	t.Helper()
	peerEnd, thirdEnd, ownEnd := peerEndpoint, "203.0.113.23:51820", selfPublic
	self := network.Member{Node: testNode, Name: "server-1", Address: "10.88.0.2", Key: n.keys.Public, Signer: n.keys.Signer, Port: 51821, Endpoint: &ownEnd}
	members := []network.Member{
		{Node: peerNode, Name: "server-2", Address: "10.88.0.1", Key: n.peer.Public, Signer: n.peer.Signer, Port: 51820, Endpoint: &peerEnd},
		{Node: thirdNode, Name: "server-3", Address: "10.88.0.3", Key: n.third.Public, Signer: n.third.Signer, Port: 51820, Endpoint: &thirdEnd},
		{Node: behindNode, Name: "server-4", Address: "10.88.0.4", Key: n.behind.Public, Signer: n.behind.Signer, Port: 51820, NAT: true},
		{Node: laptopNode, Name: "laptop-1", Address: "10.88.0.9", Key: n.laptop.Public, Signer: n.laptop.Signer, Port: 51820, Kind: "laptop"},
	}
	members = change(&self, members)
	members = append(members, self)
	sealed, err := seal.Seal(seal.Public(mustKey(t, n.executor)), testPSK)
	if err != nil {
		t.Fatal(err)
	}
	relayPort := network.FirstRelayPort
	for index := range members {
		members[index].PSK = map[string]string{}
		for _, other := range members {
			if other.Node != members[index].Node && network.Links(members[index], other) {
				members[index].PSK[other.Node] = "eyJ2IjoxfQ"
				if members[index].Node == testNode {
					members[index].PSK[other.Node] = sealed
				}
			}
		}
		if members[index].IsLaptop() {
			members[index].Relay = map[string]int{}
			for _, other := range members {
				if other.NAT && !other.IsLaptop() && !other.Cut {
					members[index].Relay[other.Node] = relayPort
					relayPort++
				}
			}
		}
	}
	n.version++
	return network.Document{V: 1, Version: n.version, Range: "10.88.0.0/24", Port: 51820, MTU: 1420, Parent: n.executor.readNetwork().Applied.Hash, Blocked: []string{}, Members: members}
}

func (n *laptopNet) apply(t *testing.T, change func(self *network.Member, members []network.Member) []network.Member) {
	t.Helper()
	document := n.document(t, change)
	id := fmt.Sprintf("0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1b%02d", document.Version)
	if result := hostRun(t, n.executor, applyDocument(t, id, document)); !result.OK {
		t.Fatalf("apply version %d: %+v", document.Version, result)
	}
}

func exitOn(self *network.Member, members []network.Member) []network.Member {
	self.Exit = true
	return members
}

func exitOnPrivate(self *network.Member, members []network.Member) []network.Member {
	self.Exit, self.Endpoint = true, nil
	return members
}

func exitOffPrivate(self *network.Member, members []network.Member) []network.Member {
	self.Endpoint = nil
	return members
}

func asIs(_ *network.Member, members []network.Member) []network.Member {
	return members
}

func withoutLaptop(_ *network.Member, members []network.Member) []network.Member {
	return slices.DeleteFunc(members, network.Member.IsLaptop)
}

func behindNAT(self *network.Member, members []network.Member) []network.Member {
	self.Endpoint, self.NAT = nil, true
	return members
}

func sysctlFile(t *testing.T, executor Executor) (string, bool) {
	t.Helper()
	body, err := os.ReadFile(executor.path(laptopExitConf))
	if errors.Is(err, os.ErrNotExist) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(body), true
}

func noMasquerade(t *testing.T, tables *fakeTables, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if lines := tables.chain(tool, "nat", "POSTROUTING"); slices.ContainsFunc(lines, func(line string) bool { return strings.Contains(line, "MASQUERADE") }) {
			t.Fatalf("%s still masquerades: %v", tool, lines)
		}
	}
}

func noExit(t *testing.T, tables *fakeTables, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		forward := tables.chain(tool, "filter", "FORWARD")
		if tables.has(tool, "filter", network.ExitChain) || slices.ContainsFunc(forward, func(line string) bool { return strings.HasSuffix(line, "-j KRY-EXIT") }) {
			t.Fatalf("%s keeps the exit:\n%s", tool, tables)
		}
	}
	noMasquerade(t, tables, tools...)
}

func procValue(t *testing.T, executor Executor, path string) string {
	t.Helper()
	return strings.TrimSpace(readRoot(t, executor, path))
}

func onTop(t *testing.T, tables *fakeTables, tool string, jumps ...string) {
	t.Helper()
	forward := tables.chain(tool, "filter", "FORWARD")
	if len(forward) < len(jumps) {
		t.Fatalf("%s FORWARD %q", tool, forward)
	}
	top := slices.Sorted(slices.Values(forward[:len(jumps)]))
	if !slices.Equal(top, slices.Sorted(slices.Values(jumps))) {
		t.Fatalf("%s FORWARD does not start with %q: %q", tool, jumps, forward)
	}
}

func dockerForward(tables *fakeTables) {
	for _, tool := range exitTools {
		tables.rules[tool+" filter FORWARD"] = []string{"-A FORWARD -j DOCKER-USER", "-A FORWARD -j REJECT --reject-with icmp-host-prohibited"}
	}
}

func withoutNATMember(_ *network.Member, members []network.Member) []network.Member {
	return slices.DeleteFunc(members, func(other network.Member) bool { return other.NAT })
}

func exitRules(uplink, source string) []string {
	return []string{
		"-A KRY-EXIT -i " + uplink + " -o kry0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"-A KRY-EXIT -s " + source + " -i kry0 -o " + uplink + " -j ACCEPT",
		"-A KRY-EXIT -i kry0 -o " + uplink + " -j DROP",
		"-A KRY-EXIT -i " + uplink + " -o kry0 -j DROP",
	}
}

func TestExitTurnsOnOnlyWhenTheDocumentSaysSo(t *testing.T) {
	net, run, tables := newLaptopNet(t)
	dockerForward(tables)
	net.apply(t, exitOffPrivate)
	noExit(t, tables, "iptables", "ip6tables")
	if slices.Contains(run.calls, "ip -4 route show default") || procValue(t, net.executor, ipForward) != "0" {
		t.Fatal("a server that is no exit looks for no uplink and forwards nothing")
	}
	run.calls = nil
	net.apply(t, exitOnPrivate)
	if got := tables.chain("iptables", "filter", network.ExitChain); !slices.Equal(got, exitRules("eth0", "10.88.0.9/32")) {
		t.Fatalf("exit chain %q", got)
	}
	onTop(t, tables, "iptables", exitOutOf, exitInto)
	if !slices.Contains(tables.chain("iptables", "nat", "POSTROUTING"), "-A POSTROUTING -s 10.88.0.9/32 -o eth0 -j MASQUERADE") {
		t.Fatalf("no masquerade:\n%s", tables)
	}
	if procValue(t, net.executor, ipForward) != "1" || tables.policy["iptables filter FORWARD"] != "DROP" {
		t.Fatalf("forwarding %q policy %q", procValue(t, net.executor, ipForward), tables.policy)
	}
	if _, found := sysctlFile(t, net.executor); found || slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "sysctl") }) {
		t.Fatalf("an IPv4 exit persists no forwarding key: %v", run.calls)
	}
	net.apply(t, exitOnPrivate)
	onTop(t, tables, "iptables", exitOutOf, exitInto, apartOf)
	if forward := tables.chain("iptables", "filter", "FORWARD"); len(forward) != 5 {
		t.Fatalf("the jumps were added twice: %q", forward)
	}
}

func TestForwardingIsSwitchedOnOnlyForAnExit(t *testing.T) {
	net, run, tables := newLaptopNet(t)
	net.apply(t, asIs)
	if procValue(t, net.executor, ipForward) != "0" || slices.Contains(run.calls, "iptables -P FORWARD DROP") {
		t.Fatalf("a meeting point relays in user space, yet forwarding is %q: %v", procValue(t, net.executor, ipForward), run.calls)
	}
	flipped := false
	run.effects = map[string]func(){"iptables -P FORWARD DROP": func() {
		flipped = procValue(t, net.executor, ipForward) == "0"
	}}
	net.apply(t, exitOn)
	if !flipped || procValue(t, net.executor, ipForward) != "1" || tables.policy["iptables filter FORWARD"] != "DROP" {
		t.Fatalf("the policy is set before forwarding: flipped %v forwarding %q policy %q", flipped, procValue(t, net.executor, ipForward), tables.policy)
	}
	if _, found := sysctlFile(t, net.executor); found {
		t.Fatal("an IPv4 exit persists no forwarding key")
	}
	net.apply(t, asIs)
	if procValue(t, net.executor, ipForward) != "1" {
		t.Fatal("forwarding is never switched back off")
	}
	other, run, tables := newLaptopNet(t)
	rootFile(t, other.executor, ipForward, "1\n")
	other.apply(t, exitOn)
	if slices.Contains(run.calls, "iptables -P FORWARD DROP") || tables.policy["iptables filter FORWARD"] != "" {
		t.Fatalf("forwarding was already on, the policy is left alone: %v", run.calls)
	}
}

func TestExitTurnsOffWhenHeldEvenIfTheDocumentSaysOn(t *testing.T) {
	net, run, tables := newLaptopNet(t)
	run.respond["ip -6 route show default"] = v6Default
	rootFile(t, net.executor, "/proc/sys/net/ipv6/conf/eth0/accept_ra", "1\n")
	asked := 0
	net.executor.Held = func(context.Context) (bool, error) {
		asked++
		return false, nil
	}
	net.apply(t, exitOn)
	if body, _ := sysctlFile(t, net.executor); body != "net.ipv6.conf.eth0.accept_ra = 2\n" {
		t.Fatalf("forwarding %q", body)
	}
	if err := net.executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if asked != 1 || !tables.has("iptables", "filter", network.ExitChain) {
		t.Fatalf("a free server: asked %d\n%s", asked, tables)
	}
	os.Remove(filepath.Join(net.executor.StateDir, heldFile))
	net.executor.Held = func(context.Context) (bool, error) { return true, nil }
	if err := net.executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	noExit(t, tables, "iptables", "ip6tables")
	if !slices.Contains(tables.chain("iptables", "filter", "FORWARD"), apartOf) || !slices.Contains(tables.chain("ip6tables", "filter", "FORWARD"), apartOf) {
		t.Fatalf("a held server still forwards nothing between peers while kry0 carries the laptops' IPv6:\n%s", tables)
	}
	if pairs, err := net.executor.relayPairs(); err != nil || len(pairs) != 1 {
		t.Fatalf("a held meeting point still relays until the laptop moves on: %+v", pairs)
	}
	if _, err := os.Stat(filepath.Join(net.executor.StateDir, "host", exitSyncMark)); err != nil {
		t.Fatalf("the exec unit left the sysctl file to the host unit: %v", err)
	}
	if err := net.executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, found := sysctlFile(t, net.executor); found {
		t.Fatal("held: the IPv6 exit's file stays")
	}
	if config := readRoot(t, net.executor, network.ConfigPath); strings.Contains(config, "fd88:88::") {
		t.Fatalf("held: the laptop's IPv6 address stays on kry0:\n%s", config)
	}
	if slices.Contains(tables.chain("ip6tables", "filter", "FORWARD"), apartOf) || !slices.Contains(tables.chain("iptables", "filter", "FORWARD"), apartOf) {
		t.Fatalf("the IPv6 drop leaves with the laptops' IPv6 addresses, never before:\n%s", tables)
	}
	if procValue(t, net.executor, ipForward) != "1" {
		t.Fatal("forwarding is never switched back off")
	}
	noExit(t, tables, "iptables", "ip6tables")
	writeJSON(net.executor.StateDir, heldFile, heldState{Held: true, At: executorNow.Add(-time.Hour)}, 0o640)
	net.executor.Held = func(context.Context) (bool, error) { return false, errors.New("no route to host") }
	if err := net.executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	noExit(t, tables, "iptables", "ip6tables")
	net.apply(t, exitOnPrivate)
	noExit(t, tables, "iptables", "ip6tables")
	if pairs, err := net.executor.relayPairs(); err != nil || pairs != nil {
		t.Fatalf("held and no meeting point: nothing relays: %+v", pairs)
	}
}

func TestAQuarantineMarkKeepsTheExitOffInTheWatchLoop(t *testing.T) {
	net, _, tables := newLaptopNet(t)
	net.apply(t, exitOnPrivate)
	mark := filepath.Join(t.TempDir(), "quarantined")
	if err := os.WriteFile(mark, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	net.executor.QuarantineMark = mark
	net.executor.syncRules(context.Background())
	noExit(t, tables, "iptables", "ip6tables")
	net.executor.Contain(context.Background())
	noExit(t, tables, "iptables", "ip6tables")
	os.Remove(mark)
	net.executor.syncRules(context.Background())
	if !tables.has("iptables", "filter", network.ExitChain) {
		t.Fatalf("the mark is gone, the exit is back:\n%s", tables)
	}
}

func TestExitOffRemovesExactlyWhatOnAdded(t *testing.T) {
	net, run, tables := newLaptopNet(t)
	run.respond["ip -6 route show default"] = v6Default
	rootFile(t, net.executor, "/proc/sys/net/ipv6/conf/eth0/accept_ra", "1\n")
	dockerForward(tables)
	net.apply(t, exitOffPrivate)
	before, config := tables.String(), readRoot(t, net.executor, network.ConfigPath)
	net.apply(t, exitOnPrivate)
	if tables.String() == before || !tables.has("ip6tables", "filter", network.ExitChain) {
		t.Fatalf("the exit added nothing:\n%s", tables)
	}
	if _, found := sysctlFile(t, net.executor); !found {
		t.Fatal("the IPv6 exit wrote no accept_ra")
	}
	tables.rules["iptables filter FORWARD"] = append(tables.rules["iptables filter FORWARD"], "-A FORWARD -i kry0 -o eth9 -j KRY-EXIT")
	net.apply(t, exitOffPrivate)
	if after := tables.String(); after != before {
		t.Fatalf("off left something:\nbefore\n%s\nafter\n%s", before, after)
	}
	if _, found := sysctlFile(t, net.executor); found {
		t.Fatal("off left the sysctl file")
	}
	if now := readRoot(t, net.executor, network.ConfigPath); now != config {
		t.Fatalf("off changed kry0:\n%s\nwas\n%s", now, config)
	}
}

func TestAnIPv6ExitKeepsRouterAdvertisements(t *testing.T) {
	net, run, tables := newLaptopNet(t)
	run.respond["ip -6 route show default"] = v6Default
	accept := "/proc/sys/net/ipv6/conf/eth0/accept_ra"
	rootFile(t, net.executor, accept, "1\n")
	ready := false
	run.effects = map[string]func(){"ip6tables -P FORWARD DROP": func() {
		ready = procValue(t, net.executor, accept) == "2" && procValue(t, net.executor, ip6Forward) == "0"
	}}
	net.apply(t, exitOnPrivate)
	if body, _ := sysctlFile(t, net.executor); body != "net.ipv6.conf.eth0.accept_ra = 2\n" {
		t.Fatalf("the file keeps only accept_ra: %q", body)
	}
	if !slices.Contains(run.calls, "sysctl -p "+net.executor.path(laptopExitConf)) || slices.Contains(run.calls, "sysctl --system") {
		t.Fatalf("the file is applied alone: %v", run.calls)
	}
	if !ready || procValue(t, net.executor, ip6Forward) != "1" || tables.policy["ip6tables filter FORWARD"] != "DROP" {
		t.Fatalf("accept_ra before forwarding: ready %v forwarding %q policy %q", ready, procValue(t, net.executor, ip6Forward), tables.policy)
	}
	if got := tables.chain("ip6tables", "filter", network.ExitChain); !slices.Equal(got, exitRules("eth0", "fd88:88::9/128")) {
		t.Fatalf("IPv6 exit %q", got)
	}
	onTop(t, tables, "ip6tables", exitOutOf, exitInto)
	if !slices.Contains(tables.chain("ip6tables", "nat", "POSTROUTING"), "-A POSTROUTING -s fd88:88::9/128 -o eth0 -j MASQUERADE") {
		t.Fatalf("no NAT66:\n%s", tables)
	}
	if config := readRoot(t, net.executor, network.ConfigPath); !strings.Contains(config, "AllowedIPs = 10.88.0.9/32, fd88:88::9/128") {
		t.Fatalf("the laptop's IPv6 address is not on kry0:\n%s", config)
	}
	if !slices.Contains(tables.chain("ip6tables", "filter", "FORWARD"), apartOf) {
		t.Fatalf("an IPv6 exit forwards between peers:\n%s", tables)
	}
	net.apply(t, exitOnPrivate)
	if body, _ := sysctlFile(t, net.executor); body != "net.ipv6.conf.eth0.accept_ra = 2\n" {
		t.Fatalf("once applied, accept_ra reads 2 and must stay in the file: %q", body)
	}
	rootFile(t, net.executor, accept, "0\n")
	net.apply(t, exitOnPrivate)
	if _, found := sysctlFile(t, net.executor); found || procValue(t, net.executor, accept) != "0" {
		t.Fatal("a static IPv6 address keeps its own setting")
	}
}

func TestAnIPv6ExitUsesTheIPv6Uplink(t *testing.T) {
	net, run, tables := newLaptopNet(t)
	run.respond["ip -6 route show default"] = "default via fe80::1 dev eth1 proto ra metric 1024\n"
	rootFile(t, net.executor, "/proc/sys/net/ipv6/conf/eth0/accept_ra", "1\n")
	rootFile(t, net.executor, "/proc/sys/net/ipv6/conf/eth1/accept_ra", "1\n")
	net.apply(t, exitOnPrivate)
	if got := tables.chain("iptables", "filter", network.ExitChain); !slices.Equal(got, exitRules("eth0", "10.88.0.9/32")) {
		t.Fatalf("IPv4 exit %q", got)
	}
	if got := tables.chain("ip6tables", "filter", network.ExitChain); !slices.Equal(got, exitRules("eth1", "fd88:88::9/128")) {
		t.Fatalf("IPv6 exit %q", got)
	}
	if !slices.Contains(tables.chain("ip6tables", "nat", "POSTROUTING"), "-A POSTROUTING -s fd88:88::9/128 -o eth1 -j MASQUERADE") {
		t.Fatalf("NAT66:\n%s", tables)
	}
	if body, _ := sysctlFile(t, net.executor); body != "net.ipv6.conf.eth1.accept_ra = 2\n" || procValue(t, net.executor, "/proc/sys/net/ipv6/conf/eth0/accept_ra") != "1" {
		t.Fatalf("accept_ra belongs to the IPv6 uplink: %q", body)
	}
}

func TestADottedUplinkUsesTheSlashKey(t *testing.T) {
	net, run, _ := newLaptopNet(t)
	run.respond["ip -6 route show default"] = "default via fe80::1 dev eth0.100 proto ra metric 1024\n"
	rootFile(t, net.executor, "/proc/sys/net/ipv6/conf/eth0.100/accept_ra", "1\n")
	net.apply(t, exitOnPrivate)
	if body, _ := sysctlFile(t, net.executor); body != "net/ipv6/conf/eth0.100/accept_ra = 2\n" {
		t.Fatalf("%q", body)
	}
}

func TestAServerWithoutIPv6GetsNoIPv6ExitRules(t *testing.T) {
	net, run, tables := newLaptopNet(t)
	rootFile(t, net.executor, "/proc/sys/net/ipv6/conf/eth0/accept_ra", "1\n")
	net.apply(t, exitOnPrivate)
	if !tables.has("iptables", "filter", network.ExitChain) {
		t.Fatalf("no IPv4 exit:\n%s", tables)
	}
	noExit(t, tables, "ip6tables")
	if slices.ContainsFunc(run.calls, func(call string) bool {
		return strings.HasPrefix(call, "ip6tables-restore") || strings.HasPrefix(call, "ip6tables -I") || strings.HasPrefix(call, "ip6tables -P") || strings.HasPrefix(call, "ip6tables -t nat -A")
	}) {
		t.Fatalf("IPv6 rules were written: %v", run.calls)
	}
	if _, found := sysctlFile(t, net.executor); found || procValue(t, net.executor, ip6Forward) != "0" {
		t.Fatal("no IPv6, no IPv6 forwarding")
	}
	if config := readRoot(t, net.executor, network.ConfigPath); strings.Contains(config, "fd88:88::") {
		t.Fatalf("kry0 carries an IPv6 route the server cannot use:\n%s", config)
	}
}

func TestServersNeverForwardBetweenPeers(t *testing.T) {
	net, run, tables := newLaptopNet(t)
	dockerForward(tables)
	for _, change := range []func(*network.Member, []network.Member) []network.Member{withoutLaptop, asIs, behindNAT, asIs} {
		net.apply(t, change)
		if forward := tables.chain("iptables", "filter", "FORWARD"); forward[0] != apartOf || slices.Index(forward[1:], apartOf) >= 0 {
			t.Fatalf("FORWARD %q", forward)
		}
		if slices.Contains(tables.chain("ip6tables", "filter", "FORWARD"), apartOf) || strings.Contains(tables.String(), "KRY-RELAY") || procValue(t, net.executor, ipForward) != "0" {
			t.Fatalf("tables:\n%s", tables)
		}
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "KRY-RELAY") }) {
		t.Fatalf("%v", run.calls)
	}
}

func TestOnlyAMeetingPointOpensItsPairPorts(t *testing.T) {
	net, run, _ := newLaptopNet(t)
	opened := "ufw allow 51920/udp comment krynodes-network"
	net.apply(t, withoutLaptop)
	if slices.Contains(run.calls, opened) || net.executor.readNetwork().Relays != nil {
		t.Fatalf("no laptop, no pair port: %v", run.calls)
	}
	run.calls = nil
	net.apply(t, asIs)
	if !slices.Contains(run.calls, opened) || !slices.Equal(net.executor.readNetwork().Relays, []int{51920}) {
		t.Fatalf("a meeting point opens its pair port: %v", run.calls)
	}
	if pairs, err := net.executor.relayPairs(); err != nil || len(pairs) != 1 || pairs[0].Port != 51920 || pairs[0].Sides != [2]string{net.laptop.Public, net.behind.Public} || pairs[0].Host.String() != "203.0.113.30" {
		t.Fatalf("pairs %+v", pairs)
	}
	run.calls = nil
	net.apply(t, asIs)
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "ufw") }) {
		t.Fatalf("an open port is opened again: %v", run.calls)
	}
	run.respond["ufw status numbered"] = "[ 1] 51821/udp ALLOW IN Anywhere # krynodes-network\n[ 2] Anywhere on kry0 ALLOW IN Anywhere # krynodes-network\n[ 3] 51920/udp ALLOW IN Anywhere # krynodes-network\n[ 4] 51920/udp (v6) ALLOW IN Anywhere (v6) # krynodes-network\n"
	run.calls = nil
	net.apply(t, withoutLaptop)
	if !slices.Contains(run.calls, "ufw --force delete 4") || !slices.Contains(run.calls, "ufw --force delete 3") || slices.ContainsFunc(run.calls, func(call string) bool {
		return call == "ufw --force delete 1" || call == "ufw --force delete 2"
	}) || net.executor.readNetwork().Relays != nil || noPairs(t, net.executor) {
		t.Fatalf("the laptop left, its pair port stays: %v", run.calls)
	}
	net.apply(t, asIs)
	run.calls = nil
	net.apply(t, behindNAT)
	if !slices.Contains(run.calls, "ufw --force delete 4") || net.executor.readNetwork().Relays != nil || noPairs(t, net.executor) {
		t.Fatalf("a member behind NAT is no meeting point: %v", run.calls)
	}
}

func noPairs(t *testing.T, executor Executor) bool {
	t.Helper()
	pairs, err := executor.relayPairs()
	if err != nil {
		t.Fatal(err)
	}
	return pairs != nil
}

func TestAnUnreadableRecordKeepsThePairsTheRelayCarries(t *testing.T) {
	net, _, _ := newLaptopNet(t)
	net.apply(t, asIs)
	path := filepath.Join(net.executor.StateDir, "network.json")
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	retry := func(do func() error) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for err := do(); err != nil; err = do() {
			if time.Now().After(deadline) {
				t.Fatal(err)
			}
			time.Sleep(time.Millisecond)
		}
	}
	sets := make(chan []relay.Pair, 64)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		net.executor.carryPairs(ctx, 5*time.Millisecond, func(pairs []relay.Pair) { sets <- pairs })
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()
	if pairs := <-sets; len(pairs) != 1 || pairs[0].Port != 51920 {
		t.Fatalf("pairs %+v", pairs)
	}
	retry(func() error { return os.Remove(path) })
	retry(func() error { return os.Mkdir(path, 0o700) })
	for drained := false; !drained; {
		select {
		case <-sets:
		case <-time.After(50 * time.Millisecond):
			drained = true
		}
	}
	select {
	case pairs := <-sets:
		t.Fatalf("an unreadable record set the pairs to %+v", pairs)
	case <-time.After(50 * time.Millisecond):
	}
	retry(func() error { return os.Remove(path) })
	retry(func() error { return os.WriteFile(path, saved, 0o644) })
	for deadline := time.After(2 * time.Second); ; {
		select {
		case pairs := <-sets:
			if len(pairs) != 1 || pairs[0].Port != 51920 {
				continue
			}
		case <-deadline:
			t.Fatal("a readable record never carries the pairs again")
		}
		break
	}
	if err := os.WriteFile(filepath.Join(net.executor.StateDir, "trust.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := net.executor.relayPairs(); err == nil {
		t.Fatal("an unreadable trust store is an error, not an empty set")
	}
}

func TestAPairPortTheFirewallRefusesFailsNothingAndIsTriedAgain(t *testing.T) {
	net, run, tables := newLaptopNet(t)
	opened := "ufw allow 51920/udp comment krynodes-network"
	run.failing = map[string]string{opened: "ERROR: Could not get lock\n"}
	net.apply(t, asIs)
	record := net.executor.readNetwork()
	if record.Relays != nil || record.Document == nil || record.Document.Version != net.version || !slices.Contains(tables.chain("iptables", "filter", "FORWARD"), apartOf) {
		t.Fatalf("a refused pair port applies the document and records no port: %+v\n%s", record.Relays, tables)
	}
	delete(run.failing, opened)
	run.calls = nil
	if err := net.executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(run.calls, opened) || !slices.Equal(net.executor.readNetwork().Relays, []int{51920}) {
		t.Fatalf("the refused port is opened on the next round, with no new document: %v", run.calls)
	}
	run.calls = nil
	if err := net.executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool {
		return strings.HasPrefix(call, "ufw") || strings.HasPrefix(call, "firewall-cmd")
	}) {
		t.Fatalf("a round with every port in place touches no firewall: %v", run.calls)
	}
	run.failing["ufw status numbered"] = "ERROR: Could not get lock\n"
	run.calls = nil
	net.apply(t, withoutLaptop)
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "ufw --force delete") }) || !slices.Equal(net.executor.readNetwork().Relays, []int{51920}) {
		t.Fatalf("an unread listing deletes nothing and keeps the port for the next apply: %v", run.calls)
	}
	delete(run.failing, "ufw status numbered")
	run.respond["ufw status numbered"] = "[ 1] 51821/udp ALLOW IN Anywhere # krynodes-network\n[ 2] 51920/udp ALLOW IN Anywhere # krynodes-network\n"
	run.calls = nil
	if err := net.executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(run.calls, "ufw --force delete 2") || slices.Contains(run.calls, "ufw --force delete 1") || slices.Contains(run.calls, "ufw reload") || net.executor.readNetwork().Relays != nil {
		t.Fatalf("the kept port is closed on the next round, with no reload: %v", run.calls)
	}
}

func TestTheRootUnitAsksTheAddressItPinnedNotTheOneInTheConfig(t *testing.T) {
	status, body, token := http.StatusOK, `{"held":true}`, ""
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/held" {
			t.Errorf("path %s", r.URL.Path)
		}
		token = r.Header.Get("Authorization")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	defer real.Close()
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"held":false}`))
	}))
	defer fake.Close()
	state := t.TempDir()
	path := filepath.Join(t.TempDir(), "config.json")
	save := func(endpoint string) {
		if err := config.Save(path, config.Config{Endpoint: endpoint, NodeID: testNode, Token: "agent-token"}); err != nil {
			t.Fatal(err)
		}
	}
	save(real.URL)
	ask := WorkerHeld(state, path, "0.7.24", real.Client())
	if held, err := ask(context.Background()); err != nil || !held || token != "Bearer agent-token" {
		t.Fatalf("held %v err %v token %q", held, err, token)
	}
	save(fake.URL)
	if held, err := ask(context.Background()); err != nil || !held {
		t.Fatalf("a changed config moved the question: held %v err %v", held, err)
	}
	body = `{"held":false}`
	if held, err := ask(context.Background()); err != nil || held {
		t.Fatalf("free: held %v err %v", held, err)
	}
	status = http.StatusUnauthorized
	if held, err := ask(context.Background()); err != nil || !held {
		t.Fatalf("a server Krynodes refuses is held: %v %v", held, err)
	}
	status = http.StatusBadGateway
	if _, err := ask(context.Background()); err == nil {
		t.Fatal("an outage is not an answer")
	}
}

func TestIPv6ForwardingStaysOffWhenRouterAdvertisementsCannotBeKept(t *testing.T) {
	net, run, tables := newLaptopNet(t)
	run.respond["ip -6 route show default"] = v6Default
	accept := "/proc/sys/net/ipv6/conf/eth0/accept_ra"
	rootFile(t, net.executor, accept, "1\n")
	run.effects = map[string]func(){"ip6tables -t nat -S POSTROUTING": func() {
		if info, err := os.Stat(net.executor.path(accept)); err == nil && !info.IsDir() {
			os.Remove(net.executor.path(accept))
			os.Mkdir(net.executor.path(accept), 0o755)
		}
	}}
	net.apply(t, exitOnPrivate)
	if procValue(t, net.executor, ip6Forward) != "0" || slices.Contains(run.calls, "ip6tables -P FORWARD DROP") || tables.policy["ip6tables filter FORWARD"] != "" {
		t.Fatalf("IPv6 forwarding was switched on without accept_ra: forwarding %q calls %v", procValue(t, net.executor, ip6Forward), run.calls)
	}
	if procValue(t, net.executor, ipForward) != "1" {
		t.Fatal("IPv4 forwarding does not depend on accept_ra")
	}
}
