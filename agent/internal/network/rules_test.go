package network

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const nodeS = "55555555-5555-4555-8555-555555555555"

func ruleDocument(rules ...Rule) Document {
	return Document{
		V: 1, Version: 1, Range: "10.88.0.0/24", Port: FirstPort, MTU: 1420,
		Members: []Member{
			{Node: nodeA, Name: "server-1", Address: "10.88.0.1"},
			{Node: nodeB, Name: "server-2", Address: "10.88.0.2"},
			{Node: nodeS, Name: "server-3", Address: "10.88.0.3"},
			{Node: nodeL, Name: "laptop-1", Address: "10.88.0.9", Kind: laptopKind},
		},
		Allow: rules,
	}
}

func everyPort(from, to Side) Rule {
	return Rule{From: from, To: to, Ports: Ports{All: true}}
}

func some(from, to Side, ports ...string) Rule {
	return Rule{From: from, To: to, Ports: Ports{List: ports}}
}

var (
	laptops = Side{Group: laptopsGroup}
	servers = Side{Group: serversGroup}
)

func node(id string) Side {
	return Side{Node: id}
}

func lines(body string) []string {
	return strings.Split(strings.TrimSuffix(body, "\n"), "\n")
}

func grantLines(body string) []string {
	var found []string
	for _, line := range lines(body) {
		if strings.HasPrefix(line, "-A KRY-") && !strings.HasPrefix(line, "-A KRY-EXIT") && !strings.HasPrefix(line, "-A KRY-EDGE") && (strings.HasSuffix(line, "-j ACCEPT") || strings.HasSuffix(line, "-j RETURN")) && !strings.Contains(line, "RELATED,ESTABLISHED") && !strings.Contains(line, "icmp") {
			found = append(found, line)
		}
	}
	return found
}

func TestTheDefaultRuleLetsLaptopsReachEveryPort(t *testing.T) {
	document := ruleDocument(everyPort(laptops, servers))
	for _, self := range []string{nodeA, nodeB, nodeS} {
		got := grantLines(RenderRules(document, self, nil, 4, ""))
		want := []string{"-A KRY-IN -s 10.88.0.9/32 -j ACCEPT", "-A KRY-FWD -s 10.88.0.9/32 -m conntrack --ctstate DNAT -j RETURN"}
		if !slices.Equal(got, want) {
			t.Fatalf("%s: grants %q", self, got)
		}
	}
}

func TestServersReachEachOtherOnlyWhereARuleSays(t *testing.T) {
	document := ruleDocument(everyPort(laptops, servers))
	if grants := Allowed(document, nodeA); len(grants) != 1 || grants[0].Source != "10.88.0.9" {
		t.Fatalf("grants %+v", grants)
	}
	document.Allow = append(document.Allow, some(servers, servers, "22/tcp"))
	got := grantLines(RenderRules(document, nodeA, nil, 4, ""))
	for _, want := range []string{
		"-A KRY-IN -s 10.88.0.2/32 -p tcp -m multiport --dports 22 -j ACCEPT",
		"-A KRY-IN -s 10.88.0.3/32 -p tcp -m multiport --dports 22 -j ACCEPT",
		"-A KRY-FWD -s 10.88.0.2/32 -p tcp -m conntrack --ctstate DNAT --ctorigdstport 22 -j RETURN",
	} {
		if !slices.Contains(got, want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}
}

func TestARuleOpensOneDirectionOnly(t *testing.T) {
	document := ruleDocument(some(node(nodeA), node(nodeB), "81/tcp"))
	want := []string{
		"-A KRY-IN -s 10.88.0.1/32 -p tcp -m multiport --dports 81 -j ACCEPT",
		"-A KRY-FWD -s 10.88.0.1/32 -p tcp -m conntrack --ctstate DNAT --ctorigdstport 81 -j RETURN",
	}
	if got := grantLines(RenderRules(document, nodeB, nil, 4, "")); !slices.Equal(got, want) {
		t.Fatalf("server-2 grants %q", got)
	}
	if got := grantLines(RenderRules(document, nodeA, nil, 4, "")); len(got) != 0 {
		t.Fatalf("server-1 grants %q", got)
	}
}

func TestAGroupRuleNeverIncludesTheServerItself(t *testing.T) {
	document := ruleDocument(everyPort(servers, servers))
	var sources []string
	for _, grant := range Allowed(document, nodeA) {
		sources = append(sources, grant.Source)
	}
	if !slices.Equal(sources, []string{"10.88.0.2", "10.88.0.3"}) {
		t.Fatalf("sources %q", sources)
	}
	document.Allow = []Rule{everyPort(node(nodeA), servers)}
	if grants := Allowed(document, nodeA); len(grants) != 0 {
		t.Fatalf("server-1 lets itself in: %+v", grants)
	}
	if grants := Allowed(document, nodeB); len(grants) != 1 || grants[0].Source != "10.88.0.1" {
		t.Fatalf("server-2 grants %+v", grants)
	}
}

func TestACutMemberIsNeverASource(t *testing.T) {
	document := ruleDocument(everyPort(laptops, servers), everyPort(servers, node(nodeA)), everyPort(node(nodeB), servers))
	document.Members[1].Cut = true
	document.Members[3].Cut = true
	var sources []string
	for _, grant := range Allowed(document, nodeA) {
		sources = append(sources, grant.Source)
	}
	if !slices.Equal(sources, []string{"10.88.0.3"}) {
		t.Fatalf("sources %q", sources)
	}
}

func TestARuleForAnotherServerRendersNothingHere(t *testing.T) {
	empty := RenderRules(ruleDocument(), nodeA, nil, 4, "")
	document := ruleDocument(everyPort(laptops, node(nodeB)), some(node(nodeS), node(nodeB), "22/tcp"))
	if got := RenderRules(document, nodeA, nil, 4, ""); got != empty {
		t.Fatalf("server-1 renders\n%s\nwant\n%s", got, empty)
	}
	if got := RenderRules(document, nodeL, nil, 4, ""); got != RenderRules(ruleDocument(), nodeL, nil, 4, "") || len(Allowed(document, nodeL)) != 0 {
		t.Fatalf("a laptop renders\n%s", got)
	}
}

func TestAllPortsMeansAnyProtocol(t *testing.T) {
	grants := Allowed(ruleDocument(everyPort(node(nodeB), node(nodeA))), nodeA)
	if !reflect.DeepEqual(grants, []Grant{{Source: "10.88.0.2", Source6: "fd88:88::2", Protocol: "all"}}) {
		t.Fatalf("grants %+v", grants)
	}
	for _, line := range grantLines(RenderRules(ruleDocument(everyPort(node(nodeB), node(nodeA))), nodeA, nil, 4, "")) {
		if strings.Contains(line, "-p ") || strings.Contains(line, "port") {
			t.Fatalf("an all-ports line matches a protocol: %q", line)
		}
	}
}

func TestPortsAreGroupedByProtocolInTheirOrder(t *testing.T) {
	grants := Allowed(ruleDocument(some(servers, node(nodeA), "22/tcp", "53/udp", "8000-8100/tcp")), nodeA)
	want := []Grant{
		{Source: "10.88.0.2", Source6: "fd88:88::2", Protocol: "tcp", Ports: []string{"22", "8000:8100"}},
		{Source: "10.88.0.2", Source6: "fd88:88::2", Protocol: "udp", Ports: []string{"53"}},
		{Source: "10.88.0.3", Source6: "fd88:88::3", Protocol: "tcp", Ports: []string{"22", "8000:8100"}},
		{Source: "10.88.0.3", Source6: "fd88:88::3", Protocol: "udp", Ports: []string{"53"}},
	}
	if !reflect.DeepEqual(grants, want) {
		t.Fatalf("grants %+v", grants)
	}
}

func TestMoreThan15PortsSplitIntoSeveralLines(t *testing.T) {
	ranges := []string{"1-2/tcp", "10-20/tcp", "30-40/tcp", "50-60/tcp", "70-80/tcp", "90-99/tcp", "100-110/tcp", "120-130/tcp"}
	got := grantLines(RenderRules(ruleDocument(some(node(nodeB), node(nodeA), ranges...)), nodeA, nil, 4, ""))
	want := []string{
		"-A KRY-IN -s 10.88.0.2/32 -p tcp -m multiport --dports 1:2,10:20,30:40,50:60,70:80,90:99,100:110 -j ACCEPT",
		"-A KRY-IN -s 10.88.0.2/32 -p tcp -m multiport --dports 120:130 -j ACCEPT",
	}
	if !slices.Equal(got[:2], want) || len(got) != 2+len(ranges) {
		t.Fatalf("grants %q", got)
	}
	var many []string
	for port := 1; port <= 20; port++ {
		many = append(many, strings.Repeat("1", port%5+1))
	}
	if chunks := multiport(many); len(chunks) != 2 || len(chunks[0]) != 15 || len(chunks[1]) != 5 {
		t.Fatalf("chunks %q", chunks)
	}
}

func TestEveryChainEndsInDrop(t *testing.T) {
	document := ruleDocument(everyPort(laptops, servers), some(servers, servers, "22/tcp"))
	for _, family := range []int{4, 6} {
		for _, self := range []string{nodeA, nodeL, nodeC} {
			body := RenderRules(document, self, []string{"10.88.0.5"}, family, "eth0")
			all := lines(body)
			if !strings.HasPrefix(body, "*filter\n:KRY-IN - [0:0]\n:KRY-FWD - [0:0]\n:KRY-EXIT - [0:0]\n:KRY-EDGE - [0:0]\n") || all[len(all)-1] != "COMMIT" {
				t.Fatalf("family %d %s:\n%s", family, self, body)
			}
			var in, forward []string
			for _, line := range all {
				switch {
				case strings.HasPrefix(line, "-A KRY-IN "):
					in = append(in, line)
				case strings.HasPrefix(line, "-A KRY-FWD "):
					forward = append(forward, line)
				case slices.Contains(edgeLines(family), line):
				case !strings.HasPrefix(line, "*") && !strings.HasPrefix(line, ":") && line != "COMMIT":
					t.Fatalf("a line outside the chains on a server that is not the exit: %q", line)
				}
			}
			if in[0] != "-A KRY-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" || in[len(in)-1] != "-A KRY-IN -j DROP" {
				t.Fatalf("family %d %s KRY-IN %q", family, self, in)
			}
			if forward[0] != "-A KRY-FWD -o kry0 -j DROP" || forward[1] != "-A KRY-FWD -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN" || forward[len(forward)-1] != "-A KRY-FWD -j DROP" {
				t.Fatalf("family %d %s KRY-FWD %q", family, self, forward)
			}
			for _, line := range forward[:len(forward)-1] {
				if strings.HasSuffix(line, "-j RETURN") && !strings.Contains(line, "--ctstate RELATED,ESTABLISHED ") && !strings.Contains(line, "--ctstate DNAT ") {
					t.Fatalf("family %d %s: a forward return that is neither a reply nor DNAT: %q", family, self, line)
				}
			}
		}
	}
}

func TestADroppedAddressIsDroppedBeforeAnyAccept(t *testing.T) {
	body := RenderRules(ruleDocument(everyPort(laptops, servers)), nodeA, []string{"10.88.0.9", "not an address"}, 4, "")
	want := []string{
		"-A KRY-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"-A KRY-IN -s 10.88.0.9/32 -j DROP",
		"-A KRY-IN -s 10.88.0.0/16 -p icmp --icmp-type echo-request -j ACCEPT",
		"-A KRY-IN -s 10.88.0.9/32 -j ACCEPT",
		"-A KRY-IN -j DROP",
		"-A KRY-FWD -o kry0 -j DROP",
		"-A KRY-FWD -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
		"-A KRY-FWD -s 10.88.0.9/32 -j DROP",
		"-A KRY-FWD -j KRY-EXIT",
		"-A KRY-FWD -s 10.88.0.9/32 -m conntrack --ctstate DNAT -j RETURN",
		"-A KRY-FWD -j DROP",
	}
	want = append(want, edgeLines(4)...)
	if got := lines(body)[5 : len(lines(body))-1]; !slices.Equal(got, want) {
		t.Fatalf("rules\n%s", strings.Join(got, "\n"))
	}
}

func TestKry0ToKry0IsNeverForwarded(t *testing.T) {
	if !slices.ContainsFunc(Jumps(), func(jump []string) bool {
		return slices.Equal(jump, []string{"FORWARD", "-i", Interface, "-o", Interface, "-j", "DROP"})
	}) {
		t.Fatalf("jumps %q", Jumps())
	}
	for _, line := range lines(RenderRules(ruleDocument(everyPort(laptops, servers)), nodeA, nil, 4, "eth0")) {
		if strings.Contains(line, "-o ") && line != "-A KRY-FWD -o kry0 -j DROP" {
			t.Fatalf("a rule names an outgoing interface: %q", line)
		}
	}
}

func TestADockerPortOnAllAddressesIsCoveredByForwardRules(t *testing.T) {
	body := RenderRules(ruleDocument(some(laptops, servers, "8080/tcp", "8000-8010/tcp", "53/udp")), nodeA, nil, 4, "")
	for _, want := range []string{
		"-A KRY-FWD -s 10.88.0.9/32 -p tcp -m conntrack --ctstate DNAT --ctorigdstport 8080 -j RETURN",
		"-A KRY-FWD -s 10.88.0.9/32 -p tcp -m conntrack --ctstate DNAT --ctorigdstport 8000:8010 -j RETURN",
		"-A KRY-FWD -s 10.88.0.9/32 -p udp -m conntrack --ctstate DNAT --ctorigdstport 53 -j RETURN",
	} {
		if !strings.Contains(body, want+"\n") {
			t.Fatalf("missing %q in\n%s", want, body)
		}
	}
	want := [][]string{
		{"INPUT", "-j", EdgeChain},
		{"INPUT", "-i", Interface, "-j", InChain},
		{"FORWARD", "-i", Interface, "-o", Interface, "-j", "DROP"},
		{"FORWARD", "-i", Interface, "-j", ForwardChain},
		{"DOCKER-USER", "-i", Interface, "-j", ForwardChain},
	}
	if got := Jumps(); !reflect.DeepEqual(got, want) {
		t.Fatalf("jumps %q", got)
	}
	if strings.Contains(body, "DOCKER-USER") {
		t.Fatalf("the restore body touches DOCKER-USER:\n%s", body)
	}
}

type chainRun struct {
	calls  []string
	exists map[string]bool
}

func (c *chainRun) run(_ context.Context, name string, args ...string) ([]byte, int, error) {
	c.calls = append(c.calls, name+" "+strings.Join(args, " "))
	switch strings.Join(args, " ") {
	case "-w -N DOCKER-USER":
		if c.exists[name] {
			return []byte(name + ": Chain already exists."), 1, errors.New("exit status 1")
		}
		c.exists[name] = true
		return nil, 0, nil
	case "-w -S DOCKER-USER":
		if c.exists[name] {
			return []byte("-N DOCKER-USER\n"), 0, nil
		}
	}
	return []byte(name + ": No chain/target/match by that name."), 1, errors.New("exit status 1")
}

func TestDockerUserIsMadeWhenMissingAndKeptWhenThere(t *testing.T) {
	ctx := context.Background()
	run := &chainRun{exists: map[string]bool{"ip6tables": true}}
	for _, tool := range []string{"iptables", "ip6tables"} {
		if err := EnsureDockerUser(ctx, run.run, tool); err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
	}
	want := []string{"iptables -w -N DOCKER-USER", "ip6tables -w -N DOCKER-USER", "ip6tables -w -S DOCKER-USER"}
	if !slices.Equal(run.calls, want) || !run.exists["iptables"] {
		t.Fatalf("calls %q", run.calls)
	}
	if err := EnsureDockerUser(ctx, run.run, "iptables"); err != nil {
		t.Fatalf("a second run: %v", err)
	}
	broken := func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		return []byte(name + ": Permission denied (you must be root)."), 4, errors.New("exit status 4")
	}
	if err := EnsureDockerUser(ctx, broken, "iptables"); err == nil || !strings.Contains(err.Error(), "DOCKER-USER") || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("a failure was hidden: %v", err)
	}
}

func TestIPv6RulesUseTheMembersV6Addresses(t *testing.T) {
	body := RenderRules(ruleDocument(everyPort(laptops, servers), some(node(nodeB), node(nodeA), "22/tcp")), nodeA, []string{"10.88.0.5"}, 6, "")
	for _, want := range []string{
		"-A KRY-IN -s fd88:88::5/128 -j DROP",
		"-A KRY-IN -s fd88:88::/64 -p ipv6-icmp --icmpv6-type echo-request -j ACCEPT",
		"-A KRY-IN -s fd88:88::9/128 -j ACCEPT",
		"-A KRY-IN -s fd88:88::2/128 -p tcp -m multiport --dports 22 -j ACCEPT",
		"-A KRY-FWD -s fd88:88::2/128 -p tcp -m conntrack --ctstate DNAT --ctorigdstport 22 -j RETURN",
	} {
		if !strings.Contains(body, want+"\n") {
			t.Fatalf("missing %q in\n%s", want, body)
		}
	}
	if strings.Contains(body, "10.88.") || strings.Contains(body, "/32") || strings.Contains(body, "-p icmp ") {
		t.Fatalf("an IPv4 match in the IPv6 rules:\n%s", body)
	}
	document := ruleDocument(everyPort(laptops, servers))
	document.Members[3].Address = "not an address"
	if grants := Allowed(document, nodeA); len(grants) != 1 || grants[0].Source6 != "" {
		t.Fatalf("grants %+v", grants)
	}
	if got := grantLines(RenderRules(document, nodeA, nil, 6, "")); len(got) != 0 {
		t.Fatalf("a member without a v6 address renders %q", got)
	}
}

func TestTheExitChainIsUnchanged(t *testing.T) {
	document := ruleDocument()
	self := document.Members[0]
	self.Exit = true
	forward, nat := Exit(self, document.Members, "eth0", 4)
	want := []string{
		"-A KRY-EXIT -i kry0 -o eth0 -d 10.0.0.0/8 -j DROP",
		"-A KRY-EXIT -i kry0 -o eth0 -d 172.16.0.0/12 -j DROP",
		"-A KRY-EXIT -i kry0 -o eth0 -d 192.168.0.0/16 -j DROP",
		"-A KRY-EXIT -i kry0 -o eth0 -d 100.64.0.0/10 -j DROP",
		"-A KRY-EXIT -i kry0 -o eth0 -d 169.254.0.0/16 -j DROP",
		"-A KRY-EXIT -i kry0 -o eth0 -d 0.0.0.0/8 -j DROP",
		"-A KRY-EXIT -i eth0 -o kry0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"-A KRY-EXIT -s 10.88.0.9/32 -i kry0 -o eth0 -j ACCEPT",
		"-A KRY-EXIT -i kry0 -o eth0 -j DROP",
		"-A KRY-EXIT -i eth0 -o kry0 -j DROP",
		"-A KRY-EXIT -i docker0 -o kry0 -j RETURN",
		"-A KRY-EXIT -i br-+ -o kry0 -j RETURN",
		"-A KRY-EXIT ! -i kry0 -o kry0 -m conntrack ! --ctstate RELATED,ESTABLISHED -j DROP",
	}
	if !slices.Equal(forward, want) || !slices.Equal(nat, []string{"-A POSTROUTING -s 10.88.0.9/32 -o eth0 -j MASQUERADE"}) {
		t.Fatalf("forward %q nat %q", forward, nat)
	}
	if forward, _ := Exit(self, document.Members, "eth0", 6); !slices.Equal(forward[:2], []string{"-A KRY-EXIT -i kry0 -o eth0 -d fc00::/7 -j DROP", "-A KRY-EXIT -i kry0 -o eth0 -d fe80::/10 -j DROP"}) || strings.Contains(strings.Join(forward, "\n"), "10.0.0.0/8") {
		t.Fatalf("v6 forward %q", forward)
	}
	document.Members[0] = self
	if body := RenderRules(document, nodeA, nil, 4, "eth0"); !strings.HasSuffix(body, "-A KRY-FWD -j DROP\n"+strings.Join(edgeLines(4), "\n")+"\n"+strings.Join(want, "\n")+"\nCOMMIT\n") {
		t.Fatalf("the exit node renders\n%s", body)
	}
	if body := RenderRules(document, nodeA, []string{"10.88.0.9"}, 4, "eth0"); !strings.Contains(body, "-A KRY-EDGE -d 10.88.0.0/16 -j DROP\n-A KRY-EXIT -s 10.88.0.9/32 -j DROP\n"+want[0]+"\n") {
		t.Fatalf("the exit node does not drop a dropped laptop first\n%s", body)
	}
	if body := RenderRules(document, nodeA, nil, 4, ""); strings.Contains(body, "-A KRY-EXIT") {
		t.Fatalf("an exit node with no uplink renders exit rules\n%s", body)
	}
	document.Members[0].Exit = false
	if forward, nat := Exit(document.Members[0], document.Members, "eth0", 4); forward != nil || nat != nil {
		t.Fatal("a server that is not the exit renders exit rules")
	}
	if forward, _ := Exit(self, document.Members, "eth0", 6); !slices.Contains(forward, "-A KRY-EXIT -s fd88:88::9/128 -i kry0 -o eth0 -j ACCEPT") {
		t.Fatalf("v6 forward %q", forward)
	}
	if !reflect.DeepEqual(ExitJumps, [][]string{{"FORWARD", "-i", Interface, "!", "-o", Interface, "-j", ExitChain}, {"FORWARD", "!", "-i", Interface, "-o", Interface, "-j", ExitChain}}) {
		t.Fatalf("exit jumps %q", ExitJumps)
	}
}

func edgeLines(family int) []string {
	pool := map[int]string{4: "10.88.0.0/16", 6: "fd88:88::/64"}[family]
	return []string{"-A KRY-EDGE -i kry0 -j RETURN", "-A KRY-EDGE -i lo -j RETURN", "-A KRY-EDGE -i docker0 -j RETURN", "-A KRY-EDGE -i br-+ -j RETURN", "-A KRY-EDGE -d " + pool + " -j DROP"}
}
