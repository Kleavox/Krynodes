package network

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

const (
	InChain      = "KRY-IN"
	ForwardChain = "KRY-FWD"
	ExitChain    = "KRY-EXIT"
	EdgeChain    = "KRY-EDGE"
	DockerUser   = "DOCKER-USER"
	allProtocols = "all"
	pool6        = "fd88:88::/64"
	multiports   = 15
)

var (
	uplinkName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	edgeInside = []string{Interface, "lo", "docker0", "br-+"}
	private    = map[int][]string{
		4: {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "0.0.0.0/8"},
		6: {"fc00::/7", "fe80::/10"},
	}
)

type Grant struct {
	Source   string
	Source6  string
	Protocol string
	Ports    []string
}

var ExitJumps = [][]string{
	{"FORWARD", "-i", Interface, "!", "-o", Interface, "-j", ExitChain},
	{"FORWARD", "!", "-i", Interface, "-o", Interface, "-j", ExitChain},
}

func Jumps() [][]string {
	return [][]string{
		{"INPUT", "-j", EdgeChain},
		{"INPUT", "-i", Interface, "-j", InChain},
		{"FORWARD", "-i", Interface, "-o", Interface, "-j", "DROP"},
		{"FORWARD", "-i", Interface, "-j", ForwardChain},
		{DockerUser, "-i", Interface, "-j", ForwardChain},
	}
}

func EnsureDockerUser(ctx context.Context, run Runner, tool string) error {
	if _, _, err := run(ctx, tool, "-w", "-N", DockerUser); err == nil {
		return nil
	}
	if output, _, err := run(ctx, tool, "-w", "-S", DockerUser); err != nil {
		return fmt.Errorf("%s cannot make the %s chain: %s", tool, DockerUser, strings.TrimSpace(string(output)))
	}
	return nil
}

func memberOf(document Document, self string) (Member, bool) {
	for _, member := range document.Members {
		if member.Node == self {
			return member, true
		}
	}
	return Member{}, false
}

func targets(rule Rule, self Member) bool {
	return rule.To.Node == self.Node || rule.To.Group == serversGroup
}

func sources(rule Rule, members []Member, self Member) []Member {
	var found []Member
	for _, member := range members {
		if member.Cut || member.Node == self.Node {
			continue
		}
		switch {
		case rule.From.Node != "":
			if member.Node == rule.From.Node {
				found = append(found, member)
			}
		case rule.From.Group == laptopsGroup && member.IsLaptop(), rule.From.Group == serversGroup && !member.IsLaptop():
			found = append(found, member)
		}
	}
	return found
}

func byProtocol(ports Ports) []Grant {
	if ports.All {
		return []Grant{{Protocol: allProtocols}}
	}
	var grants []Grant
	for _, protocol := range []string{"tcp", "udp"} {
		grant := Grant{Protocol: protocol}
		for _, text := range ports.List {
			if number, found, _ := strings.Cut(text, "/"); found == protocol {
				grant.Ports = append(grant.Ports, strings.Replace(number, "-", ":", 1))
			}
		}
		if grant.Ports != nil {
			grants = append(grants, grant)
		}
	}
	return grants
}

func Allowed(document Document, self string) []Grant {
	me, ok := memberOf(document, self)
	if !ok || me.Cut || me.IsLaptop() {
		return nil
	}
	var grants []Grant
	for _, rule := range document.Allow {
		if !targets(rule, me) {
			continue
		}
		for _, source := range sources(rule, document.Members, me) {
			for _, grant := range byProtocol(rule.Ports) {
				grant.Source, grant.Source6 = source.Address, Address6(source.Address)
				grants = append(grants, grant)
			}
		}
	}
	return grants
}

func multiport(ports []string) [][]string {
	var chunks [][]string
	weight := multiports
	for _, port := range ports {
		cost := 1 + strings.Count(port, ":")
		if weight+cost > multiports {
			chunks = append(chunks, nil)
			weight = 0
		}
		chunks[len(chunks)-1] = append(chunks[len(chunks)-1], port)
		weight += cost
	}
	return chunks
}

func host(address string, family int) string {
	parsed, err := netip.ParseAddr(address)
	if err != nil || !parsed.Is4() {
		return ""
	}
	if family == 6 {
		if address = Address6(address); address == "" {
			return ""
		}
		return address + "/128"
	}
	return address + "/32"
}

func RenderRules(document Document, self string, dropped []string, family int, uplink string) string {
	icmp, mask, network := "-s "+pool.String()+" -p icmp --icmp-type echo-request", "/32", pool.String()
	if family == 6 {
		icmp, mask, network = "-s "+pool6+" -p ipv6-icmp --icmpv6-type echo-request", "/128", pool6
	}
	var edge, exit, stopped []string
	for _, inside := range edgeInside {
		edge = append(edge, "-A "+EdgeChain+" -i "+inside+" -j RETURN")
	}
	edge = append(edge, "-A "+EdgeChain+" -d "+network+" -j DROP")
	if uplinkName.MatchString(uplink) {
		if me, ok := memberOf(document, self); ok {
			exit, _ = Exit(me, document.Members, uplink, family)
		}
	}
	in := []string{"-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"}
	forward := []string{"-o " + Interface + " -j DROP", "-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN"}
	for _, address := range dropped {
		if source := host(address, family); source != "" {
			in = append(in, "-s "+source+" -j DROP")
			forward = append(forward, "-s "+source+" -j DROP")
			stopped = append(stopped, "-A "+ExitChain+" -s "+source+" -j DROP")
		}
	}
	if exit != nil {
		exit = append(stopped, exit...)
	}
	in = append(in, icmp+" -j ACCEPT")
	forward = append(forward, "-j "+ExitChain)
	for _, grant := range Allowed(document, self) {
		source := grant.Source
		if family == 6 {
			source = grant.Source6
		}
		if source == "" {
			continue
		}
		source = "-s " + source + mask
		if grant.Protocol == allProtocols {
			in = append(in, source+" -j ACCEPT")
			forward = append(forward, source+" -m conntrack --ctstate DNAT -j RETURN")
			continue
		}
		for _, chunk := range multiport(grant.Ports) {
			in = append(in, fmt.Sprintf("%s -p %s -m multiport --dports %s -j ACCEPT", source, grant.Protocol, strings.Join(chunk, ",")))
		}
		for _, port := range grant.Ports {
			forward = append(forward, fmt.Sprintf("%s -p %s -m conntrack --ctstate DNAT --ctorigdstport %s -j RETURN", source, grant.Protocol, port))
		}
	}
	var body strings.Builder
	body.WriteString("*filter\n:" + InChain + " - [0:0]\n:" + ForwardChain + " - [0:0]\n:" + ExitChain + " - [0:0]\n:" + EdgeChain + " - [0:0]\n")
	for _, line := range append(in, "-j DROP") {
		body.WriteString("-A " + InChain + " " + line + "\n")
	}
	for _, line := range append(forward, "-j DROP") {
		body.WriteString("-A " + ForwardChain + " " + line + "\n")
	}
	for _, line := range append(edge, exit...) {
		body.WriteString(line + "\n")
	}
	body.WriteString("COMMIT\n")
	return body.String()
}

func Exit(self Member, members []Member, uplink string, family int) ([]string, []string) {
	if !self.Exit || self.Cut || self.NAT || self.IsLaptop() || (family != 4 && family != 6) || !uplinkName.MatchString(uplink) {
		return nil, nil
	}
	var forward []string
	for _, destination := range private[family] {
		forward = append(forward, fmt.Sprintf("-A %s -i %s -o %s -d %s -j DROP", ExitChain, Interface, uplink, destination))
	}
	forward = append(forward, fmt.Sprintf("-A %s -i %s -o %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", ExitChain, uplink, Interface))
	var nat []string
	for _, laptop := range Laptops(members) {
		source := laptop.Address + "/32"
		if family == 6 {
			source = Address6(laptop.Address) + "/128"
		}
		forward = append(forward, fmt.Sprintf("-A %s -s %s -i %s -o %s -j ACCEPT", ExitChain, source, Interface, uplink))
		nat = append(nat, fmt.Sprintf("-A POSTROUTING -s %s -o %s -j MASQUERADE", source, uplink))
	}
	forward = append(forward, fmt.Sprintf("-A %s -i %s -o %s -j DROP", ExitChain, Interface, uplink), fmt.Sprintf("-A %s -i %s -o %s -j DROP", ExitChain, uplink, Interface))
	for _, bridge := range []string{"docker0", "br-+"} {
		forward = append(forward, fmt.Sprintf("-A %s -i %s -o %s -j RETURN", ExitChain, bridge, Interface))
	}
	return append(forward, fmt.Sprintf("-A %s ! -i %s -o %s -m conntrack ! --ctstate RELATED,ESTABLISHED -j DROP", ExitChain, Interface, Interface)), nat
}
