package stacks

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/docker"
)

const (
	containChain = "KRY-CONTAINED"
	dockerUser   = "DOCKER-USER"
	bridges      = "krc+"
	guardTimeout = 15 * time.Second
)

var (
	guardTools    = []string{"iptables", "ip6tables"}
	GuardLock     = "/run/krynodes-guard.lock"
	resolvConf    = "/etc/resolv.conf"
	resolvSystemd = "/run/systemd/resolve/resolv.conf"
	systemdStub   = netip.MustParseAddr("127.0.0.53")
	ipv6Off       = func() bool {
		if raw, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6"); err == nil && strings.TrimSpace(string(raw)) == "1" {
			return true
		}
		_, err := os.Stat("/proc/net/if_inet6")
		return errors.Is(err, os.ErrNotExist)
	}
)

func firewall(ctx context.Context, run docker.Runner, tool string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, guardTimeout)
	defer cancel()
	output, _, err := run(ctx, tool, append([]string{"-w"}, args...)...)
	return output, err
}

var (
	returns = [][]string{
		{"-i", bridges, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN"},
		{"-i", bridges, "-o", bridges, "-j", "RETURN"},
	}
	drops = []struct {
		tool  string
		match []string
	}{
		{"iptables", []string{"-d", "10.0.0.0/8"}},
		{"iptables", []string{"-d", "172.16.0.0/12"}},
		{"iptables", []string{"-d", "192.168.0.0/16"}},
		{"iptables", []string{"-d", "100.64.0.0/10"}},
		{"iptables", []string{"-d", "169.254.0.0/16"}},
		{"iptables", []string{"-d", "198.18.0.0/15"}},
		{"iptables", []string{"-d", "100.100.100.200"}},
		{"iptables", []string{"-d", meshRanges[0].String()}},
		{"iptables", []string{"-m", "conntrack", "--ctstate", "DNAT", "--ctorigdst", meshRanges[0].String()}},
		{"ip6tables", []string{"-d", "fc00::/7"}},
		{"ip6tables", []string{"-d", "fe80::/10"}},
		{"ip6tables", []string{"-d", "fd00:ec2::254"}},
		{"ip6tables", []string{"-d", meshRanges[1].String()}},
		{"ip6tables", []string{"-m", "conntrack", "--ctstate", "DNAT", "--ctorigdst", meshRanges[1].String()}},
	}
)

func refused(tool, chain string, output []byte, err error) error {
	said := clip(string(output), maxComposeError)
	if said == "" {
		said = err.Error()
	}
	return fmt.Errorf("%s %s: %s", tool, chain, said)
}

func ensure(ctx context.Context, run docker.Runner, tool string, add []string, chain string, rule ...string) error {
	if _, err := firewall(ctx, run, tool, append([]string{"-C", chain}, rule...)...); err == nil {
		return nil
	}
	if output, err := firewall(ctx, run, tool, append(slices.Clone(add), rule...)...); err != nil {
		return refused(tool, chain, output, err)
	}
	return nil
}

func nameserversIn(path string) []netip.Addr {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var found []netip.Addr
	for line := range strings.SplitSeq(string(raw), "\n") {
		if cut := strings.IndexAny(line, "#;"); cut >= 0 {
			line = line[:cut]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if addr, err := netip.ParseAddr(fields[1]); err == nil {
			if addr = addr.WithZone("").Unmap(); !slices.Contains(found, addr) {
				found = append(found, addr)
			}
		}
	}
	return found
}

func resolvers() []netip.Addr {
	found := nameserversIn(resolvConf)
	if len(found) == 1 && found[0] == systemdStub {
		found = nameserversIn(resolvSystemd)
	}
	return found
}

func dropped(tool string, addr netip.Addr) bool {
	for _, drop := range drops {
		if drop.tool != tool || drop.match[0] != "-d" {
			continue
		}
		to, err := netip.ParsePrefix(drop.match[1])
		if err != nil {
			single := netip.MustParseAddr(drop.match[1])
			to = netip.PrefixFrom(single, single.BitLen())
		}
		if to.Contains(addr) {
			return true
		}
	}
	return false
}

func argvOf(key string) []string {
	switch key {
	case "established":
		return returns[0]
	case "bridge":
		return returns[1]
	}
	proto, addr, _ := strings.Cut(key, " ")
	return []string{"-i", bridges, "-d", addr, "-p", proto, "--dport", "53", "-j", "RETURN"}
}

func resolverReturns(tool string, servers []netip.Addr) [][]string {
	var rules [][]string
	for _, server := range servers {
		if server.IsLoopback() || server.Is4() != (tool == "iptables") || !dropped(tool, server) || slices.ContainsFunc(meshRanges, func(mesh netip.Prefix) bool { return mesh.Contains(server) }) {
			continue
		}
		for _, proto := range []string{"udp", "tcp"} {
			rules = append(rules, argvOf(proto+" "+server.String()))
		}
	}
	return rules
}

type ruleParts struct {
	in, out, jump, proto, dport, to, from string
	matches, states                       []string
}

func ruleShape(text string) (ruleParts, bool) {
	var found ruleParts
	fields := strings.Fields(text)
	for at := 0; at < len(fields); at += 2 {
		if at+1 >= len(fields) {
			return found, false
		}
		value := fields[at+1]
		switch fields[at] {
		case "-i", "--in-interface":
			found.in = value
		case "-o", "--out-interface":
			found.out = value
		case "-j", "--jump":
			found.jump = value
		case "-p", "--protocol":
			found.proto = value
		case "-d", "--destination":
			found.to = value
		case "-s", "--source":
			found.from = value
		case "-m", "--match":
			found.matches = append(found.matches, value)
		case "--ctstate", "--state":
			found.states = strings.Split(value, ",")
		case "--dport", "--destination-port":
			found.dport = value
		default:
			return found, false
		}
	}
	return found, true
}

func ownKey(text string) (string, bool) {
	found, ok := ruleShape(text)
	if !ok || found.in != bridges || found.jump != "RETURN" || found.from != "" {
		return "", false
	}
	only := func(allowed ...string) bool {
		return !slices.ContainsFunc(found.matches, func(module string) bool { return !slices.Contains(allowed, module) })
	}
	states := slices.Sorted(slices.Values(found.states))
	switch {
	case found.out == "" && found.to == "" && found.proto == "" && found.dport == "" && slices.Equal(states, []string{"ESTABLISHED", "RELATED"}) && only("conntrack", "state"):
		return "established", true
	case found.out == bridges && found.to == "" && found.proto == "" && found.dport == "" && len(states) == 0 && len(found.matches) == 0:
		return "bridge", true
	case found.out == "" && found.dport == "53" && found.proto != "" && len(states) == 0 && only(found.proto):
		to, err := netip.ParsePrefix(found.to)
		if err != nil {
			single, err := netip.ParseAddr(found.to)
			if err != nil {
				return "", false
			}
			to = netip.PrefixFrom(single, single.BitLen())
		}
		if to.Bits() != to.Addr().BitLen() {
			return "", false
		}
		return found.proto + " " + to.Addr().String(), true
	}
	return "", false
}

func dockerUserRules(listed []byte) []string {
	var rules []string
	for line := range strings.SplitSeq(string(listed), "\n") {
		if rule, found := strings.CutPrefix(strings.TrimSpace(line), "-A "+dockerUser+" "); found {
			rules = append(rules, strings.Join(strings.Fields(rule), " "))
		}
	}
	return rules
}

func ownKeys(rules []string) []string {
	found := make([]string, len(rules))
	for index, rule := range rules {
		found[index], _ = ownKey(rule)
	}
	return found
}

func resolverKeys(rules [][]string) []string {
	found := ownKeys(joined(rules))
	slices.Sort(found)
	return found
}

func joined(rules [][]string) []string {
	found := make([]string, len(rules))
	for index, rule := range rules {
		found[index] = strings.Join(rule, " ")
	}
	return found
}

func onTop(rules []string, want []string) bool {
	keys := ownKeys(rules)
	top := 2 + len(want)
	if len(keys) < top || keys[0] != "established" || keys[1] != "bridge" {
		return false
	}
	head := slices.Sorted(slices.Values(keys[2:top]))
	return slices.Equal(head, want) && !slices.ContainsFunc(keys[top:], func(key string) bool { return key != "" })
}

func readDockerUser(ctx context.Context, run docker.Runner, tool string) ([]string, error) {
	listed, err := firewall(ctx, run, tool, "-S", dockerUser)
	if err != nil {
		return nil, refused(tool, dockerUser, listed, err)
	}
	return dockerUserRules(listed), nil
}

func ours(rules []string) int {
	return len(rules) - len(slices.DeleteFunc(ownKeys(rules), func(key string) bool { return key != "" }))
}

var errNotOnTop = errors.New("the rules that let replies and same-bridge traffic through are not above the drops after the repair")

func topOfDockerUser(ctx context.Context, run docker.Runner, tool string, resolver [][]string) error {
	err := repairDockerUser(ctx, run, tool, resolver)
	if errors.Is(err, errNotOnTop) {
		err = repairDockerUser(ctx, run, tool, resolver)
	}
	return err
}

func repairDockerUser(ctx context.Context, run docker.Runner, tool string, resolver [][]string) error {
	want := resolverKeys(resolver)
	rules, err := readDockerUser(ctx, run, tool)
	if err != nil {
		return err
	}
	if onTop(rules, want) {
		return nil
	}
	for range len(rules) {
		at := slices.IndexFunc(ownKeys(rules), func(key string) bool { return key != "" })
		if at < 0 {
			break
		}
		before := ours(rules)
		key, _ := ownKey(rules[at])
		output, failed := firewall(ctx, run, tool, append([]string{"-D", dockerUser}, argvOf(key)...)...)
		if failed != nil {
			output, failed = firewall(ctx, run, tool, append([]string{"-D", dockerUser}, strings.Fields(rules[at])...)...)
		}
		if rules, err = readDockerUser(ctx, run, tool); err != nil {
			return err
		}
		if failed != nil && ours(rules) >= before {
			return refused(tool, dockerUser, output, failed)
		}
	}
	if ours(rules) > 0 {
		return fmt.Errorf("%s %s: the rules that let replies and same-bridge traffic through could not all be taken away", tool, dockerUser)
	}
	block := append(slices.Clone(returns), resolver...)
	for index := len(block) - 1; index >= 0; index-- {
		if output, err := firewall(ctx, run, tool, append([]string{"-I", dockerUser, "1"}, block[index]...)...); err != nil {
			return refused(tool, dockerUser, output, err)
		}
	}
	if rules, err = readDockerUser(ctx, run, tool); err != nil {
		return err
	}
	if !onTop(rules, want) {
		return fmt.Errorf("%s %s: %w", tool, dockerUser, errNotOnTop)
	}
	return nil
}

func Guard(ctx context.Context, run docker.Runner) error {
	unlock, err := lockGuard(ctx)
	if err != nil {
		return fmt.Errorf("another pass of the guard is still running: %w", err)
	}
	defer unlock()
	tools := guardTools
	if ipv6Off() {
		tools = guardTools[:1]
	}
	servers := resolvers()
	problems := map[string][]error{}
	for _, tool := range tools {
		firewall(ctx, run, tool, "-N", containChain)
		problems[tool] = append(problems[tool],
			ensure(ctx, run, tool, []string{"-A", containChain}, containChain, "-j", "DROP"),
			ensure(ctx, run, tool, []string{"-I", containChain, "1"}, containChain, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"),
			ensure(ctx, run, tool, []string{"-I", "INPUT", "1"}, "INPUT", "-i", bridges, "-j", containChain),
		)
		firewall(ctx, run, tool, "-N", dockerUser)
	}
	for _, drop := range drops {
		if slices.Contains(tools, drop.tool) {
			rule := append(append([]string{"-i", bridges}, drop.match...), "-j", "DROP")
			problems[drop.tool] = append(problems[drop.tool], ensure(ctx, run, drop.tool, []string{"-I", dockerUser, "1"}, dockerUser, rule...))
		}
	}
	for _, tool := range tools {
		problems[tool] = append(problems[tool], topOfDockerUser(ctx, run, tool, resolverReturns(tool, servers)))
	}
	ip6 := errors.Join(problems["ip6tables"]...)
	if ip6 != nil {
		ip6 = fmt.Errorf("IPv6 is on but ip6tables does not work, so Contained stacks cannot be kept off the server over IPv6: %w", ip6)
	}
	return errors.Join(errors.Join(problems["iptables"]...), ip6)
}

func Unguard(ctx context.Context, run docker.Runner) {
	if unlock, err := lockGuard(ctx); err == nil {
		defer unlock()
	}
	jump := []string{"INPUT", "-i", bridges, "-j", containChain}
	for _, tool := range guardTools {
		for range 8 {
			if _, err := firewall(ctx, run, tool, append([]string{"-C"}, jump...)...); err != nil {
				break
			}
			if _, err := firewall(ctx, run, tool, append([]string{"-D"}, jump...)...); err != nil {
				break
			}
		}
		firewall(ctx, run, tool, "-F", containChain)
		firewall(ctx, run, tool, "-X", containChain)
		listed, _ := firewall(ctx, run, tool, "-S", dockerUser)
		for _, rule := range dockerUserRules(listed) {
			fields := strings.Fields(rule)
			if (strings.HasSuffix(rule, "-j DROP") || strings.HasSuffix(rule, "-j RETURN")) && slices.Contains(fields, bridges) {
				firewall(ctx, run, tool, append([]string{"-D", dockerUser}, fields...)...)
			}
		}
	}
}
