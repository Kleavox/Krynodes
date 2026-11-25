package stacks

import (
	"context"
	"errors"
	"fmt"
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
	guardTools = []string{"iptables", "ip6tables"}
	ipv6Off    = func() bool {
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

func ensure(ctx context.Context, run docker.Runner, tool string, add []string, chain string, rule ...string) error {
	if _, err := firewall(ctx, run, tool, append([]string{"-C", chain}, rule...)...); err == nil {
		return nil
	}
	if output, err := firewall(ctx, run, tool, append(slices.Clone(add), rule...)...); err != nil {
		said := clip(string(output), maxComposeError)
		if said == "" {
			said = err.Error()
		}
		return fmt.Errorf("%s %s: %s", tool, chain, said)
	}
	return nil
}

func Guard(ctx context.Context, run docker.Runner) error {
	tools := guardTools
	if ipv6Off() {
		tools = guardTools[:1]
	}
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
	drops := []struct {
		tool  string
		match []string
	}{
		{"iptables", []string{"-d", "169.254.0.0/16"}},
		{"iptables", []string{"-d", "100.100.100.200"}},
		{"ip6tables", []string{"-d", "fd00:ec2::254"}},
		{"iptables", []string{"-d", meshRanges[0].String()}},
		{"ip6tables", []string{"-d", meshRanges[1].String()}},
		{"iptables", []string{"-m", "conntrack", "--ctstate", "DNAT", "--ctorigdst", meshRanges[0].String()}},
		{"ip6tables", []string{"-m", "conntrack", "--ctstate", "DNAT", "--ctorigdst", meshRanges[1].String()}},
	}
	for _, drop := range drops {
		if slices.Contains(tools, drop.tool) {
			rule := append(append([]string{"-i", bridges}, drop.match...), "-j", "DROP")
			problems[drop.tool] = append(problems[drop.tool], ensure(ctx, run, drop.tool, []string{"-I", dockerUser, "1"}, dockerUser, rule...))
		}
	}
	ip6 := errors.Join(problems["ip6tables"]...)
	if ip6 != nil {
		ip6 = fmt.Errorf("IPv6 is on but ip6tables does not work, so Contained stacks cannot be kept off the server over IPv6: %w", ip6)
	}
	return errors.Join(errors.Join(problems["iptables"]...), ip6)
}

func Unguard(ctx context.Context, run docker.Runner) {
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
		for line := range strings.SplitSeq(string(listed), "\n") {
			rule, found := strings.CutPrefix(strings.TrimSpace(line), "-A "+dockerUser+" ")
			fields := strings.Fields(rule)
			if found && strings.HasSuffix(rule, "-j DROP") && slices.Contains(fields, bridges) {
				firewall(ctx, run, tool, append([]string{"-D", dockerUser}, fields...)...)
			}
		}
	}
}
