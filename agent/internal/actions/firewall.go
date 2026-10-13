package actions

import (
	"context"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/recipes"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

var inputPolicy = regexp.MustCompile(`(?m)^\s*DEFAULT_INPUT_POLICY\s*=\s*"?(\w+)"?\s*$`)

type openPort struct {
	low, high int
	protocol  string
}

func (p openPort) lets(port int, protocol string) bool {
	return port >= p.low && port <= p.high && (p.protocol == "any" || p.protocol == protocol)
}

func (e Executor) routeInterfaces() []string {
	var names []string
	add := func(name string) {
		if name != "" && name != "lo" && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	if body, err := os.ReadFile(e.path("/proc/net/route")); err == nil {
		for line := range strings.SplitSeq(string(body), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 7 && fields[1] == "00000000" && fields[7] == "00000000" {
				add(fields[0])
			}
		}
	}
	if body, err := os.ReadFile(e.path("/proc/net/ipv6_route")); err == nil {
		for line := range strings.SplitSeq(string(body), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 10 && strings.Trim(fields[0], "0") == "" && fields[1] == "00" {
				add(fields[9])
			}
		}
	}
	return names
}

func portRanges(text, separator string) []openPort {
	var open []openPort
	for item := range strings.SplitSeq(text, ",") {
		low, high, ranged := strings.Cut(item, separator)
		if !ranged {
			high = low
		}
		from, errLow := strconv.Atoi(low)
		to, errHigh := strconv.Atoi(high)
		if errLow == nil && errHigh == nil && from <= to {
			open = append(open, openPort{low: from, high: to})
		}
	}
	return open
}

func (e Executor) ufwOpen() []openPort {
	policy, _ := os.ReadFile(e.path("/etc/default/ufw"))
	if match := inputPolicy.FindSubmatch(policy); match != nil && strings.EqualFold(string(match[1]), "ACCEPT") {
		return []openPort{{low: 0, high: 65535, protocol: "any"}}
	}
	routed := e.routeInterfaces()
	var open []openPort
	for _, file := range []string{"/etc/ufw/user.rules", "/etc/ufw/user6.rules"} {
		body, err := os.ReadFile(e.path(file))
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(body), "\n") {
			rest, ok := strings.CutPrefix(strings.TrimSpace(line), "### tuple ### ")
			if !ok {
				continue
			}
			fields := slices.DeleteFunc(strings.Fields(rest), func(field string) bool {
				return strings.HasPrefix(field, "comment=")
			})
			if len(fields) != 7 && len(fields) != 9 {
				continue
			}
			action, _, _ := strings.Cut(fields[0], "_")
			protocol, ports, sourcePort, source, direction := fields[1], fields[2], fields[4], fields[5], fields[len(fields)-1]
			if action != "allow" && action != "limit" {
				continue
			}
			if sourcePort != "any" || (source != "0.0.0.0/0" && source != "::/0") {
				continue
			}
			if direction != "in" {
				iface, bound := strings.CutPrefix(direction, "in_")
				if !bound || !slices.Contains(routed, iface) {
					continue
				}
			}
			if protocol != "any" && protocol != "tcp" && protocol != "udp" {
				continue
			}
			ranges := []openPort{{low: 0, high: 65535}}
			if ports != "any" {
				ranges = portRanges(ports, ":")
			}
			for _, item := range ranges {
				item.protocol = protocol
				open = append(open, item)
			}
		}
	}
	return open
}

func infoField(output, name string) []string {
	for line := range strings.SplitSeq(output, "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), name+":"); ok {
			return strings.Fields(value)
		}
	}
	return nil
}

func firewalldPorts(entries []string) []openPort {
	var open []openPort
	for _, entry := range entries {
		ports, protocol, ok := strings.Cut(entry, "/")
		if !ok {
			continue
		}
		for _, item := range portRanges(ports, "-") {
			item.protocol = protocol
			open = append(open, item)
		}
	}
	return open
}

func (e Executor) firewalldOpen(ctx context.Context) []openPort {
	zone := ""
	if routed := e.routeInterfaces(); len(routed) > 0 {
		zone, _ = e.output(ctx, "firewall-cmd", "--get-zone-of-interface="+routed[0])
	}
	if zone = strings.TrimSpace(zone); zone == "" {
		zone, _ = e.output(ctx, "firewall-cmd", "--get-default-zone")
		zone = strings.TrimSpace(zone)
	}
	info, _ := e.output(ctx, "firewall-cmd", "--info-zone="+zone)
	if slices.Contains(infoField(info, "target"), "ACCEPT") {
		return []openPort{{low: 0, high: 65535, protocol: "any"}}
	}
	open := firewalldPorts(infoField(info, "ports"))
	for _, service := range infoField(info, "services") {
		described, _ := e.output(ctx, "firewall-cmd", "--info-service="+service)
		open = append(open, firewalldPorts(infoField(described, "ports"))...)
	}
	return open
}

type firewallState struct {
	active    bool
	tool      string
	firewalld bool
}

func (e Executor) firewallOf(ctx context.Context, family recipes.Family) firewallState {
	ufw, _ := os.ReadFile(e.path("/etc/ufw/ufw.conf"))
	state := firewallState{active: ufwEnabled.Match(ufw), tool: "ufw"}
	if family == recipes.RHEL {
		state.tool = "firewalld"
		running, _ := e.output(ctx, "firewall-cmd", "--state")
		state.firewalld = strings.TrimSpace(running) == "running"
		state.active = state.active || state.firewalld
	}
	return state
}

func (e Executor) throughFirewall(ctx context.Context, state firewallState, listeners []reporter.Listener) []reporter.Listener {
	if !state.active {
		return listeners
	}
	open := e.ufwOpen()
	if state.firewalld {
		open = e.firewalldOpen(ctx)
	}
	return slices.DeleteFunc(listeners, func(listener reporter.Listener) bool {
		return !slices.ContainsFunc(open, func(port openPort) bool {
			return port.lets(listener.Port, listener.Protocol)
		})
	})
}
