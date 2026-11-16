package actions

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

const (
	laptopExitConf = "/etc/sysctl.d/99-krynodes-laptop-exit.conf"
	exitSyncMark   = "exit-sync"
	noUplinkMark   = "no-uplink"
)

var (
	laptopPools   = []netip.Prefix{netip.MustParsePrefix("10.88.0.0/16"), netip.MustParsePrefix("fd88:88::/64")}
	interfaceName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	relayJumps    = [][]string{{"-i", network.Interface, "-o", network.Interface, "-j", network.RelayChain}}
	exitJumps     = [][]string{{"-i", network.Interface, "!", "-o", network.Interface, "-j", network.ExitChain}, {"!", "-i", network.Interface, "-o", network.Interface, "-j", network.ExitChain}}
	exitTools     = []string{"iptables", "ip6tables"}
	routing       = map[string]string{"iptables": "/proc/sys/net/ipv4/ip_forward", "ip6tables": "/proc/sys/net/ipv6/conf/all/forwarding"}
)

type exitPlan struct {
	relay   []string
	forward map[string][]string
	nat     map[string][]string
	routes  map[string]bool
	ra      string
	sysctl  string
}

func (p exitPlan) exit6() bool {
	return p.forward["ip6tables"] != nil
}

func (e Executor) planExit(ctx context.Context, document network.Document, self network.Member, held func() bool) exitPlan {
	plan := exitPlan{forward: map[string][]string{}, nat: map[string][]string{}, routes: map[string]bool{}}
	if len(network.Laptops(document.Members)) > 0 {
		plan.relay = network.Relay(self, document.Members)
		plan.routes["iptables"] = plan.relay != nil && slices.ContainsFunc(document.Members, func(other network.Member) bool { return other.NAT && !other.Cut && !other.IsLaptop() })
	}
	missing := false
	if self.Exit && !held() {
		uplink := e.uplink(ctx, "-4")
		missing = uplink == ""
		if uplink != "" {
			plan.forward["iptables"], plan.nat["iptables"] = network.Exit(self, document.Members, uplink, 4)
		}
		if uplink6 := e.uplink(ctx, "-6"); uplink6 != "" {
			plan.forward["ip6tables"], plan.nat["ip6tables"] = network.Exit(self, document.Members, uplink6, 6)
			if plan.exit6() {
				plan.ra = e.keepsRA(uplink6)
			}
		}
	}
	e.noteUplink(missing)
	plan.routes["iptables"] = plan.routes["iptables"] || plan.forward["iptables"] != nil
	plan.routes["ip6tables"] = plan.exit6()
	if plan.ra != "" {
		key := "net.ipv6.conf." + plan.ra + ".accept_ra"
		if strings.Contains(plan.ra, ".") {
			key = "net/ipv6/conf/" + plan.ra + "/accept_ra"
		}
		plan.sysctl = key + " = 2\n"
	}
	return plan
}

func (e Executor) exitState(ctx context.Context, held func() bool) (exitPlan, bool) {
	record := e.readNetwork()
	node, err := e.selfNode()
	if !record.Joined || record.Document == nil || err != nil {
		return exitPlan{}, false
	}
	self, ok := member(*record.Document, node)
	if !ok {
		return exitPlan{}, false
	}
	return e.planExit(ctx, *record.Document, self, held), true
}

func (e Executor) uplink(ctx context.Context, family string) string {
	output, _ := e.output(ctx, "ip", family, "route", "show", "default")
	line, _, _ := strings.Cut(output, "\n")
	fields := strings.Fields(line)
	index := slices.Index(fields, "dev")
	if len(fields) == 0 || fields[0] != "default" || index < 0 || index+1 >= len(fields) || !interfaceName.MatchString(fields[index+1]) || fields[index+1] == network.Interface {
		return ""
	}
	return fields[index+1]
}

func (e Executor) noteUplink(missing bool) {
	mark := filepath.Join(e.networkDir(), noUplinkMark)
	_, err := os.Stat(mark)
	switch {
	case missing && err != nil:
		log.Printf("the exit node for laptops is on, but this server has no IPv4 default route to send their traffic out of")
		if err := writeWhole(e.networkDir(), noUplinkMark, nil, 0o600); err != nil {
			log.Printf("laptop exit: %v", err)
		}
	case !missing && err == nil:
		os.Remove(mark)
	}
}

func (e Executor) keepsRA(uplink string) string {
	current, _ := os.ReadFile(e.path("/proc/sys/net/ipv6/conf/" + uplink + "/accept_ra"))
	if value := strings.TrimSpace(string(current)); value == "1" || value == "2" {
		return uplink
	}
	return ""
}

func (e Executor) syncRelayExit(ctx context.Context, plan exitPlan) error {
	problems := e.syncForward(ctx, "iptables", network.RelayChain, relayJumps, plan.relay)
	for _, tool := range exitTools {
		problems = errors.Join(problems, e.syncForward(ctx, tool, network.ExitChain, exitJumps, plan.forward[tool]), e.syncNAT(ctx, tool, plan.nat[tool]))
	}
	return errors.Join(problems, e.switchForwarding(ctx, plan))
}

func (e Executor) switchForwarding(ctx context.Context, plan exitPlan) error {
	var problems error
	for _, tool := range exitTools {
		if !plan.routes[tool] {
			continue
		}
		if tool == "ip6tables" && plan.ra != "" {
			path := e.path("/proc/sys/net/ipv6/conf/" + plan.ra + "/accept_ra")
			current, err := os.ReadFile(path)
			if err == nil && strings.TrimSpace(string(current)) != "2" {
				err = os.WriteFile(path, []byte("2"), 0o644)
			}
			if err != nil {
				problems = errors.Join(problems, fmt.Errorf("keep router advertisements on %s, so IPv6 forwarding stays as it was: %w", plan.ra, err))
				continue
			}
		}
		path := e.path(routing[tool])
		current, err := os.ReadFile(path)
		if err != nil || strings.TrimSpace(string(current)) == "1" {
			problems = errors.Join(problems, err)
			continue
		}
		if err := e.firewall(ctx, tool, "-P", "FORWARD", "DROP"); err != nil {
			problems = errors.Join(problems, fmt.Errorf("%s FORWARD policy: %w", tool, err))
			continue
		}
		problems = errors.Join(problems, os.WriteFile(path, []byte("1"), 0o644))
	}
	return problems
}

func (e Executor) syncForward(ctx context.Context, tool, chain string, jumps [][]string, rules []string) error {
	current := e.listed(ctx, tool, chain)
	if rules == nil {
		if !strings.HasPrefix(current, "-N "+chain) {
			return nil
		}
		for line := range strings.SplitSeq(e.listed(ctx, tool, "FORWARD"), "\n") {
			if rule, found := strings.CutPrefix(line, "-A FORWARD "); found && strings.HasSuffix(rule, "-j "+chain) {
				e.firewall(ctx, tool, append([]string{"-D", "FORWARD"}, strings.Fields(rule)...)...)
			}
		}
		e.firewall(ctx, tool, "-F", chain)
		if err := e.firewall(ctx, tool, "-X", chain); err != nil {
			return fmt.Errorf("remove %s from %s: %w", chain, tool, err)
		}
		return nil
	}
	if current != strings.Join(append([]string{"-N " + chain}, rules...), "\n") {
		name := chain + "." + tool
		restore := "*filter\n:" + chain + " - [0:0]\n" + strings.Join(rules, "\n") + "\nCOMMIT\n"
		if err := writeWhole(e.networkDir(), name, []byte(restore), 0o600); err != nil {
			return err
		}
		if err := e.firewall(ctx, tool+"-restore", "--noflush", filepath.Join(e.networkDir(), name)); err != nil {
			return fmt.Errorf("write %s in %s: %w", chain, tool, err)
		}
	}
	var problems error
	for _, jump := range jumps {
		problems = errors.Join(problems, e.ensure(ctx, tool, []string{"-I", "FORWARD", "1"}, "FORWARD", jump))
	}
	return problems
}

func laptopMasquerade(line string) bool {
	fields := strings.Fields(line)
	if len(fields) != 8 || fields[0] != "-A" || fields[1] != "POSTROUTING" || fields[2] != "-s" || fields[4] != "-o" || fields[6] != "-j" || fields[7] != "MASQUERADE" {
		return false
	}
	prefix, err := netip.ParsePrefix(fields[3])
	return err == nil && prefix.IsSingleIP() && slices.ContainsFunc(laptopPools, func(pool netip.Prefix) bool { return pool.Contains(prefix.Addr()) })
}

func (e Executor) syncNAT(ctx context.Context, tool string, wanted []string) error {
	text, _ := e.output(ctx, tool, "-t", "nat", "-S", "POSTROUTING")
	var current []string
	var problems error
	for line := range strings.SplitSeq(text, "\n") {
		if line = strings.TrimSpace(line); !laptopMasquerade(line) {
			continue
		}
		current = append(current, line)
		if !slices.Contains(wanted, line) {
			problems = errors.Join(problems, e.firewall(ctx, tool, append([]string{"-t", "nat", "-D"}, strings.Fields(line)[1:]...)...))
		}
	}
	for _, line := range wanted {
		if !slices.Contains(current, line) {
			problems = errors.Join(problems, e.firewall(ctx, tool, append([]string{"-t", "nat"}, strings.Fields(line)...)...))
		}
	}
	return problems
}

func (e Executor) syncForwarding(ctx context.Context, content string) error {
	path := e.path(laptopExitConf)
	current, err := os.ReadFile(path)
	switch {
	case content == "" && errors.Is(err, os.ErrNotExist):
		return nil
	case content == "":
		return os.Remove(path)
	case err == nil && string(current) == content:
		return nil
	}
	if err := writeWhole(filepath.Dir(path), filepath.Base(path), []byte(content), 0o644); err != nil {
		return err
	}
	if output, _, err := e.Run(ctx, "sysctl", "-p", path); err != nil {
		return fmt.Errorf("sysctl -p %s: %w: %s", path, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (e Executor) dropExit(ctx context.Context) error {
	return errors.Join(e.syncRelayExit(ctx, exitPlan{}), e.syncForwarding(ctx, ""))
}

func (e Executor) leaveExitWhenHeld(ctx context.Context) {
	plan, joined := e.exitState(ctx, func() bool { return e.held(ctx) })
	if !joined {
		return
	}
	if err := e.syncRelayExit(ctx, plan); err != nil {
		log.Printf("laptop relay and exit: %v", err)
	}
	if current, _ := os.ReadFile(e.path(laptopExitConf)); string(current) != plan.sysctl {
		if err := writeJSON(filepath.Join(e.StateDir, "host"), exitSyncMark, struct{}{}, 0o600); err != nil {
			log.Printf("laptop exit: %v", err)
		}
	}
}

func (e Executor) followExit(ctx context.Context, dir string) {
	marker := filepath.Join(dir, exitSyncMark)
	if _, err := os.Stat(marker); err != nil {
		return
	}
	os.Remove(marker)
	record, self, keys, psk, err := e.joinedState()
	if err == nil {
		err = e.writeNetwork(ctx, &record, *record.Document, self, keys, psk)
	}
	if err == nil {
		plan := e.planExit(ctx, *record.Document, self, e.heldRecorded)
		err = errors.Join(e.syncRelayExit(ctx, plan), e.syncForwarding(ctx, plan.sysctl))
	}
	if err != nil {
		log.Printf("laptop exit: %v", err)
	}
}

func (e Executor) meet(ctx context.Context, request Request, args map[string]string) Result {
	record, self, keys, psk, err := e.joinedState()
	if err != nil {
		return e.refuse(request.ID, err)
	}
	document := withAnnounced(*record.Document, record.Announced)
	laptop, isLaptop := member(document, args["laptop"])
	via, isVia := member(document, args["via"])
	switch {
	case len(args) != 2 || !isLaptop || !laptop.IsLaptop() || laptop.Cut || !isVia || !network.MeetingPoint(via):
		return e.refuse(request.ID, errors.New("a meeting point names a laptop and a public server of the network"))
	case !self.NAT:
		return e.refuse(request.ID, errors.New("only a server behind NAT follows a meeting point"))
	}
	if record.Meetings == nil {
		record.Meetings = map[string]string{}
	}
	record.Meetings[laptop.Node] = via.Node
	allowed := append([]string{via.Address + "/32"}, network.Carried(document, record.Meetings)[via.Node]...)
	if err := e.networkCommand(ctx, "wg", "set", network.Interface, "peer", via.Key, "allowed-ips", strings.Join(allowed, ",")); err != nil {
		return e.failed(request, err, "")
	}
	path := e.path(network.ConfigPath)
	if err := writeWhole(filepath.Dir(path), filepath.Base(path), []byte(network.Render(document, self, keys.Private, psk, record.Meetings, false)), 0o600); err != nil {
		return e.failed(request, err, "")
	}
	if err := e.saveNetwork(record); err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: laptop.Name + " reaches this server through " + via.Name, FinishedAt: e.stamp()}
}
