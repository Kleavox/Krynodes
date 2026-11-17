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
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/relay"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

const (
	laptopExitConf = "/etc/sysctl.d/99-krynodes-laptop-exit.conf"
	exitSyncMark   = "exit-sync"
	noUplinkMark   = "no-uplink"
)

var (
	laptopPools   = []netip.Prefix{netip.MustParsePrefix("10.88.0.0/16"), netip.MustParsePrefix("fd88:88::/64")}
	interfaceName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	betweenPeers  = []string{"-i", network.Interface, "-o", network.Interface, "-j", "DROP"}
	exitJumps     = [][]string{{"-i", network.Interface, "!", "-o", network.Interface, "-j", network.ExitChain}, {"!", "-i", network.Interface, "-o", network.Interface, "-j", network.ExitChain}}
	exitTools     = []string{"iptables", "ip6tables"}
	routing       = map[string]string{"iptables": "/proc/sys/net/ipv4/ip_forward", "ip6tables": "/proc/sys/net/ipv6/conf/all/forwarding"}
)

type exitPlan struct {
	apart   map[string]bool
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
	plan := exitPlan{apart: map[string]bool{"iptables": true}, forward: map[string][]string{}, nat: map[string][]string{}, routes: map[string]bool{}}
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
	plan.routes["iptables"] = plan.forward["iptables"] != nil
	plan.routes["ip6tables"] = plan.exit6()
	plan.apart["ip6tables"] = plan.exit6() || e.carries6()
	if plan.ra != "" {
		key := "net.ipv6.conf." + plan.ra + ".accept_ra"
		if strings.Contains(plan.ra, ".") {
			key = "net/ipv6/conf/" + plan.ra + "/accept_ra"
		}
		plan.sysctl = key + " = 2\n"
	}
	return plan
}

func (e Executor) carries6() bool {
	config, _ := os.ReadFile(e.path(network.ConfigPath))
	for line := range strings.SplitSeq(string(config), "\n") {
		allowed, found := strings.CutPrefix(strings.TrimSpace(line), "AllowedIPs = ")
		if !found {
			continue
		}
		for field := range strings.SplitSeq(allowed, ",") {
			if prefix, err := netip.ParsePrefix(strings.TrimSpace(field)); err == nil && prefix.Addr().Is6() {
				return true
			}
		}
	}
	return false
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

func (e Executor) syncExit(ctx context.Context, plan exitPlan) error {
	var problems error
	for _, tool := range exitTools {
		problems = errors.Join(problems, e.keepApart(ctx, tool, plan.apart[tool]), e.syncForward(ctx, tool, network.ExitChain, exitJumps, plan.forward[tool]), e.syncNAT(ctx, tool, plan.nat[tool]))
	}
	return errors.Join(problems, e.switchForwarding(ctx, plan))
}

func (e Executor) keepApart(ctx context.Context, tool string, wanted bool) error {
	if wanted {
		return e.ensure(ctx, tool, []string{"-I", "FORWARD", "1"}, "FORWARD", betweenPeers)
	}
	if e.firewall(ctx, tool, append([]string{"-C", "FORWARD"}, betweenPeers...)...) == nil {
		return e.firewall(ctx, tool, append([]string{"-D", "FORWARD"}, betweenPeers...)...)
	}
	return nil
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
	return errors.Join(e.syncExit(ctx, exitPlan{}), e.syncForwarding(ctx, ""))
}

func (e Executor) leaveExitWhenHeld(ctx context.Context) {
	plan, joined := e.exitState(ctx, func() bool { return e.held(ctx) })
	if !joined {
		return
	}
	if err := e.syncExit(ctx, plan); err != nil {
		log.Printf("laptop exit: %v", err)
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
	defer e.lockNetwork()()
	record, self, keys, psk, err := e.joinedState()
	if err == nil {
		err = e.writeNetwork(ctx, &record, *record.Document, self, keys, psk)
	}
	if err == nil {
		plan := e.planExit(ctx, *record.Document, self, e.heldRecorded)
		err = errors.Join(e.syncExit(ctx, plan), e.syncForwarding(ctx, plan.sysctl))
	}
	if err != nil {
		log.Printf("laptop exit: %v", err)
	}
}

func (e Executor) meet(ctx context.Context, request Request, args map[string]string) Result {
	defer e.lockNetwork()()
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
	endpoint, ok := network.RelayEndpoint(document, via.Node, laptop.Node, self.Node)
	if !ok {
		return e.refuse(request.ID, fmt.Errorf("%s has no relay port for this server", laptop.Name))
	}
	if record.Meetings == nil {
		record.Meetings = map[string]string{}
	}
	record.Meetings[laptop.Node] = via.Node
	if err := e.networkCommand(ctx, "wg", "set", network.Interface, "peer", laptop.Key, "endpoint", endpoint); err != nil {
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

func (e Executor) meetingEndpoints(record networkRecord) map[string]string {
	node, err := e.selfNode()
	if !record.Joined || record.Document == nil || err != nil {
		return nil
	}
	document := withAnnounced(*record.Document, record.Announced)
	self, ok := member(document, node)
	if !ok || !self.NAT {
		return nil
	}
	wanted := map[string]string{}
	for _, laptop := range network.Laptops(document.Members) {
		if endpoint, ok := network.RelayEndpoint(document, record.Meetings[laptop.Node], laptop.Node, self.Node); ok {
			wanted[laptop.Key] = endpoint
		}
	}
	return wanted
}

func roamed(wanted map[string]string, links []network.Link) []string {
	var keys []string
	for key, endpoint := range wanted {
		link := linkOf(links, key)
		if link.Key == "" {
			continue
		}
		if link.Endpoint == nil || !network.SameEndpoint(*link.Endpoint, endpoint) {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	return keys
}

func (e Executor) holdMeetings(ctx context.Context) {
	wanted := e.meetingEndpoints(e.readNetwork())
	if len(wanted) == 0 {
		return
	}
	links := e.dump(ctx)
	if len(roamed(wanted, links)) == 0 {
		return
	}
	defer e.lockNetwork()()
	wanted = e.meetingEndpoints(e.readNetwork())
	for _, key := range roamed(wanted, links) {
		if err := e.networkCommand(ctx, "wg", "set", network.Interface, "peer", key, "endpoint", wanted[key]); err != nil {
			log.Printf("meeting point: %v", err)
		}
	}
}

func relayPorts(document network.Document, self network.Member) []int {
	if !network.MeetingPoint(self) {
		return nil
	}
	var ports []int
	for _, pair := range network.Pairs(document) {
		ports = append(ports, pair.Port)
	}
	slices.Sort(ports)
	return ports
}

func (e Executor) syncRelayPorts(ctx context.Context, record *networkRecord, document network.Document, self network.Member) error {
	wanted := relayPorts(document, self)
	var open []int
	var problems error
	for _, port := range record.Relays {
		if slices.Contains(wanted, port) {
			open = append(open, port)
			continue
		}
		if err := e.closeRelay(ctx, record.Firewall, port); err != nil {
			problems = errors.Join(problems, fmt.Errorf("close relay port %d: %w", port, err))
			open = append(open, port)
		}
	}
	for _, port := range wanted {
		if slices.Contains(record.Relays, port) {
			continue
		}
		if err := e.networkCommands(ctx, network.OpenRelay(record.Firewall, []int{port})); err != nil {
			problems = errors.Join(problems, fmt.Errorf("open relay port %d: %w", port, err))
			continue
		}
		open = append(open, port)
	}
	slices.Sort(open)
	record.Relays = open
	return problems
}

func (e Executor) relayDrift(record networkRecord) (network.Member, bool) {
	node, err := e.selfNode()
	if !record.Joined || record.Document == nil || err != nil {
		return network.Member{}, false
	}
	self, ok := member(*record.Document, node)
	return self, ok && !slices.Equal(record.Relays, relayPorts(*record.Document, self))
}

func (e Executor) retryRelayPorts(ctx context.Context) {
	if _, drift := e.relayDrift(e.readNetwork()); !drift {
		return
	}
	defer e.lockNetwork()()
	record := e.readNetwork()
	self, drift := e.relayDrift(record)
	if !drift {
		return
	}
	if err := e.syncRelayPorts(ctx, &record, *record.Document, self); err != nil {
		log.Printf("relay ports: %v", err)
	}
	if err := e.saveNetwork(record); err != nil {
		log.Printf("relay ports: %v", err)
	}
}

func (e Executor) closeRelay(ctx context.Context, firewall string, port int) error {
	numbered := ""
	if firewall == "ufw" {
		var listed bool
		if numbered, listed = e.output(ctx, "ufw", "status", "numbered"); !listed {
			return errors.New("ufw status numbered failed")
		}
	}
	return e.networkCommands(ctx, network.CloseRelay(firewall, []int{port}, numbered))
}

func (e Executor) networkCommands(ctx context.Context, commands [][]string) error {
	for _, command := range commands {
		if err := e.networkCommand(ctx, command[0], command[1:]...); err != nil {
			return err
		}
	}
	return nil
}

func (e Executor) relayPairs() ([]relay.Pair, error) {
	record, err := readState[networkRecord](e.StateDir, "network.json")
	if err != nil || !record.Joined || record.Document == nil {
		return nil, err
	}
	current, err := trust.Load(e.StateDir)
	if err != nil {
		return nil, err
	}
	document := withAnnounced(*record.Document, record.Announced)
	self, ok := member(document, current.NodeID)
	if !ok || !network.MeetingPoint(self) {
		return nil, nil
	}
	var host netip.Addr
	if signed, err := netip.ParseAddrPort(*self.Endpoint); err == nil {
		host = signed.Addr().Unmap()
	}
	var pairs []relay.Pair
	for _, pair := range network.Pairs(document) {
		pairs = append(pairs, relay.Pair{Port: pair.Port, Sides: [2]string{pair.Laptop.Key, pair.NAT.Key}, Host: host})
	}
	return pairs, nil
}

func (e Executor) CarryPairs(ctx context.Context, every time.Duration) {
	carrier := relay.New(network.Runner(e.Run))
	defer carrier.Close()
	e.carryPairs(ctx, every, carrier.Set)
}

func (e Executor) carryPairs(ctx context.Context, every time.Duration, set func([]relay.Pair)) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	failing := false
	for {
		pairs, err := e.relayPairs()
		if err == nil {
			set(pairs)
		} else if !failing {
			log.Printf("relay: keeping the pairs it carries: %v", err)
		}
		failing = err != nil
		e.holdMeetings(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
