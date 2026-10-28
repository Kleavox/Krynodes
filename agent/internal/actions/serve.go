package actions

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const (
	rulesFile  = "rules.v4"
	dockerUser = "DOCKER-USER"
)

func (e Executor) ownAddress() (network.Document, string) {
	record := e.readNetwork()
	if !record.Joined || record.Document == nil {
		return network.Document{}, ""
	}
	node, err := e.selfNode()
	if err != nil {
		return network.Document{}, ""
	}
	self, ok := member(*record.Document, node)
	if !ok {
		return network.Document{}, ""
	}
	return *record.Document, self.Address
}

func (e Executor) metaOf(directory string) stackMeta {
	meta, _ := readState[stackMeta](directory, "krynodes.json")
	return meta
}

func (e Executor) choicesFrom(command Command, access string, current stackMeta) (stackMeta, error) {
	hostPorts, err := hostPortsFrom(command, access, current.HostPorts)
	if err != nil {
		return stackMeta{}, err
	}
	meta := stackMeta{Access: access, HostPorts: hostPorts, Offers: current.Offers}
	if access == "contained" {
		meta.Serves, meta.Reaches, meta.Peers = current.Serves, current.Reaches, current.Peers
	}
	if text, given := command.Args["offers"]; given {
		if meta.Offers, err = sharedEntries(text, offerEntry, "%s is not an offer such as apps-inner/web=3001/tcp"); err != nil {
			return stackMeta{}, err
		}
	}
	if text, given := command.Args["peers"]; given {
		if meta.Peers, err = sharedEntries(text, peerEntry, "%s is not a port of another stack such as apps-inner/postgres.db:5432/tcp"); err != nil {
			return stackMeta{}, err
		}
		if len(meta.Peers) > 0 && access != "contained" {
			return stackMeta{}, errors.New("reaching other stacks on a network is for Contained stacks; a Full access stack joins a Contained network as a guest and only answers")
		}
	}
	serves, servesGiven := command.Args["serves"]
	reaches, reachesGiven := command.Args["reaches"]
	if servesGiven {
		meta.Serves = nil
	}
	if reachesGiven {
		meta.Reaches = nil
	}
	if strings.TrimSpace(serves) == "" && strings.TrimSpace(reaches) == "" {
		return meta, nil
	}
	if access != "contained" {
		return stackMeta{}, errors.New("serving and reaching the network is for Contained stacks; a Full access stack already reaches it")
	}
	document, own := e.ownAddress()
	if own == "" {
		return stackMeta{}, errors.New("this server is not in the private network")
	}
	if meta.Serves, err = network.ParseServes(serves); err != nil {
		return stackMeta{}, err
	}
	if meta.Reaches, err = network.ParsePlaces(reaches, document.Range, own); err != nil {
		return stackMeta{}, err
	}
	if !servesGiven {
		meta.Serves = current.Serves
	}
	if !reachesGiven {
		meta.Reaches = current.Reaches
	}
	return meta, nil
}

func servedPort(port map[string]any) string {
	published := asText(port["published"])
	if value, ok := port["published"].(float64); ok {
		published = strconv.Itoa(int(value))
	}
	protocol := asText(port["protocol"])
	if protocol == "" {
		protocol = "tcp"
	}
	return published + "/" + protocol
}

func localPorts(config map[string]any, own string, serves []network.Serve) {
	services := asMap(config["services"])
	for _, name := range sortedKeys(services) {
		service := asMap(services[name])
		listed := asList(service["ports"])
		if len(listed) == 0 {
			continue
		}
		var ports []any
		for _, raw := range listed {
			port := asMap(raw)
			ports = append(ports, raw)
			if port == nil {
				continue
			}
			port["host_ip"] = "127.0.0.1"
			if own != "" && slices.ContainsFunc(serves, func(serve network.Serve) bool { return serve.Port == servedPort(port) }) {
				private := maps.Clone(port)
				private["host_ip"] = own
				ports = append(ports, private)
			}
		}
		service["ports"] = ports
	}
}

func addHosts(config map[string]any, members []network.Member) {
	services := asMap(config["services"])
	for _, name := range sortedKeys(services) {
		service := asMap(services[name])
		if hosts := asMap(service["extra_hosts"]); hosts != nil {
			for _, entry := range members {
				hosts[network.DNSName(entry.Name)+".kry"] = entry.Address
			}
			continue
		}
		hosts := asList(service["extra_hosts"])
		for _, entry := range members {
			hosts = append(hosts, network.DNSName(entry.Name)+".kry:"+entry.Address)
		}
		service["extra_hosts"] = hosts
	}
}

var (
	offerEntry = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}/[A-Za-z0-9][A-Za-z0-9_.-]{0,62}=(\d{1,5})/(tcp|udp)$`)
	peerEntry  = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9_.-]{0,62})/([A-Za-z0-9][A-Za-z0-9_.-]{0,62})\.([a-z0-9][a-z0-9_-]{0,62}):(\d{1,5})/(tcp|udp)$`)
)

const maxSharedEntries = 64

func sharedEntries(text string, pattern *regexp.Regexp, wrong string) ([]string, error) {
	var entries []string
	for entry := range strings.SplitSeq(text, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		match := pattern.FindStringSubmatch(entry)
		if match == nil {
			return nil, fmt.Errorf(wrong, entry)
		}
		if number, _ := strconv.Atoi(match[len(match)-2]); number < 1 || number > 65535 {
			return nil, fmt.Errorf("%s is not a port between 1 and 65535", entry)
		}
		if !slices.Contains(entries, entry) {
			entries = append(entries, entry)
		}
	}
	if len(entries) > maxSharedEntries {
		return nil, fmt.Errorf("a stack may list at most %d ports on its networks", maxSharedEntries)
	}
	return entries, nil
}

func bridgesOf(config map[string]any) []string {
	var bridges []string
	networks := asMap(config["networks"])
	for _, name := range sortedKeys(networks) {
		if asMap(networks[name])["external"] == true {
			continue
		}
		if bridge := asText(asMap(asMap(networks[name])["driver_opts"])["com.docker.network.bridge.name"]); strings.HasPrefix(bridge, "krc") {
			bridges = append(bridges, bridge)
		}
	}
	return bridges
}

func rulesFor(project, directory string, config map[string]any, meta stackMeta) network.StackRules {
	rules := network.StackRules{Project: project}
	if meta.Access != "contained" {
		return rules
	}
	if config == nil && readJSON(filepath.Join(directory, "compose.krynodes.json"), &config) != nil {
		return rules
	}
	rules.Bridges, rules.Serves, rules.Reaches = bridgesOf(config), meta.Serves, meta.Reaches
	return rules
}

func (e Executor) diskRules(pending []network.StackRules) []network.StackRules {
	entries, _ := os.ReadDir(filepath.Join(e.StateDir, "compose"))
	var stacks []network.StackRules
	for _, entry := range entries {
		name := entry.Name()
		directory := filepath.Join(e.StateDir, "compose", name)
		if !entry.IsDir() || e.waiting(name) || slices.ContainsFunc(pending, func(rules network.StackRules) bool { return rules.Project == name }) {
			continue
		}
		if meta := e.metaOf(directory); e.accessOf(directory) == "contained" {
			meta.Access = "contained"
			stacks = append(stacks, rulesFor(name, directory, nil, meta))
		}
	}
	return append(stacks, pending...)
}

func (e Executor) chain(ctx context.Context, name string) string {
	return e.listed(ctx, "iptables", name)
}

func (e Executor) listed(ctx context.Context, tool, name string) string {
	text, _ := e.output(ctx, tool, "-S", name)
	var lines []string
	for line := range strings.SplitSeq(text, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

func (e Executor) syncRules(ctx context.Context, pending ...network.StackRules) error {
	peers := e.syncPeers(ctx)
	document, own := e.ownAddress()
	if own == "" {
		return peers
	}
	serve, reach := network.Rules(own, document.Members, e.diskRules(pending))
	tcp, udp := e.openPorts(ctx, own)
	drop, knock := network.Watch(e.droppedAddresses(document), tcp, udp)
	wanted := func(name string, rules []string) string {
		return strings.Join(append([]string{"-N " + name}, rules...), "\n")
	}
	chains := map[string][]string{network.ServeChain: serve, network.ReachChain: reach, network.DropChain: drop, network.KnockChain: knock}
	current := map[string]string{}
	for name := range chains {
		current[name] = e.chain(ctx, name)
	}
	if slices.ContainsFunc(slices.Collect(maps.Keys(chains)), func(name string) bool { return current[name] != wanted(name, chains[name]) }) {
		restore := network.Restore(serve, reach, drop, knock)
		if last, err := os.ReadFile(filepath.Join(e.networkDir(), rulesFile)); err == nil && string(last) == restore {
			e.removedRule(current, chains)
		}
		if err := writeWhole(e.networkDir(), rulesFile, []byte(restore), 0o600); err != nil {
			return err
		}
		if err := e.firewall(ctx, "iptables-restore", "--noflush", filepath.Join(e.networkDir(), rulesFile)); err != nil {
			return fmt.Errorf("write the private network's rules: %w", err)
		}
	}
	e.firewall(ctx, "iptables", "-N", dockerUser)
	for _, jump := range network.Jumps(document.Range) {
		if err := e.ensure(ctx, "iptables", []string{"-I", dockerUser, "1"}, dockerUser, jump); err != nil {
			return fmt.Errorf("send the private network through its rules: %w", err)
		}
	}
	for _, jump := range network.InputJumps() {
		if err := e.ensure(ctx, "iptables", []string{"-I", "INPUT", "1"}, "INPUT", jump); err != nil {
			return fmt.Errorf("send the private network through its rules: %w", err)
		}
	}
	return peers
}

func (e Executor) droppedAddresses(document network.Document) []string {
	addresses := slices.Clone(e.readNetwork().Dropped)
	for _, entry := range document.Members {
		if entry.Cut && !slices.Contains(addresses, entry.Address) {
			addresses = append(addresses, entry.Address)
		}
	}
	return addresses
}

func (e Executor) openPorts(ctx context.Context, own string) ([]int, []int) {
	output, _ := e.output(ctx, "ss", "-H", "-tuln")
	open := map[string][]int{}
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || (fields[0] != "tcp" && fields[0] != "udp") {
			continue
		}
		colon := strings.LastIndex(fields[4], ":")
		host := strings.Trim(fields[4][:max(colon, 0)], "[]")
		number, err := strconv.Atoi(fields[4][colon+1:])
		if colon < 0 || err != nil || (host != "0.0.0.0" && host != "*" && host != "::" && host != own) || slices.Contains(open[fields[0]], number) {
			continue
		}
		open[fields[0]] = append(open[fields[0]], number)
	}
	slices.Sort(open["tcp"])
	slices.Sort(open["udp"])
	return open["tcp"], open["udp"]
}

func (e Executor) dropRules(ctx context.Context) {
	if !strings.Contains(e.chain(ctx, network.ServeChain), "-N "+network.ServeChain) && !strings.Contains(e.chain(ctx, network.ReachChain), "-N "+network.ReachChain) {
		return
	}
	ours := []string{network.ServeChain, network.ReachChain, network.DropChain, network.KnockChain}
	for _, parent := range []string{dockerUser, "INPUT"} {
		for line := range strings.SplitSeq(e.chain(ctx, parent), "\n") {
			rule, found := strings.CutPrefix(line, "-A "+parent+" ")
			if found && slices.ContainsFunc(ours, func(name string) bool { return strings.HasSuffix(rule, "-j "+name) }) {
				e.firewall(ctx, "iptables", append([]string{"-D", parent}, strings.Fields(rule)...)...)
			}
		}
	}
	for _, name := range ours {
		e.firewall(ctx, "iptables", "-F", name)
		e.firewall(ctx, "iptables", "-X", name)
	}
}

func (e Executor) changeReach(ctx context.Context, request Request, command Command, stack Stack) Result {
	if _, given := command.Args["reaches"]; !given || len(command.Args) != 1 {
		return e.refuse(request.ID, errors.New("reach changes only the places a stack may reach"))
	}
	if e.accessOf(stack.Directory) != "contained" {
		return e.refuse(request.ID, errors.New("only a Contained stack keeps a list of places; a Full access stack already reaches every server"))
	}
	meta, err := e.choicesFrom(Command{Args: command.Args}, "contained", e.metaOf(stack.Directory))
	if err != nil {
		return e.refuse(request.ID, err)
	}
	if err := e.syncRules(ctx, rulesFor(stack.Project, stack.Directory, nil, meta)); err != nil {
		return e.failed(request, err, "")
	}
	if err := writeJSON(stack.Directory, "krynodes.json", meta, 0o640); err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: "reach changed", FinishedAt: e.stamp()}
}

func (e Executor) privateReady(ctx context.Context, document network.Document, own string, args []string) error {
	uses, binds := false, false
	for index := 1; index < len(args); index++ {
		if args[index-1] != "-f" {
			continue
		}
		text, err := os.ReadFile(args[index])
		if err != nil {
			continue
		}
		uses = uses || strings.Contains(string(text), network.Variable)
		binds = binds || (own != "" && strings.Contains(string(text), `"host_ip":"`+own+`"`))
	}
	switch {
	case uses && own == "":
		return errors.New("this server is not in the private network, so KRY_PRIVATE_IP has no value")
	case (uses || binds) && own != "":
		listed, _ := e.output(ctx, "ip", "-o", "-4", "addr", "show", "dev", network.Interface, "up")
		if !strings.Contains(listed, " "+own+"/") {
			name := own
			for _, entry := range document.Members {
				if entry.Address == own {
					name = entry.Name
				}
			}
			return fmt.Errorf("kry0 is down on %s", name)
		}
	}
	return nil
}

func (e Executor) unserve(ctx context.Context, own string) []string {
	var problems []string
	entries, _ := os.ReadDir(filepath.Join(e.StateDir, "compose"))
	for _, entry := range entries {
		name := entry.Name()
		directory := filepath.Join(e.StateDir, "compose", name)
		meta := e.metaOf(directory)
		if !entry.IsDir() || (len(meta.Serves) == 0 && len(meta.Reaches) == 0) {
			continue
		}
		served := len(meta.Serves) > 0
		meta.Serves, meta.Reaches = nil, nil
		if err := writeJSON(directory, "krynodes.json", meta, 0o640); err != nil {
			problems = append(problems, name+": "+err.Error())
			continue
		}
		var config map[string]any
		if !served || readJSON(filepath.Join(directory, "compose.krynodes.json"), &config) != nil {
			continue
		}
		for _, service := range asMap(config["services"]) {
			service := asMap(service)
			if ports := asList(service["ports"]); len(ports) > 0 {
				service["ports"] = slices.DeleteFunc(ports, func(port any) bool { return asText(asMap(port)["host_ip"]) == own })
			}
		}
		if err := writeJSON(directory, "compose.krynodes.json", config, 0o640); err != nil {
			problems = append(problems, name+": "+err.Error())
			continue
		}
		if e.waiting(name) {
			continue
		}
		stack := Stack{Project: name, Directory: directory, Files: []string{filepath.Join(directory, "compose.krynodes.json")}}
		if _, err := e.docker(ctx, upTimeout, "up", composeArgs(stack, "up", "-d")...); err != nil {
			problems = append(problems, "start "+name+" on this server only: "+err.Error())
		}
	}
	return problems
}

func hostsOverride(config map[string]any, members []network.Member) map[string]any {
	services := map[string]any{}
	for _, name := range sortedKeys(asMap(config["services"])) {
		services[name] = map[string]any{}
	}
	override := map[string]any{"services": services}
	addHosts(override, members)
	return override
}

func splitBindings(bindings []reporter.Listener, own string) ([]string, []string) {
	public, private := []string{}, []string{}
	for _, bound := range bindings {
		port := strconv.Itoa(bound.Port) + "/" + bound.Protocol
		target := &public
		if bound.Address == own {
			target = &private
		}
		if !slices.Contains(*target, port) {
			*target = append(*target, port)
		}
	}
	return public, private
}
