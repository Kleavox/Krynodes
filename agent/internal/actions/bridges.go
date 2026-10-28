package actions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const (
	bridgesFile  = "bridges.json"
	peersFile    = "peers.v4"
	labelsFormat = "{{.ID}}\t{{.Label \"com.docker.compose.project\"}}\t{{.Label \"com.docker.compose.service\"}}"
	maxNetworks  = 32
	maxMembers   = 256
	maxOffers    = 16
	maxTaken     = 128
	maxClaimed   = 128
	noFilter     = "This server's kernel does not filter traffic inside Docker bridges (br_netfilter), so a Contained network cannot be kept closed here."
)

var (
	tailscaleRange = netip.MustParsePrefix("100.64.0.0/10")
	privateRanges  = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16")}
	builtinNets    = []string{"bridge", "host", "none"}
)

type bridgeRecord struct {
	ID     string            `json:"id"`
	Kind   string            `json:"kind"`
	Subnet string            `json:"subnet"`
	Bridge string            `json:"bridge"`
	Pins   map[string]string `json:"pins,omitempty"`
	Freed  []string          `json:"freed,omitempty"`
}

type dockerNetwork struct {
	Name   string            `json:"Name"`
	ID     string            `json:"Id"`
	Driver string            `json:"Driver"`
	Labels map[string]string `json:"Labels"`
	IPAM   struct {
		Config []struct {
			Subnet string `json:"Subnet"`
		} `json:"Config"`
	} `json:"IPAM"`
	Containers map[string]struct {
		Name        string `json:"Name"`
		IPv4Address string `json:"IPv4Address"`
	} `json:"Containers"`
}

func (n dockerNetwork) subnets() []string {
	var subnets []string
	for _, config := range n.IPAM.Config {
		if prefix, err := netip.ParsePrefix(config.Subnet); err == nil && prefix.Addr().Is4() {
			subnets = append(subnets, prefix.String())
		}
	}
	return subnets
}

type claim struct {
	project, key, name string
}

func (e Executor) readBridges() map[string]bridgeRecord {
	records, _ := readState[map[string]bridgeRecord](e.StateDir, bridgesFile)
	if records == nil {
		records = map[string]bridgeRecord{}
	}
	return records
}

func (e Executor) saveBridges(records map[string]bridgeRecord) error {
	return writeJSON(e.StateDir, bridgesFile, records, 0o640)
}

func sharedBridgeName(name string) string {
	sum := sha256.Sum256([]byte("net:" + name))
	return "krc" + hex.EncodeToString(sum[:])[:12]
}

func (e Executor) ownedBridge(ctx context.Context, name string) (bridgeRecord, bool) {
	record, found := e.readBridges()[name]
	if !found || record.ID == "" {
		return bridgeRecord{}, false
	}
	id, ok := e.output(ctx, "docker", "network", "inspect", "-f", "{{.Id}}", name)
	return record, ok && strings.TrimSpace(id) == record.ID
}

func lastAddress(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Masked().Addr().As4()
	for bit := prefix.Bits(); bit < 32; bit++ {
		bytes[bit/8] |= 1 << (7 - bit%8)
	}
	return netip.AddrFrom4(bytes)
}

func pin(name string, record *bridgeRecord, key string) (string, error) {
	if address, found := record.Pins[key]; found {
		return address, nil
	}
	prefix, err := netip.ParsePrefix(record.Subnet)
	if err != nil || !prefix.Addr().Is4() {
		return "", fmt.Errorf("%s has no readable subnet", name)
	}
	used := map[string]bool{}
	for _, address := range record.Pins {
		used[address] = true
	}
	for _, address := range record.Freed {
		used[address] = true
	}
	chosen := ""
	last := lastAddress(prefix)
	for address := prefix.Masked().Addr().Next().Next(); prefix.Contains(address) && address != last; address = address.Next() {
		if !used[address.String()] {
			chosen = address.String()
			break
		}
	}
	if chosen == "" && len(record.Freed) > 0 {
		chosen, record.Freed = record.Freed[0], slices.Clone(record.Freed[1:])
	}
	if chosen == "" {
		return "", fmt.Errorf("%s has no free address left.", name)
	}
	if record.Pins == nil {
		record.Pins = map[string]string{}
	}
	record.Pins[key] = chosen
	return chosen, nil
}

func (e Executor) unpin(project string) error {
	records := e.readBridges()
	changed := false
	for name, record := range records {
		for _, key := range slices.Sorted(maps.Keys(record.Pins)) {
			if strings.HasPrefix(key, project+"/") {
				record.Freed = append(record.Freed, record.Pins[key])
				delete(record.Pins, key)
				changed = true
			}
		}
		records[name] = record
	}
	if !changed {
		return nil
	}
	return e.saveBridges(records)
}

func madeNetworks(config map[string]any, project string) map[string]string {
	made := map[string]string{}
	networks := asMap(config["networks"])
	for _, key := range sortedKeys(networks) {
		network := asMap(networks[key])
		if network["external"] == true {
			continue
		}
		name := asText(network["name"])
		if name == "" {
			name = project + "_" + key
		}
		made[key] = name
	}
	return made
}

func (e Executor) stackDirectories() []string {
	entries, _ := os.ReadDir(filepath.Join(e.StateDir, "compose"))
	var directories []string
	for _, entry := range entries {
		if entry.IsDir() {
			directories = append(directories, filepath.Join(e.StateDir, "compose", entry.Name()))
		}
	}
	return directories
}

func (e Executor) claims() []claim {
	var claims []claim
	for _, directory := range e.stackDirectories() {
		networks := e.metaOf(directory).Networks
		for _, key := range slices.Sorted(maps.Keys(networks)) {
			claims = append(claims, claim{project: filepath.Base(directory), key: key, name: networks[key]})
		}
	}
	return claims
}

func (e Executor) dockerNetworks(ctx context.Context) ([]dockerNetwork, error) {
	ids, err := e.docker(ctx, collectTimeout, "list networks", "network", "ls", "-q", "--no-trunc")
	if err != nil {
		return nil, err
	}
	if len(strings.Fields(string(ids))) == 0 {
		return nil, nil
	}
	output, err := e.docker(ctx, collectTimeout, "read networks", append([]string{"network", "inspect"}, strings.Fields(string(ids))...)...)
	if err != nil {
		return nil, err
	}
	var networks []dockerNetwork
	if err := json.Unmarshal(output, &networks); err != nil {
		return nil, errors.New("docker did not return readable networks")
	}
	return networks, nil
}

func (e Executor) containerLabels(ctx context.Context) map[string][2]string {
	output, _ := e.output(ctx, "docker", "ps", "-a", "--no-trunc", "--format", labelsFormat)
	labels := map[string][2]string{}
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(fields) == 3 && fields[1] != "" {
			labels[fields[0]] = [2]string{fields[1], fields[2]}
		}
	}
	return labels
}

func localDevice(name string) bool {
	return name != "" && name != "lo" && name != "docker0" && !strings.HasPrefix(name, "krc") && !strings.HasPrefix(name, "br-") && !strings.HasPrefix(name, "veth")
}

func (e Executor) taken(ctx context.Context, networks []dockerNetwork) []reporter.Taken {
	taken := []reporter.Taken{}
	add := func(entry reporter.Taken) {
		if !slices.Contains(taken, entry) {
			taken = append(taken, entry)
		}
	}
	for _, network := range networks {
		for _, subnet := range network.subnets() {
			add(reporter.Taken{Range: subnet, By: network.Name})
		}
	}
	var links []struct {
		Name      string `json:"ifname"`
		Addresses []struct {
			Family string `json:"family"`
			Local  string `json:"local"`
			Prefix int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if output, ok := e.output(ctx, "ip", "-j", "addr", "show"); ok {
		json.Unmarshal([]byte(output), &links)
	}
	for _, link := range links {
		for _, address := range link.Addresses {
			prefix, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", address.Local, address.Prefix))
			if err == nil && address.Family == "inet" && localDevice(link.Name) {
				add(reporter.Taken{Range: prefix.Masked().String(), By: link.Name, Own: true})
			}
		}
	}
	var routes []struct {
		Destination string `json:"dst"`
		Device      string `json:"dev"`
	}
	if output, ok := e.output(ctx, "ip", "-j", "route", "show"); ok {
		json.Unmarshal([]byte(output), &routes)
	}
	for _, route := range routes {
		destination := route.Destination
		if !strings.Contains(destination, "/") {
			destination += "/32"
		}
		if prefix, err := netip.ParsePrefix(destination); err == nil && prefix.Addr().Is4() && localDevice(route.Device) {
			add(reporter.Taken{Range: prefix.Masked().String(), By: route.Device, Own: true})
		}
	}
	return taken[:min(len(taken), maxTaken)]
}

func subnetProblem(subnet string, taken []reporter.Taken, privateRange string) string {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil || !prefix.Addr().Is4() {
		return "Write it as 172.24.0.0/24."
	}
	if prefix != prefix.Masked() {
		return "Write it as " + prefix.Masked().String() + "."
	}
	overlaps := func(text string) bool {
		other, err := netip.ParsePrefix(text)
		return err == nil && other.Overlaps(prefix)
	}
	for _, entry := range taken {
		if !entry.Own && overlaps(entry.Range) {
			return fmt.Sprintf("Overlaps %s (%s) on this server.", entry.By, entry.Range)
		}
	}
	if privateRange != "" && overlaps(privateRange) {
		return fmt.Sprintf("Overlaps your private network (%s).", privateRange)
	}
	if tailscaleRange.Overlaps(prefix) {
		return "Overlaps Tailscale's addresses (100.64.0.0/10)."
	}
	for _, entry := range taken {
		if entry.Own && overlaps(entry.Range) {
			return fmt.Sprintf("Overlaps this server's own network (%s on %s).", entry.Range, entry.By)
		}
	}
	if !slices.ContainsFunc(privateRanges, func(private netip.Prefix) bool {
		return private.Bits() <= prefix.Bits() && private.Contains(prefix.Addr())
	}) {
		return "Use a private range: 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16."
	}
	if prefix.Bits() < 16 || prefix.Bits() > 28 {
		return "Use a prefix from /16 to /28."
	}
	return ""
}

func (e Executor) bridge(ctx context.Context, request Request) Result {
	if request.Action != "create" && request.Action != "remove" {
		return e.refuse(request.ID, fmt.Errorf("unknown action %q", request.Action))
	}
	if !ValidTarget("bridge", request.Name) {
		return e.refuse(request.ID, errors.New("invalid target"))
	}
	if err := expired(request, e.Now()); err != nil {
		return e.refuse(request.ID, err)
	}
	command, err := e.authorize(request)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	if request.Action == "remove" {
		return e.removeBridge(ctx, request)
	}
	return e.createBridge(ctx, request, command)
}

func (e Executor) createBridge(ctx context.Context, request Request, command Command) Result {
	name, kind, subnet := request.Name, command.Args["kind"], command.Args["subnet"]
	if kind != "contained" && kind != "full" {
		return e.refuse(request.ID, errors.New("A network is Contained or Full Access."))
	}
	networks, err := e.dockerNetworks(ctx)
	if err != nil {
		return e.failed(request, err, "")
	}
	if slices.ContainsFunc(networks, func(network dockerNetwork) bool { return network.Name == name }) {
		return e.refuse(request.ID, fmt.Errorf("This server already has a network named %s.", name))
	}
	for _, claim := range e.claims() {
		if claim.name == name {
			return e.refuse(request.ID, fmt.Errorf("The %s stack makes its own %s network with this name. Write external: true there, or pick another name.", claim.project, claim.key))
		}
	}
	private := ""
	if document := e.readNetwork().Document; document != nil {
		private = document.Range
	}
	if problem := subnetProblem(subnet, e.taken(ctx, networks), private); problem != "" {
		return e.refuse(request.ID, errors.New(problem))
	}
	bridge := sharedBridgeName(name)
	args := []string{"network", "create", "--driver", "bridge", "--subnet", subnet}
	if kind == "contained" {
		args = append(args, "--internal", "-o", "com.docker.network.bridge.enable_icc=false", "-o", "com.docker.network.bridge.name="+bridge)
	}
	output, err := e.docker(ctx, collectTimeout, "create network", append(args, "--label", "com.krynodes.network="+kind, name)...)
	if err != nil {
		return e.failed(request, err, "")
	}
	id := ""
	if fields := strings.Fields(string(output)); len(fields) > 0 {
		id = fields[len(fields)-1]
	}
	if kind == "contained" {
		filter, _ := os.ReadFile(filepath.Join(e.Root, "proc", "sys", "net", "bridge", "bridge-nf-call-iptables"))
		if strings.TrimSpace(string(filter)) != "1" {
			e.docker(ctx, collectTimeout, "remove network", "network", "rm", name)
			return e.refuse(request.ID, errors.New(noFilter))
		}
	} else {
		bridge = "br-" + id[:min(len(id), 12)]
	}
	records := e.readBridges()
	records[name] = bridgeRecord{ID: id, Kind: kind, Subnet: subnet, Bridge: bridge}
	if err := e.saveBridges(records); err != nil {
		return e.failed(request, err, "")
	}
	e.syncRules(ctx)
	return Result{ID: request.ID, OK: true, Output: fmt.Sprintf("created %s · %s", name, subnet), FinishedAt: e.stamp()}
}

func namesNetwork(text, name string) bool {
	return regexp.MustCompile(`(^|[^A-Za-z0-9_.-])` + regexp.QuoteMeta(name) + `($|[^A-Za-z0-9_.-])`).MatchString(text)
}

func andList(names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

func (e Executor) bridgeUsers(ctx context.Context, name string) ([]string, error) {
	networks, err := e.dockerNetworks(ctx)
	if err != nil {
		return nil, err
	}
	var users []string
	for _, network := range networks {
		if network.Name != name || len(network.Containers) == 0 {
			continue
		}
		labels := e.containerLabels(ctx)
		for id, container := range network.Containers {
			user := strings.TrimPrefix(container.Name, "/")
			if label, found := labels[id]; found {
				user = label[0]
			}
			users = append(users, user)
		}
	}
	for _, directory := range e.stackDirectories() {
		if text, err := os.ReadFile(filepath.Join(directory, "compose.yaml")); err == nil && namesNetwork(string(text), name) {
			users = append(users, filepath.Base(directory))
		}
	}
	slices.Sort(users)
	return slices.Compact(users), nil
}

func (e Executor) removeBridge(ctx context.Context, request Request) Result {
	name := request.Name
	if _, owned := e.ownedBridge(ctx, name); !owned {
		return e.refuse(request.ID, fmt.Errorf("%s was not made by Krynodes on this server.", name))
	}
	users, err := e.bridgeUsers(ctx, name)
	if err != nil {
		return e.failed(request, err, "")
	}
	if len(users) > 0 {
		verb := "use"
		if len(users) == 1 {
			verb = "uses"
		}
		return e.refuse(request.ID, fmt.Errorf("%s still %s it. Take it out of their compose files first.", andList(users), verb))
	}
	if _, err := e.docker(ctx, collectTimeout, "remove network", "network", "rm", name); err != nil {
		return e.failed(request, err, "")
	}
	records := e.readBridges()
	delete(records, name)
	if err := e.saveBridges(records); err != nil {
		return e.failed(request, err, "")
	}
	e.syncRules(ctx)
	return Result{ID: request.ID, OK: true, Output: "deleted " + name, FinishedAt: e.stamp()}
}

func (e Executor) bridgesReport(ctx context.Context) *reporter.Bridges {
	networks, err := e.dockerNetworks(ctx)
	if err != nil {
		return nil
	}
	slices.SortFunc(networks, func(a, b dockerNetwork) int { return strings.Compare(a.Name, b.Name) })
	records := e.readBridges()
	var labels map[string][2]string
	listed := []reporter.BridgeNetwork{}
	for _, network := range networks {
		record, found := records[network.Name]
		entry := reporter.BridgeNetwork{Name: network.Name, Kind: "outside", Members: []reporter.BridgeMember{}}
		_, compose := network.Labels["com.docker.compose.network"]
		switch {
		case found && record.ID != "" && record.ID == network.ID:
			subnet := record.Subnet
			entry.Kind, entry.Subnet = record.Kind, &subnet
		case network.Driver != "bridge" || compose || slices.Contains(builtinNets, network.Name):
			continue
		default:
			if subnets := network.subnets(); len(subnets) > 0 {
				entry.Subnet = &subnets[0]
			}
		}
		if len(network.Containers) > 0 && labels == nil {
			labels = e.containerLabels(ctx)
		}
		for id, container := range network.Containers {
			name := strings.TrimPrefix(container.Name, "/")
			member := reporter.BridgeMember{Project: name, Service: name, Offers: []string{}}
			if label, found := labels[id]; found {
				member.Project = label[0]
				if label[1] != "" {
					member.Service = label[1]
				}
			}
			if address, _, _ := strings.Cut(container.IPv4Address, "/"); address != "" {
				member.Address = &address
			}
			directory := filepath.Join(e.StateDir, "compose", member.Project)
			if projectName.MatchString(member.Project) {
				prefix := network.Name + "/" + member.Service + "="
				for _, offer := range e.metaOf(directory).Offers {
					if port, found := strings.CutPrefix(offer, prefix); found && len(member.Offers) < maxOffers {
						member.Offers = append(member.Offers, port)
					}
				}
				member.Guest = entry.Kind == "contained" && e.accessOf(directory) == "full"
			}
			entry.Members = append(entry.Members, member)
		}
		slices.SortFunc(entry.Members, func(a, b reporter.BridgeMember) int {
			return strings.Compare(a.Project+"/"+a.Service, b.Project+"/"+b.Service)
		})
		entry.Members = entry.Members[:min(len(entry.Members), maxMembers)]
		listed = append(listed, entry)
	}
	claimed := []string{}
	for _, claim := range e.claims() {
		claimed = append(claimed, claim.name)
	}
	slices.Sort(claimed)
	claimed = slices.Compact(claimed)
	return &reporter.Bridges{Networks: listed[:min(len(listed), maxNetworks)], Taken: e.taken(ctx, networks), Claimed: claimed[:min(len(claimed), maxClaimed)]}
}

func (e Executor) bridgeFiltered() bool {
	filter, _ := os.ReadFile(filepath.Join(e.Root, "proc", "sys", "net", "bridge", "bridge-nf-call-iptables"))
	return strings.TrimSpace(string(filter)) == "1"
}

func (e Executor) peerNetworks() []network.PeerNetwork {
	records := e.readBridges()
	metas := map[string]stackMeta{}
	offered := map[string]bool{}
	for _, directory := range e.stackDirectories() {
		project := filepath.Base(directory)
		if e.waiting(project) {
			continue
		}
		meta := e.metaOf(directory)
		meta.Access = e.accessOf(directory)
		metas[project] = meta
		for _, offer := range meta.Offers {
			if where, port, found := strings.Cut(offer, "="); found {
				offered[where+"."+project+":"+port] = true
			}
		}
	}
	var networks []network.PeerNetwork
	for _, name := range slices.Sorted(maps.Keys(records)) {
		record := records[name]
		if record.Kind != "contained" || !strings.HasPrefix(record.Bridge, "krc") {
			continue
		}
		entry := network.PeerNetwork{Bridge: record.Bridge}
		for _, project := range slices.Sorted(maps.Keys(metas)) {
			if metas[project].Access != "contained" {
				continue
			}
			for _, peer := range metas[project].Peers {
				match := peerEntry.FindStringSubmatch(peer)
				if match == nil || match[1] != name || !offered[peer] {
					continue
				}
				to := record.Pins[match[3]+"/"+match[2]]
				port, _ := strconv.Atoi(match[4])
				for _, key := range slices.Sorted(maps.Keys(record.Pins)) {
					if from := record.Pins[key]; strings.HasPrefix(key, project+"/") && to != "" && from != to {
						entry.Allow = append(entry.Allow, network.PeerRule{From: from, To: to, Proto: match[5], Port: port})
					}
				}
			}
		}
		networks = append(networks, entry)
	}
	return networks
}

func (e Executor) syncPeers(ctx context.Context) error {
	networks := e.peerNetworks()
	if len(networks) == 0 {
		return nil
	}
	if !e.bridgeFiltered() {
		hour := strconv.FormatInt(e.Now().Truncate(time.Hour).Unix(), 10)
		for index := range networks {
			networks[index].Allow = nil
		}
		e.event("rule", "rule:"+shortHash("br_netfilter", hour), map[string]string{"chain": network.PeersChain, "rule": "bridge-nf-call-iptables is off, so no member of a Contained network reaches another"})
	}
	wanted := network.Peers(networks)
	if e.listed(ctx, "iptables", network.PeersChain) != strings.Join(append([]string{"-N " + network.PeersChain}, wanted...), "\n") {
		if err := writeWhole(e.networkDir(), peersFile, []byte(network.PeersRestore(wanted)), 0o600); err != nil {
			return err
		}
		if err := e.firewall(ctx, "iptables-restore", "--noflush", filepath.Join(e.networkDir(), peersFile)); err != nil {
			return fmt.Errorf("write the rules of Contained networks: %w", err)
		}
	}
	e.firewall(ctx, "iptables", "-N", dockerUser)
	bridges := map[string]bool{}
	for _, entry := range networks {
		bridges[entry.Bridge] = true
		if err := e.ensure(ctx, "iptables", []string{"-I", dockerUser, "1"}, dockerUser, network.PeersJump(entry.Bridge)); err != nil {
			return fmt.Errorf("send Contained networks through their rules: %w", err)
		}
	}
	listed, _ := e.output(ctx, "iptables", "-S", dockerUser)
	for line := range strings.SplitSeq(listed, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 8 && fields[0] == "-A" && fields[1] == dockerUser && fields[7] == network.PeersChain && !bridges[fields[3]] {
			e.firewall(ctx, "iptables", append([]string{"-D", dockerUser}, fields[2:]...)...)
		}
	}
	return nil
}

type sharedUse struct {
	key, name string
	services  []string
}

func servicesOn(config map[string]any, key string) []string {
	var names []string
	services := asMap(config["services"])
	for _, name := range sortedKeys(services) {
		service := asMap(services[name])
		joined := service["networks"]
		switch {
		case joined == nil:
			if key == "default" && service["network_mode"] == nil {
				names = append(names, name)
			}
		case asMap(joined) != nil:
			if _, found := asMap(joined)[key]; found {
				names = append(names, name)
			}
		case slices.ContainsFunc(asList(joined), func(item any) bool { return asText(item) == key }):
			names = append(names, name)
		}
	}
	return names
}

func (e Executor) kindOf(ctx context.Context) func(string) string {
	return func(name string) string {
		if record, owned := e.ownedBridge(ctx, name); owned {
			return record.Kind
		}
		if _, found := e.output(ctx, "docker", "network", "inspect", "-f", "{{.Id}}", name); found {
			return "outside"
		}
		return ""
	}
}

func externalName(key string, network map[string]any) string {
	if name := asText(network["name"]); name != "" {
		return name
	}
	return key
}

func sharedUses(config map[string]any, kindOf func(string) string) []sharedUse {
	var uses []sharedUse
	networks := asMap(config["networks"])
	for _, key := range sortedKeys(networks) {
		network := asMap(networks[key])
		if network["external"] != true {
			continue
		}
		if name := externalName(key, network); kindOf(name) == "contained" {
			uses = append(uses, sharedUse{key: key, name: name, services: servicesOn(config, key)})
		}
	}
	return uses
}

var guestCapabilities = []string{"NET_ADMIN", "NET_RAW", "ALL"}

func checkShared(config map[string]any, uses []sharedUse, guest bool) error {
	services := asMap(config["services"])
	for _, use := range uses {
		for _, name := range use.services {
			service := asMap(services[name])
			for _, copies := range []any{service["scale"], asMap(service["deploy"])["replicas"]} {
				if count, ok := number(copies); ok && count > 1 {
					return fmt.Errorf("%s runs %d copies; a service on a Contained network runs one, so its address stays fixed.", name, int(count))
				}
			}
			if !guest {
				continue
			}
			if service["privileged"] == true {
				return fmt.Errorf("%s is privileged, so it cannot join %s, a Contained network.", name, use.name)
			}
			for _, raw := range asList(service["cap_add"]) {
				capability := strings.TrimPrefix(strings.ToUpper(asText(raw)), "CAP_")
				if slices.Contains(guestCapabilities, capability) {
					return fmt.Errorf("%s adds %s, so it cannot join %s, a Contained network.", name, capability, use.name)
				}
			}
			if asText(service["network_mode"]) != "" {
				return fmt.Errorf("%s sets network_mode, so it cannot join %s, a Contained network.", name, use.name)
			}
		}
	}
	return nil
}

func (e Executor) checkEntries(project string, meta stackMeta, uses []sharedUse) error {
	joined := func(name string) (sharedUse, error) {
		for _, use := range uses {
			if use.name == name {
				return use, nil
			}
		}
		return sharedUse{}, fmt.Errorf("%s does not join %s, a Contained network on this server.", project, name)
	}
	for _, offer := range meta.Offers {
		where, _, _ := strings.Cut(offer, "=")
		name, service, _ := strings.Cut(where, "/")
		use, err := joined(name)
		if err != nil {
			return err
		}
		if !slices.Contains(use.services, service) {
			return fmt.Errorf("%s is not on %s.", service, name)
		}
	}
	for _, peer := range meta.Peers {
		match := peerEntry.FindStringSubmatch(peer)
		if match == nil {
			return fmt.Errorf("%s is not a port of another stack such as apps-inner/postgres.db:5432/tcp", peer)
		}
		if _, err := joined(match[1]); err != nil {
			return err
		}
		offers := meta.Offers
		if match[3] != project {
			offers = e.metaOf(filepath.Join(e.StateDir, "compose", match[3])).Offers
		}
		if !slices.Contains(offers, match[1]+"/"+match[2]+"="+match[4]+"/"+match[5]) {
			return fmt.Errorf("%s.%s does not offer %s/%s on %s.", match[2], match[3], match[4], match[5], match[1])
		}
	}
	return nil
}

type pinned struct {
	service, key, address, alias string
}

func (e Executor) pinShared(project string, uses []sharedUse) ([]pinned, error) {
	if len(uses) == 0 {
		return nil, nil
	}
	records := e.readBridges()
	var pins []pinned
	for _, use := range uses {
		record := records[use.name]
		for _, service := range use.services {
			address, err := pin(use.name, &record, project+"/"+service)
			if err != nil {
				return nil, err
			}
			pins = append(pins, pinned{service: service, key: use.key, address: address, alias: service + "." + project})
		}
		records[use.name] = record
	}
	return pins, e.saveBridges(records)
}

func applyPins(target, base map[string]any, pins []pinned) {
	services := asMap(target["services"])
	if services == nil {
		services = map[string]any{}
		target["services"] = services
	}
	for _, entry := range pins {
		service := asMap(services[entry.service])
		if service == nil {
			service = map[string]any{}
			services[entry.service] = service
		}
		settings := serviceNetwork(service, entry.key)
		aliases := asList(asMap(asMap(asMap(asMap(base["services"])[entry.service])["networks"])[entry.key])["aliases"])
		if !slices.Contains(aliases, any(entry.alias)) {
			aliases = append(slices.Clone(aliases), entry.alias)
		}
		settings["ipv4_address"], settings["aliases"] = entry.address, aliases
		if drops := asList(service["cap_drop"]); !slices.Contains(drops, any("NET_RAW")) {
			service["cap_drop"] = append(slices.Clone(drops), "NET_RAW")
		}
	}
}
