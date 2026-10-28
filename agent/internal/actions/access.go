package actions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

const (
	guardBridges    = "krc+"
	metadataAddress = "169.254.169.254"
	metadataIPv6    = "fd00:ec2::254"
	diskReserve     = 1_000_000_000
)

type stackMeta struct {
	Access    string            `json:"access"`
	HostPorts []string          `json:"hostPorts,omitempty"`
	Serves    []network.Serve   `json:"serves,omitempty"`
	Reaches   []string          `json:"reaches,omitempty"`
	Offers    []string          `json:"offers,omitempty"`
	Peers     []string          `json:"peers,omitempty"`
	Networks  map[string]string `json:"networks,omitempty"`
	Title     string            `json:"title,omitempty"`
	Names     map[string]string `json:"names,omitempty"`
}

const maxHostPorts = 16

var hostPortPattern = regexp.MustCompile(`^(\d{1,5})/(tcp|udp)$`)

func hostPortsFrom(command Command, access string, current []string) ([]string, error) {
	raw, given := command.Args["hostPorts"]
	if !given {
		if access != "contained" {
			return nil, nil
		}
		return current, nil
	}
	var ports []string
	for entry := range strings.SplitSeq(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		match := hostPortPattern.FindStringSubmatch(entry)
		if match == nil {
			return nil, fmt.Errorf("%s is not a port such as 3000/tcp", entry)
		}
		if number, _ := strconv.Atoi(match[1]); number < 1 || number > 65535 {
			return nil, fmt.Errorf("%s is not a port between 1 and 65535", entry)
		}
		if !slices.Contains(ports, entry) {
			ports = append(ports, entry)
		}
	}
	switch {
	case len(ports) > maxHostPorts:
		return nil, fmt.Errorf("a stack may reach at most %d ports on the server", maxHostPorts)
	case len(ports) > 0 && access != "contained":
		return nil, errors.New("reaching the server on chosen ports is for Contained stacks; a Full access stack already reaches it")
	}
	return ports, nil
}

func (e Executor) hostPortsOf(directory string) []string {
	meta, err := readState[stackMeta](directory, "krynodes.json")
	if err != nil {
		return nil
	}
	return meta.HostPorts
}

type shareLimit struct {
	key, deployKey, label string
	max                   float64
}

var shareLimits = []shareLimit{
	{"cpus", "cpus", "1 CPU", 1},
	{"mem_limit", "memory", "1 GB of memory", 1 << 30},
	{"pids_limit", "pids", "512 processes", 512},
}

func (e Executor) accessOf(directory string) string {
	if !e.ownStack(directory) {
		return ""
	}
	meta, err := readState[stackMeta](directory, "krynodes.json")
	if err == nil && (meta.Access == "contained" || meta.Access == "full") {
		return meta.Access
	}
	if regularFile(filepath.Join(directory, "compose.krynodes.json")) {
		return "contained"
	}
	return ""
}

func (e Executor) hasContained() bool {
	entries, err := os.ReadDir(filepath.Join(e.StateDir, "compose"))
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() && e.accessOf(filepath.Join(e.StateDir, "compose", entry.Name())) == "contained" {
			return true
		}
	}
	return false
}

var guardRules = [][]string{
	{"iptables", "DOCKER-USER", "-i", guardBridges, "-d", metadataAddress, "-j", "DROP"},
	{"ip6tables", "DOCKER-USER", "-i", guardBridges, "-d", metadataIPv6, "-j", "DROP"},
}

const containChain = "KRY-CONTAINED"

var (
	containTools = []string{"iptables", "ip6tables"}
	repliesRule  = []string{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}
	jumpRule     = []string{"-i", guardBridges, "-j", containChain}
	oldDropRule  = []string{"-i", guardBridges, "-j", "DROP"}
)

func (e Executor) Contain(ctx context.Context) {
	if err := e.syncRules(ctx); err != nil {
		log.Printf("private network rules: %v", err)
	}
	if !e.hasContained() {
		return
	}
	e.guard(ctx)
}

func (e Executor) firewall(ctx context.Context, tool string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()
	_, _, err := e.Run(ctx, tool, args...)
	return err
}

func (e Executor) ensure(ctx context.Context, tool string, add []string, chain string, rule []string) error {
	if e.firewall(ctx, tool, append([]string{"-C", chain}, rule...)...) == nil {
		return nil
	}
	err := e.firewall(ctx, tool, append(add, rule...)...)
	if err != nil {
		log.Printf("contain %s %s: %v", tool, chain, err)
	}
	return err
}

func (e Executor) guard(ctx context.Context) {
	for _, tool := range containTools {
		e.firewall(ctx, tool, "-N", "DOCKER-USER")
	}
	for _, rule := range guardRules {
		e.ensure(ctx, rule[0], []string{"-I", rule[1]}, rule[1], rule[2:])
	}
	for _, tool := range containTools {
		e.firewall(ctx, tool, "-N", containChain)
		e.ensure(ctx, tool, []string{"-A", containChain}, containChain, []string{"-j", "DROP"})
		e.ensure(ctx, tool, []string{"-I", containChain, "1"}, containChain, repliesRule)
		e.reach(ctx, tool)
		e.ensure(ctx, tool, []string{"-I", "INPUT", "1"}, "INPUT", jumpRule)
		if e.firewall(ctx, tool, append([]string{"-C", "INPUT"}, oldDropRule...)...) == nil {
			e.firewall(ctx, tool, append([]string{"-D", "INPUT"}, oldDropRule...)...)
		}
	}
	e.ports(ctx, e.hostPortTable())
}

var portsLog = []string{"-m", "limit", "--limit", "600/min", "-j", "LOG", "--log-prefix", network.ReachPrefix, "--log-level", "6"}

func (e Executor) ports(ctx context.Context, table map[string][]string) {
	e.firewall(ctx, "iptables", "-N", network.PortsChain)
	wanted := network.Ports(table)
	for _, rule := range wanted {
		e.ensure(ctx, "iptables", []string{"-I", network.PortsChain, "1"}, network.PortsChain, rule)
	}
	listed, _ := e.output(ctx, "iptables", "-S", network.PortsChain)
	prefix := "-A " + network.PortsChain + " "
	for line := range strings.SplitSeq(listed, "\n") {
		rule, found := strings.CutPrefix(strings.TrimSpace(line), prefix)
		if !found || !strings.HasPrefix(rule, "-i krc") || !strings.HasSuffix(rule, "-j RETURN") {
			continue
		}
		if !slices.ContainsFunc(wanted, func(want []string) bool { return strings.Join(want, " ") == rule }) {
			e.firewall(ctx, "iptables", append([]string{"-D", network.PortsChain}, strings.Fields(rule)...)...)
		}
	}
	e.ensure(ctx, "iptables", []string{"-A", network.PortsChain}, network.PortsChain, portsLog)
	e.ensure(ctx, "iptables", []string{"-A", network.PortsChain}, network.PortsChain, []string{"-j", "DROP"})
	e.ensure(ctx, "iptables", []string{"-I", "DOCKER-USER", "1"}, "DOCKER-USER", network.PortsJump)
}

func (e Executor) hostPortTable() map[string][]string {
	table := map[string][]string{}
	for _, directory := range e.stackDirectories() {
		ports := e.hostPortsOf(directory)
		if len(ports) == 0 || e.accessOf(directory) != "contained" {
			continue
		}
		var config map[string]any
		if readJSON(filepath.Join(directory, "compose.krynodes.json"), &config) != nil {
			continue
		}
		for _, bridge := range bridgesOf(config) {
			table[bridge] = ports
		}
	}
	return table
}

func (e Executor) reach(ctx context.Context, tool string) {
	wanted := e.reachRules()
	for _, rule := range wanted {
		e.ensure(ctx, tool, []string{"-I", containChain, "1"}, containChain, rule)
	}
	listed, _ := e.output(ctx, tool, "-S", containChain)
	prefix := "-A " + containChain + " "
	for line := range strings.SplitSeq(listed, "\n") {
		rule, found := strings.CutPrefix(strings.TrimSpace(line), prefix)
		if !found || !strings.HasPrefix(rule, "-i krc") || !strings.Contains(rule, "--dport") {
			continue
		}
		if !slices.ContainsFunc(wanted, func(want []string) bool { return strings.Join(want, " ") == rule }) {
			e.firewall(ctx, tool, append([]string{"-D", containChain}, strings.Fields(rule)...)...)
		}
	}
}

func (e Executor) reachRules() [][]string {
	table := e.hostPortTable()
	var rules [][]string
	for _, bridge := range slices.Sorted(maps.Keys(table)) {
		rules = append(rules, reachOn(bridge, table[bridge])...)
	}
	return rules
}

func reachOn(bridge string, ports []string) [][]string {
	var rules [][]string
	for _, port := range ports {
		number, protocol, _ := strings.Cut(port, "/")
		rules = append(rules, []string{"-i", bridge, "-p", protocol, "-m", protocol, "--dport", number, "-j", "ACCEPT"})
	}
	return rules
}

func ownPorts(config map[string]any, ports []string) map[string][]string {
	table := map[string][]string{}
	for _, bridge := range bridgesOf(config) {
		table[bridge] = ports
	}
	return table
}

func (e Executor) openReach(ctx context.Context, config map[string]any, ports []string) {
	if len(ports) == 0 {
		return
	}
	e.guard(ctx)
	for _, tool := range containTools {
		for _, bridge := range bridgesOf(config) {
			for _, rule := range reachOn(bridge, ports) {
				e.ensure(ctx, tool, []string{"-I", containChain, "1"}, containChain, rule)
			}
		}
	}
	for _, rule := range network.Ports(ownPorts(config, ports)) {
		e.ensure(ctx, "iptables", []string{"-I", network.PortsChain, "1"}, network.PortsChain, rule)
	}
}

var units = []struct {
	suffix string
	scale  float64
}{{"kb", 1 << 10}, {"mb", 1 << 20}, {"gb", 1 << 30}, {"k", 1 << 10}, {"m", 1 << 20}, {"g", 1 << 30}, {"b", 1}}

func number(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case string:
		text := strings.ToLower(strings.TrimSpace(typed))
		scale := 1.0
		for _, unit := range units {
			if strings.HasSuffix(text, unit.suffix) {
				text, scale = strings.TrimSpace(strings.TrimSuffix(text, unit.suffix)), unit.scale
				break
			}
		}
		parsed, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return 0, false
		}
		return parsed * scale, true
	}
	return 0, false
}

func limit(name string, service map[string]any) error {
	limits := asMap(asMap(asMap(service["deploy"])["resources"])["limits"])
	for _, share := range shareLimits {
		value, set := number(service[share.key])
		deployed, deploySet := number(limits[share.deployKey])
		for _, found := range []struct {
			value float64
			set   bool
		}{{value, set}, {deployed, deploySet}} {
			if found.set && (found.value <= 0 || found.value > share.max) {
				return fmt.Errorf("service %s asks for more than %s; a Contained stack gets at most that per service, so choose Full access for more", name, share.label)
			}
		}
		if !set && !deploySet {
			service[share.key] = share.max
		}
	}
	return nil
}

func bridgeName(project, network string) string {
	sum := sha256.Sum256([]byte(project + "/" + network))
	return "krc" + hex.EncodeToString(sum[:])[:12]
}

func contain(config map[string]any, project string) error {
	services := asMap(config["services"])
	for _, name := range sortedKeys(services) {
		if err := limit(name, asMap(services[name])); err != nil {
			return err
		}
	}
	networks := asMap(config["networks"])
	if networks == nil {
		networks = map[string]any{}
		config["networks"] = networks
	}
	if _, ok := networks["default"]; !ok {
		networks["default"] = map[string]any{"name": project + "_default"}
	}
	for _, name := range sortedKeys(networks) {
		network := asMap(networks[name])
		if network == nil {
			network = map[string]any{}
			networks[name] = network
		}
		if network["external"] == true {
			continue
		}
		if driver := asText(network["driver"]); driver != "" && driver != "bridge" {
			return fmt.Errorf("network %s uses the %s driver; a Contained stack uses bridge networks", name, driver)
		}
		options := asMap(network["driver_opts"])
		if options == nil {
			options = map[string]any{}
			network["driver_opts"] = options
		}
		options["com.docker.network.bridge.name"] = bridgeName(project, name)
	}
	return nil
}

type layers struct {
	Layers []struct {
		Size int64 `json:"size"`
	} `json:"layers"`
}

type platformManifest struct {
	Descriptor struct {
		Platform struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
		} `json:"platform"`
	} `json:"Descriptor"`
	SchemaV2Manifest *layers `json:"SchemaV2Manifest"`
	OCIManifest      *layers `json:"OCIManifest"`
}

func (m platformManifest) size() (int64, bool) {
	found := m.SchemaV2Manifest
	if found == nil {
		found = m.OCIManifest
	}
	if found == nil {
		return 0, false
	}
	var total int64
	for _, layer := range found.Layers {
		total += layer.Size
	}
	return total, true
}

func imageSize(raw []byte, arch string) (int64, bool) {
	var list []platformManifest
	if json.Unmarshal(raw, &list) == nil {
		for _, entry := range list {
			if entry.Descriptor.Platform.OS == "linux" && entry.Descriptor.Platform.Architecture == arch {
				return entry.size()
			}
		}
		return 0, false
	}
	var single platformManifest
	if json.Unmarshal(raw, &single) != nil {
		return 0, false
	}
	return single.size()
}

func gigabytes(size uint64) string {
	return fmt.Sprintf("%.1f GB", float64(size)/1e9)
}

func (e Executor) freeSpace(path string) (uint64, error) {
	if e.Free != nil {
		return e.Free(path)
	}
	return freeBytes(path)
}

func (e Executor) fits(ctx context.Context, config map[string]any) error {
	root, err := e.docker(ctx, collectTimeout, "info", "info", "--format", "{{.DockerRootDir}}")
	if err != nil || strings.TrimSpace(string(root)) == "" {
		return nil
	}
	available, err := e.freeSpace(strings.TrimSpace(string(root)))
	if err != nil {
		return nil
	}
	var needed uint64
	seen := map[string]bool{}
	services := asMap(config["services"])
	for _, name := range sortedKeys(services) {
		service := asMap(services[name])
		image := asText(service["image"])
		if image == "" || service["build"] != nil || seen[image] {
			continue
		}
		seen[image] = true
		if _, err := e.docker(ctx, collectTimeout, "image", "image", "inspect", "--format", "{{.Id}}", image); err == nil {
			continue
		}
		manifest, err := e.docker(ctx, collectTimeout, "manifest", "manifest", "inspect", "-v", image)
		if err != nil {
			continue
		}
		if size, ok := imageSize(manifest, runtime.GOARCH); ok && size > 0 {
			needed += uint64(size)
		}
	}
	if want := needed*2 + diskReserve; needed > 0 && want > available {
		return fmt.Errorf("the images need about %s with room to spare; the server has %s free", gigabytes(want), gigabytes(available))
	}
	return nil
}
