package actions

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

type Service = reporter.ServiceEntry

type Runner func(ctx context.Context, name string, args ...string) ([]byte, int, error)

const (
	maxServices = 500
	maxStacks   = 50
)

var collectTimeout = 30 * time.Second

var copyTimeout = 15 * time.Minute

const createdLayout = "2006-01-02 15:04:05 -0700"

const containerFormat = "{{.Names}}\t{{.State}}\t{{.Label \"com.docker.compose.project\"}}\t{{.Label \"com.docker.compose.project.working_dir\"}}\t{{.Label \"com.docker.compose.project.config_files\"}}\t{{.CreatedAt}}\t{{.Ports}}\t{{.Label \"com.docker.compose.service\"}}"

type Stack struct {
	Project    string
	Directory  string
	Files      []string
	Running    int
	Total      int
	Public     []string
	Bindings   []reporter.Listener
	Containers []string
	Services   []string
}

type Snapshot struct {
	Services []Service
	Stacks   []Stack
	Compose  bool
	Docker   string
}

type Inventory struct {
	Hash      string                   `json:"hash"`
	TakenAt   string                   `json:"takenAt"`
	Services  []Service                `json:"services"`
	Stacks    []reporter.StackEntry    `json:"stacks"`
	Trust     reporter.TrustReport     `json:"trust"`
	Docker    string                   `json:"docker,omitempty"`
	Removed   []reporter.RemovedStack  `json:"removed"`
	Leftovers []string                 `json:"leftovers"`
	SealKey   string                   `json:"sealKey,omitempty"`
	Security  *reporter.SecurityReport `json:"security,omitempty"`
	Vault     *reporter.VaultReport    `json:"vault,omitempty"`

	TailscaleVault *reporter.VaultReport      `json:"tailscaleVault,omitempty"`
	Packages       *reporter.PackagesReport   `json:"packages,omitempty"`
	PackagesHash   string                     `json:"packagesHash,omitempty"`
	Tailscale      *reporter.TailscaleReport  `json:"tailscale,omitempty"`
	Network        *reporter.NetworkInventory `json:"network,omitempty"`
	Bridges        *reporter.Bridges          `json:"bridges,omitempty"`
}

type Parts struct {
	Services  []Service
	Stacks    []reporter.StackEntry
	Trust     reporter.TrustReport
	Docker    string
	Removed   []reporter.RemovedStack
	Leftovers []string
	SealKey   string
	Security  *reporter.SecurityReport
	Vault     *reporter.VaultReport
	Packages  *reporter.PackagesReport
	Tailscale *reporter.TailscaleReport
	Network   *reporter.NetworkInventory
	Bridges   *reporter.Bridges

	TailscaleVault *reporter.VaultReport
}

var unitStates = map[string]string{
	"active": "running", "reloading": "running", "activating": "starting",
	"deactivating": "starting", "failed": "failed", "inactive": "stopped",
}

var containerStates = map[string]string{
	"running": "running", "restarting": "starting", "created": "stopped",
	"paused": "stopped", "exited": "stopped", "removing": "stopped", "dead": "failed",
}

func parseUnits(units, files string, remembered []string) []Service {
	on := map[string]bool{}
	present := map[string]bool{}
	for line := range strings.SplitSeq(files, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		present[fields[0]] = true
		if len(fields) > 1 && strings.HasPrefix(fields[1], "enabled") {
			on[fields[0]] = true
		}
	}
	listed := map[string]bool{}
	var services []Service
	for line := range strings.SplitSeq(units, "\n") {
		fields := strings.Fields(strings.TrimLeft(line, "●* "))
		if len(fields) < 4 {
			continue
		}
		name, load, active := fields[0], fields[1], fields[2]
		state, known := unitStates[active]
		if load != "loaded" || !known || !ValidTarget("systemd", name) || Protected("systemd", name) {
			continue
		}
		if active == "inactive" && !on[name] {
			continue
		}
		listed[name] = true
		services = append(services, Service{Kind: "systemd", Name: name, State: state, System: systemUnit(name)})
	}
	for _, name := range remembered {
		if listed[name] || !ValidTarget("systemd", name) || Protected("systemd", name) || !unitFileExists(present, name) {
			continue
		}
		listed[name] = true
		services = append(services, Service{Kind: "systemd", Name: name, State: "stopped", System: systemUnit(name)})
	}
	return services
}

func bootStates(show string) map[string]Service {
	states := map[string]Service{}
	for block := range strings.SplitSeq(strings.ReplaceAll(show, "\r\n", "\n"), "\n\n") {
		fields := map[string]string{}
		for line := range strings.SplitSeq(block, "\n") {
			if key, value, ok := strings.Cut(line, "="); ok {
				fields[key] = value
			}
		}
		if fields["Id"] == "" {
			continue
		}
		state := Service{State: "stopped"}
		switch {
		case fields["ConditionResult"] == "no":
			state.State = "unneeded"
		case fields["Type"] == "oneshot" && fields["Result"] == "success" && fields["ExecMainCode"] == "1" && fields["ExecMainStatus"] == "0":
			state.State = "boot"
			if at, err := time.ParseInLocation("Mon 2006-01-02 15:04:05 MST", fields["ExecMainExitTimestamp"], time.Local); err == nil {
				since := at.UTC().Format(time.RFC3339)
				state.Since = &since
			}
		}
		states[fields["Id"]] = state
	}
	return states
}

func unitFileExists(present map[string]bool, name string) bool {
	if present[name] {
		return true
	}
	if at := strings.Index(name, "@"); at >= 0 {
		return present[name[:at+1]+".service"]
	}
	return false
}

func absolute(path string) bool {
	return strings.HasPrefix(path, "/") && !strings.ContainsRune(path, 0)
}

func fieldAt(fields []string, index int) string {
	if index < len(fields) {
		return fields[index]
	}
	return ""
}

func publicPorts(text string) []string {
	var ports []string
	for _, bound := range publicBindings(text) {
		if port := strconv.Itoa(bound.Port) + "/" + bound.Protocol; !slices.Contains(ports, port) {
			ports = append(ports, port)
		}
	}
	return ports
}

func publicBindings(text string) []reporter.Listener {
	var bindings []reporter.Listener
	for item := range strings.SplitSeq(text, ",") {
		host, inside, found := strings.Cut(strings.TrimSpace(item), "->")
		if !found {
			continue
		}
		colon := strings.LastIndex(host, ":")
		_, protocol, _ := strings.Cut(inside, "/")
		if colon < 0 || (protocol != "tcp" && protocol != "udp") {
			continue
		}
		address := strings.Trim(host[:colon], "[]")
		if strings.HasPrefix(address, "127.") || address == "::1" {
			continue
		}
		first, _, _ := strings.Cut(host[colon+1:], "-")
		port, err := strconv.Atoi(first)
		if err != nil {
			continue
		}
		bindings = append(bindings, reporter.Listener{Address: address, Port: port, Protocol: protocol})
	}
	return bindings
}

func parseContainers(output string) ([]Service, []Stack) {
	var services []Service
	found := map[string]*Stack{}
	newest := map[string]time.Time{}
	broken := map[string]bool{}
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) < 2 {
			continue
		}
		name, _, _ := strings.Cut(fields[0], ",")
		state, known := containerStates[fields[1]]
		if !known || !ValidTarget("docker", name) {
			continue
		}
		services = append(services, Service{Kind: "docker", Name: name, State: state})
		if len(fields) < 5 || fields[2] == "" {
			continue
		}
		project, directory, files := fields[2], fields[3], strings.Split(fields[4], ",")
		valid := ValidTarget("compose", project) && absolute(directory)
		for _, file := range files {
			valid = valid && absolute(file)
		}
		stack, seen := found[project]
		if !valid || (seen && stack.Directory != directory) {
			broken[project] = true
			continue
		}
		var created time.Time
		if stamp := strings.Fields(fieldAt(fields, 5)); len(stamp) >= 3 {
			created, _ = time.Parse(createdLayout, strings.Join(stamp[:3], " "))
		}
		if !seen {
			stack = &Stack{Project: project, Directory: directory}
			found[project] = stack
		}
		if !seen || created.After(newest[project]) {
			stack.Files = files
			newest[project] = created
		}
		stack.Total++
		stack.Containers = append(stack.Containers, name)
		if service := fieldAt(fields, 7); ValidTarget("docker", service) && !slices.Contains(stack.Services, service) {
			stack.Services = append(stack.Services, service)
		}
		if state == "running" {
			stack.Running++
		}
		for _, port := range publicPorts(fieldAt(fields, 6)) {
			if !slices.Contains(stack.Public, port) {
				stack.Public = append(stack.Public, port)
			}
		}
		for _, bound := range publicBindings(fieldAt(fields, 6)) {
			if !slices.Contains(stack.Bindings, bound) {
				stack.Bindings = append(stack.Bindings, bound)
			}
		}
	}
	var stacks []Stack
	for project, stack := range found {
		if broken[project] {
			continue
		}
		slices.Sort(stack.Containers)
		slices.Sort(stack.Services)
		stacks = append(stacks, *stack)
	}
	slices.SortFunc(stacks, func(a, b Stack) int { return cmp.Compare(a.Project, b.Project) })
	return services, stacks
}

func NewInventory(parts Parts, now time.Time) (Inventory, error) {
	services, stacks, trust, docker, removed := parts.Services, parts.Stacks, parts.Trust, parts.Docker, parts.Removed
	removed = slices.Clone(removed)
	if removed == nil {
		removed = []reporter.RemovedStack{}
	}
	slices.SortFunc(removed, func(a, b reporter.RemovedStack) int {
		return cmp.Or(cmp.Compare(b.RemovedAt, a.RemovedAt), cmp.Compare(a.Project, b.Project))
	})
	if len(removed) > maxStacks {
		removed = removed[:maxStacks]
	}
	leftovers := slices.Clone(parts.Leftovers)
	if leftovers == nil {
		leftovers = []string{}
	}
	sorted := slices.Clone(services)
	if sorted == nil {
		sorted = []Service{}
	}
	slices.SortFunc(sorted, func(a, b Service) int {
		return cmp.Or(cmp.Compare(rank(a), rank(b)), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Name, b.Name))
	})
	if len(sorted) > maxServices {
		sorted = sorted[:maxServices]
	}
	listed := slices.Clone(stacks)
	if listed == nil {
		listed = []reporter.StackEntry{}
	}
	slices.SortFunc(listed, func(a, b reporter.StackEntry) int { return cmp.Compare(a.Project, b.Project) })
	if len(listed) > maxStacks {
		listed = listed[:maxStacks]
	}
	if trust.Core == nil {
		trust.Core = []string{}
	}
	if trust.Access == nil {
		trust.Access = []string{}
	}
	packagesHash := ""
	if parts.Packages != nil {
		encoded, err := json.Marshal(parts.Packages)
		if err != nil {
			return Inventory{}, err
		}
		sum := sha256.Sum256(encoded)
		packagesHash = hex.EncodeToString(sum[:])
	}
	encoded, err := json.Marshal(struct {
		Services  []Service                  `json:"services"`
		Stacks    []reporter.StackEntry      `json:"stacks"`
		Trust     reporter.TrustReport       `json:"trust"`
		Docker    string                     `json:"docker"`
		Removed   []reporter.RemovedStack    `json:"removed"`
		Leftovers []string                   `json:"leftovers"`
		SealKey   string                     `json:"sealKey"`
		Security  *reporter.SecurityReport   `json:"security"`
		Vault     *reporter.VaultReport      `json:"vault"`
		Packages  string                     `json:"packages"`
		Tailscale *reporter.TailscaleReport  `json:"tailscale"`
		Network   *reporter.NetworkInventory `json:"network"`

		TailscaleVault *reporter.VaultReport `json:"tailscaleVault,omitempty"`
		Bridges        *reporter.Bridges     `json:"bridges"`
	}{sorted, listed, trust, docker, removed, leftovers, parts.SealKey, parts.Security, parts.Vault, packagesHash, parts.Tailscale, parts.Network, parts.TailscaleVault, parts.Bridges})
	if err != nil {
		return Inventory{}, err
	}
	sum := sha256.Sum256(encoded)
	return Inventory{Hash: hex.EncodeToString(sum[:]), TakenAt: now.UTC().Format(time.RFC3339Nano), Services: sorted, Stacks: listed, Trust: trust, Docker: docker, Removed: removed, Leftovers: leftovers, SealKey: parts.SealKey, Security: parts.Security, Vault: parts.Vault, Packages: parts.Packages, PackagesHash: packagesHash, Tailscale: parts.Tailscale, Network: parts.Network, TailscaleVault: parts.TailscaleVault, Bridges: parts.Bridges}, nil
}

func rank(service Service) int {
	if service.System {
		return 1
	}
	return 0
}

func Collect(ctx context.Context, run Runner, remembered []string) (Snapshot, error) {
	step := func(name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, collectTimeout)
		defer cancel()
		output, _, err := run(ctx, name, args...)
		return output, err
	}
	units, err := step("systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager")
	if err != nil {
		return Snapshot{}, fmt.Errorf("list units: %w", err)
	}
	files, err := step("systemctl", "list-unit-files", "--type=service", "--no-legend", "--plain", "--no-pager")
	if err != nil {
		return Snapshot{}, fmt.Errorf("list unit files: %w", err)
	}
	snapshot := Snapshot{Services: parseUnits(string(units), string(files), remembered), Docker: "missing"}
	var stopped []string
	for _, service := range snapshot.Services {
		if service.State == "stopped" {
			stopped = append(stopped, service.Name)
		}
	}
	if len(stopped) > 0 {
		if show, err := step("systemctl", append([]string{"show", "--property=Id,Type,Result,ConditionResult,ExecMainCode,ExecMainStatus,ExecMainExitTimestamp", "--no-pager"}, stopped...)...); err == nil {
			states := bootStates(string(show))
			for index, service := range snapshot.Services {
				if found, ok := states[service.Name]; ok && service.State == "stopped" {
					snapshot.Services[index].State, snapshot.Services[index].Since = found.State, found.Since
				}
			}
		}
	}
	if containers, err := step("docker", "ps", "-a", "--no-trunc", "--format", containerFormat); err == nil {
		services, stacks := parseContainers(string(containers))
		snapshot.Services = append(snapshot.Services, services...)
		snapshot.Stacks = stacks
		snapshot.Docker = "no-compose"
		if _, err := step("docker", "compose", "version"); err == nil {
			snapshot.Compose = true
			snapshot.Docker = "ready"
		}
	}
	return snapshot, nil
}

func splitLines(data []byte, atEOF bool) (int, []byte, error) {
	if index := bytes.IndexAny(data, "\r\n"); index >= 0 {
		return index + 1, data[:index], nil
	}
	if (atEOF && len(data) > 0) || len(data) >= 8<<10 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func StreamCommand(ctx context.Context, each func(string), name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.WaitDelay = 5 * time.Second
	reader, writer := io.Pipe()
	command.Stdout, command.Stderr = writer, writer
	if err := command.Start(); err != nil {
		return err
	}
	read := make(chan struct{})
	go func() {
		defer close(read)
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 0, 4096), 16<<10)
		scanner.Split(splitLines)
		for scanner.Scan() {
			if line := strings.TrimSpace(sanitize(scanner.Bytes())); line != "" {
				each(line)
			}
		}
		io.Copy(io.Discard, reader)
	}()
	err := command.Wait()
	writer.Close()
	<-read
	return err
}
func RunCommand(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.WaitDelay = 5 * time.Second
	output, err := command.CombinedOutput()
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return output, exitErr.ExitCode(), err
	}
	if err != nil {
		return output, -1, err
	}
	return output, 0, nil
}
