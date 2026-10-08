package actions

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"slices"
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

const containerFormat = "{{.Names}}\t{{.State}}\t{{.Label \"com.docker.compose.project\"}}\t{{.Label \"com.docker.compose.project.working_dir\"}}\t{{.Label \"com.docker.compose.project.config_files\"}}\t{{.CreatedAt}}\t{{.Ports}}"

type Stack struct {
	Project   string
	Directory string
	Files     []string
	Running   int
	Total     int
	Public    []string
}

type Snapshot struct {
	Services []Service
	Stacks   []Stack
	Compose  bool
	Docker   string
}

type Inventory struct {
	Hash     string                   `json:"hash"`
	TakenAt  string                   `json:"takenAt"`
	Services []Service                `json:"services"`
	Stacks   []reporter.StackEntry    `json:"stacks"`
	Trust    reporter.TrustReport     `json:"trust"`
	Docker   string                   `json:"docker,omitempty"`
	Removed  []reporter.RemovedStack  `json:"removed"`
	SealKey  string                   `json:"sealKey,omitempty"`
	Security *reporter.SecurityReport `json:"security,omitempty"`
	Vault    *reporter.VaultReport    `json:"vault,omitempty"`
}

type Parts struct {
	Services []Service
	Stacks   []reporter.StackEntry
	Trust    reporter.TrustReport
	Docker   string
	Removed  []reporter.RemovedStack
	SealKey  string
	Security *reporter.SecurityReport
	Vault    *reporter.VaultReport
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
		if port := first + "/" + protocol; !slices.Contains(ports, port) {
			ports = append(ports, port)
		}
	}
	return ports
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
		if state == "running" {
			stack.Running++
		}
		for _, port := range publicPorts(fieldAt(fields, 6)) {
			if !slices.Contains(stack.Public, port) {
				stack.Public = append(stack.Public, port)
			}
		}
	}
	var stacks []Stack
	for project, stack := range found {
		if broken[project] {
			continue
		}
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
	encoded, err := json.Marshal(struct {
		Services []Service                `json:"services"`
		Stacks   []reporter.StackEntry    `json:"stacks"`
		Trust    reporter.TrustReport     `json:"trust"`
		Docker   string                   `json:"docker"`
		Removed  []reporter.RemovedStack  `json:"removed"`
		SealKey  string                   `json:"sealKey"`
		Security *reporter.SecurityReport `json:"security"`
		Vault    *reporter.VaultReport    `json:"vault"`
	}{sorted, listed, trust, docker, removed, parts.SealKey, parts.Security, parts.Vault})
	if err != nil {
		return Inventory{}, err
	}
	sum := sha256.Sum256(encoded)
	return Inventory{Hash: hex.EncodeToString(sum[:]), TakenAt: now.UTC().Format(time.RFC3339Nano), Services: sorted, Stacks: listed, Trust: trust, Docker: docker, Removed: removed, SealKey: parts.SealKey, Security: parts.Security, Vault: parts.Vault}, nil
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
