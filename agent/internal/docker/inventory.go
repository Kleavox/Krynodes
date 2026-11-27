package docker

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

type Runner func(ctx context.Context, name string, args ...string) ([]byte, int, error)

type StackMeta struct {
	Own      bool
	Access   *string
	Title    *string
	Network  []int
	Rollback bool
}

type Meta struct {
	Stack   func(project, directory string) StackMeta
	Removed func() []reporter.RemovedEntry
	Managed func() map[string]string
}

const (
	maxStacks     = 64
	maxContainers = 256
	maxUnits      = 256
	maxRemoved    = 64
	maxNamed      = 64
	maxServices   = 64
	maxPorts      = 32
	maxImage      = 512
	maxPort       = 128
	maxDirectory  = 4096
	maxCompose    = 64
	maxTitle      = 64
	maxSkipped    = 1024
	tunnel        = "krynodes-tunnel"
)

var collectTimeout = 30 * time.Second

const containerFormat = "{{.Names}}\t{{.State}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}\t{{.Label \"com.docker.compose.project\"}}\t{{.Label \"com.docker.compose.project.working_dir\"}}\t{{.Label \"com.docker.compose.service\"}}"

var (
	targetName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._-]{0,127}$`)
	projectName   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	ContainerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{1,127}$`)
	ServiceName   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

var protectedUnits = compile(
	`^ssh\.service$`, `^sshd\.service$`,
	`^krynodes\.service$`, `^krynodes-.+\.service$`,
	`^docker\.service$`, `^containerd\.service$`,
	`^systemd-.+\.service$`, `^dbus\.service$`, `^dbus-broker\.service$`,
	`^networking\.service$`, `^NetworkManager\.service$`,
	`^cloudflared\.service$`, `^cloudflared-.+\.service$`,
	`^getty@.*\.service$`, `^serial-getty@.*\.service$`, `^user@.*\.service$`,
	`^snap\.docker\..+\.service$`,
	`^ufw\.service$`, `^firewalld\.service$`, `^nftables\.service$`,
	`^netfilter-persistent\.service$`, `^iptables\.service$`, `^ip6tables\.service$`,
	`^wg-quick@kry0\.service$`,
)

var systemUnits = compile(
	`^cron\.service$`, `^rsyslog\.service$`, `^polkit\.service$`, `^udisks2\.service$`,
	`^snapd.*\.service$`, `^cloud-.+\.service$`, `^unattended-upgrades\.service$`,
	`^apparmor\.service$`, `^multipathd\.service$`, `^irqbalance\.service$`,
	`^ModemManager\.service$`, `^accounts-daemon\.service$`, `^packagekit\.service$`,
	`^fwupd\.service$`, `^qemu-guest-agent\.service$`, `^chrony\.service$`, `^ntp\.service$`,
	`^atd\.service$`, `^lvm2-.+\.service$`, `^rpcbind\.service$`,
	`^systemd-.+\.service$`, `^getty@.*\.service$`, `^serial-getty@.*\.service$`,
	`^user@.*\.service$`, `^user-runtime-dir@.*\.service$`, `^modprobe@.*\.service$`,
)

var unitStates = map[string]string{
	"active": "running", "reloading": "running", "failed": "failed",
	"inactive": "stopped", "activating": "stopped", "deactivating": "stopped",
}

var containerStates = map[string]string{
	"running": "running", "restarting": "restarting", "paused": "paused",
	"created": "stopped", "exited": "stopped", "removing": "stopped", "dead": "stopped",
}

var (
	skippedMu sync.Mutex
	skipped   = map[string]bool{}
)

func compile(patterns ...string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, len(patterns))
	for index, pattern := range patterns {
		compiled[index] = regexp.MustCompile(pattern)
	}
	return compiled
}

func matchesAny(patterns []*regexp.Regexp, name string) bool {
	return slices.ContainsFunc(patterns, func(pattern *regexp.Regexp) bool { return pattern.MatchString(name) })
}

func Protected(kind, name string) bool {
	if kind == "container" {
		return name == tunnel
	}
	return kind == "unit" && matchesAny(protectedUnits, name)
}

func ValidTarget(kind, name string) bool {
	switch kind {
	case "stack":
		return projectName.MatchString(name)
	case "docker":
		return name == "docker"
	case "unit":
		return targetName.MatchString(name) && strings.HasSuffix(name, ".service")
	case "container":
		return targetName.MatchString(name)
	}
	return false
}

func TitleValid(title string) bool {
	return title != "" && utf8.RuneCountInString(title) <= maxTitle && strings.TrimFunc(title, trimmed) == title && !strings.ContainsFunc(title, unicode.IsControl)
}

func skip(format, name string) {
	message := fmt.Sprintf(format, name)
	skippedMu.Lock()
	defer skippedMu.Unlock()
	if skipped[message] || len(skipped) >= maxSkipped {
		return
	}
	skipped[message] = true
	log.Print(message)
}

func collect(ctx context.Context, run Runner, meta Meta) (reporter.Inventory, []reporter.ContainerEntry, error) {
	step := func(name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, collectTimeout)
		defer cancel()
		output, _, err := run(ctx, name, args...)
		return output, err
	}
	inventory := reporter.Inventory{
		Type:       "inventory",
		Docker:     "missing",
		Stacks:     []reporter.StackEntry{},
		Containers: []reporter.ContainerEntry{},
		Units:      []reporter.UnitEntry{},
		Removed:    removed(meta),
	}
	all := []reporter.ContainerEntry{}
	output, err := step("docker", "ps", "-a", "--no-trunc", "--format", containerFormat)
	switch {
	case errors.Is(err, exec.ErrNotFound):
	case err != nil:
		inventory.Docker = "stopped"
	default:
		inventory.Docker = "ready"
		all, inventory.Stacks = parseContainers(string(output), meta)
		inventory.Containers = all[:min(len(all), maxContainers)]
		if version, err := step("docker", "compose", "version", "--short"); err == nil {
			if text := strings.TrimSpace(string(version)); text != "" && len(text) <= maxCompose {
				inventory.Compose = &text
			}
		}
	}
	inventory.Stacks = withManaged(inventory.Stacks, meta)
	units, err := step("systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager")
	if err != nil {
		return inventory, all, fmt.Errorf("list units: %w", err)
	}
	files, err := step("systemctl", "list-unit-files", "--type=service", "--no-legend", "--plain", "--no-pager")
	if err != nil {
		return inventory, all, fmt.Errorf("list unit files: %w", err)
	}
	inventory.Units = parseUnits(string(units), string(files))
	inventory.Hash, err = hash(inventory)
	return inventory, all, err
}

func hash(inventory reporter.Inventory) (string, error) {
	encoded, err := json.Marshal(inventory)
	if err != nil {
		return "", err
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return "", err
	}
	delete(fields, "hash")
	canonical, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func parseUnits(units, files string) []reporter.UnitEntry {
	enabled := map[string]bool{}
	for line := range strings.SplitSeq(files, "\n") {
		if fields := strings.Fields(line); len(fields) > 1 && strings.HasPrefix(fields[1], "enabled") {
			enabled[fields[0]] = true
		}
	}
	listed := []reporter.UnitEntry{}
	seen := map[string]bool{}
	for line := range strings.SplitSeq(units, "\n") {
		fields := strings.Fields(strings.TrimLeft(line, "●* "))
		if len(fields) < 4 || fields[1] != "loaded" {
			continue
		}
		name, active := fields[0], fields[2]
		state, known := unitStates[active]
		if fields[3] == "auto-restart" {
			state = "failed"
		}
		if !known || seen[name] || matchesAny(systemUnits, name) || (active == "inactive" && !enabled[name]) {
			continue
		}
		if !targetName.MatchString(name) {
			skip("left the unit %q out of the inventory: Krynodes cannot carry that name", name)
			continue
		}
		seen[name] = true
		listed = append(listed, reporter.UnitEntry{Name: name, State: state, Protected: Protected("unit", name)})
	}
	slices.SortFunc(listed, func(a, b reporter.UnitEntry) int { return cmp.Compare(a.Name, b.Name) })
	return listed[:min(len(listed), maxUnits)]
}

func health(status string) *string {
	for _, state := range []string{"unhealthy", "health: starting", "healthy"} {
		if strings.Contains(status, "("+state+")") {
			found := strings.TrimPrefix(state, "health: ")
			return &found
		}
	}
	return nil
}

func ports(text string) []string {
	listed := []string{}
	for item := range strings.SplitSeq(text, ",") {
		item = strings.TrimSpace(item)
		if strings.Contains(item, "->") && len(item) <= maxPort && !slices.Contains(listed, item) && len(listed) < maxPorts {
			listed = append(listed, item)
		}
	}
	return listed
}

func parseContainers(output string, meta Meta) ([]reporter.ContainerEntry, []reporter.StackEntry) {
	containers := []reporter.ContainerEntry{}
	found := map[string]*reporter.StackEntry{}
	broken := map[string]bool{}
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(fields) < 8 {
			continue
		}
		name, _, _ := strings.Cut(fields[0], ",")
		state, known := containerStates[fields[1]]
		if !known {
			continue
		}
		if !ContainerName.MatchString(name) {
			skip("left the container %q out of the inventory: Krynodes cannot carry that name", name)
			continue
		}
		entry := reporter.ContainerEntry{Name: name, Image: fields[3][:min(len(fields[3]), maxImage)], State: state, Health: health(fields[2]), Ports: ports(fields[4])}
		project, directory, service := fields[5], fields[6], fields[7]
		if project != "" && !projectName.MatchString(project) {
			skip("left the stack %q out of the inventory: Krynodes cannot carry that name", project)
		}
		if !projectName.MatchString(project) {
			containers = append(containers, entry)
			continue
		}
		entry.Project = &project
		if ServiceName.MatchString(service) {
			entry.Service = &service
		}
		containers = append(containers, entry)
		stack := found[project]
		if stack == nil {
			stack = &reporter.StackEntry{Project: project, Directory: directory, Network: []int{}, Services: []reporter.StackService{}}
			found[project] = stack
		}
		if stack.Directory != directory || !strings.HasPrefix(directory, "/") || len(directory) > maxDirectory {
			broken[project] = true
		}
		stack.Total++
		if state == "running" {
			stack.Running++
		}
		if entry.Service != nil {
			stack.Services = append(stack.Services, reporter.StackService{Service: service, Container: name})
		}
	}
	stacks := []reporter.StackEntry{}
	for project, stack := range found {
		if broken[project] {
			skip("left the stack %q out of the inventory: its containers do not share one absolute folder", project)
			continue
		}
		slices.SortFunc(stack.Services, func(a, b reporter.StackService) int {
			return cmp.Or(cmp.Compare(a.Service, b.Service), cmp.Compare(a.Container, b.Container))
		})
		stack.Services = stack.Services[:min(len(stack.Services), maxServices)]
		if meta.Stack != nil {
			described(stack, meta.Stack(project, stack.Directory))
		}
		stacks = append(stacks, *stack)
	}
	slices.SortFunc(containers, func(a, b reporter.ContainerEntry) int { return cmp.Compare(a.Name, b.Name) })
	return containers, stacks
}

func withManaged(stacks []reporter.StackEntry, meta Meta) []reporter.StackEntry {
	if meta.Managed != nil {
		for project, directory := range meta.Managed() {
			listed := slices.ContainsFunc(stacks, func(stack reporter.StackEntry) bool { return stack.Project == project })
			if listed || !projectName.MatchString(project) || !strings.HasPrefix(directory, "/") || len(directory) > maxDirectory {
				continue
			}
			stack := reporter.StackEntry{Project: project, Directory: directory, Network: []int{}, Services: []reporter.StackService{}}
			if meta.Stack != nil {
				described(&stack, meta.Stack(project, directory))
			}
			stacks = append(stacks, stack)
		}
	}
	slices.SortFunc(stacks, func(a, b reporter.StackEntry) int { return cmp.Compare(a.Project, b.Project) })
	return stacks[:min(len(stacks), maxStacks)]
}

func described(stack *reporter.StackEntry, meta StackMeta) {
	stack.Own, stack.Rollback = meta.Own, meta.Rollback
	if meta.Access != nil && (*meta.Access == "contained" || *meta.Access == "full") {
		stack.Access = meta.Access
	}
	if title := meta.Title; title != nil && TitleValid(*title) {
		stack.Title = title
	}
	for _, port := range meta.Network {
		if port >= 1 && port <= 65535 && len(stack.Network) < maxPorts {
			stack.Network = append(stack.Network, port)
		}
	}
}

func trimmed(r rune) bool {
	return unicode.IsSpace(r) || r == 0xFEFF
}

func removed(meta Meta) []reporter.RemovedEntry {
	listed := []reporter.RemovedEntry{}
	if meta.Removed == nil {
		return listed
	}
	for _, entry := range meta.Removed() {
		if _, err := time.Parse(time.RFC3339, entry.RemovedAt); err == nil && strings.HasSuffix(entry.RemovedAt, "Z") && projectName.MatchString(entry.Project) {
			entry.Names = named(entry.Project, entry.Names)
			listed = append(listed, entry)
		}
	}
	slices.SortFunc(listed, func(a, b reporter.RemovedEntry) int {
		return cmp.Or(cmp.Compare(b.RemovedAt, a.RemovedAt), cmp.Compare(a.Project, b.Project))
	})
	return listed[:min(len(listed), maxRemoved)]
}

func named(project string, names []string) []string {
	kept := slices.DeleteFunc(slices.Clone(names), func(name string) bool { return !ContainerName.MatchString(name) })
	prefixed := func(name string) int {
		if strings.HasPrefix(name, project+"-") {
			return 1
		}
		return 0
	}
	slices.SortStableFunc(kept, func(a, b string) int { return cmp.Compare(prefixed(a), prefixed(b)) })
	return kept[:min(len(kept), maxNamed)]
}
