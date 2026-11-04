package actions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/recipes"
	"github.com/Kleavox/krynodes/agent/internal/watch"
)

const watchFile = "watch.json"

var (
	readLink    = os.Readlink
	heldBy      = regexp.MustCompile(`\("[^"]*",pid=(\d+)`)
	sharedRange = netip.MustParsePrefix("100.64.0.0/10")
	acceptKinds = []string{"ssh-key", "ssh-login", "user", "sudo", "port", "firewall", "confinement"}
)

func shortHash(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:8])
}

func publicAddress(host string) bool {
	address, err := netip.ParseAddr(host)
	if host == "*" || (err == nil && address.IsUnspecified()) {
		return true
	}
	return err == nil && address.IsGlobalUnicast() && !address.IsPrivate() && !sharedRange.Contains(address.Unmap())
}

func (e Executor) watchNow(ctx context.Context) (watch.State, bool) {
	state, err := watch.Read(e.Root)
	if err != nil {
		return watch.State{}, false
	}
	settings, _ := e.sshSettings(ctx)
	output, ok := e.output(ctx, "ss", "-H", "-tulnp")
	if !ok {
		return watch.State{}, false
	}
	listeners, _ := e.listenersIn(output, settings)
	programs := e.programs(ctx, output)
	for _, listener := range listeners {
		program := programs[fmt.Sprintf("%d/%s", listener.Port, listener.Protocol)]
		if program == "" {
			program = listener.Process
		}
		item := strings.TrimSpace(fmt.Sprintf("%d/%s %s", listener.Port, listener.Protocol, program))
		if publicAddress(listener.Address) && !slices.Contains(state.Ports, item) {
			state.Ports = append(state.Ports, item)
		}
	}
	low, high := ephemeral(e.Root)
	state.Ports = collapse(state.Ports, low, high)
	return state, true
}

func (e Executor) programs(ctx context.Context, output string) map[string]string {
	programs := map[string]string{}
	holders := map[string][]string{}
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		colon := strings.LastIndex(fields[4], ":")
		if colon < 0 {
			continue
		}
		host := strings.Trim(fields[4][:colon], "[]")
		if percent := strings.Index(host, "%"); percent >= 0 {
			host = host[:percent]
		}
		if !publicAddress(host) {
			continue
		}
		key := fields[4][colon+1:] + "/" + fields[0]
		for _, match := range heldBy.FindAllStringSubmatch(fields[6], -1) {
			if !slices.Contains(holders[key], match[1]) {
				holders[key] = append(holders[key], match[1])
			}
		}
	}
	sockets := ""
	for key, pids := range holders {
		if slices.Contains(pids, "1") {
			if sockets == "" {
				sockets, _ = e.output(ctx, "systemctl", "list-sockets", "--all", "--full", "--no-legend", "--no-pager", "--show-types")
			}
			programs[key] = e.socketProgram(ctx, sockets, key)
			continue
		}
		var found []string
		for _, pid := range pids {
			if program := e.processProgram(pid); program != "" && !slices.Contains(found, program) {
				found = append(found, program)
			}
		}
		slices.Sort(found)
		programs[key] = strings.Join(found, ",")
	}
	return programs
}

func (e Executor) socketProgram(ctx context.Context, sockets, key string) string {
	port, protocol, _ := strings.Cut(key, "/")
	kind := map[string]string{"tcp": "Stream", "udp": "Datagram"}[protocol]
	for line := range strings.SplitSeq(sockets, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != kind || !strings.HasSuffix(fields[0], ":"+port) {
			continue
		}
		service, _, _ := strings.Cut(fields[3], ",")
		if program := recipes.ServiceProgram(ctx, e.recipeEnv(), service); program != "" {
			return program + "@" + service
		}
		return service
	}
	return ""
}

func (e Executor) processProgram(pid string) string {
	exe, err := readLink(e.path("/proc/" + pid + "/exe"))
	if err != nil || exe == "" {
		return ""
	}
	exe = strings.TrimSuffix(exe, " (deleted)")
	cgroup, _ := os.ReadFile(e.path("/proc/" + pid + "/cgroup"))
	for line := range strings.SplitSeq(string(cgroup), "\n") {
		if parts := strings.SplitN(line, ":", 3); len(parts) == 3 && strings.HasSuffix(path.Base(parts[2]), ".service") {
			return exe + "@" + path.Base(parts[2])
		}
	}
	return exe
}

func ephemeral(root string) (int, int) {
	raw, err := os.ReadFile(filepath.Join(root, "/proc/sys/net/ipv4/ip_local_port_range"))
	if fields := strings.Fields(string(raw)); err == nil && len(fields) == 2 {
		low, lowErr := strconv.Atoi(fields[0])
		high, highErr := strconv.Atoi(fields[1])
		if lowErr == nil && highErr == nil && low >= 1 && low <= high && high <= 65535 {
			return low, high
		}
	}
	return 32768, 60999
}

func collapse(ports []string, low, high int) []string {
	collapsed := []string{}
	for _, item := range ports {
		port, process, _ := strings.Cut(item, " ")
		if number, ok := strings.CutSuffix(port, "/udp"); ok {
			if value, err := strconv.Atoi(number); err == nil && value >= low && value <= high {
				item = strings.TrimSpace(fmt.Sprintf("%d-%d/udp %s", low, high, process))
			}
		}
		if !slices.Contains(collapsed, item) {
			collapsed = append(collapsed, item)
		}
	}
	slices.Sort(collapsed)
	return collapsed
}

func (e Executor) startWatch(ctx context.Context) {
	if _, err := os.Stat(filepath.Join(e.StateDir, watchFile)); errors.Is(err, os.ErrNotExist) {
		if now, ok := e.watchNow(ctx); ok {
			writeJSON(e.StateDir, watchFile, now, 0o640)
		}
	}
}

func (e Executor) watchServer(ctx context.Context) {
	now, ok := e.watchNow(ctx)
	if !ok {
		return
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, watchFile)); errors.Is(err, os.ErrNotExist) {
		writeJSON(e.StateDir, watchFile, now, 0o640)
		return
	}
	start, err := readState[watch.State](e.StateDir, watchFile)
	if err != nil {
		return
	}
	low, high := ephemeral(e.Root)
	start.Ports = collapse(start.Ports, low, high)
	if upgraded, changed := watch.Upgrade(start, now); changed {
		start = upgraded
		writeJSON(e.StateDir, watchFile, start, 0o640)
	}
	journal, _ := e.output(ctx, "journalctl", "-t", "sshd", "-t", "sshd-session", "--since=@"+strconv.FormatInt(e.Now().Add(-network.KnockWindow).Unix(), 10), "-o", "short-unix", "--no-pager", "-q")
	making, _ := readState[adminMark](e.StateDir, adminMarkFile)
	for _, change := range append(watch.Compare(start, now), watch.Logins(journal, start, now)...) {
		if making.covers(e.Now(), change) {
			continue
		}
		parts := []string{change.Item}
		if change.Kind == "ssh-login" {
			parts = append(parts, change.Detail["user"], change.Detail["from"], change.Detail["at"])
		}
		e.event(change.Kind, change.Kind+":"+shortHash(parts...), change.Detail)
	}
}

func (e Executor) retake(ctx context.Context, whole bool) {
	now, ok := e.watchNow(ctx)
	if !ok {
		return
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, watchFile)); !whole && err == nil {
		start, err := readState[watch.State](e.StateDir, watchFile)
		if err != nil {
			return
		}
		start.Ports, start.Sudo = now.Ports, now.Sudo
		now = start
	}
	writeJSON(e.StateDir, watchFile, now, 0o640)
}

func (e Executor) accept(request Request) Result {
	command, err := e.authorize(request)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	kind, item := command.Args["kind"], command.Args["item"]
	if len(command.Args) != 2 || !slices.Contains(acceptKinds, kind) || item == "" {
		return e.refuse(request.ID, errors.New("only a new key, sign-in, user, sudo rule, port, firewall rule or denied program can be accepted"))
	}
	if kind == "firewall" {
		return e.acceptFirewall(request, item)
	}
	if kind == "confinement" {
		return e.acceptConfinement(request, item)
	}
	start, err := readState[watch.State](e.StateDir, watchFile)
	if err != nil {
		return e.failed(request, err, "")
	}
	if !start.Accept(kind, item) {
		return Result{ID: request.ID, OK: true, Output: "already accepted", FinishedAt: e.stamp()}
	}
	if err := writeJSON(e.StateDir, watchFile, start, 0o640); err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: "accepted: it no longer warns", FinishedAt: e.stamp()}
}

func (e Executor) removedRule(current map[string]string, chains map[string][]string) {
	hour := strconv.FormatInt(e.Now().Truncate(time.Hour).Unix(), 10)
	for _, name := range slices.Sorted(maps.Keys(chains)) {
		if !strings.Contains(current[name], "-N "+name) {
			continue
		}
		present := strings.Split(current[name], "\n")
		for _, rule := range chains[name] {
			if strings.HasSuffix(rule, "-j DROP") && !slices.Contains(present, rule) {
				e.event("rule", "rule:"+shortHash(rule, hour), map[string]string{"chain": name, "rule": rule})
				break
			}
		}
	}
}
