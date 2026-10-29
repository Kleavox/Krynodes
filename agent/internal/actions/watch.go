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
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/watch"
)

const watchFile = "watch.json"

var (
	sharedRange = netip.MustParsePrefix("100.64.0.0/10")
	acceptKinds = []string{"ssh-key", "ssh-login", "user", "sudo", "port"}
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
	listeners, _ := e.publicListeners(ctx, settings)
	if listeners == nil {
		return watch.State{}, false
	}
	for _, listener := range listeners {
		item := strings.TrimSpace(fmt.Sprintf("%d/%s %s", listener.Port, listener.Protocol, listener.Process))
		if publicAddress(listener.Address) && !slices.Contains(state.Ports, item) {
			state.Ports = append(state.Ports, item)
		}
	}
	low, high := ephemeral(e.Root)
	state.Ports = collapse(state.Ports, low, high)
	return state, true
}

func ephemeral(root string) (int, int) {
	raw, err := os.ReadFile(filepath.Join(root, "proc", "sys", "net", "ipv4", "ip_local_port_range"))
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
		return e.refuse(request.ID, errors.New("only a new key, sign-in, user, sudo rule or port can be accepted"))
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
