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
	slices.Sort(state.Ports)
	return state, true
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
	journal, _ := e.output(ctx, "journalctl", "-t", "sshd", "-t", "sshd-session", "--since=@"+strconv.FormatInt(e.Now().Add(-network.KnockWindow).Unix(), 10), "-o", "short-unix", "--no-pager", "-q")
	for _, change := range append(watch.Compare(start, now), watch.Logins(journal, start, now)...) {
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
