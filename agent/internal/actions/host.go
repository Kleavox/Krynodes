package actions

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/recipes"
)

const (
	hostUnit      = "krynodes-host.service"
	staleHostWork = 40 * time.Minute
)

var errHostBusy = errors.New("Krynodes is still changing this server; try again when that finishes")

var errLockedDown = errors.New("the server is locked down; unlock it first")

var startVerbs = []string{"create", "restore", "deploy", "rollback", "start", "restart", "edit", "adopt", "expose"}

func (e Executor) lockedDown() bool {
	_, err := os.Stat(filepath.Join(e.StateDir, "lockdown.json"))
	return err == nil
}

type rebootWindow struct {
	Hour *int   `json:"hour"`
	Last string `json:"last,omitempty"`
}

type appliedRecipe struct {
	At    time.Time         `json:"at"`
	Saved map[string]string `json:"saved,omitempty"`
}

type recipeState struct {
	Applied map[string]appliedRecipe `json:"applied"`
}

type dockerState struct {
	InstalledAt time.Time `json:"installedAt"`
}

type lockdownState struct {
	Containers []string          `json:"containers"`
	Restart    map[string]string `json:"restart,omitempty"`
	SSH        bool              `json:"ssh"`
	At         time.Time         `json:"at"`
}

func (e Executor) readRecipes() recipeState {
	state, _ := readState[recipeState](e.StateDir, "recipes.json")
	if state.Applied == nil {
		state.Applied = map[string]appliedRecipe{}
	}
	return state
}

func (e Executor) appliedRecipes() []string {
	names := []string{}
	for name := range e.readRecipes().Applied {
		names = append(names, name)
	}
	if window, _ := readState[rebootWindow](e.StateDir, "reboot.json"); window.Hour != nil {
		names = append(names, "reboot-window")
	}
	slices.Sort(names)
	return names
}

func (e Executor) host(ctx context.Context, request Request) (Result, bool) {
	if err := expired(request, e.Now()); err != nil {
		return e.refuse(request.ID, err), false
	}
	server := request.Name == "server"
	switch {
	case server && request.Action == "scan":
		return Result{ID: request.ID, OK: true, Output: "checked", FinishedAt: e.stamp()}, false
	case server && (request.Action == "reboot" || request.Action == "uninstall"):
		if _, err := e.authorize(request); err != nil {
			return e.refuse(request.ID, err), false
		}
		if e.hostBusy(ctx) {
			return e.refuse(request.ID, errHostBusy), false
		}
		if request.Action == "reboot" {
			return Result{ID: request.ID, OK: true, Output: "restarting the server", FinishedAt: e.stamp()}, false
		}
		binary, err := os.Executable()
		if err != nil {
			return e.failed(request, err, ""), false
		}
		if output, _, err := e.Run(ctx, "systemd-run", "--unit", "krynodes-uninstall-"+request.ID[:8], "--on-active=30", "--collect", "--", binary, "uninstall-service"); err != nil {
			return e.failed(request, fmt.Errorf("remove Krynodes: %w", err), string(output)), false
		}
		return Result{ID: request.ID, OK: true, Output: "Krynodes leaves this server in 30 seconds; its apps keep running", FinishedAt: e.stamp()}, false
	case request.Name == "reboot-window" && (request.Action == "apply" || request.Action == "undo"):
		return e.rebootSetting(request), false
	case (server && (request.Action == "lockdown" || request.Action == "unlock")) ||
		(request.Name == "docker" && request.Action == "install") ||
		(!server && slices.Contains(Recipes, request.Name) && (request.Action == "apply" || request.Action == "undo")):
		if _, err := e.authorize(request); err != nil {
			return e.refuse(request.ID, err), false
		}
		if err := writeJSON(filepath.Join(e.StateDir, "host"), request.ID+".json", request, 0o600); err != nil {
			return e.failed(request, err, ""), false
		}
		return Result{}, true
	}
	return e.refuse(request.ID, fmt.Errorf("unknown action %q", request.Action)), false
}

func (e Executor) rebootSetting(request Request) Result {
	command, err := e.authorize(request)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	if request.Action == "undo" {
		if err := os.Remove(filepath.Join(e.StateDir, "reboot.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return e.failed(request, err, "")
		}
		return Result{ID: request.ID, OK: true, Output: "no longer restarts by itself", FinishedAt: e.stamp()}
	}
	hour, err := strconv.Atoi(command.Args["hour"])
	if err != nil || hour < 0 || hour > 23 {
		return e.refuse(request.ID, errors.New("the hour must be 0 to 23"))
	}
	if err := writeJSON(e.StateDir, "reboot.json", rebootWindow{Hour: &hour}, 0o640); err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: fmt.Sprintf("restarts at %02d:00 UTC when an update needs it", hour), FinishedAt: e.stamp()}
}

func (e Executor) rebootDue(ctx context.Context) bool {
	window, err := readState[rebootWindow](e.StateDir, "reboot.json")
	if err != nil || window.Hour == nil {
		return false
	}
	now := e.Now().UTC()
	today := now.Format(time.DateOnly)
	if now.Hour() != *window.Hour || window.Last == today {
		return false
	}
	if needed, _ := recipes.RebootNeeded(ctx, e.recipeEnv()); !needed {
		return false
	}
	if e.hostBusy(ctx) {
		return false
	}
	window.Last = today
	return writeJSON(e.StateDir, "reboot.json", window, 0o640) == nil
}

func (e Executor) hostBusy(ctx context.Context) bool {
	queued, _ := os.ReadDir(filepath.Join(e.StateDir, "host"))
	if slices.ContainsFunc(queued, func(entry os.DirEntry) bool {
		info, err := entry.Info()
		return err == nil && e.Now().Sub(info.ModTime()) < staleHostWork
	}) {
		return true
	}
	state, _ := e.output(ctx, "systemctl", "is-active", hostUnit)
	return slices.Contains([]string{"active", "activating", "reloading"}, strings.TrimSpace(state))
}

func (e Executor) HostApply(ctx context.Context) error {
	dir := filepath.Join(e.StateDir, "host")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	processed := false
	for _, entry := range entries {
		name := entry.Name()
		if !requestName.MatchString(name) {
			os.Remove(filepath.Join(dir, name))
			continue
		}
		request, readErr := readRequest(root, name)
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return err
		}
		id := strings.TrimSuffix(name, ".json")
		result := e.refuse(id, readErr)
		if readErr == nil && request.ID == id {
			result = e.applyHost(ctx, request)
		}
		if err := writeJSON(filepath.Join(e.StateDir, "results"), id+".json", result, 0o640); err != nil {
			return err
		}
		processed = true
	}
	if processed {
		os.Remove(filepath.Join(e.StateDir, "security.json"))
	}
	return nil
}

func (e Executor) applyHost(ctx context.Context, request Request) Result {
	if err := expired(request, e.Now()); err != nil {
		return e.refuse(request.ID, err)
	}
	command, err := e.authorize(request)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	env := e.recipeEnv()
	state := e.readRecipes()
	save := func(output string) Result {
		if err := writeJSON(e.StateDir, "recipes.json", state, 0o640); err != nil {
			return e.failed(request, err, "")
		}
		return Result{ID: request.ID, OK: true, Output: output, FinishedAt: e.stamp()}
	}
	switch request.Action {
	case "apply":
		if _, on := state.Applied[request.Name]; on {
			return e.refuse(request.ID, errors.New("already on; turn it off first"))
		}
		saved, err := recipes.Apply(ctx, env, request.Name, command.Args)
		if err != nil {
			return e.refuse(request.ID, err)
		}
		state.Applied[request.Name] = appliedRecipe{At: e.Now(), Saved: saved}
		if err := writeJSON(e.StateDir, "recipes.json", state, 0o640); err != nil {
			if back := recipes.Undo(ctx, env, request.Name, saved); back != nil {
				err = fmt.Errorf("%w; turning it off again also failed: %v", err, back)
			}
			return e.failed(request, err, "")
		}
		return Result{ID: request.ID, OK: true, Output: "applied", FinishedAt: e.stamp()}
	case "undo":
		if err := recipes.Undo(ctx, env, request.Name, state.Applied[request.Name].Saved); err != nil {
			return e.refuse(request.ID, err)
		}
		delete(state.Applied, request.Name)
		return save("undone")
	case "install":
		if request.Name != "docker" {
			return e.refuse(request.ID, fmt.Errorf("%s cannot be installed", request.Name))
		}
		result, err := recipes.InstallDocker(ctx, env, command.Args)
		if err != nil {
			return e.refuse(request.ID, err)
		}
		if result.Installed {
			if err := writeJSON(e.StateDir, "docker.json", dockerState{InstalledAt: e.Now()}, 0o640); err != nil {
				return e.failed(request, err, "")
			}
		}
		return Result{ID: request.ID, OK: true, Output: result.Message, FinishedAt: e.stamp()}
	case "lockdown":
		return e.lockdown(ctx, request, env)
	case "unlock":
		return e.unlock(ctx, request, env)
	}
	return e.refuse(request.ID, fmt.Errorf("unknown action %q", request.Action))
}

func (e Executor) lockdown(ctx context.Context, request Request, env recipes.Env) Result {
	if _, err := os.Stat(filepath.Join(e.StateDir, "lockdown.json")); err == nil {
		return e.refuse(request.ID, errors.New("the server is already locked down"))
	}
	output, ok := e.output(ctx, "docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Ports}}")
	state := lockdownState{Containers: []string{}, At: e.Now()}
	if ok {
		for line := range strings.SplitSeq(output, "\n") {
			fields := strings.Split(strings.TrimRight(line, "\r"), "\t")
			if len(fields) < 2 || fields[0] == "" {
				continue
			}
			if fields[1] == TunnelContainer || (len(fields) > 2 && len(publicPorts(fields[2])) > 0) {
				state.Containers = append(state.Containers, fields[0])
			}
		}
	}
	state.Restart = map[string]string{}
	var held []string
	for _, id := range state.Containers {
		output, _ := e.docker(ctx, collectTimeout, "inspect", "inspect", "--format", "{{.HostConfig.RestartPolicy.Name}}:{{.HostConfig.RestartPolicy.MaximumRetryCount}}", id)
		name, retries, _ := strings.Cut(strings.TrimSpace(string(output)), ":")
		switch {
		case name == "" || name == "no":
			continue
		case name == "on-failure" && retries != "" && retries != "0":
			state.Restart[id] = name + ":" + retries
		default:
			state.Restart[id] = name
		}
		held = append(held, id)
	}
	giveBack := func(err error) Result {
		if undo := e.reopen(ctx, state); undo != nil {
			err = fmt.Errorf("%w; putting the containers back also failed: %v", err, undo)
		}
		return e.failed(request, err, "")
	}
	if len(held) > 0 {
		if _, err := e.docker(ctx, collectTimeout, "hold", append([]string{"update", "--restart", "no"}, held...)...); err != nil {
			return giveBack(err)
		}
	}
	if len(state.Containers) > 0 {
		if _, err := e.docker(ctx, upTimeout, "stop", append([]string{"stop"}, state.Containers...)...); err != nil {
			return giveBack(err)
		}
	}
	if _, applied := e.readRecipes().Applied["ssh-keys-only"]; !applied && len(recipes.SSHLogins(ctx, env)) > 0 {
		if _, err := recipes.Apply(ctx, env, "ssh-keys-only", nil); err != nil {
			log.Printf("lockdown ssh: %v", err)
		} else {
			state.SSH = true
		}
	}
	if err := writeJSON(e.StateDir, "lockdown.json", state, 0o640); err != nil {
		if state.SSH {
			if undo := recipes.Undo(ctx, env, "ssh-keys-only", nil); undo != nil {
				err = fmt.Errorf("%w; turning SSH keys only off again also failed: %v", err, undo)
			}
		}
		return giveBack(err)
	}
	return Result{ID: request.ID, OK: true, Output: fmt.Sprintf("locked down: %d containers stopped", len(state.Containers)), FinishedAt: e.stamp()}
}

func (e Executor) reopen(ctx context.Context, state lockdownState) error {
	for _, id := range state.Containers {
		if policy := state.Restart[id]; policy != "" {
			if _, err := e.docker(ctx, collectTimeout, "restore restart", "update", "--restart", policy, id); err != nil && !gone(err) {
				return err
			}
		}
	}
	if len(state.Containers) == 0 {
		return nil
	}
	if _, err := e.docker(ctx, upTimeout, "start", append([]string{"start"}, state.Containers...)...); err != nil && !gone(err) {
		return err
	}
	return nil
}

func gone(err error) bool {
	var failed stepError
	if !errors.As(err, &failed) {
		return false
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(failed.output)), "\n") {
		if !strings.Contains(line, "No such container") && !strings.HasPrefix(line, "Error: failed to start containers") {
			return false
		}
	}
	return true
}

func (e Executor) unlock(ctx context.Context, request Request, env recipes.Env) Result {
	state, err := readState[lockdownState](e.StateDir, "lockdown.json")
	if err != nil {
		return e.failed(request, err, "")
	}
	if state.At.IsZero() {
		return e.refuse(request.ID, errors.New("the server is not locked down"))
	}
	if err := e.reopen(ctx, state); err != nil {
		return e.failed(request, err, "")
	}
	if state.SSH {
		if err := recipes.Undo(ctx, env, "ssh-keys-only", nil); err != nil {
			return e.refuse(request.ID, err)
		}
	}
	if err := os.Remove(filepath.Join(e.StateDir, "lockdown.json")); err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: "unlocked", FinishedAt: e.stamp()}
}
