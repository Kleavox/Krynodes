package actions

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/apt"
	"github.com/Kleavox/krynodes/agent/internal/confine"
	"github.com/Kleavox/krynodes/agent/internal/recipes"
)

const (
	setupFile  = "setup.json"
	aliveEvery = 10 * time.Second
	finishWait = 10 * time.Second
)

type setupProgress struct {
	Phase string    `json:"phase"`
	Step  int       `json:"step"`
	Of    int       `json:"of"`
	At    time.Time `json:"at"`
	Boot  string    `json:"boot"`
	Quiet bool      `json:"quiet,omitempty"`
}

type setupTrack struct {
	executor Executor
	phases   []string
	quiet    bool
	mu       sync.Mutex
	current  setupProgress
	stop     chan struct{}
	stopped  chan struct{}
}

func setupPhases(options SetupOptions, confined string) []string {
	var phases []string
	for _, phase := range []struct {
		on   bool
		name string
	}{
		{options.Admin != "", "admin"},
		{options.Upgrade, "upgrade"},
		{options.Recommended, "protections"},
		{options.Confine && confined != "", confined},
		{options.Docker, "docker"},
		{options.Network != "", "network"},
		{options.Restart, "restart"},
	} {
		if phase.on {
			phases = append(phases, phase.name)
		}
	}
	return phases
}

func (e Executor) track(phases []string) *setupTrack {
	begun, _ := readState[setupProgress](e.StateDir, setupFile)
	track := &setupTrack{executor: e, phases: phases, quiet: begun.Quiet && begun.Boot == e.boot() && e.Now().Sub(begun.At) <= setupStale, stop: make(chan struct{}), stopped: make(chan struct{})}
	go func() {
		defer close(track.stopped)
		ticker := time.NewTicker(aliveEvery)
		defer ticker.Stop()
		for {
			select {
			case <-track.stop:
				return
			case <-ticker.C:
				track.alive()
			}
		}
	}()
	return track
}

func (t *setupTrack) enter(phase string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	step := slices.Index(t.phases, phase) + 1
	if step == 0 {
		return
	}
	t.current = setupProgress{Phase: phase, Step: step, Of: len(t.phases), At: t.executor.Now(), Boot: t.executor.boot(), Quiet: t.quiet}
	writeJSON(t.executor.StateDir, setupFile, t.current, 0o644)
}

func (t *setupTrack) alive() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.current.Phase == "" {
		return
	}
	t.current.At = t.executor.Now()
	writeJSON(t.executor.StateDir, setupFile, t.current, 0o644)
}

func (t *setupTrack) end(restart bool) {
	close(t.stop)
	<-t.stopped
	if restart {
		t.enter("restart")
		return
	}
	os.Remove(filepath.Join(t.executor.StateDir, setupFile))
}

func (e Executor) boot() string {
	body, _ := os.ReadFile(e.path("/proc/sys/kernel/random/boot_id"))
	return strings.TrimSpace(string(body))
}

func (e Executor) restartNeeded(ctx context.Context, env recipes.Env) bool {
	needed, _ := recipes.RebootNeeded(ctx, env)
	return needed || apt.KernelWaiting(e.Root)
}

func (e Executor) confined(options SetupOptions, family recipes.Family) string {
	if !options.Confine {
		return ""
	}
	return confine.Read(e.Root, string(family)).System
}

func (e Executor) BeginSetup(options SetupOptions) error {
	platform := recipes.Detect(e.recipeEnv())
	if platform.Family == "" {
		return nil
	}
	phases := setupPhases(options, e.confined(options, platform.Family))
	if len(phases) == 0 {
		return nil
	}
	return writeJSON(e.StateDir, setupFile, setupProgress{Phase: phases[0], Step: 1, Of: len(phases), At: e.Now(), Boot: e.boot(), Quiet: true}, 0o644)
}

func (e Executor) FinishSetup(ctx context.Context, out io.Writer) error {
	progress, err := readState[setupProgress](e.StateDir, setupFile)
	if err != nil || progress.Phase != "restart" || progress.Boot != e.boot() {
		return nil
	}
	fmt.Fprintf(out, "Restarting the server in %d seconds to finish setup.\n", int(finishWait.Seconds()))
	if e.Sleep != nil {
		e.Sleep(finishWait)
	} else {
		time.Sleep(finishWait)
	}
	_, _, err = e.Run(ctx, "systemctl", "reboot", "--no-block")
	return err
}

type SetupOptions struct {
	Recommended bool
	Confine     bool
	Docker      bool
	Upgrade     bool
	Restart     bool
	RebootHour  *int
	Network     string
	Admin       string
	AdminKeys   []recipes.AdminKey
	Terminal    recipes.Terminal
}

var setupSteps = []struct{ id, title string }{
	{"security-updates", "Automatic security updates"},
	{"reboot-window", "Restart when needed"},
	{"ssh-keys-only", "SSH keys only"},
	{"fail2ban", "Block repeated login failures"},
	{"firewall", "Firewall"},
}

func (e Executor) Setup(ctx context.Context, options SetupOptions, out io.Writer) error {
	env := e.recipeEnv()
	platform := recipes.Detect(env)
	name := platform.Pretty
	if name == "" {
		name = platform.Name
	}
	if platform.Family == "" {
		fmt.Fprintf(out, "Detected: %s\n%s; skipped.\n", name, recipes.ErrUnsupported)
		return nil
	}
	tools := "apt, ufw"
	if platform.Family == recipes.RHEL {
		tools = "dnf, firewalld"
	}
	fmt.Fprintf(out, "Detected: %s (%s)\n", name, tools)
	args := map[string]string{}
	mark := func(sign, title, rest string) {
		fmt.Fprintf(out, "%s %s%s\n", sign, title, rest)
	}
	confined := e.confined(options, platform.Family)
	track := e.track(setupPhases(options, confined))
	e.startWatch(ctx)
	admin := false
	if options.Admin != "" {
		track.enter("admin")
		defer e.markAdmin(options.Admin, options.AdminKeys)()
		var result recipes.AdminResult
		result, admin = e.addAdmin(ctx, options.Admin, options.AdminKeys, options.Terminal, mark)
		if result.Group != "" {
			e.acceptAdmin(options.Admin, result, options.AdminKeys)
		}
	}
	if options.Upgrade {
		track.enter("upgrade")
		if err := recipes.Upgrade(ctx, env); err != nil {
			mark("✗", "Packages", ": "+err.Error())
		} else {
			mark("✓", "Packages updated", "")
		}
		e.retake(ctx, false)
	}
	if options.Recommended {
		track.enter("protections")
		state := e.readRecipes()
		for _, step := range setupSteps {
			if step.id == "reboot-window" {
				e.setupRebootWindow(ctx, env, options.RebootHour, step.title, mark)
				continue
			}
			if _, on := state.Applied[step.id]; on {
				mark("–", step.title, " already on")
				continue
			}
			if step.id == "ssh-keys-only" && len(recipes.SSHLogins(ctx, env)) == 0 {
				mark("–", step.title, " skipped: first let root or a sudo user log in over SSH with a key")
				continue
			}
			stepArgs, rest := args, ""
			if step.id == "firewall" {
				stepArgs, rest = e.closedSetup(ctx, env, platform.Family, args)
			}
			saved, err := recipes.Apply(ctx, env, step.id, stepArgs)
			if err == nil && stepArgs["closed"] == "1" {
				if err = e.rememberClosed(ctx, env, stepArgs["ports"]); err != nil {
					recipes.Undo(ctx, env, step.id, saved)
				}
			}
			if err == nil {
				state.Applied[step.id] = appliedRecipe{At: e.Now(), Saved: saved}
				err = writeJSON(e.StateDir, "recipes.json", state, 0o640)
			}
			if errors.Is(err, recipes.ErrNoNotices) {
				mark("–", step.title, " not available: "+platform.Name+" marks no security updates")
				continue
			}
			if err != nil {
				mark("✗", step.title, ": "+err.Error())
				continue
			}
			mark("✓", step.title, rest)
		}
		e.syncPublish(ctx)
	}
	restart := false
	if options.Confine {
		track.enter(confined)
		restart = e.setupConfine(ctx, env, platform.Family, mark)
	}
	if options.Docker {
		track.enter("docker")
		result, err := recipes.InstallDocker(ctx, env, e.installArgs(args))
		if err == nil && result.Installed {
			err = writeJSON(e.StateDir, "docker.json", dockerState{InstalledAt: e.Now()}, 0o640)
		}
		if err == nil && result.Confined {
			err = writeJSON(e.StateDir, dockerSELinuxFile, dockerSELinuxRecord{Previous: result.Previous, Existed: result.Existed}, 0o640)
		}
		switch {
		case err != nil:
			mark("✗", "Docker", ": "+err.Error())
		case !result.Installed && result.Message == "Docker is already installed":
			mark("–", result.Message, "")
		default:
			mark("✓", result.Message, "")
		}
	}
	if options.Network != "" {
		track.enter("network")
		if _, err := e.prepareNetwork(ctx, options.Network, 0); err != nil {
			mark("✗", "Private network", ": "+err.Error())
		} else {
			mark("✓", "Private network ready", " · it joins when you press Join on the dashboard")
		}
	}
	if admin {
		e.noRootLogin(ctx, options.Admin, mark)
	}
	os.Remove(filepath.Join(e.StateDir, "security.json"))
	restart = options.Restart && (restart || e.restartNeeded(ctx, env))
	track.end(restart)
	if restart {
		mark("✓", "Restart", " · the server restarts when the install finishes")
	}
	return nil
}

func (e Executor) closedSetup(ctx context.Context, env recipes.Env, family recipes.Family, args map[string]string) (map[string]string, string) {
	closed := maps.Clone(args)
	closed["closed"] = "1"
	if !e.firewallOf(ctx, family).active {
		return closed, " · closed"
	}
	var ports, keys []string
	for _, opening := range recipes.Adopt(ctx, env, recipes.ReadRules(ctx, env), e.networkPort()).Open {
		ports, keys = append(ports, opening.String()), append(keys, opening.Key())
	}
	closed["ports"] = strings.Join(ports, ",")
	if len(keys) == 0 {
		return closed, " · closed"
	}
	return closed, " · closed · kept open: " + strings.Join(keys, ", ")
}

func (e Executor) setupConfine(ctx context.Context, env recipes.Env, family recipes.Family, mark func(sign, title, rest string)) bool {
	found := confine.Read(e.Root, string(family))
	title := map[string]string{confine.SELinux: "SELinux", confine.AppArmor: "AppArmor"}[found.System]
	state := e.readRecipes()
	switch _, on := state.Applied["confinement"]; {
	case title == "":
		mark("–", "SELinux or AppArmor", " skipped: neither is on this system")
		return false
	case on:
		mark("–", title, " already on")
		return false
	}
	if err := e.markConfinement("apply"); err != nil {
		mark("✗", title, ": "+err.Error())
		return false
	}
	saved, err := recipes.Apply(ctx, env, "confinement", nil)
	if err == nil {
		state.Applied["confinement"] = appliedRecipe{At: e.Now(), Saved: saved}
		err = writeJSON(e.StateDir, "recipes.json", state, 0o640)
	}
	switch {
	case err != nil:
		mark("✗", title, ": "+err.Error())
	case saved["restart"] == "1":
		mark("–", title, ": restart to finish")
		return true
	default:
		mark("✓", title, " · enforcing")
	}
	return false
}

func (e Executor) setupRebootWindow(ctx context.Context, env recipes.Env, hour *int, title string, mark func(sign, title, rest string)) {
	window, _ := readState[rebootWindow](e.StateDir, "reboot.json")
	switch {
	case window.Hour != nil:
		mark("–", title, " already on")
	case hour == nil:
		mark("–", title, " skipped: no restart hour was given")
	default:
		if err := recipes.RestartMarked(ctx, env); err != nil {
			mark("✗", title, ": "+err.Error())
			return
		}
		chosen := *hour
		if err := writeJSON(e.StateDir, "reboot.json", rebootWindow{Hour: &chosen}, 0o640); err != nil {
			mark("✗", title, ": "+err.Error())
			return
		}
		mark("✓", title, fmt.Sprintf(" · %02d:00 UTC", chosen))
	}
}
