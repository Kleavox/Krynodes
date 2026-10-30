package actions

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/confine"
	"github.com/Kleavox/krynodes/agent/internal/recipes"
)

type SetupOptions struct {
	Recommended bool
	Confine     bool
	Docker      bool
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
	e.startWatch(ctx)
	admin := false
	if options.Admin != "" {
		defer e.markAdmin(options.Admin, options.AdminKeys)()
		var result recipes.AdminResult
		result, admin = e.addAdmin(ctx, options.Admin, options.AdminKeys, options.Terminal, mark)
		if result.Group != "" {
			e.acceptAdmin(options.Admin, result, options.AdminKeys)
		}
	}
	if options.Recommended {
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
			if err != nil {
				mark("✗", step.title, ": "+err.Error())
				continue
			}
			mark("✓", step.title, rest)
		}
		e.syncPublish(ctx)
	}
	if options.Confine {
		e.setupConfine(ctx, env, platform.Family, mark)
	}
	if options.Docker {
		result, err := recipes.InstallDocker(ctx, env, e.installArgs(args))
		if err == nil && result.Installed {
			err = writeJSON(e.StateDir, "docker.json", dockerState{InstalledAt: e.Now()}, 0o640)
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

func (e Executor) setupConfine(ctx context.Context, env recipes.Env, family recipes.Family, mark func(sign, title, rest string)) {
	found := confine.Read(e.Root, string(family))
	title := map[string]string{confine.SELinux: "SELinux", confine.AppArmor: "AppArmor"}[found.System]
	state := e.readRecipes()
	switch _, on := state.Applied["confinement"]; {
	case title == "":
		mark("–", "SELinux or AppArmor", " skipped: neither is on this system")
		return
	case on:
		mark("–", title, " already on")
		return
	}
	if err := e.markConfinement("apply"); err != nil {
		mark("✗", title, ": "+err.Error())
		return
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
	default:
		mark("✓", title, " · enforcing")
	}
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
