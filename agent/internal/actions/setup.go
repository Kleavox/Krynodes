package actions

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Kleavox/krynodes/agent/internal/recipes"
)

type SetupOptions struct {
	Recommended bool
	Docker      bool
	Anyway      bool
	RebootHour  *int
	Command     string
}

type Asker func(question string) (yes bool, asked bool)

var setupSteps = []struct{ id, title string }{
	{"security-updates", "Automatic security updates"},
	{"reboot-window", "Restart when needed"},
	{"ssh-keys-only", "SSH keys only"},
	{"fail2ban", "Block repeated login failures"},
}

func (e Executor) Setup(ctx context.Context, options SetupOptions, out io.Writer, ask Asker) error {
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
	if sentence := platform.Unverified(); sentence != "" {
		fmt.Fprintln(out, sentence)
		if !options.Anyway {
			if yes, _ := ask("Run the setup anyway? [y/N] "); !yes {
				fmt.Fprintf(out, "Setup held. Run it later with: sudo %s --anyway\n", options.Command)
				return nil
			}
		}
		args["anyway"] = "yes"
	}
	mark := func(sign, title, rest string) {
		fmt.Fprintf(out, "%s %s%s\n", sign, title, rest)
	}
	if options.Recommended {
		state := e.readRecipes()
		for _, step := range setupSteps {
			if step.id == "reboot-window" {
				e.setupRebootWindow(options.RebootHour, step.title, mark)
				continue
			}
			if _, on := state.Applied[step.id]; on {
				mark("–", step.title, " already on")
				continue
			}
			if step.id == "ssh-keys-only" && len(recipes.KeyedUsers(env)) == 0 {
				mark("–", step.title, " skipped: add an SSH key for root or a sudo user first")
				continue
			}
			saved, err := recipes.Apply(ctx, env, step.id, args)
			if err == nil {
				state.Applied[step.id] = appliedRecipe{At: e.Now(), Saved: saved}
				err = writeJSON(e.StateDir, "recipes.json", state, 0o640)
			}
			if err != nil {
				mark("✗", step.title, ": "+err.Error())
				continue
			}
			mark("✓", step.title, "")
		}
	}
	if options.Docker {
		result, err := recipes.InstallDocker(ctx, env, args)
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
	os.Remove(filepath.Join(e.StateDir, "security.json"))
	return nil
}

func (e Executor) setupRebootWindow(hour *int, title string, mark func(sign, title, rest string)) {
	window, _ := readState[rebootWindow](e.StateDir, "reboot.json")
	switch {
	case window.Hour != nil:
		mark("–", title, " already on")
	case hour == nil:
		mark("–", title, " skipped: no restart hour was given")
	default:
		chosen := *hour
		if err := writeJSON(e.StateDir, "reboot.json", rebootWindow{Hour: &chosen}, 0o640); err != nil {
			mark("✗", title, ": "+err.Error())
			return
		}
		mark("✓", title, fmt.Sprintf(" · %02d:00 UTC", chosen))
	}
}
