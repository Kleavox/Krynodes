package actions

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/recipes"
)

type Removal struct {
	TurnedOff []string
	Apps      []string
	Problems  []string
	Docker    string
	Token     string
}

var turnedOff = map[string]string{
	"security-updates": "Automatic security updates are off",
	"ssh-keys-only":    "SSH accepts passwords again",
	"fail2ban":         "fail2ban no longer guards SSH",
	"firewall":         "The firewall rules Krynodes added are gone",
	"free-port-53":     "systemd-resolved holds port 53 again",
}

var krynodesFiles = []string{"krynodes.json", "compose.krynodes.previous.json", "compose.previous.yaml", ".env.previous"}

func (e Executor) Uninstall(ctx context.Context, deleteApps bool) Removal {
	var removal Removal
	problem := func(what string, err error) bool {
		if err != nil {
			removal.Problems = append(removal.Problems, fmt.Sprintf("%s: %v", what, err))
		}
		return err != nil
	}
	env := recipes.Env{Root: e.Root, Run: recipes.Runner(e.Run)}
	if state, err := readState[lockdownState](e.StateDir, "lockdown.json"); err == nil && !state.At.IsZero() {
		problem("start what Lock down stopped", e.reopen(ctx, state))
		if state.SSH && !problem("SSH keys only", recipes.Undo(ctx, env, "ssh-keys-only", nil)) {
			removal.TurnedOff = append(removal.TurnedOff, turnedOff["ssh-keys-only"])
		}
	}
	applied := e.readRecipes().Applied
	for _, name := range slices.Sorted(maps.Keys(applied)) {
		if !problem(name, recipes.Undo(ctx, env, name, applied[name].Saved)) {
			removal.TurnedOff = append(removal.TurnedOff, turnedOff[name])
		}
	}
	e.docker(ctx, upTimeout, "remove the tunnel", "rm", "-f", TunnelContainer)
	e.docker(ctx, upTimeout, "remove the tunnel image", "image", "rm", cloudflaredImage)
	for _, rule := range guardRules {
		ruleCtx, cancel := context.WithTimeout(ctx, collectTimeout)
		e.Run(ruleCtx, rule[0], append([]string{"-D"}, rule[1:]...)...)
		cancel()
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "docker.json")); err == nil {
		remove := "sudo apt-get purge "
		if recipes.Detect(env).Family == recipes.RHEL {
			remove = "sudo dnf remove "
		}
		removal.Docker = "Docker stays for your apps. Krynodes installed it; remove it with: " + remove + "docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
		if written, _ := os.ReadFile(filepath.Join(e.Root, recipes.DockerDaemon)); string(written) == recipes.DockerLogs {
			removal.Docker += " && sudo rm " + recipes.DockerDaemon
		}
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "vault.json")); err == nil {
		removal.Token = "This server held a piece of the Cloudflare token. Unless the dashboard spread the token before this, spread it again on its Cloudflare page so enough servers keep a piece."
	}
	composeDir := filepath.Join(e.StateDir, "compose")
	keepDir := filepath.Join(filepath.Dir(e.StateDir), "krynodes-stacks")
	entries, _ := os.ReadDir(composeDir)
	stayed := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name, directory := entry.Name(), filepath.Join(composeDir, entry.Name())
		if deleteApps {
			if !problem(name, e.deleteApp(ctx, name, directory)) {
				removal.Apps = append(removal.Apps, name+": deleted with its data")
			}
			continue
		}
		target := filepath.Join(keepDir, name)
		file, err := e.keepApp(directory, target)
		if problem(fmt.Sprintf("%s stays in %s", name, directory), err) {
			stayed = true
			continue
		}
		removal.Apps = append(removal.Apps, fmt.Sprintf("%s keeps running; manage it with: cd %s && docker compose -p %s -f %s ps", name, target, name, file))
	}
	if !stayed {
		problem("remove "+e.StateDir, os.RemoveAll(e.StateDir))
		return removal
	}
	rest, _ := os.ReadDir(e.StateDir)
	for _, entry := range rest {
		if entry.Name() != "compose" {
			problem("remove "+entry.Name(), os.RemoveAll(filepath.Join(e.StateDir, entry.Name())))
		}
	}
	return removal
}

func (e Executor) stackFiles(directory string) []string {
	if vetted := filepath.Join(directory, "compose.krynodes.json"); regularFile(vetted) {
		return []string{vetted}
	}
	files, _ := e.composeFiles(Stack{Directory: directory})
	return files
}

func (e Executor) deleteApp(ctx context.Context, name, directory string) error {
	stack := Stack{Project: name, Directory: directory, Files: e.stackFiles(directory)}
	if len(stack.Files) > 0 {
		if _, err := e.docker(ctx, upTimeout, "down", composeArgs(stack, "down", "-v", "--remove-orphans")...); err != nil {
			return err
		}
	}
	return e.wipe(ctx, name, directory)
}

func (e Executor) keepApp(directory, target string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return "", err
	}
	if err := os.Rename(directory, target); err != nil {
		return "", err
	}
	for _, name := range krynodesFiles {
		os.Remove(filepath.Join(target, name))
	}
	files := e.stackFiles(target)
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(file, []byte(strings.ReplaceAll(string(body), directory, target)), 0o600); err != nil {
			return "", err
		}
	}
	if len(files) == 0 {
		return "", fmt.Errorf("no compose file in %s", target)
	}
	return filepath.Base(files[0]), nil
}
