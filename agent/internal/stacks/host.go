package stacks

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/docker"
	"github.com/Kleavox/krynodes/agent/internal/platform"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/safefile"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

func (e Env) container(ctx context.Context, cmd trust.Command, _ func(string)) (string, error) {
	name := cmd.Name
	if cmd.Action == "logs" {
		output, err := e.docker(ctx, stepTimeout, "logs", "--tail", cmd.Args["lines"], "--timestamps", "--", name)
		if err != nil {
			return "", failed("logs", nil, err)
		}
		if err := e.deliver(ctx, cmd.Args["to"], cut(output)); err != nil {
			return "", err
		}
		return fmt.Sprintf("The last %s lines of %s.", cmd.Args["lines"], name), nil
	}
	action := cmd.Action
	if action == "start" {
		paused, err := e.docker(ctx, stepTimeout, "container", "inspect", "--format", "{{.State.Paused}}", "--", name)
		if words := strings.Fields(string(paused)); err == nil && len(words) > 0 && words[len(words)-1] == "true" {
			action = "unpause"
		}
	}
	if action == "stop" {
		e.mark([]string{name}, e.Now().Add(upTimeout+ownerGrace))
		defer func() { e.mark([]string{name}, e.Now().Add(ownerGrace)) }()
	}
	if output, err := e.docker(ctx, upTimeout, action, "--", name); err != nil {
		return "", failed(action, []byte(redact(sanitize(output), e.stackEnv(ctx, name))), err)
	}
	return fmt.Sprintf("%s %s %s.", e.Server, pastTense[cmd.Action], name), nil
}

func (e Env) stackEnv(ctx context.Context, container string) []byte {
	output, err := e.docker(ctx, stepTimeout, "container", "inspect", "--format", stackLabels, "--", container)
	if err != nil {
		return nil
	}
	project, from, _ := strings.Cut(strings.TrimSpace(string(output)), "\t")
	if docker.ValidTarget("stack", project) {
		if env, _ := readEnv(e.folder(project)); env != nil {
			return env
		}
	}
	if !filepath.IsAbs(from) || filepath.Clean(from) != from {
		return nil
	}
	env, _ := readEnv(from)
	return env
}

func (e Env) unit(ctx context.Context, cmd trust.Command, _ func(string)) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, upTimeout)
	defer cancel()
	if output, _, err := e.Run(ctx, "systemctl", cmd.Action, "--", cmd.Name); err != nil {
		return "", failed(cmd.Action, output, err)
	}
	return fmt.Sprintf("%s %s %s.", e.Server, pastTense[cmd.Action], cmd.Name), nil
}

func (e Env) installDocker(ctx context.Context, _ trust.Command, progress func(string)) (string, error) {
	progress(stepDocker)
	version, installed, err := platform.InstallDocker(ctx, e.Platform)
	switch {
	case err != nil:
		return "", err
	case !installed:
		return fmt.Sprintf("Docker with Compose is already on %s.", e.Server), nil
	case version == "":
		return fmt.Sprintf("%s runs Docker with Compose now.", e.Server), nil
	}
	return fmt.Sprintf("%s runs Docker %s with Compose now.", e.Server, version), nil
}

func (e Env) Meta(ctx context.Context) docker.Meta {
	return docker.Meta{
		Stack: func(project, directory string) docker.StackMeta {
			dir := e.folder(project)
			meta, err := ReadMeta(dir)
			if err != nil || (directory != dir && (meta.Home == "" || directory != meta.Home)) {
				return docker.StackMeta{}
			}
			kept, _ := load[record](e.recordPath(project))
			described := docker.StackMeta{Own: true, Access: &meta.Access, Network: meta.Network, Rollback: len(kept.Previous) > 0}
			if meta.Title != "" {
				described.Title = &meta.Title
			}
			return described
		},
		Removed: e.removedList,
		Managed: e.stackFolders,
	}
}

func (e Env) stackFolders() map[string]string {
	entries, err := os.ReadDir(filepath.Join(e.State, "compose"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("the stack folders: %v", err)
	}
	bin := e.bin()
	found := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if _, gone := bin[name]; gone || !entry.IsDir() || !docker.ValidTarget("stack", name) {
			continue
		}
		dir := e.folder(name)
		if meta, err := ReadMeta(dir); err == nil {
			found[name] = home(dir, meta)
		}
	}
	return found
}

func (e Env) bin() map[string]removal {
	binMu.Lock()
	bin, err := load[map[string]removal](e.binPath())
	binMu.Unlock()
	if err != nil {
		log.Printf("the Removed list: %v", err)
	}
	maps.DeleteFunc(bin, func(name string, _ removal) bool { return !docker.ValidTarget("stack", name) })
	return bin
}

func (e Env) removedList() []reporter.RemovedEntry {
	bin := e.bin()
	listed := []reporter.RemovedEntry{}
	for _, name := range slices.Sorted(maps.Keys(bin)) {
		listed = append(listed, reporter.RemovedEntry{Project: name, RemovedAt: bin[name].RemovedAt.UTC().Format(time.RFC3339)})
	}
	return listed
}

func (e Env) sweep(ctx context.Context) {
	synced := sync.OnceValue(func() bool {
		ctx, cancel := context.WithTimeout(ctx, stepTimeout)
		defer cancel()
		answer, _, _ := e.Run(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value")
		return strings.TrimSpace(string(answer)) != "no"
	})
	for name, entry := range e.bin() {
		if e.Now().Sub(entry.RemovedAt) < keepRemoved || !synced() {
			continue
		}
		if unlock, locked := tryLock(name); locked {
			if err := e.wipe(ctx, name); err != nil {
				log.Printf("delete the removed stack %s: %v", name, err)
			}
			unlock()
		}
	}
}

func (e Env) SweepRemoved(ctx context.Context, every time.Duration) {
	for {
		e.sweep(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

func (e Env) contained() bool {
	entries, _ := os.ReadDir(filepath.Join(e.State, "compose"))
	return slices.ContainsFunc(entries, func(entry os.DirEntry) bool {
		meta, err := ReadMeta(filepath.Join(e.State, "compose", entry.Name()))
		return err == nil && meta.Access == "contained"
	})
}

func (e Env) keepGuard(ctx context.Context) error {
	var problems []error
	host := e.Platform
	if e.contained() {
		host.Prove = nil
		if err := Guard(ctx, e.Run); err != nil {
			problems = append(problems, fmt.Errorf("the guard of Contained stacks: %w", err))
		}
	}
	if err := host.GuardInstalledDocker(ctx); err != nil && !errors.Is(err, platform.ErrNoDockerUnit) {
		problems = append(problems, fmt.Errorf("Docker's guard drop-in: %w", err))
	}
	return errors.Join(problems...)
}

func (e Env) GuardContained(ctx context.Context, every time.Duration) {
	said := ""
	for {
		err := e.keepGuard(ctx)
		if text := fmt.Sprint(err); err != nil && text != said {
			log.Print(text)
		}
		said = fmt.Sprint(err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

func Uninstall(ctx context.Context, host platform.Env, state string, deleteApps bool) ([]string, []string, bool) {
	run := docker.Runner(host.Run)
	e := Env{Run: run, State: state, Server: "this server", Now: time.Now}
	var said, problems []string
	if err := host.UnguardDocker(ctx); err != nil {
		problems = append(problems, fmt.Sprintf("the guard drop-in %s: %v; Docker does not start until it is gone and systemd is reloaded", platform.DockerGuardDropInPath, err))
	}
	Unguard(ctx, run)
	stayed := false
	keepIn := filepath.Join(filepath.Dir(state), "krynodes-stacks")
	entries, _ := os.ReadDir(filepath.Join(state, "compose"))
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || !docker.ValidTarget("stack", name) {
			continue
		}
		var err error
		meta, _ := ReadMeta(e.folder(name))
		if deleteApps {
			output, down := e.compose(ctx, upTimeout, name, "down", "-v", "--remove-orphans")
			if left, _ := e.list(ctx, name); down != nil && len(left) > 0 {
				err = e.composeFailed(name, "down", output, down)
			} else {
				err = e.wipe(ctx, name)
			}
		} else {
			err = move(e.folder(name), filepath.Join(keepIn, name))
		}
		switch {
		case err != nil:
			problems, stayed = append(problems, fmt.Sprintf("%s stays in %s: %v", name, e.folder(name), err)), true
		case deleteApps:
			said = append(said, name+": deleted with its data")
		default:
			target := filepath.Join(keepIn, name)
			said = append(said, fmt.Sprintf("%s stays in %s; manage it with: cd %s && sudo docker compose -p %s -f %s ps", name, target, target, name, runFile))
			if meta.Access == "contained" {
				said = append(said, fmt.Sprintf("%s keeps running without the Contained guard: its containers can now reach this server and its private network", name))
			}
		}
	}
	if stayed {
		rest, _ := os.ReadDir(state)
		for _, entry := range rest {
			if entry.Name() == "compose" {
				continue
			}
			if err := os.RemoveAll(filepath.Join(state, entry.Name())); err != nil {
				problems = append(problems, fmt.Sprintf("remove %s: %v", filepath.Join(state, entry.Name()), err))
			}
		}
	}
	return said, problems, stayed
}

func move(from, to string) error {
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return err
	}
	if err := os.Rename(from, to); err != nil {
		return err
	}
	path := filepath.Join(to, runFile)
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return safefile.Write(path, []byte(strings.ReplaceAll(string(body), from, to)), 0o600)
}
