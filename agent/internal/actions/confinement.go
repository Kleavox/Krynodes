package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/confine"
	"github.com/Kleavox/krynodes/agent/internal/recipes"
)

const (
	confinementMark   = "confinement-mark.json"
	dockerSELinuxFile = "docker-selinux.json"
	markFor           = 2 * time.Minute
)

var booleanName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

type confinementMarkRecord struct {
	What  string    `json:"what"`
	From  time.Time `json:"from"`
	Until time.Time `json:"until"`
}

type dockerSELinuxRecord struct {
	Previous string `json:"previous"`
	Existed  bool   `json:"existed"`
}

func (e Executor) markConfinement(what string) error {
	now := e.Now()
	mark, _ := readState[confinementMarkRecord](e.StateDir, confinementMark)
	if mark.What != what || !now.Before(mark.Until) {
		mark.From = now
	}
	mark.What, mark.Until = what, now.Add(markFor)
	return writeJSON(e.StateDir, confinementMark, mark, 0o640)
}

func (e Executor) holdConfinement(what string) func() {
	extend := func() {
		mark, _ := readState[confinementMarkRecord](e.StateDir, confinementMark)
		if mark.What != what {
			mark.From = e.Now()
		}
		mark.What, mark.Until = what, e.Now().Add(markFor)
		writeJSON(e.StateDir, confinementMark, mark, 0o640)
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(markFor / 4)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				extend()
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		extend()
	}
}

func (e Executor) restartFinished(found confine.State) {
	state := e.readRecipes()
	applied, on := state.Applied["confinement"]
	running := found.System == confine.SELinux && (found.Mode == confine.Enforcing || found.Mode == confine.Permissive) ||
		found.System == confine.AppArmor && found.Mode == confine.On
	if !on || applied.Saved["system"] != found.System || applied.Saved["restart"] != "1" || applied.Saved["finished"] == "1" || !running {
		return
	}
	applied.Saved["finished"] = "1"
	state.Applied["confinement"] = applied
	if err := writeJSON(e.StateDir, "recipes.json", state, 0o640); err != nil {
		log.Printf("confinement restart: %v", err)
	}
}

func restartDue(state confine.State, saved map[string]string) bool {
	return state.Restart ||
		(saved["restart"] == "1" && saved["finished"] != "1" && state.Mode == confine.KernelOff) ||
		(saved["enforce"] == "1" && state.Mode == confine.Permissive)
}

func (e Executor) finishSELinux(ctx context.Context) {
	state := e.readRecipes()
	applied, on := state.Applied["confinement"]
	if !on || applied.Saved["enforce"] != "1" {
		return
	}
	env := e.recipeEnv()
	found := confine.Read(e.Root, string(recipes.Detect(env).Family))
	if found.System != confine.SELinux || found.Mode != confine.Permissive || found.Restart {
		return
	}
	if err := e.markConfinement("apply"); err != nil {
		log.Printf("SELinux enforcing: %v", err)
		return
	}
	if err := recipes.EnforceSELinux(ctx, env); err != nil {
		log.Printf("SELinux enforcing: %v", err)
		return
	}
	delete(applied.Saved, "enforce")
	state.Applied["confinement"] = applied
	if err := writeJSON(e.StateDir, "recipes.json", state, 0o640); err != nil {
		log.Printf("SELinux enforcing: %v", err)
	}
}

func (e Executor) managedSystem() string {
	return e.readRecipes().Applied["confinement"].Saved["system"]
}

func (e Executor) installArgs(args map[string]string) map[string]string {
	if e.managedSystem() != confine.SELinux {
		return args
	}
	merged := maps.Clone(args)
	if merged == nil {
		merged = map[string]string{}
	}
	merged["selinux"] = "1"
	return merged
}

func dropLabels(target map[string]any) {
	for _, raw := range asMap(target["services"]) {
		service := asMap(raw)
		options := slices.DeleteFunc(asList(service["security_opt"]), func(option any) bool {
			return strings.HasPrefix(asText(option), "label=")
		})
		if len(options) == 0 {
			delete(service, "security_opt")
		} else {
			service["security_opt"] = options
		}
	}
}

func (e Executor) labelStacks(ctx context.Context, on bool) ([]string, []string) {
	var restarted, problems []string
	entries, _ := os.ReadDir(filepath.Join(e.StateDir, "compose"))
	for _, entry := range entries {
		name := entry.Name()
		directory := filepath.Join(e.StateDir, "compose", name)
		if !entry.IsDir() || e.waiting(name) {
			continue
		}
		problem := func(err error) { problems = append(problems, name+": "+err.Error()) }
		level := ""
		if on {
			var err error
			if level, err = e.levelFor(name); err != nil {
				problem(err)
				continue
			}
		}
		stack := Stack{Project: name, Directory: directory}
		if e.accessOf(directory) == "contained" {
			var config map[string]any
			if readJSON(filepath.Join(directory, "compose.krynodes.json"), &config) != nil {
				continue
			}
			dropLabels(config)
			if on {
				addLabels(config, config, directory, level, false)
			}
			if err := writeJSON(directory, "compose.krynodes.json", config, 0o640); err != nil {
				problem(err)
				continue
			}
			stack.Files = []string{filepath.Join(directory, "compose.krynodes.json")}
		} else {
			stack.Files = []string{filepath.Join(directory, "compose.yaml")}
			hosts := filepath.Join(directory, hostsFile)
			override := map[string]any{}
			kept := readJSON(hosts, &override) == nil
			if asMap(override["services"]) == nil {
				override["services"] = map[string]any{}
			}
			dropLabels(override)
			if on {
				output, err := e.docker(ctx, collectTimeout, "read", composeArgs(stack, "config", "--format", "json")...)
				var config map[string]any
				if start := bytes.IndexByte(output, '{'); err != nil || start < 0 || json.Unmarshal(output[start:], &config) != nil {
					problem(errors.New("compose did not return a readable file"))
					continue
				}
				addLabels(override, config, directory, level, true)
			}
			if kept || on {
				if err := writeJSON(directory, hostsFile, override, 0o640); err != nil {
					problem(err)
					continue
				}
				stack.Files = append(stack.Files, hosts)
			}
		}
		if on {
			if err := e.relabelFolder(ctx, directory, level); err != nil {
				problem(err)
				continue
			}
		}
		if e.knocked(name) {
			continue
		}
		_, err := e.docker(ctx, upTimeout, "up", composeArgs(stack, "up", "-d")...)
		e.markConfinement("containers")
		if err != nil {
			problem(err)
			continue
		}
		restarted = append(restarted, name)
	}
	return restarted, problems
}

func (e Executor) confineContainers(ctx context.Context, request Request, command Command) Result {
	if e.managedSystem() != confine.SELinux {
		return e.refuse(request.ID, errors.New("Confine Containers needs SELinux managed by Krynodes; turn it on first"))
	}
	on := command.Args["on"] == "1"
	env := e.recipeEnv()
	record, err := readState[dockerSELinuxRecord](e.StateDir, dockerSELinuxFile)
	if err != nil {
		return e.failed(request, err, "")
	}
	_, missing := os.Stat(filepath.Join(e.StateDir, dockerSELinuxFile))
	if !on && missing != nil {
		return e.refuse(request.ID, errors.New("Krynodes did not confine this server's containers"))
	}
	if on && missing != nil {
		previous, existed, err := recipes.MergeDaemon(env, "selinux-enabled", true)
		if err != nil {
			return e.refuse(request.ID, err)
		}
		record = dockerSELinuxRecord{Previous: previous, Existed: existed}
		if err := writeJSON(e.StateDir, dockerSELinuxFile, record, 0o640); err != nil {
			recipes.RestoreDaemon(env, previous, existed)
			return e.failed(request, err, "")
		}
	}
	if !on {
		if err := recipes.RestoreDaemon(env, record.Previous, record.Existed); err != nil {
			return e.failed(request, err, "")
		}
		os.Remove(filepath.Join(e.StateDir, dockerSELinuxFile))
	}
	output, _, err := e.Run(ctx, "systemctl", "restart", "docker")
	e.markConfinement("containers")
	if err != nil {
		return e.failed(request, errors.New("Docker did not restart: "+strings.TrimSpace(string(output))), "")
	}
	restarted, problems := e.labelStacks(ctx, on)
	if len(problems) > 0 {
		return e.failed(request, errors.New(strings.Join(problems, "; ")), "")
	}
	text := "Docker confines containers now"
	if !on {
		text = "Docker no longer confines containers"
	}
	if len(restarted) > 0 {
		text += "; restarted " + strings.Join(restarted, ", ")
	}
	return Result{ID: request.ID, OK: true, Output: text, FinishedAt: e.stamp()}
}

func (e Executor) setBoolean(ctx context.Context, request Request, command Command) Result {
	if e.managedSystem() != confine.SELinux {
		return e.refuse(request.ID, errors.New("Change Boolean needs SELinux managed by Krynodes; turn it on first"))
	}
	name, on := command.Args["name"], command.Args["on"]
	want := map[string]string{"1": "on", "0": "off"}[on]
	if len(command.Args) != 2 || !booleanName.MatchString(name) || want == "" {
		return e.refuse(request.ID, errors.New("a boolean takes its name and on as 1 or 0"))
	}
	output, ok := e.output(ctx, "getsebool", name)
	shown, was, found := strings.Cut(strings.TrimSpace(output), " --> ")
	if !ok || !found || shown != name || (was != "on" && was != "off") {
		return e.refuse(request.ID, fmt.Errorf("SELinux has no boolean %s", name))
	}
	if was == want {
		return Result{ID: request.ID, OK: true, Output: name + " is already " + want, FinishedAt: e.stamp()}
	}
	if output, _, err := e.Run(ctx, "setsebool", "-P", name, want); err != nil {
		return e.failed(request, errors.New("setsebool did not finish: "+strings.TrimSpace(string(output))), "")
	}
	return Result{ID: request.ID, OK: true, Output: name + " is " + want + " now (was " + was + ")", FinishedAt: e.stamp()}
}
