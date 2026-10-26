package actions

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/apt"
	"github.com/Kleavox/krynodes/agent/internal/recipes"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/seal"
	"github.com/Kleavox/krynodes/agent/internal/tailscale"
)

const (
	execUnit      = "krynodes-exec.service"
	maxAskedBytes = 4 << 10
	progressEvery = time.Second
)

var aptJobs = []string{"install", "upgrade", "remove", "purge", "addrepo", "droprepo"}

func asked(request Request) (map[string]string, error) {
	args := map[string]string{}
	if request.Attachment == "" {
		return args, nil
	}
	if len(request.Attachment) > maxAskedBytes*2 {
		return nil, errors.New("the question is too large")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(request.Attachment, "="))
	if err != nil {
		return nil, errors.New("the question is not readable")
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, errors.New("the question is not readable")
	}
	return args, nil
}

func (e Executor) answer(request Request, value any, ok bool) Result {
	encoded, err := json.Marshal(value)
	if err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: ok, Output: string(encoded), FinishedAt: e.stamp()}
}

func (e Executor) apt(ctx context.Context, request Request) (Result, bool) {
	if err := expired(request, e.Now()); err != nil {
		return e.refuse(request.ID, err), false
	}
	if !ValidTarget(request.Kind, request.Name) {
		return e.refuse(request.ID, errors.New("invalid target")), false
	}
	switch request.Action {
	case "find":
		args, err := asked(request)
		if err != nil {
			return e.refuse(request.ID, err), false
		}
		matches, err := e.aptJob(request.ID).Find(ctx, args["term"], e.aptSources())
		if err != nil {
			return e.refuse(request.ID, err), false
		}
		return e.answer(request, map[string]any{"matches": matches}, true), false
	case "hold", "unhold":
		if _, err := e.authorize(request); err != nil {
			return e.refuse(request.ID, err), false
		}
		if e.hostBusy(ctx) {
			return e.refuse(request.ID, errHostBusy), false
		}
		ctx, cancel := context.WithTimeout(ctx, commandTimeout)
		defer cancel()
		if output, _, err := e.Run(ctx, "apt-mark", request.Action, request.Name); err != nil {
			return e.failed(request, err, string(output)), false
		}
		said := strings.TrimSpace(request.Action + " " + request.Name + " " + apt.Version(e.Root, request.Name))
		return Result{ID: request.ID, OK: true, Output: said, FinishedAt: e.stamp()}, false
	case "preview", "refresh":
		if _, err := asked(request); err != nil {
			return e.refuse(request.ID, err), false
		}
	default:
		if !slices.Contains(aptJobs, request.Action) {
			return e.refuse(request.ID, fmt.Errorf("unknown action %q", request.Action)), false
		}
		if _, err := e.authorize(request); err != nil {
			return e.refuse(request.ID, err), false
		}
	}
	if err := writeJSON(filepath.Join(e.StateDir, "host"), request.ID+".json", request, 0o600); err != nil {
		return e.failed(request, err, ""), false
	}
	return Result{}, true
}

func (e Executor) aptFacts() (string, []apt.Group, []string) {
	groups, ours := e.krynodesPackages()
	return recipes.Detect(e.recipeEnv()).ID, groups, ours
}

func (e Executor) aptSources() []reporter.SourceEntry {
	distro, _, ours := e.aptFacts()
	return apt.ReadSources(e.Root, distro, ours)
}

func (e Executor) aptJob(id string) apt.Job {
	_, groups, _ := e.aptFacts()
	features := map[string]string{}
	for _, group := range groups {
		for _, name := range group.Packages {
			if group.Feature != "" {
				features[name] = group.Feature
			}
		}
	}
	var wrote time.Time
	return apt.Job{
		Root: e.Root, Run: apt.Runner(e.Run), Stream: e.Stream, Now: e.Now, Features: features, Get: e.recipeEnv().Get,
		Step: func(step apt.Step) {
			if e.Now().Sub(wrote) < progressEvery {
				return
			}
			wrote = e.Now()
			progress := reporter.Progress{ID: id, At: e.stamp(), Done: step.Done, Total: step.Total, Line: step.Line}
			if err := writeJSON(filepath.Join(e.StateDir, "progress"), id+".json", progress, 0o640); err != nil {
				return
			}
		},
	}
}

func (e Executor) recordApt(change func(*aptState)) error {
	state, _ := readState[aptState](e.StateDir, "apt.json")
	change(&state)
	slices.Sort(state.Installed)
	state.Installed = slices.Compact(state.Installed)
	slices.Sort(state.Sources)
	state.Sources = slices.Compact(state.Sources)
	return writeJSON(e.StateDir, "apt.json", state, 0o640)
}

func repoFrom(name string, args map[string]string) apt.Repo {
	return apt.Repo{
		Name: name, URI: args["uri"], Suites: strings.Fields(args["suites"]), Components: strings.Fields(args["components"]),
		Key: args["key"], List: args["list"], Fingerprint: args["fingerprint"],
	}
}

func (e Executor) runningUnits(ctx context.Context) map[string]string {
	listed, _ := e.output(ctx, "systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain")
	var names []string
	for line := range strings.SplitSeq(listed, "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && strings.HasSuffix(fields[0], ".service") {
			names = append(names, fields[0])
		}
	}
	since := map[string]string{}
	if len(names) == 0 {
		return since
	}
	shown, _ := e.output(ctx, "systemctl", append([]string{"show", "-p", "Id", "-p", "ActiveEnterTimestampMonotonic"}, names...)...)
	id := ""
	for line := range strings.SplitSeq(shown, "\n") {
		key, value, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch key {
		case "Id":
			id = value
		case "ActiveEnterTimestampMonotonic":
			if id != "" {
				since[id] = value
			}
		}
	}
	return since
}

func (e Executor) stackStates(ctx context.Context) []apt.StackState {
	listed, ok := e.output(ctx, "docker", "ps", "-a", "--no-trunc", "--format", containerFormat)
	if !ok {
		return nil
	}
	_, stacks := parseContainers(listed)
	states := make([]apt.StackState, 0, len(stacks))
	for _, stack := range stacks {
		states = append(states, apt.StackState{Project: stack.Project, Running: stack.Running, Total: stack.Total})
	}
	return states
}

func restartedBetween(before, after map[string]string) []string {
	var restarted []string
	for unit, at := range after {
		if was, ran := before[unit]; ran && was != at {
			restarted = append(restarted, unit)
		}
	}
	slices.Sort(restarted)
	return restarted
}

func (e Executor) newListeners(ctx context.Context, before []reporter.Listener) []reporter.Listener {
	settings, _ := e.sshSettings(ctx)
	after, _ := e.publicListeners(ctx, settings)
	return slices.DeleteFunc(after, func(listener reporter.Listener) bool { return slices.Contains(before, listener) })
}

func (e Executor) firewallFor(ctx context.Context, preview *apt.InstallPreview) {
	state := e.firewallOf(ctx, recipes.Detect(e.recipeEnv()).Family)
	if !state.active {
		return
	}
	preview.Firewall = &state.tool
	open := e.ufwOpen()
	if state.firewalld {
		open = e.firewalldOpen(ctx)
	}
	for _, unit := range preview.Services {
		for index := range unit.Ports {
			port := unit.Ports[index]
			lets := slices.ContainsFunc(open, func(rule openPort) bool { return rule.lets(port.Port, port.Protocol) })
			unit.Ports[index].Open = &lets
		}
	}
}

func (e Executor) applyApt(ctx context.Context, request Request) Result {
	if err := expired(request, e.Now()); err != nil {
		return e.refuse(request.ID, err)
	}
	args, err := asked(request)
	if request.Action != "preview" && request.Action != "refresh" {
		var command Command
		command, err = e.authorize(request)
		args = command.Args
	}
	if err != nil {
		return e.refuse(request.ID, err)
	}
	if request.Action != "preview" {
		defer e.Run(context.WithoutCancel(ctx), "systemctl", "start", "--no-block", execUnit)
	}
	job := e.aptJob(request.ID)
	distro, _, _ := e.aptFacts()
	switch request.Action {
	case "refresh":
		if err := job.Refresh(ctx); err != nil {
			return e.refuse(request.ID, err)
		}
		return Result{ID: request.ID, OK: true, Output: "checked", FinishedAt: e.stamp()}
	case "preview":
		switch args["what"] {
		case "install":
			preview := job.PreviewInstall(ctx, request.Name, filepath.Join(e.StateDir, "preview", request.ID))
			e.firewallFor(ctx, &preview)
			return e.answer(request, preview, true)
		case "remove", "purge":
			return e.answer(request, job.PreviewRemove(ctx, request.Name, args["what"] == "purge"), true)
		case "upgrade":
			return e.answer(request, job.PreviewUpgrade(ctx), true)
		case "addrepo":
			return e.answer(request, job.PreviewRepo(ctx, repoFrom(request.Name, args)), true)
		}
		return e.refuse(request.ID, fmt.Errorf("nothing to try for %q", args["what"]))
	case "addrepo":
		file, err := job.AddRepo(ctx, repoFrom(request.Name, args))
		if err != nil {
			return e.refuse(request.ID, err)
		}
		if err := e.recordApt(func(state *aptState) { state.Sources = append(state.Sources, file) }); err != nil {
			return e.failed(request, err, "")
		}
		return e.answer(request, map[string]string{"file": file}, true)
	case "droprepo":
		if err := job.DropRepo(ctx, request.Name, distro); err != nil {
			return e.refuse(request.ID, err)
		}
		if err := e.recordApt(func(state *aptState) {
			state.Sources = slices.DeleteFunc(state.Sources, func(file string) bool {
				return strings.TrimSuffix(strings.TrimSuffix(filepath.Base(file), ".sources"), ".list") == request.Name
			})
		}); err != nil {
			return e.failed(request, err, "")
		}
		return Result{ID: request.ID, OK: true, Output: "removed " + request.Name, FinishedAt: e.stamp()}
	}
	settings, _ := e.sshSettings(ctx)
	listening, _ := e.publicListeners(ctx, settings)
	running := e.runningUnits(ctx)
	var outcome apt.Outcome
	switch request.Action {
	case "install":
		outcome, err = job.Install(ctx, request.Name)
	case "upgrade":
		outcome, err = job.Upgrade(ctx)
	case "remove", "purge":
		outcome, err = job.Remove(ctx, request.Name, request.Action == "purge")
	default:
		return e.refuse(request.ID, fmt.Errorf("unknown action %q", request.Action))
	}
	if err != nil && outcome.Failed == "" {
		return e.refuse(request.ID, err)
	}
	outcome.Restarted = restartedBetween(running, e.runningUnits(ctx))
	if slices.Contains(outcome.Restarted, "docker.service") {
		outcome.Stacks = e.stackStates(ctx)
	}
	outcome.Old = apt.OldLibraries(e.Root)
	if request.Action == "install" {
		outcome.Listeners = e.newListeners(ctx, listening)
	}
	record := e.recordApt(func(state *aptState) {
		switch {
		case request.Action == "install" && err == nil:
			state.Installed = append(state.Installed, request.Name)
		case request.Action == "remove" || request.Action == "purge":
			state.Installed = slices.DeleteFunc(state.Installed, func(name string) bool { return slices.Contains(outcome.Removed, name) })
		}
	})
	if record != nil {
		return e.failed(request, record, "")
	}
	return e.answer(request, outcome, err == nil)
}

func (e Executor) signIn(ctx context.Context, request Request, command Command) Result {
	if _, err := os.Stat(e.path(tailscale.Binary)); err != nil {
		return e.refuse(request.ID, errors.New("tailscale is not installed"))
	}
	login, err := tailscale.SignIn(ctx, tailscale.Runner(e.Run), e.Stream)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	if login.Running {
		return e.answer(request, map[string]bool{"running": true}, true)
	}
	plain, err := json.Marshal(map[string]string{"url": login.URL})
	if err != nil {
		return e.failed(request, err, "")
	}
	sealed, err := seal.Seal(command.Args["key"], plain)
	if err != nil {
		return e.refuse(request.ID, errors.New("the browser's key is not usable; open Sign In again"))
	}
	return e.answer(request, map[string]string{"sealed": sealed}, true)
}
