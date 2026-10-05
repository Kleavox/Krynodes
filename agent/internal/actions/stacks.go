package actions

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const (
	maxComposeBytes = 32 << 10
	healsPerHour    = 3
	keepRemoved     = 7 * 24 * time.Hour
)

var (
	autoVerbs   = []string{"autorestart", "manual", "heal"}
	includeLine = regexp.MustCompile(`(?m)^include\s*:`)
	pastTense   = map[string]string{"start": "started", "stop": "stopped", "restart": "restarted"}
)

type autoRestart struct {
	Units map[string][]time.Time `json:"units"`
}

type removedStack struct {
	Directory string    `json:"directory"`
	Files     []string  `json:"files"`
	RemovedAt time.Time `json:"removedAt"`
}

type stackBin struct {
	Stacks map[string]removedStack `json:"stacks"`
}

func (e Executor) readBin() (stackBin, error) {
	bin, err := readState[stackBin](e.StateDir, "bin.json")
	if bin.Stacks == nil {
		bin.Stacks = map[string]removedStack{}
	}
	return bin, err
}

func (e Executor) saveBin(bin stackBin) error {
	return writeJSON(e.StateDir, "bin.json", bin, 0o640)
}

func (e Executor) waiting(name string) bool {
	bin, _ := e.readBin()
	_, ok := bin.Stacks[name]
	return ok
}

func (e Executor) wipe(ctx context.Context, project, directory string) error {
	volumes, err := e.docker(ctx, collectTimeout, "list volumes", "volume", "ls", "-q", "--filter", "label=com.docker.compose.project="+project)
	if err != nil {
		return err
	}
	if names := strings.Fields(string(volumes)); len(names) > 0 {
		if _, err := e.docker(ctx, upTimeout, "remove volumes", append([]string{"volume", "rm"}, names...)...); err != nil {
			return err
		}
	}
	if e.ownStack(directory) {
		return os.RemoveAll(directory)
	}
	return nil
}

func (e Executor) removedStack(ctx context.Context, request Request, snapshot Snapshot) Result {
	bin, err := e.readBin()
	if err != nil {
		return e.failed(request, err, "")
	}
	entry, ok := bin.Stacks[request.Name]
	if !ok {
		return e.refuse(request.ID, fmt.Errorf("%s is not on this server", request.Name))
	}
	if !snapshot.Compose {
		return e.refuse(request.ID, errors.New("docker compose is not available"))
	}
	if request.Action == "purge" {
		if err := e.wipe(ctx, request.Name, entry.Directory); err != nil {
			return e.failed(request, err, "")
		}
		delete(bin.Stacks, request.Name)
		if err := e.saveBin(bin); err != nil {
			return e.failed(request, err, "")
		}
		return Result{ID: request.ID, OK: true, Output: "deleted permanently", FinishedAt: e.stamp()}
	}
	stack := Stack{Project: request.Name, Directory: entry.Directory, Files: entry.Files}
	files, err := e.composeFiles(stack)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	stack.Files = files
	if _, err := e.docker(ctx, pullTimeout, "up", composeArgs(stack, "up", "-d")...); err != nil {
		return e.failed(request, err, e.states(ctx, stack))
	}
	if states, err := e.healthy(ctx, stack); err != nil {
		return e.failed(request, err, states)
	}
	delete(bin.Stacks, request.Name)
	if err := e.saveBin(bin); err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: "restored", FinishedAt: e.stamp()}
}

func (e Executor) sweepRemoved(ctx context.Context, snapshot Snapshot) []reporter.RemovedStack {
	bin, err := e.readBin()
	if err != nil {
		log.Printf("%v", err)
	}
	changed := false
	names := make([]string, 0, len(bin.Stacks))
	for name := range bin.Stacks {
		names = append(names, name)
	}
	slices.Sort(names)
	listed := []reporter.RemovedStack{}
	for _, name := range names {
		entry := bin.Stacks[name]
		if slices.ContainsFunc(snapshot.Stacks, func(stack Stack) bool { return stack.Project == name }) {
			delete(bin.Stacks, name)
			changed = true
			continue
		}
		if snapshot.Docker != "missing" && e.Now().Sub(entry.RemovedAt) >= keepRemoved {
			if err := e.wipe(ctx, name, entry.Directory); err != nil {
				log.Printf("delete removed stack %s: %v", name, err)
			} else {
				delete(bin.Stacks, name)
				changed = true
				continue
			}
		}
		listed = append(listed, reporter.RemovedStack{Project: name, Directory: entry.Directory, RemovedAt: entry.RemovedAt.UTC().Format(time.RFC3339Nano)})
	}
	if changed {
		if err := e.saveBin(bin); err != nil {
			log.Printf("%v", err)
		}
	}
	return listed
}

func (e Executor) lifecycle(ctx context.Context, request Request, stack Stack) Result {
	if _, err := e.docker(ctx, upTimeout, request.Action, composeArgs(stack, request.Action)...); err != nil {
		return e.failed(request, err, e.states(ctx, stack))
	}
	return Result{ID: request.ID, OK: true, Output: pastTense[request.Action], FinishedAt: e.stamp()}
}

func (e Executor) ownStack(directory string) bool {
	relative, err := filepath.Rel(filepath.Join(e.StateDir, "compose"), directory)
	return err == nil && relative != "." && !strings.HasPrefix(relative, "..") && !strings.ContainsAny(relative, `/\`)
}

func (e Executor) remove(ctx context.Context, request Request, stack Stack) Result {
	args := []string{"down", "--remove-orphans"}
	output := "moved to Removed"
	if request.Action == "purge" {
		args = []string{"down", "-v", "--remove-orphans"}
		output = "deleted permanently"
	}
	if _, err := e.docker(ctx, upTimeout, "down", composeArgs(stack, args...)...); err != nil {
		return e.failed(request, err, "")
	}
	if err := os.Remove(filepath.Join(e.StateDir, "stacks", stack.Project+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return e.failed(request, err, "")
	}
	if request.Action == "purge" && e.ownStack(stack.Directory) {
		if err := os.RemoveAll(stack.Directory); err != nil {
			return e.failed(request, err, "")
		}
	}
	bin, err := e.readBin()
	if err != nil {
		return e.failed(request, err, "")
	}
	if request.Action == "purge" {
		delete(bin.Stacks, stack.Project)
	} else {
		bin.Stacks[stack.Project] = removedStack{Directory: stack.Directory, Files: stack.Files, RemovedAt: e.Now()}
	}
	if err := e.saveBin(bin); err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: output, FinishedAt: e.stamp()}
}

func (e Executor) create(ctx context.Context, request Request, command Command, snapshot Snapshot) Result {
	name := request.Name
	access, err := accessFrom(command, "contained")
	if err != nil {
		return e.refuse(request.ID, err)
	}
	switch {
	case !projectName.MatchString(name):
		return e.refuse(request.ID, errors.New("the stack name may hold lowercase letters, digits, - and _"))
	case snapshot.Docker != "ready":
		return e.refuse(request.ID, errors.New("docker compose is not available on this server"))
	case slices.ContainsFunc(snapshot.Stacks, func(stack Stack) bool { return stack.Project == name }):
		return e.refuse(request.ID, fmt.Errorf("a stack named %s already runs on this server", name))
	case e.waiting(name):
		return e.refuse(request.ID, fmt.Errorf("a stack named %s waits in Removed; restore it or delete it permanently first", name))
	}
	if err := checkText(command.Compose, access); err != nil {
		return e.refuse(request.ID, err)
	}
	directory := filepath.Join(e.StateDir, "compose", name)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return e.failed(request, err, "")
	}
	if err := e.prepare(request, command, directory); err != nil {
		return e.refuse(request.ID, err)
	}
	if err := os.WriteFile(filepath.Join(directory, "compose.yaml"), []byte(command.Compose), 0o640); err != nil {
		return e.failed(request, err, "")
	}
	return e.launch(ctx, request, name, directory, access, "created")
}

func asMap(value any) map[string]any {
	found, _ := value.(map[string]any)
	return found
}

func asList(value any) []any {
	found, _ := value.([]any)
	return found
}

func asText(value any) string {
	found, _ := value.(string)
	return found
}

func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func within(directory, path string) bool {
	if path == "" {
		return true
	}
	relative, err := filepath.Rel(directory, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func resolve(path string) string {
	rest := ""
	for current := path; ; current = filepath.Dir(current) {
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			return filepath.Join(resolved, rest)
		}
		if filepath.Dir(current) == current {
			return path
		}
		rest = filepath.Join(filepath.Base(current), rest)
	}
}

func confined(directory, path string) bool {
	return path == "" || (within(directory, path) && within(resolve(directory), resolve(path)))
}

func filePath(value any) string {
	if path := asText(value); path != "" {
		return path
	}
	return asText(asMap(value)["path"])
}

func vet(config map[string]any, directory string) error {
	networks := asMap(config["networks"])
	for _, name := range sortedKeys(networks) {
		network := asMap(networks[name])
		if network["external"] == true {
			return fmt.Errorf("network %s is external; a stack may only use its own networks", name)
		}
		switch asText(network["driver"]) {
		case "host", "macvlan", "ipvlan":
			return fmt.Errorf("network %s uses the %s driver, which reaches the server's own network", name, asText(network["driver"]))
		}
	}
	volumes := asMap(config["volumes"])
	for _, name := range sortedKeys(volumes) {
		volume := asMap(volumes[name])
		options := asMap(volume["driver_opts"])
		if volume["external"] == true {
			return fmt.Errorf("volume %s is external; a stack may only use its own volumes", name)
		}
		if asText(options["device"]) != "" || strings.Contains(asText(options["o"]), "bind") {
			return fmt.Errorf("volume %s binds a path on the server", name)
		}
	}
	for _, section := range []string{"secrets", "configs"} {
		entries := asMap(config[section])
		for _, name := range sortedKeys(entries) {
			if file := asText(asMap(entries[name])["file"]); !confined(directory, file) {
				return fmt.Errorf("%s %s reads %s from the server", strings.TrimSuffix(section, "s"), name, file)
			}
		}
	}
	services := asMap(config["services"])
	for _, name := range sortedKeys(services) {
		if err := vetService(name, asMap(services[name]), directory); err != nil {
			return err
		}
	}
	return nil
}

func vetService(name string, service map[string]any, directory string) error {
	if service["build"] != nil {
		return fmt.Errorf("service %s builds from source; only ready images can run", name)
	}
	if service["privileged"] == true {
		return fmt.Errorf("service %s asks for privileged mode", name)
	}
	for _, key := range []string{"network_mode", "pid", "ipc", "uts", "userns_mode", "cgroup"} {
		value := asText(service[key])
		label := strings.TrimSuffix(key, "_mode")
		if value == "host" {
			return fmt.Errorf("service %s shares the server's %s", name, label)
		}
		if strings.HasPrefix(value, "container:") {
			return fmt.Errorf("service %s shares the %s of another container", name, label)
		}
	}
	if len(asList(service["cap_add"])) > 0 {
		return fmt.Errorf("service %s asks for extra capabilities", name)
	}
	if len(asList(service["devices"])) > 0 || len(asList(service["device_cgroup_rules"])) > 0 {
		return fmt.Errorf("service %s asks for devices", name)
	}
	for _, option := range asList(service["security_opt"]) {
		if text := asText(option); strings.Contains(text, "unconfined") || strings.Contains(text, "disable") {
			return fmt.Errorf("service %s turns off confinement (%s)", name, text)
		}
	}
	for _, raw := range asList(service["volumes"]) {
		volume := asMap(raw)
		if asText(volume["type"]) == "bind" && !confined(directory, asText(volume["source"])) {
			return fmt.Errorf("service %s mounts %s from the server", name, asText(volume["source"]))
		}
	}
	for _, raw := range asList(service["volumes_from"]) {
		if strings.HasPrefix(asText(raw), "container:") {
			return fmt.Errorf("service %s uses the volumes of another container", name)
		}
	}
	for _, raw := range asList(service["env_file"]) {
		if path := filePath(raw); !confined(directory, path) {
			return fmt.Errorf("service %s reads %s from the server", name, path)
		}
	}
	return nil
}

func localPorts(config map[string]any) {
	services := asMap(config["services"])
	for _, name := range sortedKeys(services) {
		for _, raw := range asList(asMap(services[name])["ports"]) {
			if port := asMap(raw); port != nil {
				port["host_ip"] = "127.0.0.1"
			}
		}
	}
}

func (e Executor) autoRestart(ctx context.Context, request Request, snapshot Snapshot, stopped []string) Result {
	if err := expired(request, e.Now()); err != nil {
		return e.refuse(request.ID, err)
	}
	if request.Kind != "systemd" || !ValidTarget(request.Kind, request.Name) {
		return e.refuse(request.ID, errors.New("invalid target"))
	}
	state, err := readState[autoRestart](e.StateDir, "autorestart.json")
	if err != nil {
		return e.failed(request, err, "")
	}
	if state.Units == nil {
		state.Units = map[string][]time.Time{}
	}
	name := request.Name
	save := func(output string) Result {
		if err := writeJSON(e.StateDir, "autorestart.json", state, 0o640); err != nil {
			return e.failed(request, err, "")
		}
		return Result{ID: request.ID, OK: true, Output: output, FinishedAt: e.stamp()}
	}
	switch request.Action {
	case "autorestart":
		if _, err := e.authorize(request); err != nil {
			return e.refuse(request.ID, err)
		}
		if Protected(request.Kind, name) {
			return e.refuse(request.ID, fmt.Errorf("%s is protected", name))
		}
		if !slices.ContainsFunc(snapshot.Services, func(service Service) bool { return service.Kind == "systemd" && service.Name == name }) {
			return e.refuse(request.ID, fmt.Errorf("%s is not on this server", name))
		}
		if _, ok := state.Units[name]; !ok {
			state.Units[name] = []time.Time{}
		}
		return save("auto-restart on")
	case "manual":
		delete(state.Units, name)
		return save("auto-restart off")
	case "heal":
		return e.heal(ctx, request, state, stopped, save)
	}
	return e.refuse(request.ID, fmt.Errorf("unknown action %q", request.Action))
}

func (e Executor) heal(ctx context.Context, request Request, state autoRestart, stopped []string, save func(string) Result) Result {
	name := request.Name
	heals, ok := state.Units[name]
	if !ok {
		return e.refuse(request.ID, fmt.Errorf("auto-restart is not on for %s", name))
	}
	if slices.Contains(stopped, name) {
		return e.refuse(request.ID, fmt.Errorf("%s was stopped on purpose; it stays stopped", name))
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	output, _, _ := e.Run(ctx, "systemctl", "is-active", "--", name)
	if words := strings.Fields(string(output)); len(words) > 0 && words[0] == "active" {
		return Result{ID: request.ID, OK: true, Output: "already running", FinishedAt: e.stamp()}
	}
	recent := slices.DeleteFunc(slices.Clone(heals), func(at time.Time) bool { return e.Now().Sub(at) >= time.Hour })
	if len(recent) >= healsPerHour {
		return e.refuse(request.ID, fmt.Errorf("restarted automatically %d times in the last hour; left as it is", healsPerHour))
	}
	state.Units[name] = append(recent, e.Now())
	restarted, code, err := e.Run(ctx, "systemctl", "restart", "--", name)
	saved := save("restarted automatically")
	if !saved.OK || err == nil {
		return saved
	}
	result := Result{ID: request.ID, OK: false, Output: clean(restarted), FinishedAt: e.stamp()}
	if code >= 0 {
		result.ExitCode = &code
	}
	if result.Output == "" {
		result.Output = clean([]byte(err.Error()))
	}
	return result
}
