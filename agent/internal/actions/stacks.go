package actions

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
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
	includeLine = regexp.MustCompile(`(?m)(^|[{,])\s*["']?include["']?\s*:`)
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
	if err := e.stillContained(ctx, entry.Directory); err != nil {
		return e.refuse(request.ID, err)
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
	var synced *bool
	trusted := func() bool {
		if synced == nil {
			answer, _ := e.output(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value")
			ok := strings.TrimSpace(answer) != "no"
			synced = &ok
		}
		return *synced
	}
	for _, name := range names {
		entry := bin.Stacks[name]
		if slices.ContainsFunc(snapshot.Stacks, func(stack Stack) bool { return stack.Project == name }) {
			delete(bin.Stacks, name)
			changed = true
			continue
		}
		if snapshot.Docker != "missing" && e.Now().Sub(entry.RemovedAt) >= keepRemoved && trusted() {
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
	var open []string
	for hostname, address := range e.addresses() {
		if address.Project == stack.Project {
			open = append(open, hostname)
		}
	}
	if len(open) > 0 {
		slices.Sort(open)
		return e.refuse(request.ID, fmt.Errorf("%s is reachable at %s; close its web address first", stack.Project, strings.Join(open, ", ")))
	}
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
	_, err = os.Lstat(directory)
	fresh := errors.Is(err, os.ErrNotExist)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return e.failed(request, err, "")
	}
	tidy := func(result Result) Result {
		if !fresh {
			return result
		}
		ids, err := e.docker(ctx, collectTimeout, "inspect", "ps", "-a", "--no-trunc", "--filter", "label=com.docker.compose.project="+name, "--format", "{{.ID}}")
		if err == nil && strings.TrimSpace(string(ids)) == "" {
			os.RemoveAll(directory)
		}
		return result
	}
	if err := e.prepare(request, command, directory); err != nil {
		return tidy(e.refuse(request.ID, err))
	}
	if err := writeWhole(directory, "compose.yaml", []byte(command.Compose), 0o640); err != nil {
		return tidy(e.failed(request, err, ""))
	}
	result := e.launch(ctx, request, name, directory, access, "created")
	if !result.OK {
		return tidy(result)
	}
	return result
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

var containedTop = []string{"name", "services", "networks", "volumes", "secrets", "configs"}

var containedKeys = []string{
	"annotations", "attach", "blkio_config", "cap_add", "cap_drop", "cgroup", "command", "configs",
	"container_name", "cpu_count", "cpu_percent", "cpu_period", "cpu_quota", "cpu_rt_period",
	"cpu_rt_runtime", "cpu_shares", "cpus", "cpuset", "depends_on", "deploy", "develop", "device_cgroup_rules",
	"devices", "dns", "dns_opt", "dns_search", "domainname", "entrypoint", "env_file", "environment",
	"expose", "external_links", "extra_hosts", "gpus", "group_add", "healthcheck", "hostname", "image",
	"init", "ipc", "label_file", "labels", "links", "logging", "mac_address", "mem_limit",
	"mem_reservation", "mem_swappiness", "memswap_limit", "network_mode", "networks", "oom_kill_disable",
	"oom_score_adj", "pid", "pids_limit", "platform", "ports", "post_start", "pre_stop", "privileged",
	"profiles", "pull_policy", "read_only", "restart", "runtime", "scale", "secrets", "security_opt",
	"shm_size", "stdin_open", "stop_grace_period", "stop_signal", "storage_opt", "sysctls", "tmpfs", "tty",
	"ulimits", "user", "userns_mode", "uts", "volumes", "volumes_from", "working_dir",
}

func unknownKey(values map[string]any, allowed []string) string {
	for _, key := range sortedKeys(values) {
		if !strings.HasPrefix(key, "x-") && !slices.Contains(allowed, key) {
			return key
		}
	}
	return ""
}

func vet(config map[string]any, directory string) error {
	project := asText(config["name"])
	if project == "" {
		project = filepath.Base(directory)
	}
	networks := asMap(config["networks"])
	for _, name := range sortedKeys(networks) {
		network := asMap(networks[name])
		if network["external"] == true {
			return fmt.Errorf("network %s is external; a stack may only use its own networks", name)
		}
		if own := asText(network["name"]); own != "" && own != project+"_"+name {
			return fmt.Errorf("network %s is named %s; a Contained stack may only use its own networks", name, own)
		}
		if network["enable_ipv6"] == true {
			return fmt.Errorf("network %s turns on IPv6, which a Contained stack cannot use", name)
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
		if own := asText(volume["name"]); own != "" && own != project+"_"+name {
			return fmt.Errorf("volume %s is named %s; a Contained stack may only use its own volumes", name, own)
		}
		if driver := asText(volume["driver"]); driver != "" && driver != "local" {
			return fmt.Errorf("volume %s uses the %s driver; a Contained stack uses local volumes", name, driver)
		}
		if asText(options["device"]) != "" || strings.Contains(asText(options["o"]), "bind") {
			return fmt.Errorf("volume %s binds a path on the server", name)
		}
		if len(options) > 0 {
			return fmt.Errorf("volume %s sets driver options; a Contained stack uses plain volumes", name)
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
	if len(asMap(config["models"])) > 0 {
		return errors.New("models run through a program on the server; a Contained stack cannot use them")
	}
	if key := unknownKey(config, containedTop); key != "" {
		return fmt.Errorf("the compose file uses %s, which a Contained stack does not allow; choose Full access to run it", key)
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
	for _, hook := range append(asList(service["post_start"]), asList(service["pre_stop"])...) {
		if asMap(hook)["privileged"] == true {
			return fmt.Errorf("service %s runs a privileged hook", name)
		}
	}
	if service["provider"] != nil {
		return fmt.Errorf("service %s is a provider, which runs a program on the server", name)
	}
	if runtime := asText(service["runtime"]); runtime != "" && runtime != "runc" {
		return fmt.Errorf("service %s asks for the runtime %s", name, runtime)
	}
	if host := registryHost(asText(service["image"])); host != "" {
		return fmt.Errorf("service %s pulls its image from %s, which is the server itself", name, host)
	}
	logging := asMap(service["logging"])
	if driver := asText(logging["driver"]); !slices.Contains([]string{"", "local", "json-file", "none"}, driver) {
		return fmt.Errorf("service %s sends its logs through %s, which runs on the server's own network", name, driver)
	}
	for _, option := range sortedKeys(asMap(logging["options"])) {
		if !slices.Contains([]string{"max-size", "max-file", "compress"}, option) {
			return fmt.Errorf("service %s sets the logs option %s; only max-size, max-file and compress are allowed", name, option)
		}
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
	if mode := asText(service["network_mode"]); mode != "" && mode != "none" && !strings.HasPrefix(mode, "container:") && !strings.HasPrefix(mode, "service:") {
		return fmt.Errorf("service %s joins the network %s; a Contained stack uses only its own networks", name, mode)
	}
	if swap, ok := number(service["memswap_limit"]); ok && (swap < 0 || swap > 2<<30) {
		return fmt.Errorf("service %s asks for more than 2 GB of memory with swap; a Contained stack gets at most that", name)
	}
	for _, copies := range []any{service["scale"], asMap(service["deploy"])["replicas"]} {
		if count, ok := number(copies); ok && count > 1 {
			return fmt.Errorf("service %s asks for %d copies; a Contained service runs one, so its limits hold", name, int(count))
		}
	}
	if len(asList(service["cap_add"])) > 0 {
		return fmt.Errorf("service %s asks for extra capabilities", name)
	}
	reserved := asList(asMap(asMap(asMap(service["deploy"])["resources"])["reservations"])["devices"])
	if len(asList(service["devices"])) > 0 || len(asList(service["device_cgroup_rules"])) > 0 || service["gpus"] != nil || len(reserved) > 0 {
		return fmt.Errorf("service %s asks for devices", name)
	}
	for _, option := range asList(service["security_opt"]) {
		if text := asText(option); !strings.HasPrefix(text, "no-new-privileges") {
			return fmt.Errorf("service %s changes its confinement (%s)", name, text)
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
	for _, raw := range append(asList(service["env_file"]), asList(service["label_file"])...) {
		if path := filePath(raw); !confined(directory, path) {
			return fmt.Errorf("service %s reads %s from the server", name, path)
		}
	}
	if key := unknownKey(service, containedKeys); key != "" {
		return fmt.Errorf("service %s uses %s, which a Contained stack does not allow; choose Full access to run it", name, key)
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

func registryOf(image string) string {
	first, _, found := strings.Cut(image, "/")
	if !found || !strings.ContainsAny(first, ".:[") && first != "localhost" {
		return ""
	}
	host := first
	if strings.HasPrefix(host, "[") {
		host, _, _ = strings.Cut(strings.TrimPrefix(host, "["), "]")
	} else if name, _, cut := strings.Cut(host, ":"); cut {
		host = name
	}
	return host
}

func serverAddress(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

func registryHost(image string) string {
	host := registryOf(image)
	if strings.EqualFold(host, "localhost") {
		return host
	}
	if ip := net.ParseIP(host); ip != nil && serverAddress(ip) {
		return host
	}
	return ""
}

func (e Executor) checkRegistries(ctx context.Context, config map[string]any) error {
	lookup := e.LookupIP
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	services := asMap(config["services"])
	for _, name := range sortedKeys(services) {
		host := registryOf(asText(asMap(services[name])["image"]))
		if host == "" || net.ParseIP(host) != nil || strings.EqualFold(host, "localhost") {
			continue
		}
		resolving, cancel := context.WithTimeout(ctx, 5*time.Second)
		addresses, err := lookup(resolving, host)
		cancel()
		if err == nil && slices.ContainsFunc(addresses, serverAddress) {
			return fmt.Errorf("service %s pulls its image from %s, which points at the server itself", name, host)
		}
	}
	return nil
}

func (e Executor) stillContained(ctx context.Context, directory string) error {
	if !e.ownStack(directory) || e.accessOf(directory) != "contained" {
		return nil
	}
	var config map[string]any
	if err := readJSON(filepath.Join(directory, "compose.krynodes.json"), &config); err != nil {
		return err
	}
	if err := vet(config, directory); err != nil {
		return fmt.Errorf("%w; it was made under older rules, so edit it or choose Full access", err)
	}
	return e.checkRegistries(ctx, config)
}
