package stacks

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Kleavox/krynodes/agent/internal/daemon"
	"github.com/Kleavox/krynodes/agent/internal/docker"
	"github.com/Kleavox/krynodes/agent/internal/platform"
	"github.com/Kleavox/krynodes/agent/internal/safefile"
	"github.com/Kleavox/krynodes/agent/internal/seal"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

const (
	pullTimeout      = 10 * time.Minute
	upTimeout        = 5 * time.Minute
	stepTimeout      = time.Minute
	ownerGrace       = 30 * time.Second
	keepRemoved      = 7 * 24 * time.Hour
	maxOutput        = 64 << 10
	maxFailure       = 1500
	maxDetail        = 8 << 10
	maxState         = 1 << 20
	maxSealedEnv     = 29337
	maxSealedCompose = 58464
	maxNetwork       = 32
	maxLines         = 500
	maxNames         = 64
	maxCopies        = 64
	runFile          = "compose.run.json"
	stateFormat      = "{{.Service}}\t{{.State}}\t{{.Health}}\t{{.ExitCode}}"
	startsFormat     = "{{.Id}} {{.RestartCount}} {{.State.StartedAt}}"
	imageFormat      = "{{index .Config.Labels \"com.docker.compose.service\"}}\t{{.Config.Image}}\t{{.Image}}"
	homeFormat       = "{{.Label \"com.docker.compose.project.working_dir\"}}"
	stackLabels      = "{{index .Config.Labels \"com.docker.compose.project\"}}\t{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}"
	projectLabel     = "label=com.docker.compose.project="
	cutLine          = "… earlier lines cut\n"
	stepChecking     = "Checking the compose file"
	stepPulling      = "Pulling the images"
	stepStarting     = "Starting the containers"
	stepWaiting      = "Waiting until the containers are healthy"
	stepBack         = "Going back to the previous images"
	stepDocker       = "Installing Docker"
)

var (
	healthTimeout = 2 * time.Minute
	healthEvery   = 5 * time.Second
	healthSettle  = 20 * time.Second
	locks         sync.Map
	binMu         sync.Mutex
	sealedText    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	portText      = regexp.MustCompile(`^[1-9]\d{0,4}$`)
	linesText     = regexp.MustCompile(`^[1-9]\d{0,2}$`)
	pastTense     = map[string]string{"start": "started", "stop": "stopped", "restart": "restarted"}
	steps         = []string{stepChecking, stepPulling, stepStarting, stepWaiting, stepBack, stepDocker}
	labels        = map[string]string{
		"create": "Create", "deploy": "Deploy", "edit": "Edit", "read": "Read", "rollback": "Rollback",
		"start": "Start", "stop": "Stop", "restart": "Restart", "remove": "Remove", "restore": "Restore",
		"purge": "Delete", "adopt": "Adopt", "logs": "Logs",
	}
	standardFiles = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}
	verbs         = map[string][]string{
		"stack":     {"create", "deploy", "edit", "read", "rollback", "start", "stop", "restart", "remove", "restore", "purge", "adopt", "logs"},
		"container": {"start", "stop", "restart", "logs"},
		"unit":      {"start", "stop", "restart"},
		"docker":    {"install"},
	}
)

type Env struct {
	Run      docker.Runner
	State    string
	Server   string
	Name     func() string
	Own      func() string
	Unseal   func(string) ([]byte, error)
	Sealing  *ecdh.PrivateKey
	Checks   *docker.Checks
	Now      func() time.Time
	Platform platform.Env
}

func (e Env) server() string {
	if e.Name != nil {
		if name := e.Name(); name != "" {
			return name
		}
	}
	return e.Server
}

type pinned struct {
	Service   string `json:"service"`
	Reference string `json:"reference"`
	ID        string `json:"id"`
}

type record struct {
	Previous []pinned `json:"previous"`
	Failed   bool     `json:"failed,omitempty"`
}

type removal struct {
	RemovedAt time.Time `json:"removedAt"`
}

type rule func(string) bool

func Handlers(env Env) map[string]daemon.Handler {
	stack := map[string]daemon.Handler{
		"create": env.create, "deploy": env.deploy, "edit": env.edit, "read": env.read, "rollback": env.rollback,
		"start": env.lifecycle, "stop": env.lifecycle, "restart": env.lifecycle, "remove": env.remove,
		"restore": env.restore, "purge": env.purge, "adopt": env.adopt, "logs": env.logs,
	}
	handlers := map[string]daemon.Handler{"docker/install": env.guarded(env.installDocker)}
	for action, handle := range stack {
		handlers["stack/"+action] = env.guarded(handle)
	}
	for _, action := range verbs["container"] {
		handlers["container/"+action] = env.guarded(env.container)
	}
	for _, action := range verbs["unit"] {
		handlers["unit/"+action] = env.guarded(env.unit)
	}
	return handlers
}

func (e Env) guarded(handle daemon.Handler) daemon.Handler {
	return func(ctx context.Context, cmd trust.Command, progress func(string)) (message string, err error) {
		switch {
		case !docker.ValidTarget(cmd.Kind, cmd.Name):
			return "", fmt.Errorf("%q is not a %s name Krynodes can use", cmd.Name, cmd.Kind)
		case docker.Protected(cmd.Kind, cmd.Name):
			return "", fmt.Errorf("%s is protected; Krynodes leaves it alone", cmd.Name)
		case !ArgsValid(cmd.Kind, cmd.Action, cmd.Args):
			return "", fmt.Errorf("%s %s came with arguments this server does not take", cmd.Kind, cmd.Action)
		}
		if cmd.Kind == "stack" || cmd.Kind == "container" {
			defer func() {
				if err != nil {
					message, err = "", e.sealFailure(ctx, cmd, err)
				}
			}()
		}
		if cmd.Kind == "stack" && (cmd.Action == "create" || cmd.Action == "edit") {
			plain, err := e.Unseal(cmd.Args["compose"])
			if err != nil {
				return "", fmt.Errorf("the compose file: %w", err)
			}
			if len(plain) > maxComposeBytes {
				return "", errComposeLarge
			}
			if strings.TrimSpace(string(plain)) == "" {
				return "", errComposeEmpty
			}
			cmd.Args = maps.Clone(cmd.Args)
			cmd.Args["compose"] = string(plain)
		}
		if cmd.Kind == "stack" && cmd.Action != "logs" && cmd.Action != "read" {
			defer lock(cmd.Name)()
		}
		if e.Checks != nil {
			defer e.Checks.Changed()
		}
		return handle(ctx, cmd, func(line string) {
			if slices.Contains(steps, line) {
				progress(line)
			}
		})
	}
}

func (e Env) sealFailure(ctx context.Context, cmd trust.Command, failure error) error {
	message := fmt.Sprintf("%s of %s failed.", labels[cmd.Action], cmd.Name)
	if e.deliver(ctx, cmd.Args["to"], tail([]byte(failure.Error()), maxDetail)) != nil {
		message += " Its details could not be sealed."
	}
	return errors.New(message)
}

func lock(name string) func() {
	held, _ := locks.LoadOrStore(name, &sync.Mutex{})
	mu := held.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func tryLock(name string) (func(), bool) {
	held, _ := locks.LoadOrStore(name, &sync.Mutex{})
	mu := held.(*sync.Mutex)
	return mu.Unlock, mu.TryLock()
}

func ArgsValid(kind, action string, args map[string]string) bool {
	if !slices.Contains(verbs[kind], action) {
		return false
	}
	need, may := shape(kind, action)
	for key := range need {
		if _, given := args[key]; !given {
			return false
		}
	}
	for key, value := range args {
		check, known := need[key]
		if !known {
			check, known = may[key]
		}
		if !known || !check(value) {
			return false
		}
	}
	return true
}

func shape(kind, action string) (map[string]rule, map[string]rule) {
	need, may := map[string]rule{}, map[string]rule(nil)
	switch {
	case kind == "stack" && (action == "create" || action == "edit"):
		need = map[string]rule{"compose": composeValid, "access": accessValid, "network": networkValid}
		may = map[string]rule{"env": envValid, "title": docker.TitleValid, "names": namesValid}
	case kind == "stack" && action == "adopt":
		need = map[string]rule{"access": accessValid}
	case action == "logs":
		need = map[string]rule{"lines": linesValid}
		if kind == "stack" {
			may = map[string]rule{"service": docker.ServiceName.MatchString}
		}
	}
	if kind == "stack" || kind == "container" {
		need["to"] = seal.ValidRecipient
	}
	return need, may
}

func composeValid(text string) bool {
	return len(text) <= maxSealedCompose && sealedText.MatchString(text)
}

func accessValid(text string) bool { return text == "contained" || text == "full" }

func envValid(text string) bool { return len(text) <= maxSealedEnv && sealedText.MatchString(text) }

func linesValid(text string) bool {
	count, err := strconv.Atoi(text)
	return linesText.MatchString(text) && err == nil && count <= maxLines
}

func networkValid(text string) bool {
	if text == "" {
		return true
	}
	ports := strings.Split(text, ",")
	for index, port := range ports {
		number, err := strconv.Atoi(port)
		if !portText.MatchString(port) || err != nil || number > 65535 || slices.Contains(ports[:index], port) {
			return false
		}
	}
	return len(ports) <= maxNetwork
}

func namesValid(text string) bool {
	if text == "" {
		return true
	}
	entries := strings.Split(text, ",")
	services, containers := []string{}, []string{}
	for _, entry := range entries {
		parts := strings.Split(entry, "=")
		if len(parts) != 2 || slices.Contains(services, parts[0]) || slices.Contains(containers, parts[1]) ||
			!docker.ServiceName.MatchString(parts[0]) || !docker.ContainerName.MatchString(parts[1]) {
			return false
		}
		services, containers = append(services, parts[0]), append(containers, parts[1])
	}
	return len(entries) <= maxNames
}

func (e Env) folder(name string) string { return filepath.Join(e.State, "compose", name) }

func (e Env) recordPath(name string) string { return filepath.Join(e.State, "stacks", name+".json") }

func (e Env) binPath() string { return filepath.Join(e.State, "bin.json") }

func load[T any](path string) (T, error) {
	var value T
	raw, err := safefile.Read(path, maxState)
	if errors.Is(err, os.ErrNotExist) {
		return value, nil
	}
	if err != nil {
		return value, err
	}
	return value, json.Unmarshal(raw, &value)
}

func store(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return safefile.Write(path, raw, 0o600)
}

func (e Env) changeBin(change func(map[string]removal)) error {
	binMu.Lock()
	defer binMu.Unlock()
	bin, err := load[map[string]removal](e.binPath())
	if err != nil {
		return fmt.Errorf("the Removed list: %w", err)
	}
	if bin == nil {
		bin = map[string]removal{}
	}
	change(bin)
	return store(e.binPath(), bin)
}

func (e Env) removed(name string) bool {
	binMu.Lock()
	defer binMu.Unlock()
	bin, _ := load[map[string]removal](e.binPath())
	_, found := bin[name]
	return found
}

func (e Env) docker(ctx context.Context, timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output, _, err := e.Run(ctx, "docker", args...)
	return output, err
}

func (e Env) compose(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	dir := e.folder(name)
	meta, err := ReadMeta(dir)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := append(append([]string{"-i", searchPath}, composeCommand(name, home(dir, meta), dir, filepath.Join(dir, runFile))...), args...)
	output, _, err := e.Run(ctx, "env", command...)
	return output, err
}

func home(dir string, meta Meta) string {
	if meta.Home != "" {
		return meta.Home
	}
	return dir
}

func (e Env) list(ctx context.Context, name string, filters ...string) ([]string, error) {
	args := append([]string{"ps", "-a", "--no-trunc", "--filter", projectLabel + name}, filters...)
	output, err := e.docker(ctx, stepTimeout, append(args, "--format", "{{.Names}}")...)
	if err != nil {
		return nil, fmt.Errorf("Docker did not answer on %s: %w", e.server(), failed("ps", output, err))
	}
	return strings.Fields(string(output)), nil
}

func (e Env) images(ctx context.Context, name string) ([]pinned, error) {
	containers, err := e.list(ctx, name)
	if err != nil || len(containers) == 0 {
		return nil, err
	}
	output, err := e.docker(ctx, stepTimeout, append([]string{"inspect", "--format", imageFormat}, containers...)...)
	if err != nil {
		return nil, failed("inspect", output, err)
	}
	var images []pinned
	for line := range strings.SplitSeq(string(output), "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) == 3 && fields[1] != "" && fields[2] != "" {
			images = append(images, pinned{Service: fields[0], Reference: fields[1], ID: fields[2]})
		}
	}
	return images, nil
}

func (e Env) starts(ctx context.Context, name string) string {
	containers, err := e.list(ctx, name)
	if err != nil || len(containers) == 0 {
		return ""
	}
	output, _ := e.docker(ctx, stepTimeout, append([]string{"inspect", "--format", startsFormat}, containers...)...)
	lines := strings.Fields(strings.ReplaceAll(string(output), " ", "|"))
	slices.Sort(lines)
	return strings.Join(lines, ",")
}

func (e Env) mark(containers []string, until time.Time) {
	if e.Checks == nil {
		return
	}
	for _, container := range containers {
		e.Checks.Owner(container, until)
	}
}

func (e Env) planned(name string) []string {
	path := filepath.Join(e.folder(name), runFile)
	config, err := load[map[string]any](path)
	if err != nil {
		log.Printf("read %s: %v", path, err)
	}
	services := asMap(config["services"])
	var names []string
	for _, service := range sortedKeys(services) {
		settings := asMap(services[service])
		if container := asText(settings["container_name"]); container != "" {
			names = append(names, container)
			continue
		}
		copies := 1
		for _, field := range []any{settings["scale"], asMap(settings["deploy"])["replicas"]} {
			if count, ok := number(field); ok {
				copies = max(copies, int(min(count, maxCopies)))
			}
		}
		for index := 1; index <= copies; index++ {
			names = append(names, fmt.Sprintf("%s-%s-%d", name, service, index))
		}
	}
	return names
}

func (e Env) owned(ctx context.Context, name string, limit time.Duration, expected ...string) func() {
	before, _ := e.list(ctx, name)
	before = append(before, expected...)
	e.mark(before, e.Now().Add(limit+ownerGrace))
	return func() {
		after, _ := e.list(ctx, name)
		e.mark(append(before, after...), e.Now().Add(ownerGrace))
	}
}

func (e Env) managed(name string) error {
	if e.removed(name) {
		return fmt.Errorf("%s is in Removed on %s; restore it first", name, e.server())
	}
	if _, err := ReadMeta(e.folder(name)); err != nil {
		return fmt.Errorf("Krynodes does not manage %s on %s; adopt it first", name, e.server())
	}
	return nil
}

func hostEnv(env []byte) error {
	for line := range strings.SplitSeq(string(env), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[0] == "export" {
			fields = fields[1:]
		}
		if len(fields) > 0 && (strings.HasPrefix(fields[0], "COMPOSE_") || strings.HasPrefix(fields[0], "DOCKER_")) {
			key, _, _ := strings.Cut(fields[0], "=")
			return fmt.Errorf("the .env sets %s; a Contained stack leaves COMPOSE_ and DOCKER_ settings alone", key)
		}
	}
	return nil
}

func (e Env) prepare(ctx context.Context, name string) error {
	err := e.fit(ctx, name)
	if err == nil {
		return nil
	}
	env, _ := readEnv(e.folder(name))
	return errors.New(redact(err.Error(), env))
}

func (e Env) fit(ctx context.Context, name string) error {
	dir := e.folder(name)
	meta, err := ReadMeta(dir)
	if err != nil {
		return fmt.Errorf("%s has no settings on %s: %w", name, e.server(), err)
	}
	text, _, err := Read(dir)
	if err != nil {
		return err
	}
	if err := CheckText(text, meta.Access); err != nil {
		return err
	}
	env, err := readEnv(dir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	var config map[string]any
	switch meta.Access {
	case "contained":
		if err := hostEnv(env); err != nil {
			return err
		}
		config, err = Normalise(ctx, e.Run, name, []byte(text), env)
	case "full":
		config, err = NormaliseFull(ctx, e.Run, name, home(dir, meta), dir)
	default:
		return fmt.Errorf("unknown access %q", meta.Access)
	}
	if err != nil {
		return err
	}
	if err := Vet(config, dir, meta.Access); err != nil {
		return err
	}
	services := asMap(config["services"])
	for service, container := range meta.Names {
		if found := asMap(services[service]); found != nil {
			found["container_name"] = container
		}
	}
	own := ""
	if len(meta.Network) > 0 {
		if own = e.Own(); own == "" {
			return fmt.Errorf("%s is not in the private network, so no port can be served to it", e.server())
		}
	}
	if err := Bind(config, own, meta.Network); err != nil {
		return err
	}
	if meta.Access == "contained" {
		if err := Guard(ctx, e.Run); err != nil {
			return fmt.Errorf("the guard of Contained stacks: %w", err)
		}
		host := e.Platform
		host.Prove = nil
		if err := host.GuardInstalledDocker(ctx); errors.Is(err, platform.ErrNoDockerUnit) {
			return errors.New("Contained stacks need Docker's boot guard, and this server's Docker has no docker.service.")
		} else if err != nil {
			return fmt.Errorf("Contained stacks need Docker's boot guard, and the guard drop-in is missing or overridden: %w", err)
		}
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return safefile.Write(filepath.Join(dir, runFile), encoded, 0o600)
}

func (e Env) launch(ctx context.Context, name string, progress func(string)) (string, error) {
	progress(stepChecking)
	if err := e.prepare(ctx, name); err != nil {
		return "", err
	}
	progress(stepPulling)
	if output, err := e.compose(ctx, pullTimeout, name, "pull"); err != nil {
		return "", e.composeFailed(name, "pull", output, err)
	}
	return e.up(ctx, name, progress)
}

func (e Env) up(ctx context.Context, name string, progress func(string), pull ...string) (string, error) {
	progress(stepStarting)
	if output, err := e.compose(ctx, upTimeout, name, append([]string{"up", "-d", "--remove-orphans"}, pull...)...); err != nil {
		return "", e.composeFailed(name, "up", output, err)
	}
	progress(stepWaiting)
	good, total, err := e.healthy(ctx, name)
	if err != nil {
		return "", fmt.Errorf("the health check failed: %w", err)
	}
	return fmt.Sprintf("%s runs %s: %d of %d containers healthy.", e.server(), name, good, total), nil
}

func judge(output []byte) (string, int, int) {
	var states []string
	good := 0
	for line := range strings.SplitSeq(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) < 2 {
			continue
		}
		health, code := "", ""
		if len(fields) > 2 {
			health = fields[2]
		}
		if len(fields) > 3 {
			code = fields[3]
		}
		state, fine := fields[0]+" "+fields[1], false
		switch {
		case fields[1] == "exited":
			state += " (" + code + ")"
			fine = code == "0"
		case health != "":
			state += " (" + health + ")"
			fine = fields[1] == "running" && health == "healthy"
		default:
			fine = fields[1] == "running"
		}
		if fine {
			good++
		}
		states = append(states, state)
	}
	return strings.Join(states, ", "), good, len(states)
}

func (e Env) healthy(ctx context.Context, name string) (int, int, error) {
	deadline := time.Now().Add(healthTimeout)
	var since time.Time
	baseline, restarted := "", false
	for {
		output, err := e.compose(ctx, stepTimeout, name, "ps", "--all", "--format", stateFormat)
		states, good, total := judge(output)
		switch {
		case err != nil || total == 0 || good < total:
			since = time.Time{}
		case since.IsZero():
			since, baseline = time.Now(), e.starts(ctx, name)
		case time.Since(since) >= healthSettle:
			if e.starts(ctx, name) == baseline {
				return good, total, nil
			}
			restarted, since = true, time.Time{}
		}
		if time.Now().After(deadline) {
			if states == "" {
				states = "no container answered"
			}
			if restarted {
				states += "; a container restarted during the check"
			}
			return good, total, errors.New(states)
		}
		select {
		case <-ctx.Done():
			return good, total, ctx.Err()
		case <-time.After(healthEvery):
		}
	}
}

func (e Env) vacant(ctx context.Context, name string) error {
	containers, err := e.list(ctx, name)
	switch {
	case err != nil:
		return err
	case len(containers) > 0:
		return fmt.Errorf("a stack named %s already runs on %s", name, e.server())
	case e.removed(name):
		return fmt.Errorf("a stack named %s waits in Removed on %s; restore it or delete it permanently first", name, e.server())
	}
	volumes, err := e.volumes(ctx, name)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(e.folder(name)); err == nil || len(volumes) > 0 {
		return fmt.Errorf("files left from an earlier %s are still on %s; delete them permanently first", name, e.server())
	}
	return nil
}

func (e Env) volumes(ctx context.Context, name string) ([]string, error) {
	output, err := e.docker(ctx, stepTimeout, "volume", "ls", "-q", "--filter", projectLabel+name)
	if err != nil {
		return nil, failed("volume ls", output, err)
	}
	return strings.Fields(string(output)), nil
}

func (e Env) namesFree(ctx context.Context, name, text string) error {
	names, err := parseNames(text)
	if err != nil || len(names) == 0 {
		return err
	}
	output, err := e.docker(ctx, stepTimeout, "ps", "-a", "--format", "{{.Names}}\t{{.Label \"com.docker.compose.project\"}}")
	if err != nil {
		return failed("ps", output, err)
	}
	taken := map[string]string{}
	for line := range strings.SplitSeq(string(output), "\n") {
		container, project, _ := strings.Cut(strings.TrimSpace(line), "\t")
		taken[container] = project
	}
	for _, service := range slices.Sorted(maps.Keys(names)) {
		if project, used := taken[names[service]]; used && project != name {
			return fmt.Errorf("the container name %s is taken on %s", names[service], e.server())
		}
	}
	return nil
}

func (e Env) create(ctx context.Context, cmd trust.Command, progress func(string)) (string, error) {
	name, dir := cmd.Name, e.folder(cmd.Name)
	if err := e.vacant(ctx, name); err != nil {
		return "", err
	}
	if err := CheckText(cmd.Args["compose"], cmd.Args["access"]); err != nil {
		return "", err
	}
	if err := e.namesFree(ctx, name, cmd.Args["names"]); err != nil {
		return "", err
	}
	if err := Write(dir, cmd, e.Unseal); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	message, err := e.launch(ctx, name, progress)
	if err != nil {
		if left, listed := e.list(ctx, name); listed == nil && len(left) == 0 {
			if tidy := e.wipe(ctx, name); tidy != nil {
				log.Printf("tidy %s: %v", name, tidy)
			}
		}
		return "", err
	}
	return message, nil
}

type kept map[string][]byte

func keep(dir string) kept {
	saved := kept{}
	for _, file := range []string{composeFile, envFile, metaFile, runFile} {
		body, _ := safefile.Read(filepath.Join(dir, file), maxState)
		saved[filepath.Join(dir, file)] = body
	}
	return saved
}

func (k kept) put() {
	for path, body := range k {
		if body == nil {
			os.Remove(path)
			continue
		}
		mode := os.FileMode(0o640)
		if base := filepath.Base(path); base == envFile || base == runFile {
			mode = 0o600
		}
		if err := safefile.Write(path, body, mode); err != nil {
			log.Printf("put back %s: %v", path, err)
		}
	}
}

func (e Env) edit(ctx context.Context, cmd trust.Command, progress func(string)) (string, error) {
	name, dir := cmd.Name, e.folder(cmd.Name)
	if err := e.managed(name); err != nil {
		return "", err
	}
	if err := CheckText(cmd.Args["compose"], cmd.Args["access"]); err != nil {
		return "", err
	}
	if err := e.namesFree(ctx, name, cmd.Args["names"]); err != nil {
		return "", err
	}
	running, err := e.list(ctx, name, "--filter", "status=running")
	if err != nil {
		return "", err
	}
	saved := keep(dir)
	if err := Write(dir, cmd, e.Unseal); err != nil {
		saved.put()
		return "", err
	}
	message, err := e.launch(ctx, name, progress)
	if err == nil {
		return message, nil
	}
	saved.put()
	if len(running) == 0 {
		return "", fmt.Errorf("%w; the previous file is back", err)
	}
	if check := e.prepare(ctx, name); check != nil {
		return "", fmt.Errorf("%w; the previous file is back but did not pass its check, so it was not started: %w", err, check)
	}
	output, again := e.compose(ctx, upTimeout, name, "up", "-d", "--remove-orphans", "--pull", "never")
	if again != nil {
		return "", fmt.Errorf("%w; the previous file did not start again: %w", err, e.composeFailed(name, "up", output, again))
	}
	return "", fmt.Errorf("%w; the previous file runs again", err)
}

func (e Env) retag(ctx context.Context, images []pinned) (int, error) {
	retagged := 0
	for _, image := range images {
		if strings.Contains(image.Reference, "@sha256:") {
			continue
		}
		if output, err := e.docker(ctx, stepTimeout, "tag", image.ID, image.Reference); err != nil {
			return retagged, failed("tag", output, err)
		}
		retagged++
	}
	return retagged, nil
}

func holds(images []pinned, id string) bool {
	return slices.ContainsFunc(images, func(image pinned) bool { return image.ID == id })
}

func sameImages(a, b []pinned) bool {
	return len(a) == len(b) && !slices.ContainsFunc(a, func(image pinned) bool { return !holds(b, image.ID) })
}

func (e Env) deploy(ctx context.Context, cmd trust.Command, progress func(string)) (string, error) {
	name := cmd.Name
	if err := e.managed(name); err != nil {
		return "", err
	}
	progress(stepChecking)
	if err := e.prepare(ctx, name); err != nil {
		return "", err
	}
	running, err := e.list(ctx, name, "--filter", "status=running")
	if err != nil {
		return "", err
	}
	original, err := load[record](e.recordPath(name))
	if err != nil {
		return "", err
	}
	candidate, err := e.images(ctx, name)
	if err != nil {
		return "", err
	}
	progress(stepPulling)
	if output, err := e.compose(ctx, pullTimeout, name, "pull"); err != nil {
		return "", e.composeFailed(name, "pull", output, err)
	}
	previous := candidate
	if original.Failed {
		previous = original.Previous
	}
	message := fmt.Sprintf("%s has the new images of %s; it stays stopped.", e.server(), name)
	if len(running) == 0 {
		release := e.owned(ctx, name, upTimeout, e.planned(name)...)
		output, err := e.compose(ctx, upTimeout, name, "up", "--no-start", "--remove-orphans")
		release()
		if err != nil {
			return "", e.composeFailed(name, "up", output, err)
		}
	} else {
		if err := store(e.recordPath(name), record{Previous: previous, Failed: true}); err != nil {
			return "", err
		}
		if message, err = e.up(ctx, name, progress); err != nil {
			return "", e.back(ctx, name, previous, err, progress)
		}
	}
	after, _ := e.images(ctx, name)
	if sameImages(after, candidate) {
		previous = original.Previous
	}
	if err := store(e.recordPath(name), record{Previous: previous}); err != nil {
		return "", err
	}
	for _, image := range original.Previous {
		if !holds(previous, image.ID) && !holds(after, image.ID) {
			e.docker(ctx, stepTimeout, "image", "rm", image.ID)
		}
	}
	return message, nil
}

func (e Env) back(ctx context.Context, name string, previous []pinned, failure error, progress func(string)) error {
	retagged, err := e.retag(ctx, previous)
	if err == nil && retagged == 0 {
		err = errors.New("there are no earlier images to go back to")
	}
	if err == nil {
		progress(stepBack)
		_, err = e.up(ctx, name, progress, "--pull", "never")
	}
	if err != nil {
		return fmt.Errorf("%w; going back to the previous images failed too: %w", failure, err)
	}
	if err := store(e.recordPath(name), record{Previous: previous}); err != nil {
		return fmt.Errorf("%w; %s went back to the previous images of %s but could not note it: %w", failure, e.server(), name, err)
	}
	return fmt.Errorf("%w; %s went back to the previous images of %s, and Rollback is still there", failure, e.server(), name)
}

func (e Env) rollback(ctx context.Context, cmd trust.Command, progress func(string)) (string, error) {
	name := cmd.Name
	if err := e.managed(name); err != nil {
		return "", err
	}
	original, err := load[record](e.recordPath(name))
	if err != nil {
		return "", err
	}
	if len(original.Previous) == 0 {
		return "", fmt.Errorf("%s has nothing to roll back to", name)
	}
	progress(stepChecking)
	if err := e.prepare(ctx, name); err != nil {
		return "", err
	}
	retagged, err := e.retag(ctx, original.Previous)
	if err != nil {
		return "", err
	}
	if retagged == 0 {
		return "", errors.New("nothing to roll back to: every image of this stack is pinned by digest, so the compose file already names the exact image; put the earlier digest back with Edit Compose")
	}
	message, err := e.up(ctx, name, progress, "--pull", "never")
	if err != nil {
		return "", err
	}
	if err := store(e.recordPath(name), record{Previous: []pinned{}}); err != nil {
		return "", err
	}
	return message, nil
}

func (e Env) lifecycle(ctx context.Context, cmd trust.Command, _ func(string)) (string, error) {
	name := cmd.Name
	if err := e.managed(name); err != nil {
		return "", err
	}
	if cmd.Action != "stop" {
		if err := e.prepare(ctx, name); err != nil {
			return "", err
		}
	}
	if cmd.Action == "stop" {
		defer e.owned(ctx, name, upTimeout)()
	}
	if output, err := e.compose(ctx, upTimeout, name, cmd.Action); err != nil {
		return "", e.composeFailed(name, cmd.Action, output, err)
	}
	return fmt.Sprintf("%s %s %s.", e.server(), pastTense[cmd.Action], name), nil
}

func (e Env) remove(ctx context.Context, cmd trust.Command, _ func(string)) (string, error) {
	name := cmd.Name
	if err := e.managed(name); err != nil {
		return "", err
	}
	release := e.owned(ctx, name, upTimeout)
	output, err := e.compose(ctx, upTimeout, name, "down", "--remove-orphans")
	release()
	if err != nil {
		return "", e.composeFailed(name, "down", output, err)
	}
	if err := os.Remove(e.recordPath(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := e.changeBin(func(bin map[string]removal) { bin[name] = removal{RemovedAt: e.Now().UTC()} }); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s moved %s to Removed; it is deleted for good after 7 days.", e.server(), name), nil
}

func (e Env) restore(ctx context.Context, cmd trust.Command, progress func(string)) (string, error) {
	name := cmd.Name
	if !e.removed(name) {
		return "", fmt.Errorf("%s is not in Removed on %s", name, e.server())
	}
	message, err := e.launch(ctx, name, progress)
	if err != nil {
		return "", err
	}
	if err := e.changeBin(func(bin map[string]removal) { delete(bin, name) }); err != nil {
		return "", err
	}
	return message, nil
}

func (e Env) purge(ctx context.Context, cmd trust.Command, _ func(string)) (string, error) {
	name := cmd.Name
	containers, err := e.list(ctx, name)
	if err != nil {
		return "", err
	}
	volumes, err := e.volumes(ctx, name)
	if err != nil {
		return "", err
	}
	_, missing := os.Lstat(e.folder(name))
	switch {
	case missing != nil && len(containers) > 0:
		return "", fmt.Errorf("Krynodes does not manage %s on %s; adopt it first", name, e.server())
	case missing != nil && !e.removed(name) && len(volumes) == 0:
		return "", fmt.Errorf("%s is not on %s", name, e.server())
	}
	if len(containers) > 0 {
		release := e.owned(ctx, name, upTimeout)
		output, err := e.compose(ctx, upTimeout, name, "down", "-v", "--remove-orphans")
		release()
		if err != nil {
			return "", e.composeFailed(name, "down", output, err)
		}
	}
	if err := e.wipe(ctx, name); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s deleted %s and its data for good.", e.server(), name), nil
}

func (e Env) wipe(ctx context.Context, name string) error {
	names, err := e.volumes(ctx, name)
	if err != nil {
		return err
	}
	if len(names) > 0 {
		if output, err := e.docker(ctx, upTimeout, append([]string{"volume", "rm"}, names...)...); err != nil {
			return failed("volume rm", output, err)
		}
	}
	if err := os.RemoveAll(e.folder(name)); err != nil {
		return err
	}
	if err := os.Remove(e.recordPath(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return e.changeBin(func(bin map[string]removal) { delete(bin, name) })
}

func (e Env) foreign(ctx context.Context, name string) (string, string, error) {
	output, err := e.docker(ctx, stepTimeout, "ps", "-a", "--no-trunc", "--filter", projectLabel+name, "--format", homeFormat)
	if err != nil {
		return "", "", failed("ps", output, err)
	}
	var homes []string
	for line := range strings.SplitSeq(string(output), "\n") {
		if line = strings.TrimRight(line, "\r"); line != "" && !slices.Contains(homes, line) {
			homes = append(homes, line)
		}
	}
	switch {
	case len(homes) == 0:
		return "", "", fmt.Errorf("%s is not on %s", name, e.server())
	case len(homes) > 1:
		return "", "", fmt.Errorf("the containers of %s do not share one folder", name)
	case !filepath.IsAbs(homes[0]) || filepath.Clean(homes[0]) != homes[0]:
		return "", "", fmt.Errorf("%s does not name a folder Krynodes can read", name)
	}
	for _, file := range standardFiles {
		if info, err := os.Lstat(filepath.Join(homes[0], file)); err == nil && info.Mode().IsRegular() {
			return homes[0], file, nil
		}
	}
	return "", "", fmt.Errorf("%s holds no compose file Krynodes can adopt", homes[0])
}

func (e Env) adopt(ctx context.Context, cmd trust.Command, progress func(string)) (string, error) {
	name, dir := cmd.Name, e.folder(cmd.Name)
	if _, err := os.Lstat(dir); err == nil || e.removed(name) {
		return "", fmt.Errorf("Krynodes already has a stack named %s on %s", name, e.server())
	}
	from, file, err := e.foreign(ctx, name)
	if err != nil {
		return "", err
	}
	text, err := safefile.Read(filepath.Join(from, file), maxComposeBytes+1)
	if err != nil {
		return "", err
	}
	access := cmd.Args["access"]
	if err := CheckText(string(text), access); err != nil {
		return "", err
	}
	env, err := readEnv(from)
	if err != nil {
		return "", err
	}
	before, err := e.members(ctx, name)
	if err != nil {
		return "", err
	}
	if err := e.takeIn(ctx, name, from, access, text, env); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	message, err := e.up(ctx, name, progress)
	if err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("%w; %s", err, e.startAgain(ctx, name, from, before))
	}
	return fmt.Sprintf("%s Krynodes manages it now, with %s access.", message, strings.ToUpper(access[:1])+access[1:]), nil
}

func (e Env) members(ctx context.Context, name string) (map[string]string, error) {
	output, err := e.docker(ctx, stepTimeout, "ps", "-a", "--no-trunc", "--filter", projectLabel+name, "--format", "{{.ID}}\t{{.Names}}")
	if err != nil {
		return nil, failed("ps", output, err)
	}
	found := map[string]string{}
	for line := range strings.SplitSeq(string(output), "\n") {
		if id, container, ok := strings.Cut(strings.TrimSpace(line), "\t"); ok && id != "" {
			found[id] = container
		}
	}
	return found, nil
}

func (e Env) startAgain(ctx context.Context, name, from string, before map[string]string) string {
	now, _ := e.members(ctx, name)
	var ids, containers []string
	for _, id := range slices.Sorted(maps.Keys(before)) {
		if _, still := now[id]; still {
			ids, containers = append(ids, id), append(containers, before[id])
		}
	}
	if len(ids) == 0 {
		if running, err := e.list(ctx, name, "--filter", "status=restarting", "--filter", "status=running"); err == nil && len(running) > 0 {
			return fmt.Sprintf("the containers Krynodes started still run, unmanaged; run docker compose up -d in %s to go back to your own.", from)
		}
		return fmt.Sprintf("Start it again from %s.", from)
	}
	if output, err := e.docker(ctx, upTimeout, append([]string{"start", "--"}, ids...)...); err != nil {
		return fmt.Sprintf("its containers did not start again (%v). Start it again from %s.", startFailed(from, output, err), from)
	}
	return fmt.Sprintf("its containers run again as they were, from %s.", from)
}

func (e Env) takeIn(ctx context.Context, name, from, access string, text, env []byte) error {
	dir := e.folder(name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := safefile.Write(filepath.Join(dir, composeFile), text, 0o640); err != nil {
		return err
	}
	if env != nil {
		if err := safefile.Write(filepath.Join(dir, envFile), env, 0o600); err != nil {
			return err
		}
	}
	if err := writeMeta(dir, Meta{Access: access, Network: []int{}, Home: from}); err != nil {
		return err
	}
	return e.prepare(ctx, name)
}

func (e Env) logs(ctx context.Context, cmd trust.Command, _ func(string)) (string, error) {
	name := cmd.Name
	if err := e.managed(name); err != nil {
		return "", err
	}
	args := []string{"logs", "--tail", cmd.Args["lines"], "--timestamps", "--no-color"}
	if service := cmd.Args["service"]; service != "" {
		args = append(args, "--", service)
	}
	output, err := e.compose(ctx, stepTimeout, name, args...)
	if err != nil {
		return "", failed("logs", nil, err)
	}
	if err := e.deliver(ctx, cmd.Args["to"], cut(output)); err != nil {
		return "", err
	}
	return fmt.Sprintf("The last %s lines of %s.", cmd.Args["lines"], name), nil
}

func (e Env) deliver(ctx context.Context, to, text string) error {
	if e.Sealing == nil {
		return errors.New("this server's seal key is not loaded, so it cannot prove its answer")
	}
	sealed, err := seal.SealFrom(e.Sealing, to, []byte(text))
	if err != nil {
		return err
	}
	daemon.Output(ctx, sealed)
	return nil
}

func (e Env) read(ctx context.Context, cmd trust.Command, _ func(string)) (string, error) {
	name, dir := cmd.Name, e.folder(cmd.Name)
	if err := e.managed(name); err != nil {
		return "", err
	}
	text, envNames, err := Read(dir)
	if err != nil {
		return "", err
	}
	meta, err := ReadMeta(dir)
	if err != nil {
		return "", err
	}
	if meta.Names == nil {
		meta.Names = map[string]string{}
	}
	encoded, err := json.Marshal(struct {
		Compose string            `json:"compose"`
		Access  string            `json:"access"`
		Title   string            `json:"title"`
		Names   map[string]string `json:"names"`
		Network []int             `json:"network"`
		Env     []string          `json:"env"`
	}{text, meta.Access, meta.Title, meta.Names, meta.Network, envNames})
	if err != nil {
		return "", err
	}
	if len(encoded) > maxOutput {
		return "", fmt.Errorf("the compose file of %s does not fit in one answer", name)
	}
	if err := e.deliver(ctx, cmd.Args["to"], string(encoded)); err != nil {
		return "", err
	}
	return fmt.Sprintf("The compose file of %s.", name), nil
}

func failed(step string, output []byte, err error) error {
	if text := tail(output, maxFailure); text != "" {
		return fmt.Errorf("%s failed: %s", step, text)
	}
	return fmt.Errorf("%s failed: %w", step, err)
}

func startFailed(from string, output []byte, err error) error {
	env, _ := readEnv(from)
	return failed("start", []byte(redact(sanitize(output), env)), err)
}

func (e Env) composeFailed(name, step string, output []byte, err error) error {
	env, _ := readEnv(e.folder(name))
	return failed(step, []byte(redact(sanitize(output), env)), err)
}

func sanitize(output []byte) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || !unicode.IsControl(r) {
			return r
		}
		return -1
	}, strings.ToValidUTF8(string(output), ""))
}

func tail(output []byte, most int) string {
	text := strings.TrimSpace(sanitize(output))
	if len(text) <= most {
		return text
	}
	text = text[len(text)-most:]
	for !utf8.ValidString(text) {
		text = text[1:]
	}
	return text
}

func cut(output []byte) string {
	text := sanitize(output)
	if len(text) <= maxOutput {
		return text
	}
	text = text[len(text)-maxOutput+len(cutLine):]
	if end := strings.IndexByte(text, '\n'); end >= 0 {
		text = text[end+1:]
	}
	for !utf8.ValidString(text) {
		text = text[1:]
	}
	return cutLine + text
}
