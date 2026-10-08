package actions

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	pullTimeout          = 10 * time.Minute
	upTimeout            = 5 * time.Minute
	defaultHealthTimeout = 2 * time.Minute
	defaultHealthEvery   = 5 * time.Second
	defaultHealthSettle  = 20 * time.Second
	stateFormat          = "{{.Service}}\t{{.State}}\t{{.Health}}\t{{.ExitCode}}"
	startsFormat         = "{{.Id}} {{.RestartCount}} {{.State.StartedAt}}"
	imageFormat          = "{{index .Config.Labels \"com.docker.compose.service\"}}\t{{.Config.Image}}\t{{.Image}}"
)

type imageRecord struct {
	Service   string `json:"service"`
	Reference string `json:"reference"`
	ID        string `json:"id"`
}

type stackRecord struct {
	Previous []imageRecord `json:"previous"`
	Failed   bool          `json:"failed,omitempty"`
}

type stepError struct {
	step   string
	output []byte
	code   int
}

func (e stepError) Error() string { return e.step + " failed" }

var standardComposeFiles = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}

func (e Executor) composeFiles(stack Stack) ([]string, error) {
	exists := e.Exists
	if exists == nil {
		exists = regularFile
	}
	if len(stack.Files) > 0 && !slices.ContainsFunc(stack.Files, func(file string) bool { return !exists(file) }) {
		return stack.Files, nil
	}
	for _, name := range standardComposeFiles {
		if file := path.Join(stack.Directory, name); exists(file) {
			return []string{file}, nil
		}
	}
	return nil, fmt.Errorf("no compose file found in %s", stack.Directory)
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func composeArgs(stack Stack, rest ...string) []string {
	args := []string{"compose", "--project-name", stack.Project, "--project-directory", stack.Directory}
	for _, file := range stack.Files {
		args = append(args, "-f", file)
	}
	return append(args, rest...)
}

func (e Executor) docker(ctx context.Context, timeout time.Duration, step string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output, code, err := e.Run(ctx, "docker", args...)
	if err != nil {
		return output, stepError{step: step, output: output, code: code}
	}
	return output, nil
}

func (e Executor) compose(ctx context.Context, request Request, snapshot Snapshot) Result {
	if err := expired(request, e.Now()); err != nil {
		return e.refuse(request.ID, err)
	}
	command, err := e.authorize(request)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	if slices.Contains(startVerbs, request.Action) && e.lockedDown() {
		return e.refuse(request.ID, errLockedDown)
	}
	if request.Action == "create" {
		return e.create(ctx, request, command, snapshot)
	}
	index := slices.IndexFunc(snapshot.Stacks, func(stack Stack) bool { return stack.Project == request.Name })
	if index < 0 && (request.Action == "restore" || request.Action == "purge") {
		return e.removedStack(ctx, request, snapshot)
	}
	if index < 0 {
		return e.refuse(request.ID, fmt.Errorf("%s is not on this server", request.Name))
	}
	if request.Action == "restore" {
		return e.refuse(request.ID, fmt.Errorf("%s already runs", request.Name))
	}
	if !snapshot.Compose {
		return e.refuse(request.ID, errors.New("docker compose is not available"))
	}
	stack := snapshot.Stacks[index]
	files, err := e.composeFiles(stack)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	stack.Files = files
	if request.Action == "deploy" || request.Action == "rollback" {
		if err := e.stillContained(ctx, stack.Directory); err != nil {
			return e.refuse(request.ID, err)
		}
	}
	switch request.Action {
	case "deploy":
		return e.deploy(ctx, request, stack)
	case "rollback":
		return e.rollback(ctx, request, stack)
	case "start", "stop", "restart":
		return e.lifecycle(ctx, request, stack)
	case "remove", "purge":
		return e.remove(ctx, request, stack)
	case "edit":
		return e.edit(ctx, request, command, stack)
	case "read":
		return e.read(ctx, request, stack)
	case "export":
		return e.export(request, command, stack)
	case "adopt":
		return e.adopt(ctx, request, stack)
	case "expose":
		return e.expose(ctx, request, command, stack)
	case "unexpose":
		return e.unexpose(ctx, request, command)
	}
	return e.refuse(request.ID, fmt.Errorf("unknown action %q", request.Action))
}

func (e Executor) running(ctx context.Context, stack Stack) ([]imageRecord, error) {
	ids, err := e.docker(ctx, collectTimeout, "inspect", "ps", "-a", "--no-trunc", "--filter", "label=com.docker.compose.project="+stack.Project, "--format", "{{.ID}}")
	if err != nil {
		return nil, err
	}
	containers := strings.Fields(string(ids))
	if len(containers) == 0 {
		return nil, nil
	}
	output, err := e.docker(ctx, collectTimeout, "inspect", append([]string{"inspect", "--format", imageFormat}, containers...)...)
	if err != nil {
		return nil, err
	}
	var images []imageRecord
	for line := range strings.SplitSeq(string(output), "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) != 3 || fields[1] == "" || fields[2] == "" {
			continue
		}
		images = append(images, imageRecord{Service: fields[0], Reference: fields[1], ID: fields[2]})
	}
	return images, nil
}

func judge(output []byte) (string, bool) {
	var states []string
	healthy := true
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
		state := fields[0] + " " + fields[1]
		switch {
		case fields[1] == "exited":
			state += " (" + code + ")"
			if code != "0" {
				healthy = false
			}
		case fields[1] != "running" || (health != "" && health != "healthy"):
			healthy = false
			if health != "" {
				state += " (" + health + ")"
			}
		case health != "":
			state += " (" + health + ")"
		}
		states = append(states, state)
	}
	return strings.Join(states, ", "), healthy && len(states) > 0
}

func (e Executor) starts(ctx context.Context, stack Stack) string {
	ids, err := e.docker(ctx, collectTimeout, "health check", "ps", "-a", "--no-trunc", "--filter", "label=com.docker.compose.project="+stack.Project, "--format", "{{.ID}}")
	containers := strings.Fields(string(ids))
	if err != nil || len(containers) == 0 {
		return ""
	}
	output, _ := e.docker(ctx, collectTimeout, "health check", append([]string{"inspect", "--format", startsFormat}, containers...)...)
	lines := strings.Fields(strings.ReplaceAll(string(output), " ", "|"))
	slices.Sort(lines)
	return strings.Join(lines, ",")
}

func (e Executor) healthy(ctx context.Context, stack Stack) (string, error) {
	timeout, every, settle := e.HealthTimeout, e.HealthEvery, e.HealthSettle
	if timeout == 0 {
		timeout = defaultHealthTimeout
	}
	if every == 0 {
		every = defaultHealthEvery
	}
	if settle == 0 {
		settle = defaultHealthSettle
	}
	deadline := time.Now().Add(timeout)
	var since time.Time
	var baseline string
	restarted := false
	for {
		output, err := e.docker(ctx, collectTimeout, "health check", composeArgs(stack, "ps", "--all", "--format", stateFormat)...)
		states, ok := judge(output)
		switch {
		case err != nil || !ok:
			since = time.Time{}
		case since.IsZero():
			since, baseline = time.Now(), e.starts(ctx, stack)
		case time.Since(since) >= settle:
			if e.starts(ctx, stack) == baseline {
				return states, nil
			}
			restarted = true
			since = time.Time{}
		}
		if time.Now().After(deadline) {
			if restarted {
				states += "; a container restarted during the check"
			}
			return states, stepError{step: "health check", output: []byte(states)}
		}
		select {
		case <-ctx.Done():
			return states, stepError{step: "health check", output: []byte(states)}
		case <-time.After(every):
		}
	}
}

func (e Executor) failed(request Request, err error, states string) Result {
	var failure stepError
	if !errors.As(err, &failure) {
		failure = stepError{step: "deploy", output: []byte(err.Error()), code: -1}
	}
	header := failure.step + " failed:\n"
	footer := ""
	if states != "" && failure.step != "health check" {
		footer = "\n" + states
	}
	body := tail(failure.output, maxOutputBytes-len(header)-len(footer))
	result := Result{ID: request.ID, OK: false, Output: clean([]byte(header + body + footer)), FinishedAt: e.stamp()}
	if failure.code > 0 {
		code := failure.code
		result.ExitCode = &code
	}
	return result
}

func (e Executor) states(ctx context.Context, stack Stack) string {
	output, _ := e.docker(ctx, collectTimeout, "health check", composeArgs(stack, "ps", "--all", "--format", stateFormat)...)
	states, _ := judge(output)
	return states
}

func holds(images []imageRecord, id string) bool {
	return slices.ContainsFunc(images, func(image imageRecord) bool { return image.ID == id })
}

func sameImages(a, b []imageRecord) bool {
	if len(a) != len(b) {
		return false
	}
	for _, image := range a {
		if !holds(b, image.ID) {
			return false
		}
	}
	return true
}

func (e Executor) deploy(ctx context.Context, request Request, stack Stack) Result {
	directory := filepath.Join(e.StateDir, "stacks")
	name := stack.Project + ".json"
	original, _ := readState[stackRecord](directory, name)
	candidate, err := e.running(ctx, stack)
	if err != nil {
		return e.failed(request, err, "")
	}
	if _, err := e.docker(ctx, pullTimeout, "pull", composeArgs(stack, "pull")...); err != nil {
		return e.failed(request, err, "")
	}
	previous := candidate
	if original.Failed {
		previous = original.Previous
	}
	if err := writeJSON(directory, name, stackRecord{Previous: previous, Failed: true}, 0o640); err != nil {
		return e.failed(request, err, "")
	}
	if _, err := e.docker(ctx, upTimeout, "up", composeArgs(stack, "up", "-d")...); err != nil {
		return e.failed(request, err, e.states(ctx, stack))
	}
	if states, err := e.healthy(ctx, stack); err != nil {
		return e.failed(request, err, states)
	}
	after, err := e.running(ctx, stack)
	if err == nil && sameImages(after, candidate) {
		previous = original.Previous
	}
	if err := writeJSON(directory, name, stackRecord{Previous: previous}, 0o640); err != nil {
		return e.failed(request, err, "")
	}
	for _, image := range original.Previous {
		if !holds(previous, image.ID) && !holds(after, image.ID) {
			_, _ = e.docker(ctx, collectTimeout, "prune", "image", "rm", image.ID)
		}
	}
	return Result{ID: request.ID, OK: true, Output: "deployed", FinishedAt: e.stamp()}
}

func (e Executor) rollback(ctx context.Context, request Request, stack Stack) Result {
	directory := filepath.Join(e.StateDir, "stacks")
	record, _ := readState[stackRecord](directory, stack.Project+".json")
	if len(record.Previous) == 0 {
		return e.refuse(request.ID, errors.New("nothing to roll back to"))
	}
	for _, image := range record.Previous {
		if strings.Contains(image.Reference, "@sha256:") {
			continue
		}
		if _, err := e.docker(ctx, collectTimeout, "tag", "tag", image.ID, image.Reference); err != nil {
			return e.failed(request, err, "")
		}
	}
	if _, err := e.docker(ctx, upTimeout, "up", composeArgs(stack, "up", "-d")...); err != nil {
		return e.failed(request, err, e.states(ctx, stack))
	}
	if states, err := e.healthy(ctx, stack); err != nil {
		return e.failed(request, err, states)
	}
	if err := writeJSON(directory, stack.Project+".json", stackRecord{Previous: []imageRecord{}}, 0o640); err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: "rolled back", FinishedAt: e.stamp()}
}
