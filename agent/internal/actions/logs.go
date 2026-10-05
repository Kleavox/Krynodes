package actions

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

const (
	maxLogBytes = 64 << 10
	logLines    = "300"
	logsTimeout = 30 * time.Second
)

func (e Executor) logs(ctx context.Context, request Request, snapshot Snapshot) Result {
	if !ValidTarget(request.Kind, request.Name) {
		return e.refuse(request.ID, errors.New("invalid target"))
	}
	if err := expired(request, e.Now()); err != nil {
		return e.refuse(request.ID, err)
	}
	if _, err := e.authorize(request); err != nil {
		return e.refuse(request.ID, err)
	}
	command, err := e.logCommand(request, snapshot)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	ctx, cancel := context.WithTimeout(ctx, logsTimeout)
	defer cancel()
	output, code, err := e.Run(ctx, command[0], command[1:]...)
	result := Result{ID: request.ID, OK: err == nil, Output: tail(output, maxLogBytes), FinishedAt: e.stamp()}
	if code >= 0 {
		result.ExitCode = &code
	}
	if err != nil && result.Output == "" {
		result.Output = clean([]byte(err.Error()))
	}
	return result
}

func (e Executor) logCommand(request Request, snapshot Snapshot) ([]string, error) {
	absent := fmt.Errorf("%s is not on this server", request.Name)
	switch request.Kind {
	case "systemd", "docker":
		if !slices.ContainsFunc(snapshot.Services, func(service Service) bool {
			return service.Kind == request.Kind && service.Name == request.Name
		}) {
			return nil, absent
		}
		if request.Kind == "systemd" {
			return []string{"journalctl", "--unit=" + request.Name, "--lines=" + logLines, "--no-pager", "--output=short-iso"}, nil
		}
		return []string{"docker", "logs", "--tail", logLines, "--timestamps", "--", request.Name}, nil
	case "compose":
		index := slices.IndexFunc(snapshot.Stacks, func(stack Stack) bool { return stack.Project == request.Name })
		if index < 0 {
			return nil, absent
		}
		if !snapshot.Compose {
			return nil, errors.New("docker compose is not available")
		}
		stack := snapshot.Stacks[index]
		files, err := e.composeFiles(stack)
		if err != nil {
			return nil, err
		}
		stack.Files = files
		return append([]string{"docker"}, composeArgs(stack, "logs", "--tail", logLines, "--timestamps", "--no-color")...), nil
	}
	return nil, fmt.Errorf("%s has no logs", request.Kind)
}
