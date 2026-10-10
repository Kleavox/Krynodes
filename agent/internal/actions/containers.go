package actions

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/containers"
)

var containerEvents = []string{"create", "start", "restart", "die", "stop", "kill", "pause", "unpause", "destroy", "rename", "health_status"}

type Watcher struct {
	Save   func(containers.State) error
	Now    func() time.Time
	Run    Runner
	Follow func(ctx context.Context) (io.ReadCloser, error)
	Docker func() bool
	Wait   func(ctx context.Context, wait time.Duration) bool
	Beat   time.Duration
}

func NewWatcher() Watcher {
	return Watcher{
		Save:   stateWriter(StateDir),
		Now:    time.Now,
		Run:    RunCommand,
		Follow: followEvents,
		Docker: func() bool {
			_, err := exec.LookPath("docker")
			return err == nil
		},
		Wait: func(ctx context.Context, wait time.Duration) bool {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(wait):
				return true
			}
		},
		Beat: time.Minute,
	}
}

func followEvents(ctx context.Context) (io.ReadCloser, error) {
	args := []string{"events", "--format", "{{json .}}", "--filter", "type=container"}
	for _, event := range containerEvents {
		args = append(args, "--filter", "event="+event)
	}
	command := exec.CommandContext(ctx, "docker", args...)
	stream, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	return eventStream{ReadCloser: stream, command: command}, nil
}

type eventStream struct {
	io.ReadCloser
	command *exec.Cmd
}

func (s eventStream) Close() error {
	s.ReadCloser.Close()
	if s.command.Process != nil {
		s.command.Process.Kill()
	}
	return s.command.Wait()
}

func (w Watcher) Watch(ctx context.Context) {
	for ctx.Err() == nil {
		if !w.Docker() {
			w.write(containers.State{At: w.Now(), Containers: []containers.Container{}})
			if !w.Wait(ctx, time.Minute) {
				return
			}
			continue
		}
		w.session(ctx)
		if !w.Wait(ctx, 5*time.Second) {
			return
		}
	}
}

func (w Watcher) session(ctx context.Context) {
	stream, err := w.Follow(ctx)
	if err != nil {
		return
	}
	defer stream.Close()
	listed, ok := w.snapshot(ctx)
	if !ok {
		return
	}
	lines := make(chan struct{})
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(stream)
		for scanner.Scan() {
			select {
			case lines <- struct{}{}:
			case <-ctx.Done():
				return
			}
		}
	}()
	beat := time.NewTicker(w.Beat)
	defer beat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case _, open := <-lines:
			if !open {
				return
			}
			if listed, ok = w.snapshot(ctx); !ok {
				return
			}
		case <-beat.C:
			w.write(containers.State{At: w.Now(), Docker: true, Containers: listed})
		}
	}
}

func (w Watcher) snapshot(ctx context.Context) ([]containers.Container, bool) {
	output, _, err := w.Run(ctx, "docker", "ps", "-a", "--format", containers.Format)
	if err != nil {
		return nil, false
	}
	listed := containers.Parse(string(output))
	w.write(containers.State{At: w.Now(), Docker: true, Containers: listed})
	return listed, true
}

func (w Watcher) write(state containers.State) {
	_ = w.Save(state)
}

func stateWriter(dir string) func(containers.State) error {
	return func(state containers.State) error {
		return writeJSON(dir, containers.File, state, 0o640)
	}
}
