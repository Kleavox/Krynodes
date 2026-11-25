package docker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
	"time"
)

var (
	settle     = 2 * time.Second
	every      = time.Minute
	firstRetry = time.Second
	lastRetry  = 30 * time.Second
)

const maxStderr = 2048

var containerEvents = []string{"create", "start", "restart", "die", "stop", "kill", "pause", "unpause", "destroy", "rename", "health_status"}

type Watcher struct {
	Run    Runner
	Send   func(any) error
	Checks *Checks
	Meta   Meta
	Now    func() time.Time
	Follow func(context.Context) (io.ReadCloser, error)

	sent   string
	sentAt time.Time
	held   bool
}

func Watch(ctx context.Context, run Runner, send func(any) error, checks *Checks, meta Meta) {
	(&Watcher{Run: run, Send: send, Checks: checks, Meta: meta, Now: time.Now, Follow: follow}).Watch(ctx)
}

func follow(ctx context.Context) (io.ReadCloser, error) {
	args := []string{"events", "--format", "{{json .}}", "--filter", "type=container"}
	for _, event := range containerEvents {
		args = append(args, "--filter", "event="+event)
	}
	return spawn(ctx, "docker", args...)
}

func spawn(ctx context.Context, name string, args ...string) (io.ReadCloser, error) {
	command := exec.CommandContext(ctx, name, args...)
	stderr := &bounded{}
	command.Stderr = stderr
	stream, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	return events{ReadCloser: stream, command: command, stderr: stderr}, nil
}

type bounded struct {
	text []byte
}

func (b *bounded) Write(p []byte) (int, error) {
	b.text = append(b.text, p[:min(len(p), maxStderr-len(b.text))]...)
	return len(p), nil
}

type events struct {
	io.ReadCloser
	command *exec.Cmd
	stderr  *bounded
}

func (e events) Close() error {
	e.ReadCloser.Close()
	exited := make(chan error, 1)
	go func() { exited <- e.command.Wait() }()
	var err error
	select {
	case err = <-exited:
	case <-time.After(time.Second):
		e.command.Process.Kill()
		err = <-exited
	}
	if said := strings.TrimSpace(string(e.stderr.text)); err != nil && said != "" {
		return fmt.Errorf("%w: %s", err, said)
	}
	return err
}

func (w *Watcher) Watch(ctx context.Context) {
	retry := firstRetry
	for ctx.Err() == nil {
		began := time.Now()
		w.session(ctx)
		if time.Since(began) > lastRetry {
			retry = firstRetry
		}
		timer := time.NewTimer(retry)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-w.Checks.wake:
		case <-timer.C:
		}
		timer.Stop()
		retry = min(retry*2, lastRetry)
	}
}

func (w *Watcher) session(ctx context.Context) {
	stream, err := w.Follow(ctx)
	w.refresh(ctx)
	if err != nil {
		skip("cannot follow Docker's events: %s", err.Error())
		return
	}
	defer func() {
		if err := stream.Close(); err != nil && ctx.Err() == nil {
			log.Printf("Docker's events stopped: %v", err)
		}
	}()
	lines := make(chan struct{})
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(stream)
		scanner.Buffer(make([]byte, 0, 4096), 1<<20)
		for scanner.Scan() {
			select {
			case lines <- struct{}{}:
			case <-ctx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil && ctx.Err() == nil {
			log.Printf("reading Docker's events: %v", err)
		}
	}()
	tick := time.NewTicker(every)
	defer tick.Stop()
	var settled <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case _, open := <-lines:
			if !open {
				return
			}
			if settled == nil {
				settled = time.After(settle)
			}
		case <-settled:
			settled = nil
			w.refresh(ctx)
		case <-tick.C:
			w.refresh(ctx)
		case <-w.Checks.wake:
			w.refresh(ctx)
		case <-w.due():
			w.refresh(ctx)
		}
	}
}

func (w *Watcher) due() <-chan time.Time {
	now := w.Now()
	at, ok := w.Checks.next(now)
	if held := w.sentAt.Add(rate); w.held && (!ok || held.Before(at)) {
		at, ok = held, true
	}
	if !ok {
		return nil
	}
	return time.After(at.Sub(now))
}

func (w *Watcher) refresh(ctx context.Context) {
	urgent := w.Checks.hurried()
	inventory, all, err := collect(ctx, w.Run, w.Meta)
	if ctx.Err() != nil {
		return
	}
	if w.Checks.restated() {
		w.sent, urgent = "", true
	}
	now := w.Now()
	w.held = false
	switch {
	case err != nil:
		log.Printf("inventory: %v", err)
	case inventory.Hash == w.sent:
	case !urgent && !w.sentAt.IsZero() && now.Before(w.sentAt.Add(rate)):
		w.held = true
	case w.Send(inventory) == nil:
		w.sent, w.sentAt = inventory.Hash, now
	}
	inventory.Containers = all
	w.Checks.observe(inventory, w.Now())
	w.flush()
}

func (w *Watcher) flush() {
	now := w.Now()
	for _, check := range w.Checks.due(now) {
		if w.Send(check) != nil {
			return
		}
		w.Checks.sent(check, now)
	}
}
