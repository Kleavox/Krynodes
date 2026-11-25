package docker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

type server struct {
	mu         sync.Mutex
	containers string
	docker     error
	ps         int
	now        time.Time
}

func (s *server) run(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if name == "docker" && args[0] == "ps" {
		s.ps++
	}
	return (&fake{containers: s.containers, docker: s.docker}).run(ctx, name, args...)
}

func (s *server) set(containers string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.containers = containers
}

func (s *server) clock() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now
}

func (s *server) advance(by time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = s.now.Add(by)
}

func (s *server) listed() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ps
}

type harness struct {
	machine  *server
	watcher  *Watcher
	follows  chan *io.PipeWriter
	messages chan any
}

func watch(t *testing.T, machine *server, checks *Checks, follow func(context.Context) (io.ReadCloser, error)) *harness {
	t.Helper()
	before := [4]time.Duration{settle, every, firstRetry, lastRetry}
	settle, every, firstRetry, lastRetry = 10*time.Millisecond, time.Hour, 10*time.Millisecond, 40*time.Millisecond
	h := &harness{machine: machine, follows: make(chan *io.PipeWriter, 8), messages: make(chan any, 64)}
	if follow == nil {
		follow = func(context.Context) (io.ReadCloser, error) {
			reader, writer := io.Pipe()
			h.follows <- writer
			return reader, nil
		}
	}
	if machine.now.IsZero() {
		machine.now = start
	}
	h.watcher = &Watcher{Run: machine.run, Send: func(message any) error { h.messages <- message; return nil }, Checks: checks, Now: machine.clock, Follow: follow}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.watcher.Watch(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		settle, every, firstRetry, lastRetry = before[0], before[1], before[2], before[3]
	})
	return h
}

func (h *harness) next(t *testing.T) any {
	t.Helper()
	select {
	case message := <-h.messages:
		return message
	case <-time.After(2 * time.Second):
		t.Fatal("nothing was sent")
		return nil
	}
}

func (h *harness) quiet(t *testing.T) {
	t.Helper()
	select {
	case message := <-h.messages:
		t.Fatalf("unexpected %+v", message)
	case <-time.After(100 * time.Millisecond):
	}
}

func (h *harness) stream(t *testing.T) *io.PipeWriter {
	t.Helper()
	select {
	case writer := <-h.follows:
		return writer
	case <-time.After(2 * time.Second):
		t.Fatal("the event stream was not followed")
		return nil
	}
}

func (h *harness) inventory(t *testing.T) reporter.Inventory {
	t.Helper()
	inventory, ok := h.next(t).(reporter.Inventory)
	if !ok {
		t.Fatal("expected an inventory")
	}
	return inventory
}

func (h *harness) checks(t *testing.T, count int) map[string]reporter.Check {
	t.Helper()
	got := map[string]reporter.Check{}
	for range count {
		check, ok := h.next(t).(reporter.Check)
		if !ok {
			t.Fatal("expected a check")
		}
		got[check.Name] = check
	}
	return got
}

func until(t *testing.T, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestInventoryIsSentOnlyWhenItsHashChanges(t *testing.T) {
	machine := &server{containers: "web-1\trunning\tUp\tbusybox\t\t\t\t\n"}
	h := watch(t, machine, NewChecks(), nil)
	events := h.stream(t)
	first := h.inventory(t)
	events.Write([]byte("{\"status\":\"start\"}\n"))
	until(t, func() bool { return machine.listed() == 2 })
	h.quiet(t)
	machine.advance(time.Minute)
	machine.set("web-1\texited\tExited (0)\tbusybox\t\t\t\t\n")
	events.Write([]byte("{\"status\":\"die\"}\n"))
	if second := h.inventory(t); second.Hash == first.Hash || second.Containers[0].State != "stopped" {
		t.Fatalf("second %+v", second)
	}
}

func TestInventoryIsSentAtMostOncePerMinuteUnlessAVerbFinished(t *testing.T) {
	machine := &server{containers: "web-1\trunning\tUp\tbusybox\t\t\t\t\n"}
	checks := NewChecks()
	h := watch(t, machine, checks, nil)
	events := h.stream(t)
	h.inventory(t)
	machine.set("web-1\texited\tExited (0)\tbusybox\t\t\t\t\n")
	events.Write([]byte("{\"status\":\"die\"}\n"))
	until(t, func() bool { return machine.listed() == 2 })
	h.quiet(t)
	checks.Changed()
	if inventory := h.inventory(t); inventory.Containers[0].State != "stopped" {
		t.Fatalf("after a verb %+v", inventory)
	}
	machine.advance(30 * time.Second)
	machine.set("web-1\trunning\tUp\tbusybox\t\t\t\t\n")
	events.Write([]byte("{\"status\":\"start\"}\n"))
	until(t, func() bool { return machine.listed() == 4 })
	h.quiet(t)
	machine.advance(30 * time.Second)
	events.Write([]byte("{\"status\":\"start\"}\n"))
	if inventory := h.inventory(t); inventory.Containers[0].State != "running" {
		t.Fatalf("a minute on %+v", inventory)
	}
	machine.set("web-1\texited\tExited (0)\tbusybox\t\t\t\t\n")
	checks.Restate()
	if inventory := h.inventory(t); inventory.Containers[0].State != "stopped" {
		t.Fatalf("after a reconnect %+v", inventory)
	}
}

func TestAfterTheEventStreamDropsOnlyChangedStatesAreReported(t *testing.T) {
	machine := &server{containers: "a-1\trunning\tUp\tbusybox\t\t\t\t\nb-1\trunning\tUp\tbusybox\t\t\t\t\nc-1\trestarting\tRestarting\tbusybox\t\t\t\t\n"}
	checks := NewChecks()
	checks.Choose([]string{"a-1", "b-1", "c-1"})
	h := watch(t, machine, checks, nil)
	events := h.stream(t)
	h.inventory(t)
	first := h.checks(t, 3)
	if first["a-1"].State != "up" || first["b-1"].State != "up" || first["c-1"].State != "down" {
		t.Fatalf("first %+v", first)
	}
	machine.advance(5 * time.Minute)
	machine.set("a-1\texited\tExited (1)\tbusybox\t\t\t\t\nb-1\trunning\tUp\tbusybox\t\t\t\t\nc-1\trunning\tUp (health: starting)\tbusybox\t\t\t\t\n")
	events.Close()
	h.stream(t)
	h.inventory(t)
	after := h.checks(t, 1)
	if a, ok := after["a-1"]; !ok || a.State != "down" || a.Detail != "stopped" || a.At != "2026-11-24T10:05:00Z" {
		t.Fatalf("after %+v", after)
	}
	h.quiet(t)
}

func TestChoosingChecksReportsThemAtOnce(t *testing.T) {
	machine := &server{containers: "web-1\trunning\tUp (healthy)\tbusybox\t\t\t\t\n"}
	checks := NewChecks()
	h := watch(t, machine, checks, nil)
	h.stream(t)
	h.inventory(t)
	checks.Choose([]string{"web-1", "gone-1"})
	got := h.checks(t, 2)
	if got["web-1"].State != "up" || got["web-1"].Detail != "healthy" || got["gone-1"].State != "gone" {
		t.Fatalf("got %+v", got)
	}
}

func TestADockerThatCannotBeFollowedIsStillReported(t *testing.T) {
	machine := &server{docker: &exec.Error{Name: "docker", Err: exec.ErrNotFound}}
	checks := NewChecks()
	checks.Choose([]string{"web-1"})
	h := watch(t, machine, checks, func(context.Context) (io.ReadCloser, error) {
		return nil, errors.New("docker: executable file not found")
	})
	if inventory := h.inventory(t); inventory.Docker != "missing" {
		t.Fatalf("inventory %+v", inventory)
	}
	if got := h.checks(t, 1); got["web-1"].State != "gone" {
		t.Fatalf("got %+v", got)
	}
	until(t, func() bool { return machine.listed() >= 3 })
	h.quiet(t)
}

func TestAReconnectRestatesEverything(t *testing.T) {
	machine := &server{containers: "web-1\texited\tExited (1)\tbusybox\t\t\t\t\n"}
	checks := NewChecks()
	checks.Choose([]string{"web-1"})
	h := watch(t, machine, checks, nil)
	h.stream(t)
	first := h.inventory(t)
	if got := h.checks(t, 1); got["web-1"].State != "down" {
		t.Fatalf("got %+v", got)
	}
	machine.advance(2 * time.Minute)
	checks.Restate()
	if again := h.inventory(t); again.Hash != first.Hash {
		t.Fatalf("again %+v", again)
	}
	if got := h.checks(t, 1); got["web-1"].State != "down" || got["web-1"].At != "2026-11-24T10:00:00Z" {
		t.Fatalf("got %+v", got)
	}
	h.quiet(t)
}

func TestACheckedContainerPastTheInventoryLimitIsNotGone(t *testing.T) {
	var listed strings.Builder
	for index := range 300 {
		fmt.Fprintf(&listed, "c-%03d\trunning\tUp\tbusybox\t\t\t\t\n", index)
	}
	machine := &server{containers: listed.String()}
	checks := NewChecks()
	checks.Choose([]string{"c-299"})
	h := watch(t, machine, checks, nil)
	h.stream(t)
	if inventory := h.inventory(t); len(inventory.Containers) != 256 {
		t.Fatalf("containers %d", len(inventory.Containers))
	}
	if got := h.checks(t, 1); got["c-299"].State != "up" {
		t.Fatalf("got %+v", got)
	}
}

func TestAHeldBackTransitionIsReadAgainFromDocker(t *testing.T) {
	machine := &server{containers: "web-1\trunning\tUp\tbusybox\t\t\t\t\n"}
	checks := NewChecks()
	checks.Choose([]string{"web-1"})
	h := watch(t, machine, checks, nil)
	events := h.stream(t)
	h.inventory(t)
	h.checks(t, 1)
	settle = time.Hour
	machine.set("web-1\texited\tExited (1)\tbusybox\t\t\t\t\n")
	checks.Choose([]string{"web-1"})
	until(t, func() bool { return machine.listed() == 2 })
	h.quiet(t)
	machine.set("web-1\trunning\tUp\tbusybox\t\t\t\t\n")
	machine.advance(time.Minute - 50*time.Millisecond)
	events.Write([]byte("{\"status\":\"start\"}\n"))
	until(t, func() bool { return machine.listed() == 3 })
	h.quiet(t)
}

func TestEventsHelper(t *testing.T) {
	if os.Getenv("KRY_EVENTS_HELPER") == "" {
		return
	}
	fmt.Println(`{"status":"start"}`)
	fmt.Fprint(os.Stderr, strings.Repeat("e", 5000))
	os.Exit(3)
}

func TestAFailedEventStreamSaysWhy(t *testing.T) {
	t.Setenv("KRY_EVENTS_HELPER", "1")
	stream, err := spawn(context.Background(), os.Args[0], "-test.run=^TestEventsHelper$")
	if err != nil {
		t.Fatal(err)
	}
	if read, _ := io.ReadAll(stream); !strings.Contains(string(read), `"start"`) {
		t.Fatalf("read %q", read)
	}
	err = stream.Close()
	if err == nil || !strings.Contains(err.Error(), "exit status 3") || strings.Count(err.Error(), "e") < maxStderr || strings.Contains(err.Error(), strings.Repeat("e", maxStderr+1)) {
		t.Fatalf("err %.200v (%d bytes)", err, len(fmt.Sprint(err)))
	}
}
