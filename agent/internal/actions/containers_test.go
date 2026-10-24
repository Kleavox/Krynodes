package actions

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/containers"
)

type watchFake struct {
	mu        sync.Mutex
	listing   []string
	inspect   string
	inspectOK bool
	inspected [][]string
	calls     int
	saved     []containers.State
	streams   chan *io.PipeWriter
	waits     chan time.Duration
	docker    bool
}

func newWatchFake(listing ...string) *watchFake {
	return &watchFake{listing: listing, streams: make(chan *io.PipeWriter, 4), waits: make(chan time.Duration, 4), docker: true, inspectOK: true}
}

func (f *watchFake) watcher(t *testing.T) Watcher {
	return Watcher{
		Now: func() time.Time { return time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC) },
		Run: func(_ context.Context, name string, args ...string) ([]byte, int, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if name == "docker" && len(args) > 2 && args[0] == "inspect" && args[1] == "--format" && args[2] == containers.StartedFormat {
				f.inspected = append(f.inspected, args[3:])
				if !f.inspectOK {
					return nil, 1, errors.New("no such object")
				}
				return []byte(f.inspect), 0, nil
			}
			if name != "docker" || strings.Join(args, " ") != "ps -a --no-trunc --format "+containers.Format {
				t.Errorf("ran %s %q", name, args)
			}
			index := min(f.calls, len(f.listing)-1)
			f.calls++
			return []byte(f.listing[index]), 0, nil
		},
		Follow: func(context.Context) (io.ReadCloser, error) {
			reader, writer := io.Pipe()
			f.streams <- writer
			return reader, nil
		},
		Docker: func() bool { return f.docker },
		Wait: func(ctx context.Context, wait time.Duration) bool {
			f.waits <- wait
			<-ctx.Done()
			return false
		},
		Save: func(state containers.State) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.saved = append(f.saved, state)
			return nil
		},
		Beat: time.Hour,
	}
}

func (f *watchFake) waitFor(t *testing.T, check func(containers.State) bool) containers.State {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		var last containers.State
		found := len(f.saved) > 0
		if found {
			last = f.saved[len(f.saved)-1]
		}
		f.mu.Unlock()
		if found && check(last) {
			return last
		}
		if time.Now().After(deadline) {
			t.Fatalf("last saved state %#v", last)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestTheWatcherWritesASnapshotAndRefreshesOnEachEvent(t *testing.T) {
	fake := newWatchFake("web\trunning\tUp 1 second\n", "web\texited\tExited (1) now\n", "web\trunning\tUp now\nnew\trunning\tUp now\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fake.watcher(t).Watch(ctx)
	stream := <-fake.streams
	fake.waitFor(t, func(state containers.State) bool {
		return state.Docker && len(state.Containers) == 1 && state.Containers[0].State == "running"
	})
	io.WriteString(stream, `{"status":"die","id":"a"}`+"\n")
	fake.waitFor(t, func(state containers.State) bool {
		return len(state.Containers) == 1 && state.Containers[0].State == "exited"
	})
	io.WriteString(stream, `{"status":"start","id":"a"}`+"\n"+`{"status":"start","id":"b"}`+"\n")
	fake.waitFor(t, func(state containers.State) bool { return len(state.Containers) == 2 })
}

func TestASnapshotRecordsWhenRunningContainersStarted(t *testing.T) {
	up, down := strings.Repeat("a1", 32), strings.Repeat("b2", 32)
	fake := newWatchFake("web\trunning\tUp 3 days\t" + up + "\tsite\nold\texited\tExited (0) 2 days ago\t" + down + "\tsite\n")
	fake.inspect = up + "\t2026-10-24T09:24:39.123456789Z\n"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fake.watcher(t).Watch(ctx)
	<-fake.streams
	state := fake.waitFor(t, func(state containers.State) bool { return len(state.Containers) == 2 })
	if state.Containers[0].Started != "2026-10-24T09:24:39Z" || state.Containers[0].Project != "site" {
		t.Fatalf("running container %#v", state.Containers[0])
	}
	if state.Containers[1].Started != "" {
		t.Fatalf("an exited container has no start: %#v", state.Containers[1])
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.inspected) != 1 || strings.Join(fake.inspected[0], " ") != up {
		t.Fatalf("inspected %q; only running containers, in one call", fake.inspected)
	}
}

func TestAnInspectThatFailsStillSavesTheList(t *testing.T) {
	fake := newWatchFake("web\trunning\tUp 3 days\t" + strings.Repeat("a1", 32) + "\t\n")
	fake.inspectOK = false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fake.watcher(t).Watch(ctx)
	<-fake.streams
	state := fake.waitFor(t, func(state containers.State) bool { return len(state.Containers) == 1 })
	if state.Containers[0].Started != "" || state.Containers[0].State != "running" {
		t.Fatalf("state %#v", state)
	}
}

func TestASnapshotWithNothingRunningInspectsNothing(t *testing.T) {
	fake := newWatchFake("old\texited\tExited (0) 2 days ago\t" + strings.Repeat("b2", 32) + "\t\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fake.watcher(t).Watch(ctx)
	<-fake.streams
	fake.waitFor(t, func(state containers.State) bool { return len(state.Containers) == 1 })
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.inspected) != 0 {
		t.Fatalf("inspected %q", fake.inspected)
	}
}

func TestTheWatcherSnapshotsAgainWhenDockerRestarts(t *testing.T) {
	fake := newWatchFake("web\trunning\tUp\n", "web\trunning\tUp\nback\trunning\tUp\n")
	watcher := fake.watcher(t)
	waited := make(chan time.Duration, 4)
	watcher.Wait = func(ctx context.Context, wait time.Duration) bool {
		waited <- wait
		return ctx.Err() == nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.Watch(ctx)
	(<-fake.streams).Close()
	if wait := <-waited; wait != 5*time.Second {
		t.Fatalf("waited %v before reconnecting", wait)
	}
	<-fake.streams
	fake.waitFor(t, func(state containers.State) bool { return len(state.Containers) == 2 })
}

func TestTheWatcherSaysWhenDockerIsMissing(t *testing.T) {
	fake := newWatchFake("")
	fake.docker = false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fake.watcher(t).Watch(ctx)
	if wait := <-fake.waits; wait != time.Minute {
		t.Fatalf("waited %v; the state must stay fresher than the 3 minutes a check accepts", wait)
	}
	state := fake.waitFor(t, func(state containers.State) bool { return !state.At.IsZero() })
	if state.Docker || len(state.Containers) != 0 {
		t.Fatalf("state %#v", state)
	}
}

func TestTheWatcherHeartbeatKeepsTheLastContainers(t *testing.T) {
	fake := newWatchFake("web\trunning\tUp\n")
	watcher := fake.watcher(t)
	watcher.Beat = 20 * time.Millisecond
	tick := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	watcher.Now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		tick = tick.Add(time.Minute)
		return tick
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.Watch(ctx)
	<-fake.streams
	first := fake.waitFor(t, func(state containers.State) bool { return len(state.Containers) == 1 })
	later := fake.waitFor(t, func(state containers.State) bool { return state.At.After(first.At) })
	if len(later.Containers) != 1 || later.Containers[0].Name != "web" {
		t.Fatalf("heartbeat lost the containers: %#v", later)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.calls != 1 {
		t.Fatalf("a heartbeat must not run Docker, ran %d times", fake.calls)
	}
}

func TestTheWatcherStateIsWrittenForTheCheckToRead(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	want := containers.State{At: at, Docker: true, Containers: []containers.Container{{Name: "web", State: "running", Health: "healthy"}}}
	if err := stateWriter(dir)(want); err != nil {
		t.Fatal(err)
	}
	got, err := containers.Read(filepath.Join(dir, containers.File))
	if err != nil || !got.At.Equal(at) || !got.Docker || len(got.Containers) != 1 || got.Containers[0] != want.Containers[0] {
		t.Fatalf("got %#v err %v", got, err)
	}
}
