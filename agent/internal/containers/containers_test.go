package containers

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func TestParseReadsNamesStatesAndHealth(t *testing.T) {
	got := Parse("adguard-adguard-1\trunning\tUp 3 hours\n" +
		"web\trunning\tUp 2 minutes (healthy)\n" +
		"db\trunning\tUp 1 minute (unhealthy)\n" +
		"api\trunning\tUp 5 seconds (health: starting)\n" +
		"old\texited\tExited (0) 2 days ago\n" +
		"\n" +
		"broken line\n")
	want := []Container{
		{Name: "adguard-adguard-1", State: "running"},
		{Name: "web", State: "running", Health: "healthy"},
		{Name: "db", State: "running", Health: "unhealthy"},
		{Name: "api", State: "running", Health: "starting"},
		{Name: "old", State: "exited"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %#v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("row %d: got %#v want %#v", index, got[index], want[index])
		}
	}
}

func TestParseKeepsAtMostFiveHundred(t *testing.T) {
	text := ""
	for range 600 {
		text += "c\trunning\tUp\n"
	}
	if got := len(Parse(text)); got != 500 {
		t.Fatalf("got %d", got)
	}
}

func TestVerdict(t *testing.T) {
	fresh := State{At: now.Add(-time.Minute), Docker: true, Containers: []Container{
		{Name: "up", State: "running"},
		{Name: "healthy", State: "running", Health: "healthy"},
		{Name: "starting", State: "running", Health: "starting"},
		{Name: "sick", State: "running", Health: "unhealthy"},
		{Name: "gone", State: "exited"},
		{Name: "loop", State: "restarting"},
	}}
	for _, row := range []struct {
		state State
		err   error
		name  string
		want  string
	}{
		{fresh, nil, "up", ""},
		{fresh, nil, "healthy", ""},
		{fresh, nil, "starting", ""},
		{fresh, nil, "sick", "unhealthy"},
		{fresh, nil, "gone", "exited"},
		{fresh, nil, "loop", "restarting"},
		{fresh, nil, "missing", "Container not found"},
		{State{}, os.ErrNotExist, "up", "Container status is not available yet"},
		{State{At: now.Add(-4 * time.Minute), Docker: true, Containers: fresh.Containers}, nil, "up", "Container status is stale"},
		{State{At: now, Docker: false}, nil, "up", "Docker is not installed"},
	} {
		err := Verdict(row.state, row.err, row.name, now)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != row.want {
			t.Errorf("%s: got %q want %q", row.name, got, row.want)
		}
	}
}

func TestReadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), File)
	if _, err := Read(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"at":"2026-10-10T12:00:00Z","docker":true,"containers":[{"name":"web","state":"running","health":"healthy"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := Read(path)
	if err != nil || !state.At.Equal(now) || !state.Docker || len(state.Containers) != 1 || state.Containers[0].Health != "healthy" {
		t.Fatalf("state %#v err %v", state, err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil {
		t.Fatal("a torn file is an error")
	}
}
