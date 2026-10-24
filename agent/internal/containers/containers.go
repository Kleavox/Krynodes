package containers

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
)

const (
	File          = "containers.json"
	Format        = "{{.Names}}\t{{.State}}\t{{.Status}}\t{{.ID}}\t{{.Label \"com.docker.compose.project\"}}"
	StartedFormat = "{{.Id}}\t{{.State.StartedAt}}"
	maxListed     = 500
	staleAfter    = 3 * time.Minute
)

type Container struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	Health  string `json:"health,omitempty"`
	Project string `json:"project,omitempty"`
	Started string `json:"started,omitempty"`
	ID      string `json:"-"`
}

type State struct {
	At         time.Time   `json:"at"`
	Docker     bool        `json:"docker"`
	Containers []Container `json:"containers"`
}

func Parse(text string) []Container {
	listed := []Container{}
	for line := range strings.SplitSeq(text, "\n") {
		fields := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(fields) < 3 || fields[0] == "" || fields[1] == "" {
			continue
		}
		if len(listed) == maxListed {
			break
		}
		listed = append(listed, Container{Name: fields[0], State: fields[1], Health: health(fields[2]), ID: field(fields, 3), Project: field(fields, 4)})
	}
	return listed
}

func field(fields []string, index int) string {
	if index < len(fields) {
		return fields[index]
	}
	return ""
}

func ParseStarted(text string) map[string]string {
	started := map[string]string{}
	for line := range strings.SplitSeq(text, "\n") {
		id, at, found := strings.Cut(strings.TrimRight(line, "\r"), "\t")
		if !found || id == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339Nano, at)
		if err != nil || parsed.Year() < 2000 {
			continue
		}
		started[id] = parsed.UTC().Format(time.RFC3339)
	}
	return started
}

func Find(state State, name string) (Container, bool) {
	for _, container := range state.Containers {
		if container.Name == name {
			return container, true
		}
	}
	return Container{}, false
}

func health(status string) string {
	switch {
	case strings.Contains(status, "(unhealthy)"):
		return "unhealthy"
	case strings.Contains(status, "(health: starting)"):
		return "starting"
	case strings.Contains(status, "(healthy)"):
		return "healthy"
	}
	return ""
}

func Read(path string) (State, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return State{}, err
	}
	var state State
	err = json.Unmarshal(encoded, &state)
	return state, err
}

func Verdict(state State, readErr error, name string, now time.Time) error {
	switch {
	case readErr != nil:
		return errors.New("Container status is not available yet")
	case now.Sub(state.At) > staleAfter:
		return errors.New("Container status is stale")
	case !state.Docker:
		return errors.New("Docker is not installed")
	}
	container, found := Find(state, name)
	switch {
	case !found:
		return errors.New("Container not found")
	case container.State != "running":
		return errors.New(container.State)
	case container.Health == "unhealthy":
		return errors.New("unhealthy")
	}
	return nil
}
