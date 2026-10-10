package checks

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/containers"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

func TestContainerChecksReadTheWatcherStateOnce(t *testing.T) {
	reads := 0
	previous := containerState
	containerState = func() (containers.State, error) {
		reads++
		return containers.State{At: time.Now(), Docker: true, Containers: []containers.Container{
			{Name: "adguard-adguard-1", State: "running"},
			{Name: "db", State: "running", Health: "unhealthy"},
			{Name: "old", State: "exited"},
		}}, nil
	}
	defer func() { containerState = previous }()
	results := runOnce(context.Background(), []reporter.Check{
		{ID: "a", Kind: "CONTAINER", Target: "adguard-adguard-1"},
		{ID: "b", Kind: "CONTAINER", Target: "db"},
		{ID: "c", Kind: "CONTAINER", Target: "old"},
		{ID: "d", Kind: "CONTAINER", Target: "missing"},
	})
	if reads != 1 {
		t.Fatalf("read the state %d times", reads)
	}
	want := []string{"UP", "DOWN unhealthy", "DOWN exited", "DOWN Container not found"}
	for index, result := range results {
		got := result.Status
		if result.Message != nil {
			got += " " + *result.Message
		}
		if got != want[index] {
			t.Errorf("%s: got %q want %q", result.CheckID, got, want[index])
		}
	}
}

func TestAContainerCheckOnItsOwnIsDownWithoutTheWatcher(t *testing.T) {
	previous := containerState
	containerState = func() (containers.State, error) { return containers.State{}, os.ErrNotExist }
	defer func() { containerState = previous }()
	result := Run(context.Background(), reporter.Check{ID: "a", Kind: "CONTAINER", Target: "web"})
	if result.Status != "DOWN" || *result.Message != "Container status is not available yet" {
		t.Fatalf("result %#v", result)
	}
}

func TestMain(m *testing.M) {
	recheckDelay = 0
	os.Exit(m.Run())
}

func TestHTTPCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	result := Run(context.Background(), reporter.Check{
		ID: "check", Kind: "HTTP", Target: server.URL, TimeoutSeconds: 2,
	})
	if result.Status != "UP" {
		t.Fatalf("expected UP, got %s", result.Status)
	}
}

func TestHTTPCheckIdentifiesAsTheKrynodesAgent(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	Run(context.Background(), reporter.Check{
		ID: "check", Kind: "HTTP", Target: server.URL, TimeoutSeconds: 2,
	})
	if got != "kry-agent-check" {
		t.Fatalf("expected User-Agent kry-agent-check, got %q", got)
	}
}

func TestRejectsUnsupportedCheck(t *testing.T) {
	result := Run(context.Background(), reporter.Check{
		ID: "check", Kind: "SHELL", Target: "echo unsafe", TimeoutSeconds: 2,
	})
	if result.Status != "DOWN" {
		t.Fatalf("expected DOWN, got %s", result.Status)
	}
}

func TestHTTPChecksReuseTheirConnection(t *testing.T) {
	var opened atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("page ", 2000)))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			opened.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	check := reporter.Check{ID: "check", Kind: "HTTP", Target: server.URL, TimeoutSeconds: 2}
	for range 3 {
		if result := RunAll(context.Background(), []reporter.Check{check})[0]; result.Status != "UP" {
			t.Fatalf("result %+v", result)
		}
	}
	if opened.Load() != 1 {
		t.Fatalf("opened %d connections for three checks", opened.Load())
	}
}

func TestServiceChecksShareOneSystemctlCall(t *testing.T) {
	var calls [][]string
	previous := serviceStates
	serviceStates = func(_ context.Context, units []string) (string, error) {
		calls = append(calls, units)
		states := map[string]string{"nginx.service": "active", "docker": "inactive"}
		var answer strings.Builder
		for _, unit := range units {
			answer.WriteString(states[unit] + "\n")
		}
		return answer.String(), nil
	}
	defer func() { serviceStates = previous }()

	results := RunAll(context.Background(), []reporter.Check{
		{ID: "nginx", Kind: "SERVICE", Target: "nginx.service", TimeoutSeconds: 2},
		{ID: "bad", Kind: "SERVICE", Target: "bad;unit", TimeoutSeconds: 2},
		{ID: "docker", Kind: "SERVICE", Target: "docker", TimeoutSeconds: 2},
	})
	if len(calls) == 0 || strings.Join(calls[0], " ") != "nginx.service docker" {
		t.Fatalf("calls %#v", calls)
	}
	if results[0].Status != "UP" || results[2].Status != "DOWN" || *results[2].Message != "inactive" {
		t.Fatalf("results %+v %+v", results[0], results[2])
	}
	if results[1].Status != "DOWN" || *results[1].Message != "invalid service unit" {
		t.Fatalf("invalid unit %+v", results[1])
	}
}

func TestServiceChecksFailTogetherWhenSystemctlCannotAnswer(t *testing.T) {
	previous := serviceStates
	serviceStates = func(context.Context, []string) (string, error) {
		return "", context.DeadlineExceeded
	}
	defer func() { serviceStates = previous }()

	results := RunAll(context.Background(), []reporter.Check{
		{ID: "a", Kind: "SERVICE", Target: "a.service", TimeoutSeconds: 2},
		{ID: "b", Kind: "SERVICE", Target: "b.service", TimeoutSeconds: 2},
	})
	for _, result := range results {
		if result.Status != "DOWN" || result.Message == nil {
			t.Fatalf("result %+v", result)
		}
	}
}

func TestServiceUnitsNeverReachSystemctlAsOptions(t *testing.T) {
	args := systemctlArgs([]string{"--help", "nginx.service"})
	if strings.Join(args, " ") != "is-active -- --help nginx.service" {
		t.Fatalf("args %q", args)
	}
}

func TestAFailingCheckIsRetriedBeforeItCountsAsDown(t *testing.T) {
	previous := recheckDelay
	recheckDelay = 0
	defer func() { recheckDelay = previous }()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	result := RunAll(context.Background(), []reporter.Check{{ID: "web", Kind: "HTTP", Target: server.URL, TimeoutSeconds: 2}})[0]
	if result.Status != "UP" || requests.Load() != 2 {
		t.Fatalf("result %+v after %d requests", result, requests.Load())
	}
}

func TestACheckIsDownOnlyAfterThreeFailedAttempts(t *testing.T) {
	previous := recheckDelay
	recheckDelay = 0
	defer func() { recheckDelay = previous }()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	result := RunAll(context.Background(), []reporter.Check{{ID: "web", Kind: "HTTP", Target: server.URL, TimeoutSeconds: 2}})[0]
	if result.Status != "DOWN" || requests.Load() != 3 {
		t.Fatalf("result %+v after %d requests", result, requests.Load())
	}
}

func TestOnlyFailedServicesAreAskedAgain(t *testing.T) {
	previous, delay := serviceStates, recheckDelay
	recheckDelay = 0
	var calls []string
	serviceStates = func(_ context.Context, units []string) (string, error) {
		calls = append(calls, strings.Join(units, " "))
		if len(calls) == 1 {
			return "active\nactivating\n", nil
		}
		return "active\n", nil
	}
	defer func() { serviceStates, recheckDelay = previous, delay }()

	results := RunAll(context.Background(), []reporter.Check{
		{ID: "nginx", Kind: "SERVICE", Target: "nginx.service", TimeoutSeconds: 2},
		{ID: "app", Kind: "SERVICE", Target: "app.service", TimeoutSeconds: 2},
	})
	if strings.Join(calls, "|") != "nginx.service app.service|app.service" {
		t.Fatalf("calls %q", calls)
	}
	if results[0].Status != "UP" || results[1].Status != "UP" {
		t.Fatalf("results %+v", results)
	}
}
