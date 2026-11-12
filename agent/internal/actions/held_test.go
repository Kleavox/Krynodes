package actions

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/config"
)

func TestAHeldServerStopsItsExitNodeEvenWhenNothingMarkedItQuarantined(t *testing.T) {
	executor, run := tailnetServer(t)
	rootFile(t, executor, exitNodeFile, "net.ipv4.ip_forward = 1\n")
	asked, answer, failure := 0, false, error(nil)
	executor.Held = func(context.Context) (bool, error) {
		asked++
		return answer, failure
	}
	stops := func() int {
		count := 0
		for _, call := range run.calls {
			if call == "tailscale set --advertise-exit-node=false" {
				count++
			}
		}
		return count
	}
	for range 2 {
		if err := executor.Execute(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if asked != 1 || stops() != 0 {
		t.Fatalf("a free server: asked %d times, stopped %d times", asked, stops())
	}
	os.Remove(filepath.Join(executor.StateDir, heldFile))
	answer = true
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stops() != 1 {
		t.Fatalf("held by Krynodes, calls %v", run.calls)
	}
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(executor.path(exitNodeFile)); !os.IsNotExist(err) || !slices.Contains(run.calls, "sysctl --system") {
		t.Fatalf("the host unit did not take the rest: file %v calls %v", err, run.calls)
	}
	rootFile(t, executor, exitNodeFile, "net.ipv4.ip_forward = 1\n")
	writeJSON(executor.StateDir, heldFile, heldState{Held: true, At: executorNow.Add(-time.Hour)}, 0o640)
	failure = errors.New("no route to host")
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stops() != 2 {
		t.Fatalf("a server last known held stays held while Krynodes cannot be asked, calls %v", run.calls)
	}
}

func TestTheRootUnitAsksTheAddressItPinnedNotTheOneInTheConfig(t *testing.T) {
	status, body, token := http.StatusOK, `{"held":true}`, ""
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/held" {
			t.Errorf("path %s", r.URL.Path)
		}
		token = r.Header.Get("Authorization")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	defer real.Close()
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"held":false}`))
	}))
	defer fake.Close()
	state := t.TempDir()
	path := filepath.Join(t.TempDir(), "config.json")
	save := func(endpoint string) {
		if err := config.Save(path, config.Config{Endpoint: endpoint, NodeID: testNode, Token: "agent-token"}); err != nil {
			t.Fatal(err)
		}
	}
	save(real.URL)
	ask := WorkerHeld(state, path, "0.7.21", real.Client())
	if held, err := ask(context.Background()); err != nil || !held || token != "Bearer agent-token" {
		t.Fatalf("held %v err %v token %q", held, err, token)
	}
	save(fake.URL)
	if held, err := ask(context.Background()); err != nil || !held {
		t.Fatalf("a changed config moved the question: held %v err %v", held, err)
	}
	body = `{"held":false}`
	if held, err := ask(context.Background()); err != nil || held {
		t.Fatalf("free: held %v err %v", held, err)
	}
	status = http.StatusUnauthorized
	if held, err := ask(context.Background()); err != nil || !held {
		t.Fatalf("a server Krynodes refuses is held: %v %v", held, err)
	}
	status = http.StatusBadGateway
	if _, err := ask(context.Background()); err == nil {
		t.Fatal("an outage is not an answer")
	}
}
