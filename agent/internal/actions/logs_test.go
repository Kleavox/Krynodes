package actions

import (
	"context"
	"strings"
	"testing"
	"time"
)

const idC = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a03"

func logsExecutor(t *testing.T) (Executor, *fakeRun) {
	t.Helper()
	executor, run := newTrustedExecutor(t)
	executor.Collect = func(context.Context, []string) (Snapshot, error) {
		return Snapshot{
			Services: []Service{{Kind: "systemd", Name: "ssh.service", State: "running"}, {Kind: "docker", Name: "resolver", State: "running"}},
			Stacks:   []Stack{{Project: "listmonk", Directory: "/opt/listmonk"}},
			Compose:  true,
		}, nil
	}
	executor.Exists = func(path string) bool { return path == "/opt/listmonk/compose.yaml" }
	return executor, run
}

func TestExecutorReadsLogsEvenForProtectedUnits(t *testing.T) {
	executor, run := logsExecutor(t)
	run.respond = map[string]string{
		"journalctl --unit=ssh.service --lines=300 --no-pager --output=short-iso":                                                                        "line one\nline two",
		"docker logs --tail 300 --timestamps -- resolver":                                                                                                "resolver ready",
		"docker compose --project-name listmonk --project-directory /opt/listmonk -f /opt/listmonk/compose.yaml logs --tail 300 --timestamps --no-color": "app | ok",
	}
	later := executorNow.Add(time.Minute)
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "systemd", "ssh.service", "logs", later))
	writeRequest(t, executor.RequestDir, idB+".json", request(t, idB, "docker", "resolver", "logs", later))
	writeRequest(t, executor.RequestDir, idC+".json", request(t, idC, "compose", "listmonk", "logs", later))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{idA: "line one\nline two", idB: "resolver ready", idC: "app | ok"} {
		result := readResult(t, executor, id)
		if !result.OK || result.Output != want {
			t.Fatalf("%s: got %+v, want output %q", id, result, want)
		}
	}
	for _, call := range run.calls {
		if strings.HasPrefix(call, "systemctl") || strings.Contains(call, " up ") {
			t.Fatalf("reading logs changed something: %s", call)
		}
	}
}

func TestExecutorKeepsTheLast64KiBOfLogs(t *testing.T) {
	executor, run := logsExecutor(t)
	run.output = strings.Repeat("a", 70<<10) + "END"
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "docker", "resolver", "logs", executorNow.Add(time.Minute)))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	result := readResult(t, executor, idA)
	if !result.OK || len(result.Output) != 64<<10 || !strings.HasSuffix(result.Output, "END") {
		t.Fatalf("got ok=%v len=%d", result.OK, len(result.Output))
	}
}

func TestExecutorRefusesLogsForAbsentTargets(t *testing.T) {
	executor, _ := logsExecutor(t)
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "docker", "ghost", "logs", executorNow.Add(time.Minute)))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	result := readResult(t, executor, idA)
	if result.OK || !strings.Contains(result.Output, "not on this server") {
		t.Fatalf("got %+v", result)
	}
}
