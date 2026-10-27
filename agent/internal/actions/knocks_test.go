package actions

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

func journalCall() string {
	return fmt.Sprintf("journalctl -k --since=@%d -o short-unix --no-pager -q", executorNow.Add(-network.KnockWindow).Unix())
}

func knockLines(prefix, in, src string, count int, target func(int) string) string {
	var lines []string
	for index := range count {
		address, port, _ := strings.Cut(target(index), ":")
		lines = append(lines, fmt.Sprintf("%d.000000 vps-2 kernel: %sIN=%s OUT= SRC=%s DST=%s LEN=60 PROTO=TCP SPT=40000 DPT=%s", executorNow.Add(-10e9).Unix(), prefix, in, src, address, port))
	}
	return strings.Join(lines, "\n") + "\n"
}

func readEvents(t *testing.T, executor Executor) []reporter.Event {
	t.Helper()
	log, _ := readState[eventLog](executor.StateDir, eventsFile)
	return log.Events
}

func TestAScanDropsTheKnockerAtOnceAndWritesOneEvent(t *testing.T) {
	executor, run, _, _, _ := joinedServer(t)
	run.respond[journalCall()] = knockLines(network.KnockPrefix, "kry0", "10.88.0.1", 10, func(index int) string { return fmt.Sprintf("10.88.0.2:%d", 5000+index) })
	for range 2 {
		executor.watchKnocks(context.Background())
	}
	if dropped := executor.readNetwork().Dropped; !slices.Equal(dropped, []string{"10.88.0.1"}) {
		t.Fatalf("dropped %v", dropped)
	}
	if rules, _ := os.ReadFile(filepath.Join(executor.networkDir(), rulesFile)); !strings.Contains(string(rules), "-A KRY-DROP -s 10.88.0.1/32 -j DROP") {
		t.Fatalf("rules %s", rules)
	}
	events := readEvents(t, executor)
	if len(events) != 1 || events[0].Kind != "knock" || events[0].Detail["from"] != "10.88.0.1" || events[0].Detail["count"] != "10" {
		t.Fatalf("events %+v", events)
	}
}

func knockingStack(t *testing.T, executor Executor) {
	t.Helper()
	directory := filepath.Join(executor.StateDir, "compose", "app")
	if err := writeJSON(directory, "krynodes.json", stackMeta{Access: "contained"}, 0o640); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{"services": map[string]any{}, "networks": map[string]any{"default": map[string]any{"driver_opts": map[string]any{"com.docker.network.bridge.name": "krc111111111111"}}}}
	if err := writeJSON(directory, "compose.krynodes.json", config, 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestAStackThatTriesPlacesItWasNotGivenIsStoppedAndStaysStopped(t *testing.T) {
	executor, run, _, _, _ := joinedServer(t)
	knockingStack(t, executor)
	run.respond[journalCall()] = knockLines(network.ReachPrefix, "krc111111111111", "172.30.0.2", 14, func(index int) string { return fmt.Sprintf("10.88.0.%d:6379", index+1) })
	run.respond["docker ps -a --filter label=com.docker.compose.project=app --format {{.ID}}"] = "c1\n"
	run.respond["docker inspect --format {{.HostConfig.RestartPolicy.Name}} c1"] = "unless-stopped\n"
	run.calls = nil
	executor.watchKnocks(context.Background())
	for _, call := range []string{"env KRY_PRIVATE_IP=10.88.0.2 docker compose --project-name app stop", "docker update --restart no c1"} {
		if !slices.Contains(run.calls, call) {
			t.Fatalf("missing %q in %v", call, run.calls)
		}
	}
	events := readEvents(t, executor)
	if len(events) != 1 || events[0].Kind != "stack" || events[0].Detail["stack"] != "app" || events[0].Detail["count"] != "14" || events[0].Detail["stopped"] != "true" {
		t.Fatalf("events %+v", events)
	}
	run.calls = nil
	executor.watchKnocks(context.Background())
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasSuffix(call, "stop") }) {
		t.Fatalf("stopped twice: %v", run.calls)
	}
	executor.unknock(context.Background(), "app")
	if !slices.Contains(run.calls, "docker update --restart unless-stopped c1") {
		t.Fatalf("policy not put back: %v", run.calls)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "knocked", "app.json")); !os.IsNotExist(err) {
		t.Fatalf("mark kept: %v", err)
	}
}

func TestWarnOnlyStopsNothing(t *testing.T) {
	executor, run, _, _, _ := joinedServer(t)
	record := executor.readNetwork()
	record.Document.Knocks = &network.Knocks{Scan: 10, Stop: false}
	if err := executor.saveNetwork(record); err != nil {
		t.Fatal(err)
	}
	knockingStack(t, executor)
	run.respond[journalCall()] = knockLines(network.ReachPrefix, "krc111111111111", "172.30.0.2", 14, func(index int) string { return fmt.Sprintf("10.88.0.%d:6379", index+1) })
	run.calls = nil
	executor.watchKnocks(context.Background())
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasSuffix(call, "stop") }) {
		t.Fatalf("stopped: %v", run.calls)
	}
	if events := readEvents(t, executor); len(events) != 1 || events[0].Detail["stopped"] != "false" {
		t.Fatalf("events %+v", events)
	}
}
