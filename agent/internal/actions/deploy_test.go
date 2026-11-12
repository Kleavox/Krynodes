package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var listmonk = Stack{Project: "listmonk", Directory: "/opt/listmonk", Files: []string{"/opt/listmonk/docker-compose.yml"}, Running: 2, Total: 2}

const (
	composeBase  = "docker compose --project-name listmonk --project-directory /opt/listmonk -f /opt/listmonk/docker-compose.yml"
	pullCall     = composeBase + " pull"
	upCall       = composeBase + " up -d"
	healthCall   = composeBase + " ps --all --format {{.Service}}\t{{.State}}\t{{.Health}}\t{{.ExitCode}}"
	idsCall      = "docker ps -a --no-trunc --filter label=com.docker.compose.project=listmonk --format {{.ID}}"
	inspectStart = "docker inspect --format {{index .Config.Labels \"com.docker.compose.service\"}}\t{{.Config.Image}}\t{{.Image}}"
	startsCall   = "docker inspect --format {{.Id}} {{.RestartCount}} {{.State.StartedAt}} c1 c2"
	imagesBefore = "app\tlistmonk/listmonk:latest\tsha256:old\ndb\tpostgres:17\tsha256:pg\n"
	imagesAfter  = "app\tlistmonk/listmonk:latest\tsha256:new\ndb\tpostgres:17\tsha256:pg\n"
)

func deployExecutor(t *testing.T, action string) (Executor, *fakeRun, Request) {
	t.Helper()
	executor, run := newExecutor(t)
	c := newDeployCase(t, algES256)
	c.command.Action = action
	request := c.request(t)
	request.Action = action
	if err := SaveTrust(executor.StateDir, c.trust); err != nil {
		t.Fatal(err)
	}
	executor.Collect = func(context.Context, []string) (Snapshot, error) {
		return Snapshot{Stacks: []Stack{listmonk}, Compose: true}, nil
	}
	executor.Exists = func(string) bool { return true }
	executor.HealthTimeout = 80 * time.Millisecond
	executor.HealthEvery = 5 * time.Millisecond
	executor.HealthSettle = 10 * time.Millisecond
	run.respond = map[string]string{
		idsCall:    "c1\nc2\n",
		healthCall: "app\trunning\t\t0\ndb\trunning\thealthy\t0\n",
		startsCall: "c1 0 2026-09-29T10:00:00Z\nc2 0 2026-09-29T10:00:00Z\n",
	}
	run.sequence = map[string][]string{inspectStart + " c1 c2": {imagesBefore, imagesAfter}}
	writeRequest(t, executor.RequestDir, testID+".json", request)
	return executor, run, request
}

func keptRecord(t *testing.T, executor Executor) stackRecord {
	t.Helper()
	var record stackRecord
	if err := readJSON(filepath.Join(executor.StateDir, "stacks", "listmonk.json"), &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func keep(t *testing.T, executor Executor, images ...imageRecord) {
	t.Helper()
	if err := writeJSON(filepath.Join(executor.StateDir, "stacks"), "listmonk.json", stackRecord{Previous: images}, 0o640); err != nil {
		t.Fatal(err)
	}
}

func execute(t *testing.T, executor Executor) Result {
	t.Helper()
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	return readResult(t, executor, testID)
}

func TestADeployPullsThenStartsThenChecksHealthInOrder(t *testing.T) {
	executor, run, _ := deployExecutor(t, "deploy")
	result := execute(t, executor)
	if !result.OK || result.Output != "deployed" {
		t.Fatalf("result %+v", result)
	}
	order := []string{inspectStart + " c1 c2", pullCall, upCall, healthCall, startsCall}
	last := -1
	for _, call := range order {
		index := slices.Index(run.calls, call)
		if index <= last {
			t.Fatalf("%q out of order in %q", call, run.calls)
		}
		last = index
	}
}

func TestADeployKeepsWhatRanBeforeForRollback(t *testing.T) {
	executor, _, _ := deployExecutor(t, "deploy")
	execute(t, executor)
	record := keptRecord(t, executor)
	want := []imageRecord{{Service: "app", Reference: "listmonk/listmonk:latest", ID: "sha256:old"}, {Service: "db", Reference: "postgres:17", ID: "sha256:pg"}}
	if !slices.Equal(record.Previous, want) {
		t.Fatalf("kept %+v", record.Previous)
	}
	var inventory Inventory
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil || len(inventory.Stacks) != 1 || !inventory.Stacks[0].Rollback {
		t.Fatalf("inventory %+v err %v", inventory.Stacks, err)
	}
}

func TestAFailedPullStopsAndReportsTheStep(t *testing.T) {
	executor, run, _ := deployExecutor(t, "deploy")
	run.failing = map[string]string{pullCall: "Error response from daemon: pull access denied for listmonk/listmonk"}
	result := execute(t, executor)
	if result.OK || !strings.HasPrefix(result.Output, "pull failed:") || !strings.Contains(result.Output, "pull access denied") {
		t.Fatalf("result %+v", result)
	}
	if slices.Contains(run.calls, upCall) {
		t.Fatal("a failed pull must not start anything")
	}
}

func TestAFailedUpReportsTheStepAndStillKeepsWhatRanBefore(t *testing.T) {
	executor, run, _ := deployExecutor(t, "deploy")
	run.failing = map[string]string{upCall: "port is already allocated"}
	result := execute(t, executor)
	if result.OK || !strings.HasPrefix(result.Output, "up failed:") || !strings.Contains(result.Output, "already allocated") {
		t.Fatalf("result %+v", result)
	}
	if len(keptRecord(t, executor).Previous) != 2 {
		t.Fatal("a failed deploy must keep what ran before so it can be rolled back")
	}
}

func TestARestartingContainerFailsTheHealthCheck(t *testing.T) {
	executor, run, _ := deployExecutor(t, "deploy")
	run.respond[healthCall] = "app\trestarting\t\t0\ndb\trunning\thealthy\t0\n"
	result := execute(t, executor)
	if result.OK || !strings.HasPrefix(result.Output, "health check failed:") || !strings.Contains(result.Output, "app restarting") {
		t.Fatalf("result %+v", result)
	}
}

func TestTheHealthCheckWaitsForAStartingContainer(t *testing.T) {
	executor, run, _ := deployExecutor(t, "deploy")
	delete(run.respond, healthCall)
	run.sequence[healthCall] = []string{"app\trunning\tstarting\t0\n", "app\trunning\thealthy\t0\n"}
	if result := execute(t, executor); !result.OK {
		t.Fatalf("result %+v", result)
	}
}

func TestOlderImagesAreRemovedWhenReplaced(t *testing.T) {
	executor, run, _ := deployExecutor(t, "deploy")
	keep(t, executor, imageRecord{Service: "app", Reference: "listmonk/listmonk:latest", ID: "sha256:older"}, imageRecord{Service: "db", Reference: "postgres:17", ID: "sha256:pg"})
	execute(t, executor)
	if !slices.Contains(run.calls, "docker image rm sha256:older") {
		t.Fatalf("calls %q", run.calls)
	}
	if slices.Contains(run.calls, "docker image rm sha256:pg") || slices.Contains(run.calls, "docker image rm sha256:old") {
		t.Fatalf("an image still kept must stay: %q", run.calls)
	}
}

func TestRollbackRetagsAndStartsThePreviousImages(t *testing.T) {
	executor, run, _ := deployExecutor(t, "rollback")
	keep(t, executor, imageRecord{Service: "app", Reference: "listmonk/listmonk:latest", ID: "sha256:old"}, imageRecord{Service: "db", Reference: "postgres@sha256:abc", ID: "sha256:pg"})
	result := execute(t, executor)
	if !result.OK || result.Output != "rolled back" {
		t.Fatalf("result %+v", result)
	}
	want := []string{"docker tag sha256:old listmonk/listmonk:latest", upCall, healthCall}
	if len(run.calls) < len(want) || !slices.Equal(run.calls[:len(want)], want) {
		t.Fatalf("calls\n got %q\nwant %q", run.calls, want)
	}
	if len(keptRecord(t, executor).Previous) != 0 {
		t.Fatal("a rollback is one step only")
	}
}

func TestAFailedRollbackKeepsTheRecordForAnotherTry(t *testing.T) {
	executor, run, _ := deployExecutor(t, "rollback")
	keep(t, executor, imageRecord{Service: "app", Reference: "listmonk/listmonk:latest", ID: "sha256:old"})
	run.failing = map[string]string{upCall: "boom"}
	if result := execute(t, executor); result.OK {
		t.Fatalf("result %+v", result)
	}
	if len(keptRecord(t, executor).Previous) != 1 {
		t.Fatal("a failed rollback must keep the record")
	}
}

func TestRollbackWithNothingKeptIsRefused(t *testing.T) {
	executor, run, _ := deployExecutor(t, "rollback")
	result := execute(t, executor)
	if result.OK || !strings.Contains(result.Output, "nothing to roll back to") || len(run.calls) != 0 {
		t.Fatalf("result %+v calls %q", result, run.calls)
	}
}

func TestAnUnsignedComposeRequestIsRefused(t *testing.T) {
	executor, run, request := deployExecutor(t, "deploy")
	request.Signed = nil
	writeRequest(t, executor.RequestDir, testID+".json", request)
	result := execute(t, executor)
	if result.OK || !strings.Contains(result.Output, "refused: the request is not signed") || len(run.calls) != 0 {
		t.Fatalf("result %+v calls %q", result, run.calls)
	}
}

func TestAComposeRequestWithoutTrustIsRefused(t *testing.T) {
	executor, run, _ := deployExecutor(t, "deploy")
	if err := SaveTrust(executor.StateDir, Trust{}); err != nil {
		t.Fatal(err)
	}
	result := execute(t, executor)
	if result.OK || !strings.Contains(result.Output, "no trusted devices") || len(run.calls) != 0 {
		t.Fatalf("result %+v calls %q", result, run.calls)
	}
}

func TestAComposeRequestForAMissingStackIsRefused(t *testing.T) {
	executor, run, _ := deployExecutor(t, "deploy")
	executor.Collect = func(context.Context, []string) (Snapshot, error) { return Snapshot{Compose: true}, nil }
	result := execute(t, executor)
	if result.OK || !strings.Contains(result.Output, "listmonk is not on this server") || len(run.calls) != 0 {
		t.Fatalf("result %+v calls %q", result, run.calls)
	}
}

func TestAServerWithoutComposeRefusesADeploy(t *testing.T) {
	executor, run, _ := deployExecutor(t, "deploy")
	executor.Collect = func(context.Context, []string) (Snapshot, error) { return Snapshot{Stacks: []Stack{listmonk}}, nil }
	result := execute(t, executor)
	if result.OK || !strings.Contains(result.Output, "docker compose is not available") || len(run.calls) != 0 {
		t.Fatalf("result %+v calls %q", result, run.calls)
	}
}

func TestAnEightKilobyteRequestIsRead(t *testing.T) {
	executor, _, request := deployExecutor(t, "deploy")
	var signed map[string]any
	if err := json.Unmarshal(request.Signed, &signed); err != nil {
		t.Fatal(err)
	}
	signed["padding"] = strings.Repeat("a", 6000)
	padded, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	request.Signed = padded
	writeRequest(t, executor.RequestDir, testID+".json", request)
	result := execute(t, executor)
	if strings.Contains(result.Output, "too large") || !strings.Contains(result.Output, "malformed") {
		t.Fatalf("a 7 KiB request must be read (and then refused for its extra field), got %+v", result)
	}
}

func TestTheOutputKeepsTheTail(t *testing.T) {
	executor, run, _ := deployExecutor(t, "deploy")
	run.failing = map[string]string{pullCall: strings.Repeat("progress line\n", 400) + "THE END"}
	result := execute(t, executor)
	if !strings.HasPrefix(result.Output, "pull failed:") || !strings.HasSuffix(strings.TrimSpace(result.Output), "THE END") || len(result.Output) > maxOutputBytes {
		t.Fatalf("output %d bytes: %q", len(result.Output), result.Output[:80])
	}
}

func TestACrashLoopingContainerFailsTheHealthCheck(t *testing.T) {
	executor, run, _ := deployExecutor(t, "deploy")
	delete(run.respond, startsCall)
	var starts []string
	for count := range 400 {
		starts = append(starts, fmt.Sprintf("c1 %d 2026-09-29T10:00:%02dZ\nc2 0 2026-09-29T10:00:00Z\n", count, count%60))
	}
	run.sequence[startsCall] = starts
	result := execute(t, executor)
	if result.OK || !strings.HasPrefix(result.Output, "health check failed:") || !strings.Contains(result.Output, "restarted") {
		t.Fatalf("a container that keeps restarting must fail the deploy, got %+v", result)
	}
}

func TestAOneShotContainerThatExitedCleanlyCountsAsDone(t *testing.T) {
	executor, run, _ := deployExecutor(t, "deploy")
	run.respond[healthCall] = "app\trunning\t\t0\nmigrate\texited\t\t0\n"
	if result := execute(t, executor); !result.OK {
		t.Fatalf("result %+v", result)
	}
}

func TestAContainerThatExitedWithAnErrorFailsTheHealthCheck(t *testing.T) {
	executor, run, _ := deployExecutor(t, "deploy")
	run.respond[healthCall] = "app\trunning\t\t0\nmigrate\texited\t\t1\n"
	result := execute(t, executor)
	if result.OK || !strings.Contains(result.Output, "migrate exited (1)") {
		t.Fatalf("result %+v", result)
	}
}

func TestRetryingAFailedDeployKeepsTheLastGoodVersion(t *testing.T) {
	executor, run, _ := deployExecutor(t, "deploy")
	good := []imageRecord{{Service: "app", Reference: "listmonk/listmonk:latest", ID: "sha256:good"}}
	if err := writeJSON(filepath.Join(executor.StateDir, "stacks"), "listmonk.json", stackRecord{Previous: good, Failed: true}, 0o640); err != nil {
		t.Fatal(err)
	}
	if result := execute(t, executor); !result.OK {
		t.Fatalf("result %+v", result)
	}
	record := keptRecord(t, executor)
	if !slices.Equal(record.Previous, good) || record.Failed {
		t.Fatalf("the last good version must stay the rollback target, got %+v", record)
	}
	if slices.Contains(run.calls, "docker image rm sha256:good") {
		t.Fatal("the last good version must not be removed")
	}
}

func TestADeployThatChangesNothingKeepsTheRecord(t *testing.T) {
	executor, run, _ := deployExecutor(t, "deploy")
	run.sequence[inspectStart+" c1 c2"] = []string{imagesBefore, imagesBefore}
	older := []imageRecord{{Service: "app", Reference: "listmonk/listmonk:latest", ID: "sha256:older"}}
	keep(t, executor, older...)
	execute(t, executor)
	if record := keptRecord(t, executor); !slices.Equal(record.Previous, older) {
		t.Fatalf("a deploy that pulled nothing new must keep the rollback target, got %+v", record)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "docker image rm") }) {
		t.Fatalf("nothing may be pruned: %q", run.calls)
	}
}

func TestAHugeStateListStillFitsTheOutputLimit(t *testing.T) {
	executor, run, _ := deployExecutor(t, "deploy")
	run.failing = map[string]string{upCall: "port is already allocated"}
	run.respond[healthCall] = strings.Repeat("a-very-long-service-name-for-this-stack\trestarting\t\t1\n", 300)
	result := execute(t, executor)
	if len(result.Output) > maxOutputBytes || !strings.HasPrefix(result.Output, "up failed:") {
		t.Fatalf("output %d bytes: %q", len(result.Output), result.Output[:60])
	}
}

func TestAMissingComposeFileFallsBackToTheStandardFileInTheStackDirectory(t *testing.T) {
	executor, run, _ := deployExecutor(t, "deploy")
	executor.Exists = func(path string) bool { return path == "/opt/listmonk/compose.yaml" }
	execute(t, executor)
	want := "docker compose --project-name listmonk --project-directory /opt/listmonk -f /opt/listmonk/compose.yaml pull"
	if !slices.Contains(run.calls, want) {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestADeployWithoutAnyComposeFileIsRefused(t *testing.T) {
	executor, run, _ := deployExecutor(t, "deploy")
	executor.Exists = func(string) bool { return false }
	result := execute(t, executor)
	if result.OK || !strings.Contains(result.Output, "refused: no compose file found in /opt/listmonk") || slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, " pull") }) {
		t.Fatalf("result %+v calls %q", result, run.calls)
	}
}

func TestRollbackSaysSoWhenEveryImageIsPinnedByDigest(t *testing.T) {
	executor, run, _ := deployExecutor(t, "rollback")
	keep(t, executor, imageRecord{Service: "db", Reference: "postgres@sha256:abc", ID: "sha256:pg"})
	result := execute(t, executor)
	if result.OK || !strings.Contains(result.Output, "pinned by digest") || slices.Contains(run.calls, upCall) {
		t.Fatalf("result %+v calls %q", result, run.calls)
	}
}
