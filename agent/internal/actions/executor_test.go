package actions

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const (
	idA = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a01"
	idB = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a02"
)

var executorNow = time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)

type fakeRun struct {
	calls    []string
	output   string
	code     int
	err      error
	during   func()
	respond  map[string]string
	failing  map[string]string
	sequence map[string][]string
}

func (f *fakeRun) run(_ context.Context, name string, args ...string) ([]byte, int, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if answer, ok := f.respond[call]; ok {
		return []byte(answer), 0, nil
	}
	if answer, ok := f.failing[call]; ok {
		return []byte(answer), 1, errors.New("exit status 1")
	}
	if answers, ok := f.sequence[call]; ok && len(answers) > 0 {
		answer := answers[0]
		if len(answers) > 1 {
			f.sequence[call] = answers[1:]
		}
		return []byte(answer), 0, nil
	}
	if f.during != nil {
		during := f.during
		f.during = nil
		during()
	}
	return []byte(f.output), f.code, f.err
}

func newExecutor(t *testing.T) (Executor, *fakeRun) {
	t.Helper()
	base := t.TempDir()
	requests := filepath.Join(base, "actions")
	if err := os.MkdirAll(requests, 0o750); err != nil {
		t.Fatal(err)
	}
	run := &fakeRun{}
	services := []Service{{Kind: "docker", Name: "adguard", State: "running"}, {Kind: "systemd", Name: "nginx.service", State: "running"}}
	return Executor{
		RequestDir: requests,
		StateDir:   filepath.Join(base, "exec"),
		Now:        func() time.Time { return executorNow },
		Run:        run.run,
		Collect:    func(context.Context, []string) (Snapshot, error) { return Snapshot{Services: services}, nil },
	}, run
}

func writeRequest(t *testing.T, dir, file string, body any) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, file), encoded, 0o640); err != nil {
		t.Fatal(err)
	}
}

var serviceSigner *deployCase

func testSigner(t *testing.T) *deployCase {
	t.Helper()
	if serviceSigner == nil {
		serviceSigner = newDeployCase(t, algES256)
	}
	return serviceSigner
}

func newTrustedExecutor(t *testing.T) (Executor, *fakeRun) {
	t.Helper()
	executor, run := newExecutor(t)
	if err := SaveTrust(executor.StateDir, testSigner(t).trust); err != nil {
		t.Fatal(err)
	}
	return executor, run
}

func request(t *testing.T, id, kind, name, action string, expires time.Time) Request {
	t.Helper()
	c := *testSigner(t)
	c.command.ID, c.command.Kind, c.command.Name, c.command.Action = id, kind, name, action
	signed := c.request(t)
	signed.ID, signed.Kind, signed.Name, signed.Action, signed.ExpiresAt = id, kind, name, action, expires.Format(time.RFC3339Nano)
	return signed
}

func readResult(t *testing.T, executor Executor, id string) Result {
	t.Helper()
	var result Result
	if err := readJSON(filepath.Join(executor.StateDir, "results", id+".json"), &result); err != nil {
		t.Fatalf("read result %s: %v", id, err)
	}
	return result
}

func TestARestartRunsWithExactArgumentsAndReportsSuccess(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "docker", "adguard", "restart", executorNow.Add(10*time.Minute)))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !slices.Equal(run.calls, []string{"docker restart -- adguard"}) {
		t.Fatalf("unexpected calls %#v", run.calls)
	}
	result := readResult(t, executor, idA)
	if !result.OK || result.ExitCode == nil || *result.ExitCode != 0 || result.FinishedAt != "2026-09-29T10:00:00Z" {
		t.Fatalf("unexpected result %#v", result)
	}
	var inventory Inventory
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil || len(inventory.Services) != 2 {
		t.Fatalf("inventory %#v err %v", inventory, err)
	}
}

func TestRefusalsRunNothingAndSayWhy(t *testing.T) {
	cases := map[string]Request{
		"protected": request(t, idA, "systemd", "ssh.service", "restart", executorNow.Add(time.Minute)),
		"not here":  request(t, idA, "docker", "ghost", "restart", executorNow.Add(time.Minute)),
		"expired":   request(t, idA, "docker", "adguard", "restart", executorNow.Add(-2*time.Minute)),
		"action":    request(t, idA, "docker", "adguard", "exec", executorNow.Add(time.Minute)),
		"name":      request(t, idA, "docker", "-rm", "restart", executorNow.Add(time.Minute)),
		"other id":  request(t, idB, "docker", "adguard", "restart", executorNow.Add(time.Minute)),
	}
	for label, body := range cases {
		t.Run(label, func(t *testing.T) {
			executor, run := newTrustedExecutor(t)
			writeRequest(t, executor.RequestDir, idA+".json", body)
			if err := executor.Execute(context.Background()); err != nil {
				t.Fatalf("execute: %v", err)
			}
			result := readResult(t, executor, idA)
			if len(run.calls) != 0 || result.OK || result.ExitCode != nil || !strings.HasPrefix(result.Output, "refused: ") {
				t.Fatalf("calls %#v result %#v", run.calls, result)
			}
		})
	}
}

func TestAnExpiryWithinTheSkewStillRuns(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "docker", "adguard", "restart", executorNow.Add(-30*time.Second)))
	if err := executor.Execute(context.Background()); err != nil || len(run.calls) != 1 {
		t.Fatalf("calls %#v err %v", run.calls, err)
	}
}

func TestUnknownFieldsAreRefused(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	writeRequest(t, executor.RequestDir, idA+".json", map[string]string{"id": idA, "kind": "docker", "name": "adguard", "action": "restart", "expiresAt": executorNow.Add(time.Minute).Format(time.RFC3339), "shell": "rm -rf /"})
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(run.calls) != 0 || readResult(t, executor, idA).OK {
		t.Fatal("a request with unknown fields must be refused")
	}
}

func TestEachRequestRunsOnceAndIsRecordedFirst(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "docker", "adguard", "restart", executorNow.Add(time.Minute)))
	run.during = func() {
		raw, err := os.ReadFile(filepath.Join(executor.StateDir, "executed.json"))
		if err != nil || !strings.Contains(string(raw), idA) {
			t.Errorf("the ledger must hold the id before the command runs: %s %v", raw, err)
		}
	}
	for range 2 {
		if err := executor.Execute(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(run.calls) != 1 {
		t.Fatalf("expected one run, got %#v", run.calls)
	}
}

func TestARequestWrittenDuringARunIsNotLeftForTheTimer(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "docker", "adguard", "restart", executorNow.Add(time.Minute)))
	run.during = func() {
		writeRequest(t, executor.RequestDir, idB+".json", request(t, idB, "systemd", "nginx.service", "stop", executorNow.Add(time.Minute)))
	}
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(run.calls, []string{"docker restart -- adguard", "systemctl stop -- nginx.service"}) {
		t.Fatalf("unexpected calls %#v", run.calls)
	}
}

func TestTheRequestDirectoryIsNeverWritten(t *testing.T) {
	executor, _ := newTrustedExecutor(t)
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "docker", "adguard", "restart", executorNow.Add(time.Minute)))
	for _, name := range []string{"refresh", ".x.tmp", "notes.json"} {
		if err := os.WriteFile(filepath.Join(executor.RequestDir, name), []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := os.ReadDir(executor.RequestDir)
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadDir(executor.RequestDir)
	if len(before) != len(after) {
		t.Fatalf("the request directory changed: %d -> %d entries", len(before), len(after))
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "results", "notes.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("only id-named files are requests")
	}
}

func TestOversizedAndSymlinkedRequestsAreRefused(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	if err := os.WriteFile(filepath.Join(executor.RequestDir, idA+".json"), []byte(strings.Repeat(" ", 5000)), 0o640); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret")
	writeRequest(t, filepath.Dir(outside), "secret", request(t, idB, "docker", "adguard", "restart", executorNow.Add(time.Minute)))
	symlinked := os.Symlink(outside, filepath.Join(executor.RequestDir, idB+".json")) == nil
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if readResult(t, executor, idA).OK {
		t.Fatal("an oversized request must be refused")
	}
	if symlinked && readResult(t, executor, idB).OK {
		t.Fatal("a symlinked request must be refused")
	}
	if len(run.calls) != 0 {
		t.Fatalf("nothing may run, got %#v", run.calls)
	}
}

func TestASymlinkedRequestDirectoryIsIgnored(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	elsewhere := t.TempDir()
	writeRequest(t, elsewhere, idA+".json", request(t, idA, "docker", "adguard", "restart", executorNow.Add(time.Minute)))
	if err := os.Remove(executor.RequestDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, executor.RequestDir); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(run.calls) != 0 {
		t.Fatalf("a symlinked request directory must be ignored, got %#v", run.calls)
	}
}

func TestAUnitStoppedThroughKrynodesIsRememberedUntilItStartsAgain(t *testing.T) {
	executor, _ := newTrustedExecutor(t)
	var seen [][]string
	services := []Service{{Kind: "systemd", Name: "nginx.service", State: "running"}}
	executor.Collect = func(_ context.Context, remembered []string) (Snapshot, error) {
		seen = append(seen, slices.Clone(remembered))
		return Snapshot{Services: services}, nil
	}
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "systemd", "nginx.service", "stop", executorNow.Add(time.Minute)))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if last := seen[len(seen)-1]; !slices.Equal(last, []string{"nginx.service"}) {
		t.Fatalf("after a stop the unit must be remembered, got %#v", last)
	}
	writeRequest(t, executor.RequestDir, idB+".json", request(t, idB, "systemd", "nginx.service", "start", executorNow.Add(time.Minute)))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if first, last := seen[len(seen)-2], seen[len(seen)-1]; !slices.Equal(first, []string{"nginx.service"}) || len(last) != 0 {
		t.Fatalf("the next run must start from the stored list and forget the unit once started, got %#v then %#v", first, last)
	}
}

func TestAFailedStopIsNotRemembered(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	run.code, run.err = 1, errors.New("exit status 1")
	var last []string
	executor.Collect = func(_ context.Context, remembered []string) (Snapshot, error) {
		last = remembered
		return Snapshot{Services: []Service{{Kind: "systemd", Name: "nginx.service", State: "running"}}}, nil
	}
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "systemd", "nginx.service", "stop", executorNow.Add(time.Minute)))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(last) != 0 {
		t.Fatalf("a failed stop must not be remembered, got %#v", last)
	}
}

func TestAFailedCommandKeepsItsExitCodeAndCleanOutput(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	run.code, run.err = 1, errors.New("exit status 1")
	run.output = "Job for nginx.service failed.\r\n\x00" + strings.Repeat("x", 3000)
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "systemd", "nginx.service", "restart", executorNow.Add(time.Minute)))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	result := readResult(t, executor, idA)
	if result.OK || result.ExitCode == nil || *result.ExitCode != 1 {
		t.Fatalf("unexpected result %#v", result)
	}
	if len(result.Output) != 2048 || strings.ContainsAny(result.Output, "\r\x00") || !strings.HasPrefix(result.Output, "Job for nginx.service failed.\n") {
		t.Fatalf("unexpected output %q...", result.Output[:40])
	}
}

func TestStartUnpausesAPausedContainer(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	run.respond = map[string]string{"docker container inspect --format {{.State.Paused}} -- adguard": "WARNING: config file is unreadable\ntrue\n"}
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "docker", "adguard", "start", executorNow.Add(time.Minute)))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"docker container inspect --format {{.State.Paused}} -- adguard", "docker unpause -- adguard"}
	if !slices.Equal(run.calls, want) {
		t.Fatalf("calls %#v", run.calls)
	}
}

func TestStartRunsDockerStartWhenNotPaused(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	run.respond = map[string]string{"docker container inspect --format {{.State.Paused}} -- adguard": "false\n"}
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "docker", "adguard", "start", executorNow.Add(time.Minute)))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if run.calls[len(run.calls)-1] != "docker start -- adguard" {
		t.Fatalf("calls %#v", run.calls)
	}
}

func TestACorruptLedgerIsSetAsideInsteadOfStoppingEveryRun(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	if err := os.MkdirAll(executor.StateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(executor.StateDir, "executed.json"), []byte("{\"trunc"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "docker", "adguard", "restart", executorNow.Add(time.Minute)))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(run.calls) != 1 {
		t.Fatalf("calls %#v", run.calls)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "executed.json.corrupt")); err != nil {
		t.Fatal("the corrupt ledger must be kept aside")
	}
}

func TestACorruptStoppedListIsSetAsideInsteadOfStoppingEveryRun(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	if err := os.MkdirAll(executor.StateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(executor.StateDir, "stopped.json"), []byte("[\"trunc"), 0o640); err != nil {
		t.Fatal(err)
	}
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "docker", "adguard", "restart", executorNow.Add(time.Minute)))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(run.calls) != 1 {
		t.Fatalf("calls %#v", run.calls)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "stopped.json.corrupt")); err != nil {
		t.Fatal("the corrupt list must be kept aside")
	}
}

func TestALedgerOfTheWrongShapeStartsEmpty(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	if err := os.MkdirAll(executor.StateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(executor.StateDir, "executed.json"), []byte("null"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "docker", "adguard", "restart", executorNow.Add(time.Minute)))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(run.calls) != 1 {
		t.Fatalf("calls %#v", run.calls)
	}
}

func TestARequestThatAlreadyHasAResultIsNotRunAgain(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	if err := os.MkdirAll(filepath.Join(executor.StateDir, "results"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(executor.StateDir, "executed.json"), []byte("{\"trunc"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := Result{ID: idA, OK: true, FinishedAt: executorNow.Format(time.RFC3339Nano)}
	if err := writeJSON(filepath.Join(executor.StateDir, "results"), idA+".json", done, 0o640); err != nil {
		t.Fatal(err)
	}
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "docker", "adguard", "restart", executorNow.Add(time.Minute)))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(run.calls) != 0 {
		t.Fatalf("calls %#v", run.calls)
	}
}

func TestTheInventoryListsStacksWithRollback(t *testing.T) {
	executor, _ := newTrustedExecutor(t)
	executor.Collect = func(context.Context, []string) (Snapshot, error) {
		return Snapshot{
			Stacks:  []Stack{{Project: "listmonk", Directory: "/opt/listmonk", Files: []string{"/opt/listmonk/docker-compose.yml"}, Running: 5, Total: 5}, {Project: "shop", Directory: "/opt/shop", Files: []string{"/opt/shop/compose.yml"}, Running: 1, Total: 2}},
			Compose: true,
		}, nil
	}
	kept := stackRecord{Previous: []imageRecord{{Service: "app", Reference: "listmonk/listmonk:latest", ID: "sha256:old"}}}
	if err := writeJSON(filepath.Join(executor.StateDir, "stacks"), "listmonk.json", kept, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	var inventory Inventory
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	want := []reporter.StackEntry{
		{Project: "listmonk", Directory: "/opt/listmonk", Running: 5, Total: 5, Compose: true, Rollback: true},
		{Project: "shop", Directory: "/opt/shop", Running: 1, Total: 2, Compose: true, Rollback: false},
	}
	if !reflect.DeepEqual(inventory.Stacks, want) {
		t.Fatalf("stacks\n got %#v\nwant %#v", inventory.Stacks, want)
	}
}

func refusedWithoutRunning(t *testing.T, executor Executor, run *fakeRun, reason string) {
	t.Helper()
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	result := readResult(t, executor, idA)
	if len(run.calls) != 0 || result.OK || !strings.Contains(result.Output, reason) {
		t.Fatalf("calls %#v result %#v", run.calls, result)
	}
}

func TestAnUnsignedServiceActionIsRefused(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	unsigned := request(t, idA, "docker", "adguard", "restart", executorNow.Add(time.Minute))
	unsigned.Signed = nil
	writeRequest(t, executor.RequestDir, idA+".json", unsigned)
	refusedWithoutRunning(t, executor, run, "refused: the request is not signed")
}

func TestAServiceActionWithoutTrustIsRefused(t *testing.T) {
	executor, run := newExecutor(t)
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "docker", "adguard", "restart", executorNow.Add(time.Minute)))
	refusedWithoutRunning(t, executor, run, "refused: no trusted devices")
}

func TestASignatureForAnotherActionIsRefused(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	restart := request(t, idA, "docker", "adguard", "restart", executorNow.Add(time.Minute))
	restart.Action = "stop"
	writeRequest(t, executor.RequestDir, idA+".json", restart)
	refusedWithoutRunning(t, executor, run, "does not match the request")
}

func TestARestartOfTheServerIsReportedBeforeItReboots(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "host", "server", "reboot", executorNow.Add(time.Minute)))
	resultWritten := false
	run.during = func() {
		_, err := os.Stat(filepath.Join(executor.StateDir, "results", idA+".json"))
		resultWritten = err == nil
	}
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	result := readResult(t, executor, idA)
	if !result.OK || result.Output != "restarting the server" {
		t.Fatalf("result %+v", result)
	}
	if !slices.Equal(run.calls, []string{"systemctl reboot --no-block"}) || !resultWritten {
		t.Fatalf("calls %q, result written first: %v", run.calls, resultWritten)
	}
}

func TestAnUnsignedServerRestartIsRefused(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	unsigned := request(t, idA, "host", "server", "reboot", executorNow.Add(time.Minute))
	unsigned.Signed = nil
	writeRequest(t, executor.RequestDir, idA+".json", unsigned)
	refusedWithoutRunning(t, executor, run, "refused: the request is not signed")
}

func TestAServerRestartWithAnotherActionIsRefused(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "host", "server", "stop", executorNow.Add(time.Minute)))
	refusedWithoutRunning(t, executor, run, "refused: ")
}

func TestOnlyTheServerItselfCanBeRestarted(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	writeRequest(t, executor.RequestDir, idA+".json", request(t, idA, "host", "firewall", "reboot", executorNow.Add(time.Minute)))
	refusedWithoutRunning(t, executor, run, "refused: ")
}

func signedRequest(t *testing.T, command Command) Request {
	t.Helper()
	c := *testSigner(t)
	command.V, command.NodeID, command.IssuedAt, command.ExpiresAt = c.command.V, c.command.NodeID, c.command.IssuedAt, c.command.ExpiresAt
	c.command = command
	signed := c.request(t)
	signed.ID, signed.Kind, signed.Name, signed.Action, signed.ExpiresAt = command.ID, command.Kind, command.Name, command.Action, executorNow.Add(time.Minute).Format(time.RFC3339Nano)
	return signed
}

func TestTheExecutorReportsAStableSealKey(t *testing.T) {
	executor, _ := newTrustedExecutor(t)
	var keys []string
	for range 2 {
		if err := executor.Execute(context.Background()); err != nil {
			t.Fatal(err)
		}
		var inventory Inventory
		if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, inventory.SealKey)
	}
	if len(keys[0]) != 87 || keys[0] != keys[1] {
		t.Fatalf("the seal key must be reported and kept: %q", keys)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "keys", "seal.key")); err != nil {
		t.Fatal(err)
	}
}

func TestARequestCarriesAnAttachmentAndSignedOptions(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	restart := signedRequest(t, Command{ID: idA, Kind: "docker", Name: "adguard", Action: "restart", Access: "full", Secrets: "c2VhbGVk", Piece: "cGllY2U", Args: map[string]string{"op": "x"}})
	restart.Attachment = strings.Repeat("A", 200<<10)
	writeRequest(t, executor.RequestDir, idA+".json", restart)
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, idA); !result.OK || len(run.calls) != 1 {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
}

func TestRequestsLargerThan256KBAreRefused(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	restart := request(t, idA, "docker", "adguard", "restart", executorNow.Add(time.Minute))
	restart.Attachment = strings.Repeat("A", 257<<10)
	writeRequest(t, executor.RequestDir, idA+".json", restart)
	refusedWithoutRunning(t, executor, run, "too large")
}
