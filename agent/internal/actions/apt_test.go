package actions

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/apt"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/seal"
	"github.com/Kleavox/krynodes/agent/internal/tailscale"
)

func aptRequest(t *testing.T, id, name, action string, args map[string]string) Request {
	t.Helper()
	return signedRequest(t, Command{ID: id, Kind: "apt", Name: name, Action: action, Args: args})
}

func askApt(t *testing.T, id, name, action string, args map[string]string) Request {
	t.Helper()
	asked := request(t, id, "apt", name, action, executorNow.Add(10*time.Minute))
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	asked.Attachment = base64.RawURLEncoding.EncodeToString(encoded)
	return asked
}

func queued(executor Executor, id string) bool {
	_, err := os.Stat(filepath.Join(executor.StateDir, "host", id+".json"))
	return err == nil
}

func TestAptChangesGoToTheHostUnitOnlySigned(t *testing.T) {
	executor, _ := securityExecutor(t)
	writeRequest(t, executor.RequestDir, idA+".json", aptRequest(t, idA, "nginx", "install", nil))
	unsigned := aptRequest(t, idB, "nginx", "remove", nil)
	unsigned.Signed = nil
	writeRequest(t, executor.RequestDir, idB+".json", unsigned)
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !queued(executor, idA) || queued(executor, idB) {
		t.Fatal("only the signed change goes to the host unit")
	}
	if result := readResult(t, executor, idB); result.OK || !strings.HasPrefix(result.Output, "refused:") {
		t.Fatalf("got %+v", result)
	}
}

func TestDryRunsGoToTheHostUnitWithoutASignature(t *testing.T) {
	executor, _ := securityExecutor(t)
	writeRequest(t, executor.RequestDir, idA+".json", askApt(t, idA, "nginx", "preview", map[string]string{"what": "install"}))
	writeRequest(t, executor.RequestDir, idB+".json", askApt(t, idB, "system", "refresh", nil))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !queued(executor, idA) || !queued(executor, idB) {
		t.Fatal("dry runs and Check for Updates run in the host unit")
	}
}

func TestFindingAPackageAnswersAtOnce(t *testing.T) {
	executor, run := securityExecutor(t)
	run.respond["env LC_ALL=C apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= search nginx"] = "nginx - small, powerful, scalable web/proxy server\n"
	writeRequest(t, executor.RequestDir, idA+".json", askApt(t, idA, "system", "find", map[string]string{"term": "nginx"}))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	result := readResult(t, executor, idA)
	var found struct {
		Matches []apt.Match `json:"matches"`
	}
	if err := json.Unmarshal([]byte(result.Output), &found); !result.OK || err != nil || len(found.Matches) != 1 || found.Matches[0].Name != "nginx" {
		t.Fatalf("got %+v (%v)", result, err)
	}
}

func TestHoldWaitsWhileKrynodesChangesTheServer(t *testing.T) {
	executor, run := securityExecutor(t)
	if err := writeJSON(filepath.Join(executor.StateDir, "host"), idB+".json", aptRequest(t, idB, "system", "upgrade", nil), 0o600); err != nil {
		t.Fatal(err)
	}
	writeRequest(t, executor.RequestDir, idA+".json", aptRequest(t, idA, "nodejs", "hold", nil))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, idA); result.OK || !strings.Contains(result.Output, "still changing") {
		t.Fatalf("got %+v", result)
	}
	if err := os.Remove(filepath.Join(executor.StateDir, "host", idB+".json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(executor.StateDir, "results", idA+".json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(executor.StateDir, "executed.json")); err != nil {
		t.Fatal(err)
	}
	rootFile(t, executor, "/var/lib/dpkg/status", "Package: nodejs\nStatus: install ok installed\nVersion: 20.18.0\n")
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, idA); !result.OK || result.Output != "hold nodejs 20.18.0" || !slices.Contains(run.calls, "apt-mark hold nodejs") {
		t.Fatalf("got %+v after %v", result, run.calls)
	}
}

func dpkgHas(t *testing.T, executor Executor, names ...string) {
	t.Helper()
	var stanzas []string
	for _, name := range names {
		stanzas = append(stanzas, "Package: "+name+"\nStatus: install ok installed\nVersion: 1.0\n")
	}
	rootFile(t, executor, "/var/lib/dpkg/status", strings.Join(stanzas, "\n"))
}

func hostQueue(t *testing.T, executor Executor, requests ...Request) {
	t.Helper()
	for _, queuedRequest := range requests {
		if err := writeJSON(filepath.Join(executor.StateDir, "host"), queuedRequest.ID+".json", queuedRequest, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAnInstallRecordsWhatItAddedAndShowsItsProgress(t *testing.T) {
	executor, run := securityExecutor(t)
	dpkgHas(t, executor, "base-files")
	var seen []reporter.Progress
	executor.Stream = func(_ context.Context, each func(string), name string, args ...string) error {
		if slices.Contains(args, "install") {
			each("0 upgraded, 2 newly installed, 0 to remove and 0 not upgraded.")
			each("pmstatus:nginx:50:Unpacking nginx (amd64)")
			var step reporter.Progress
			if err := readJSON(filepath.Join(executor.StateDir, "progress", idA+".json"), &step); err == nil {
				seen = append(seen, step)
			}
			dpkgHas(t, executor, "base-files", "nginx", "nginx-common")
		}
		return nil
	}
	hostQueue(t, executor, aptRequest(t, idA, "nginx", "install", nil))
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	result := readResult(t, executor, idA)
	var outcome apt.Outcome
	if err := json.Unmarshal([]byte(result.Output), &outcome); !result.OK || err != nil || !slices.Equal(outcome.Added, []string{"nginx", "nginx-common"}) {
		t.Fatalf("got %+v (%v)", result, err)
	}
	if len(seen) != 1 || seen[0].ID != idA || seen[0].Done != 1 || seen[0].Total != 2 || seen[0].Line != "unpacking nginx" {
		t.Fatalf("progress %+v", seen)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "progress", idA+".json")); !os.IsNotExist(err) {
		t.Fatal("the progress file outlived its result")
	}
	state, _ := readState[aptState](executor.StateDir, "apt.json")
	if !slices.Equal(state.Installed, []string{"nginx"}) {
		t.Fatalf("recorded %+v", state)
	}
	if !slices.Contains(run.calls, "systemctl start --no-block krynodes-exec.service") {
		t.Fatalf("the inventory was not read again: %v", run.calls)
	}
}

func TestAnUpgradeThatRestartsDockerRecordsItsStacks(t *testing.T) {
	executor, run := securityExecutor(t)
	dpkgHas(t, executor, "docker-ce")
	run.respond["systemctl list-units --type=service --state=running --no-legend --plain"] = "docker.service loaded active running Docker\n"
	run.sequence = map[string][]string{
		"systemctl show -p Id -p ActiveEnterTimestampMonotonic docker.service": {
			"Id=docker.service\nActiveEnterTimestampMonotonic=100\n",
			"Id=docker.service\nActiveEnterTimestampMonotonic=200\n",
		},
	}
	run.respond["docker ps -a --no-trunc --format "+containerFormat] = "db-1\trunning\tdb\t/srv/db\t/srv/db/compose.yaml\t2026-10-26 09:00:00 +0000 UTC\t\n" +
		"web-1\texited\tweb\t/srv/web\t/srv/web/compose.yaml\t2026-10-26 09:00:00 +0000 UTC\t\n"
	executor.Stream = func(context.Context, func(string), string, ...string) error { return nil }
	hostQueue(t, executor, aptRequest(t, idA, "system", "upgrade", nil))
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	result := readResult(t, executor, idA)
	var outcome apt.Outcome
	if err := json.Unmarshal([]byte(result.Output), &outcome); !result.OK || err != nil {
		t.Fatalf("got %+v (%v)", result, err)
	}
	want := []apt.StackState{{Project: "db", Running: 1, Total: 1}, {Project: "web", Running: 0, Total: 1}}
	if !slices.Equal(outcome.Restarted, []string{"docker.service"}) || !slices.Equal(outcome.Stacks, want) {
		t.Fatalf("restarted %v, stacks %+v", outcome.Restarted, outcome.Stacks)
	}
}

func TestAFeaturePackageIsNotRemovedFromPackages(t *testing.T) {
	executor, _ := securityExecutor(t)
	dpkgHas(t, executor, "docker-ce", "containerd.io")
	if err := writeJSON(executor.StateDir, "docker.json", dockerState{InstalledAt: executorNow}, 0o640); err != nil {
		t.Fatal(err)
	}
	streamed := false
	executor.Stream = func(context.Context, func(string), string, ...string) error {
		streamed = true
		return nil
	}
	hostQueue(t, executor, aptRequest(t, idA, "docker-ce", "remove", nil))
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, idA); result.OK || !strings.Contains(result.Output, "came with docker") || streamed {
		t.Fatalf("got %+v", result)
	}
}

func TestTheSignInLinkIsSealedToTheBrowser(t *testing.T) {
	executor, run := securityExecutor(t)
	browser, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootFile(t, executor, tailscale.Binary, "")
	run.respond["tailscale status --json"] = `{"BackendState":"NeedsLogin"}`
	link := "https://login.tailscale.com/a/1a2b3c4d5e6f"
	executor.Stream = func(ctx context.Context, each func(string), name string, args ...string) error {
		each("To authenticate, visit:")
		each("\t" + link)
		return ctx.Err()
	}
	hostQueue(t, executor, hostRequest(t, idA, "tailscale", "signin", map[string]string{"key": seal.Public(browser)}))
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	result := readResult(t, executor, idA)
	raw, _ := os.ReadFile(filepath.Join(executor.StateDir, "results", idA+".json"))
	if !result.OK || strings.Contains(string(raw), "login.tailscale.com") {
		t.Fatalf("the link is in clear: %s", raw)
	}
	var sealed struct {
		Sealed string `json:"sealed"`
	}
	if err := json.Unmarshal([]byte(result.Output), &sealed); err != nil {
		t.Fatal(err)
	}
	opened, err := seal.Open(browser, sealed.Sealed)
	if err != nil || string(opened) != `{"url":"`+link+`"}` {
		t.Fatalf("opened %s %v", opened, err)
	}
	if _, err := seal.Open(mustKey(t, executor), sealed.Sealed); err == nil {
		t.Fatal("the server's own key opens the link")
	}
}

func mustKey(t *testing.T, executor Executor) *ecdh.PrivateKey {
	t.Helper()
	key, err := executor.sealKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestProgressIsPostedWhenItChangesAndAtMostEveryFiveSeconds(t *testing.T) {
	relay, poster := newRelay(t)
	now := executorNow
	relay.Now = func() time.Time { return now }
	step := func(done int, line string) {
		if err := writeJSON(filepath.Join(relay.StateDir, "progress"), idA+".json", reporter.Progress{ID: idA, At: now.Format(time.RFC3339Nano), Done: done, Total: 14, Line: line}, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	poll := func() {
		if err := relay.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	step(1, "unpacking docker-ce")
	poll()
	poll()
	now = now.Add(2 * time.Second)
	step(2, "unpacking containerd.io")
	poll()
	now = now.Add(3 * time.Second)
	poll()
	now = now.Add(10 * time.Second)
	poll()
	var sent []int
	for _, report := range poster.reports {
		for _, progress := range report.Progress {
			sent = append(sent, progress.Done)
		}
	}
	if !slices.Equal(sent, []int{1, 2}) || len(poster.reports) != 2 {
		t.Fatalf("sent %v in %d reports", sent, len(poster.reports))
	}
	poster.err = errors.New("offline")
	now = now.Add(10 * time.Second)
	step(3, "setting up docker-ce")
	if err := relay.Poll(context.Background()); err == nil {
		t.Fatal("expected the post to fail")
	}
	poster.err = nil
	now = now.Add(10 * time.Minute)
	poll()
	if last := poster.reports[len(poster.reports)-1]; len(last.Progress) != 1 || last.Progress[0].Done != 3 {
		t.Fatalf("a step that failed to post was not sent again: %+v", last)
	}
}
