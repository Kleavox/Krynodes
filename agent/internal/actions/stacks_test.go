package actions

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func stackExecutor(t *testing.T, stacks ...Stack) (Executor, *fakeRun) {
	t.Helper()
	executor, run := newTrustedExecutor(t)
	services := []Service{{Kind: "docker", Name: "adguard", State: "running"}, {Kind: "systemd", Name: "nginx.service", State: "running"}, {Kind: "systemd", Name: "ssh.service", State: "running"}}
	executor.Collect = func(context.Context, []string) (Snapshot, error) {
		return Snapshot{Services: services, Stacks: stacks, Compose: true, Docker: "ready"}, nil
	}
	executor.Exists = func(string) bool { return true }
	executor.HealthTimeout = 80 * time.Millisecond
	executor.HealthEvery = 5 * time.Millisecond
	executor.HealthSettle = 10 * time.Millisecond
	return executor, run
}

func runRequest(t *testing.T, executor Executor, request Request) Result {
	t.Helper()
	writeRequest(t, executor.RequestDir, request.ID+".json", request)
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	return readResult(t, executor, request.ID)
}

func soon() time.Time { return executorNow.Add(10 * time.Minute) }

func TestAStackStartsStopsAndRestartsWithCompose(t *testing.T) {
	for _, verb := range []string{"start", "stop", "restart"} {
		executor, run := stackExecutor(t, listmonk)
		result := runRequest(t, executor, request(t, idA, "compose", "listmonk", verb, soon()))
		if !result.OK || !slices.Contains(run.calls, composeBase+" "+verb) {
			t.Fatalf("%s: result %#v calls %q", verb, result, run.calls)
		}
	}
}

func TestRemoveTakesAStackDownAndKeepsItsData(t *testing.T) {
	executor, run := stackExecutor(t, listmonk)
	collected := 0
	executor.Collect = func(context.Context, []string) (Snapshot, error) {
		collected++
		if collected == 1 {
			return Snapshot{Stacks: []Stack{listmonk}, Compose: true, Docker: "ready"}, nil
		}
		return Snapshot{Compose: true, Docker: "ready"}, nil
	}
	keep(t, executor, imageRecord{Service: "app", Reference: "listmonk/listmonk:latest", ID: "sha256:old"})
	result := runRequest(t, executor, request(t, idA, "compose", "listmonk", "remove", soon()))
	if !result.OK || !slices.Contains(run.calls, composeBase+" down --remove-orphans") {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "stacks", "listmonk.json")); !os.IsNotExist(err) {
		t.Fatalf("the rollback record must go with the stack: %v", err)
	}
	removed := binOf(t, executor).Stacks["listmonk"]
	if removed.Directory != "/opt/listmonk" || len(removed.Files) != 1 || !removed.RemovedAt.Equal(executorNow) {
		t.Fatalf("the stack must wait in Removed: %#v", removed)
	}
	var inventory Inventory
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	if len(inventory.Removed) != 1 || inventory.Removed[0].Project != "listmonk" {
		t.Fatalf("the inventory must list it: %#v", inventory.Removed)
	}
}

func binOf(t *testing.T, executor Executor) stackBin {
	t.Helper()
	bin, err := readState[stackBin](executor.StateDir, "bin.json")
	if err != nil {
		t.Fatal(err)
	}
	return bin
}

func park(t *testing.T, executor Executor, entries map[string]removedStack) {
	t.Helper()
	if err := writeJSON(executor.StateDir, "bin.json", stackBin{Stacks: entries}, 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreBringsARemovedStackBack(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := kumaDir(executor)
	file := filepath.Join(dir, "compose.krynodes.json")
	park(t, executor, map[string]removedStack{"kuma": {Directory: dir, Files: []string{file}, RemovedAt: executorNow.Add(-time.Hour)}})
	run.respond = map[string]string{
		composeCall(dir, "compose.krynodes.json", "ps --all --format {{.Service}}\t{{.State}}\t{{.Health}}\t{{.ExitCode}}"): "web\trunning\t\t0\n",
	}
	result := runRequest(t, executor, request(t, idA, "compose", "kuma", "restore", soon()))
	if !result.OK || !slices.Contains(run.calls, composeCall(dir, "compose.krynodes.json", "up -d")) {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	if _, ok := binOf(t, executor).Stacks["kuma"]; ok {
		t.Fatal("a restored stack leaves Removed")
	}
}

func TestRestoreWithoutItsFilesIsRefusedAndKeepsTheEntry(t *testing.T) {
	executor, run := stackExecutor(t)
	executor.Exists = func(string) bool { return false }
	park(t, executor, map[string]removedStack{"shop": {Directory: "/opt/shop", Files: []string{"/opt/shop/compose.yml"}, RemovedAt: executorNow}})
	result := runRequest(t, executor, request(t, idA, "compose", "shop", "restore", soon()))
	if result.OK || !strings.Contains(result.Output, "no compose file") || len(run.calls) != 0 {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	if _, ok := binOf(t, executor).Stacks["shop"]; !ok {
		t.Fatal("the entry must stay")
	}
}

func TestDeletingARemovedStackRemovesItsVolumesAndOnlyItsOwnFolder(t *testing.T) {
	executor, run := stackExecutor(t)
	own := kumaDir(executor)
	if err := os.MkdirAll(own, 0o750); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	park(t, executor, map[string]removedStack{
		"kuma": {Directory: own, RemovedAt: executorNow},
		"shop": {Directory: elsewhere, RemovedAt: executorNow},
	})
	run.respond = map[string]string{
		"docker volume ls -q --filter label=com.docker.compose.project=kuma": "kuma_data\n",
		"docker volume ls -q --filter label=com.docker.compose.project=shop": "shop_db\n",
	}
	if result := runRequest(t, executor, request(t, idA, "compose", "kuma", "purge", soon())); !result.OK {
		t.Fatalf("result %#v", result)
	}
	if result := runRequest(t, executor, request(t, idB, "compose", "shop", "purge", soon())); !result.OK {
		t.Fatalf("result %#v", result)
	}
	for _, call := range []string{"docker volume rm kuma_data", "docker volume rm shop_db"} {
		if !slices.Contains(run.calls, call) {
			t.Fatalf("missing %q in %q", call, run.calls)
		}
	}
	if _, err := os.Stat(own); !os.IsNotExist(err) {
		t.Fatalf("its own folder must go: %v", err)
	}
	if _, err := os.Stat(elsewhere); err != nil {
		t.Fatalf("a folder elsewhere stays: %v", err)
	}
	if len(binOf(t, executor).Stacks) != 0 {
		t.Fatal("both leave Removed")
	}
}

func TestAStackWithAWebAddressIsNotRemovedUntilTheAddressIsClosed(t *testing.T) {
	for _, verb := range []string{"remove", "purge"} {
		executor, run := stackExecutor(t, listmonk)
		if err := writeJSON(executor.StateDir, "addresses.json", map[string]webAddress{"mail.kleavox.xyz": {Project: "listmonk", Service: "app", Network: "listmonk_default"}}, 0o640); err != nil {
			t.Fatal(err)
		}
		result := runRequest(t, executor, request(t, idA, "compose", "listmonk", verb, soon()))
		if result.OK || !strings.Contains(result.Output, "mail.kleavox.xyz") || slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "docker compose") }) {
			t.Fatalf("%s: %#v %q", verb, result, run.calls)
		}
	}
}

func TestRemovedStacksAreDeletedAfterSevenDays(t *testing.T) {
	executor, run := stackExecutor(t)
	old := filepath.Join(executor.StateDir, "compose", "old")
	if err := os.MkdirAll(old, 0o750); err != nil {
		t.Fatal(err)
	}
	park(t, executor, map[string]removedStack{
		"old":   {Directory: old, RemovedAt: executorNow.Add(-8 * 24 * time.Hour)},
		"fresh": {Directory: "/opt/fresh", RemovedAt: executorNow.Add(-24 * time.Hour)},
	})
	run.respond = map[string]string{"docker volume ls -q --filter label=com.docker.compose.project=old": "old_data\n"}
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	bin := binOf(t, executor)
	if _, ok := bin.Stacks["old"]; ok || !slices.Contains(run.calls, "docker volume rm old_data") {
		t.Fatalf("bin %#v calls %q", bin, run.calls)
	}
	if _, ok := bin.Stacks["fresh"]; !ok {
		t.Fatal("a stack removed a day ago waits")
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("its folder must go: %v", err)
	}
}

func TestOldRemovedStacksWaitWhileTheClockIsNotSynchronized(t *testing.T) {
	executor, run := stackExecutor(t)
	old := filepath.Join(executor.StateDir, "compose", "old")
	if err := os.MkdirAll(old, 0o750); err != nil {
		t.Fatal(err)
	}
	park(t, executor, map[string]removedStack{"old": {Directory: old, RemovedAt: executorNow.Add(-8 * 24 * time.Hour)}})
	run.respond = map[string]string{"timedatectl show -p NTPSynchronized --value": "no\n"}
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := binOf(t, executor).Stacks["old"]; !ok {
		t.Fatal("a clock that may be wrong deletes nothing")
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatalf("its folder stays: %v", err)
	}
}

func TestOldRemovedStacksWaitWhileDockerIsGone(t *testing.T) {
	executor, run := stackExecutor(t)
	executor.Collect = func(context.Context, []string) (Snapshot, error) {
		return Snapshot{Docker: "missing"}, nil
	}
	old := filepath.Join(executor.StateDir, "compose", "old")
	if err := os.MkdirAll(old, 0o750); err != nil {
		t.Fatal(err)
	}
	park(t, executor, map[string]removedStack{"old": {Directory: old, RemovedAt: executorNow.Add(-8 * 24 * time.Hour)}})
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := binOf(t, executor).Stacks["old"]; !ok || len(run.calls) != 0 {
		t.Fatalf("bin %#v calls %q", binOf(t, executor), run.calls)
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatalf("its folder waits too: %v", err)
	}
}

func TestAStackThatComesBackLeavesRemovedWithNothingDeleted(t *testing.T) {
	executor, run := stackExecutor(t, listmonk)
	park(t, executor, map[string]removedStack{"listmonk": {Directory: "/opt/listmonk", RemovedAt: executorNow.Add(-9 * 24 * time.Hour)}})
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := binOf(t, executor).Stacks["listmonk"]; ok || slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "volume") }) {
		t.Fatalf("bin %#v calls %q", binOf(t, executor), run.calls)
	}
}

func TestANewStackRefusesANameWaitingInRemoved(t *testing.T) {
	executor, run := stackExecutor(t)
	park(t, executor, map[string]removedStack{"kuma": {Directory: kumaDir(executor), RemovedAt: executorNow}})
	result := runRequest(t, executor, createRequest(t, idA, "kuma", kumaText))
	if result.OK || !strings.Contains(result.Output, "Removed") || len(run.calls) != 0 {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
}

func TestRemoveWithDataDeletesOnlyAFolderKrynodesMade(t *testing.T) {
	executor, run := stackExecutor(t)
	own := filepath.Join(executor.StateDir, "compose", "kuma")
	if err := os.MkdirAll(filepath.Join(own, "data"), 0o750); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	stacks := []Stack{
		{Project: "kuma", Directory: own, Files: []string{filepath.Join(own, "compose.krynodes.json")}, Running: 1, Total: 1},
		{Project: "shop", Directory: elsewhere, Files: []string{filepath.Join(elsewhere, "compose.yml")}, Running: 1, Total: 1},
	}
	executor.Collect = func(context.Context, []string) (Snapshot, error) {
		return Snapshot{Stacks: stacks, Compose: true, Docker: "ready"}, nil
	}
	result := runRequest(t, executor, request(t, idA, "compose", "kuma", "purge", soon()))
	if !result.OK || !strings.Contains(strings.Join(run.calls, "\n"), "down -v --remove-orphans") {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	if _, err := os.Stat(own); !os.IsNotExist(err) {
		t.Fatalf("its own folder must be deleted: %v", err)
	}
	result = runRequest(t, executor, request(t, idB, "compose", "shop", "purge", soon()))
	if !result.OK {
		t.Fatalf("result %#v", result)
	}
	if _, err := os.Stat(elsewhere); err != nil {
		t.Fatalf("a folder elsewhere must stay: %v", err)
	}
}

func TestAContainerIsRemovedWithForce(t *testing.T) {
	executor, run := stackExecutor(t)
	result := runRequest(t, executor, request(t, idA, "docker", "adguard", "remove", soon()))
	if !result.OK || !slices.Contains(run.calls, "docker rm -f -- adguard") {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	executor, _ = stackExecutor(t)
	result = runRequest(t, executor, request(t, idA, "systemd", "nginx.service", "remove", soon()))
	if result.OK {
		t.Fatal("a unit is never removed")
	}
}

const kumaText = "services:\n  web:\n    image: louislam/uptime-kuma:1\n    ports:\n      - \"3001:3001\"\n    volumes:\n      - ./data:/app/data\n"

func createRequest(t *testing.T, id, name, text string) Request {
	t.Helper()
	c := *testSigner(t)
	c.command.ID, c.command.Kind, c.command.Name, c.command.Action, c.command.Compose = id, "compose", name, "create", text
	signed := c.request(t)
	signed.ID, signed.Kind, signed.Name, signed.Action, signed.ExpiresAt = id, "compose", name, "create", soon().Format(time.RFC3339Nano)
	return signed
}

func kumaDir(executor Executor) string { return filepath.Join(executor.StateDir, "compose", "kuma") }

func composeCall(dir, file, rest string) string {
	return "docker compose --project-name kuma --project-directory " + dir + " -f " + filepath.Join(dir, file) + " " + rest
}

func resolved(t *testing.T, dir string, service map[string]any, extra map[string]any) string {
	t.Helper()
	config := map[string]any{"name": "kuma", "services": map[string]any{"web": service}}
	for key, value := range extra {
		config[key] = value
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func kumaService(dir string) map[string]any {
	return map[string]any{
		"image":   "louislam/uptime-kuma:1",
		"ports":   []any{map[string]any{"mode": "ingress", "host_ip": "", "target": 3001, "published": "3001", "protocol": "tcp"}},
		"volumes": []any{map[string]any{"type": "bind", "source": filepath.Join(dir, "data"), "target": "/app/data"}},
	}
}

func TestANewStackRunsItsResolvedFileWithPortsOnTheServerOnly(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := kumaDir(executor)
	run.respond = map[string]string{
		composeCall(dir, "compose.yaml", "config --format json"):                                                            resolved(t, dir, kumaService(dir), nil),
		composeCall(dir, "compose.krynodes.json", "ps --all --format {{.Service}}\t{{.State}}\t{{.Health}}\t{{.ExitCode}}"): "web\trunning\t\t0\n",
	}
	result := runRequest(t, executor, createRequest(t, idA, "kuma", kumaText))
	if !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	written, err := os.ReadFile(filepath.Join(dir, "compose.yaml"))
	if err != nil || string(written) != kumaText {
		t.Fatalf("the file as given must be kept: %q %v", written, err)
	}
	var config map[string]any
	if err := readJSON(filepath.Join(dir, "compose.krynodes.json"), &config); err != nil {
		t.Fatal(err)
	}
	port := config["services"].(map[string]any)["web"].(map[string]any)["ports"].([]any)[0].(map[string]any)
	if port["host_ip"] != "127.0.0.1" {
		t.Fatalf("ports must open on the server only: %#v", port)
	}
	pull := slices.Index(run.calls, composeCall(dir, "compose.krynodes.json", "pull"))
	up := slices.Index(run.calls, composeCall(dir, "compose.krynodes.json", "up -d"))
	if pull < 0 || up < pull {
		t.Fatalf("pull then up the resolved file: %q", run.calls)
	}
}

func TestANewStackThatNeverStartedLeavesNoFolder(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := kumaReady(t, executor, run, kumaService(kumaDir(executor)), nil)
	run.failing = map[string]string{composeCall(dir, "compose.krynodes.json", "pull"): "pull access denied"}
	request := createRequest(t, idA, "kuma", kumaText)
	if result := runRequest(t, executor, request); result.OK {
		t.Fatalf("result %#v", result)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("a stack that never started leaves no folder or secrets behind")
	}
	executor, run = stackExecutor(t)
	dir = kumaReady(t, executor, run, kumaService(kumaDir(executor)), nil)
	run.respond["docker ps -a --no-trunc --filter label=com.docker.compose.project=kuma --format {{.ID}}"] = "c0ffee\n"
	run.failing = map[string]string{composeCall(dir, "compose.krynodes.json", "up -d"): "port is already allocated"}
	if result := runRequest(t, executor, createRequest(t, idA, "kuma", kumaText)); result.OK {
		t.Fatalf("result %#v", result)
	}
	if _, err := os.Stat(filepath.Join(dir, "compose.yaml")); err != nil {
		t.Fatal("a stack with containers keeps its folder so it can be fixed or removed")
	}
	executor, run = stackExecutor(t)
	dir = kumaReady(t, executor, run, kumaService(kumaDir(executor)), nil)
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data", "kuma.db"), []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	run.failing = map[string]string{composeCall(dir, "compose.krynodes.json", "pull"): "pull access denied"}
	if result := runRequest(t, executor, createRequest(t, idA, "kuma", kumaText)); result.OK {
		t.Fatalf("result %#v", result)
	}
	if kept, _ := os.ReadFile(filepath.Join(dir, "data", "kuma.db")); string(kept) != "old" {
		t.Fatal("a folder that was there before keeps its data")
	}
}

func TestANewStackRefusesWhatCouldTakeOverTheServer(t *testing.T) {
	cases := []struct {
		name    string
		change  func(dir string, service map[string]any, extra map[string]any)
		message string
	}{
		{"privileged", func(_ string, s map[string]any, _ map[string]any) { s["privileged"] = true }, "privileged"},
		{"host network", func(_ string, s map[string]any, _ map[string]any) { s["network_mode"] = "host" }, "network"},
		{"host pid", func(_ string, s map[string]any, _ map[string]any) { s["pid"] = "host" }, "pid"},
		{"another container", func(_ string, s map[string]any, _ map[string]any) { s["network_mode"] = "container:adguard" }, "another container"},
		{"capabilities", func(_ string, s map[string]any, _ map[string]any) { s["cap_add"] = []any{"NET_ADMIN"} }, "capabilities"},
		{"devices", func(_ string, s map[string]any, _ map[string]any) { s["devices"] = []any{"/dev/sda:/dev/sda"} }, "devices"},
		{"docker socket", func(_ string, s map[string]any, _ map[string]any) {
			s["volumes"] = []any{map[string]any{"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}}
		}, "/var/run/docker.sock"},
		{"root folder", func(dir string, s map[string]any, _ map[string]any) {
			s["volumes"] = []any{map[string]any{"type": "bind", "source": filepath.Join(dir, "..", ".."), "target": "/host"}}
		}, "mounts"},
		{"volume that binds", func(_ string, s map[string]any, extra map[string]any) {
			s["volumes"] = []any{map[string]any{"type": "volume", "source": "etc", "target": "/etc2"}}
			extra["volumes"] = map[string]any{"etc": map[string]any{"driver_opts": map[string]any{"type": "none", "o": "bind", "device": "/etc"}}}
		}, "binds a path"},
		{"env file", func(_ string, s map[string]any, _ map[string]any) {
			s["env_file"] = []any{map[string]any{"path": "/etc/shadow", "required": true}}
		}, "/etc/shadow"},
		{"secret file", func(_ string, _ map[string]any, extra map[string]any) {
			extra["secrets"] = map[string]any{"key": map[string]any{"file": "/root/.ssh/id_ed25519"}}
		}, "id_ed25519"},
		{"unconfined", func(_ string, s map[string]any, _ map[string]any) { s["security_opt"] = []any{"seccomp=unconfined"} }, "confinement"},
		{"selinux super type", func(_ string, s map[string]any, _ map[string]any) { s["security_opt"] = []any{"label=type:spc_t"} }, "label=type:spc_t"},
		{"own seccomp profile", func(_ string, s map[string]any, _ map[string]any) {
			s["security_opt"] = []any{"seccomp=./allow-all.json"}
		}, "seccomp=./allow-all.json"},
		{"own apparmor profile", func(_ string, s map[string]any, _ map[string]any) { s["security_opt"] = []any{"apparmor=lenient"} }, "apparmor=lenient"},
		{"gpus", func(_ string, s map[string]any, _ map[string]any) {
			s["gpus"] = []any{map[string]any{"driver": "nvidia", "count": -1}}
		}, "devices"},
		{"reserved devices", func(_ string, s map[string]any, _ map[string]any) {
			s["deploy"] = map[string]any{"resources": map[string]any{"reservations": map[string]any{"devices": []any{map[string]any{"capabilities": []any{"gpu"}}}}}}
		}, "devices"},
		{"build", func(_ string, s map[string]any, _ map[string]any) { s["build"] = map[string]any{"context": "."} }, "builds"},
		{"external network", func(_ string, _ map[string]any, extra map[string]any) {
			extra["networks"] = map[string]any{"lan": map[string]any{"name": "lan", "external": true}}
		}, "network lan"},
		{"macvlan", func(_ string, _ map[string]any, extra map[string]any) {
			extra["networks"] = map[string]any{"lan": map[string]any{"driver": "macvlan"}}
		}, "network lan"},
		{"volumes from", func(_ string, s map[string]any, _ map[string]any) { s["volumes_from"] = []any{"container:adguard"} }, "another container"},
		{"docker's own bridge", func(_ string, _ map[string]any, extra map[string]any) {
			extra["networks"] = map[string]any{"default": map[string]any{"name": "bridge"}}
		}, "network default"},
		{"another stack's network", func(_ string, _ map[string]any, extra map[string]any) {
			extra["networks"] = map[string]any{"default": map[string]any{"name": "kuma_default"}, "shop": map[string]any{"name": "kuma_x_default"}}
		}, "network shop"},
		{"other runtime", func(_ string, s map[string]any, _ map[string]any) { s["runtime"] = "nvidia" }, "runtime nvidia"},
		{"log driver on the server's network", func(_ string, s map[string]any, _ map[string]any) {
			s["logging"] = map[string]any{"driver": "syslog", "options": map[string]any{"syslog-address": "tcp://127.0.0.1:6379"}}
		}, "logs"},
		{"image from the server itself", func(_ string, s map[string]any, _ map[string]any) { s["image"] = "127.0.0.1:5000/app:1" }, "127.0.0.1"},
		{"image from localhost", func(_ string, s map[string]any, _ map[string]any) { s["image"] = "localhost:5000/app" }, "localhost"},
		{"image from the metadata address", func(_ string, s map[string]any, _ map[string]any) { s["image"] = "169.254.169.254/latest/app" }, "169.254.169.254"},
		{"image from ipv6 loopback", func(_ string, s map[string]any, _ map[string]any) { s["image"] = "[::1]:5000/app" }, "::1"},
		{"privileged hook", func(_ string, s map[string]any, _ map[string]any) {
			s["post_start"] = []any{map[string]any{"command": []any{"insmod", "/x.ko"}, "privileged": true}}
		}, "privileged"},
		{"privileged stop hook", func(_ string, s map[string]any, _ map[string]any) {
			s["pre_stop"] = []any{map[string]any{"command": []any{"sh"}, "privileged": true}}
		}, "privileged"},
		{"provider", func(_ string, s map[string]any, _ map[string]any) {
			delete(s, "image")
			s["provider"] = map[string]any{"type": "sh", "options": map[string]any{"c": "id"}}
		}, "program on the server"},
		{"label file", func(_ string, s map[string]any, _ map[string]any) { s["label_file"] = []any{"/etc/shadow"} }, "/etc/shadow"},
		{"models", func(_ string, _ map[string]any, extra map[string]any) {
			extra["models"] = map[string]any{"llm": map[string]any{"model": "ai/smollm2"}}
		}, "models"},
		{"another stack's volume", func(_ string, s map[string]any, extra map[string]any) {
			s["volumes"] = []any{map[string]any{"type": "volume", "source": "data", "target": "/data"}}
			extra["volumes"] = map[string]any{"data": map[string]any{"name": "shop_data"}}
		}, "volume data"},
		{"docker's default bridge", func(_ string, s map[string]any, _ map[string]any) { s["network_mode"] = "bridge" }, "network bridge"},
		{"a network by mode", func(_ string, s map[string]any, _ map[string]any) { s["network_mode"] = "shop_default" }, "network shop_default"},
		{"unlimited swap", func(_ string, s map[string]any, _ map[string]any) { s["memswap_limit"] = float64(-1) }, "swap"},
		{"large swap", func(_ string, s map[string]any, _ map[string]any) { s["memswap_limit"] = "8g" }, "swap"},
		{"many copies", func(_ string, s map[string]any, _ map[string]any) { s["scale"] = float64(50) }, "copies"},
		{"many replicas", func(_ string, s map[string]any, _ map[string]any) {
			s["deploy"] = map[string]any{"replicas": float64(50)}
		}, "copies"},
		{"docker api socket", func(_ string, s map[string]any, _ map[string]any) { s["use_api_socket"] = true }, "use_api_socket"},
		{"a key compose added later", func(_ string, s map[string]any, _ map[string]any) { s["host_takeover"] = true }, "host_takeover"},
		{"cgroup parent", func(_ string, s map[string]any, _ map[string]any) { s["cgroup_parent"] = "system.slice" }, "cgroup_parent"},
		{"a top-level key compose added later", func(_ string, _ map[string]any, extra map[string]any) {
			extra["plugins"] = map[string]any{"x": map[string]any{}}
		}, "plugins"},
		{"log option", func(_ string, s map[string]any, _ map[string]any) {
			s["logging"] = map[string]any{"driver": "json-file", "options": map[string]any{"labels-regex": ".*", "path": "/etc/cron.d/x"}}
		}, "logs"},
		{"overlay volume", func(_ string, s map[string]any, extra map[string]any) {
			s["volumes"] = []any{map[string]any{"type": "volume", "source": "etc", "target": "/etc2"}}
			extra["volumes"] = map[string]any{"etc": map[string]any{"driver_opts": map[string]any{"type": "overlay", "o": "lowerdir=/etc,upperdir=/tmp/u,workdir=/tmp/w"}}}
		}, "volume etc"},
		{"volume plugin", func(_ string, s map[string]any, extra map[string]any) {
			s["volumes"] = []any{map[string]any{"type": "volume", "source": "etc", "target": "/etc2"}}
			extra["volumes"] = map[string]any{"etc": map[string]any{"driver": "local-persist", "driver_opts": map[string]any{"mountpoint": "/etc"}}}
		}, "volume etc"},
		{"ipv6", func(_ string, _ map[string]any, extra map[string]any) {
			extra["networks"] = map[string]any{"default": map[string]any{"name": "kuma_default", "enable_ipv6": true}}
		}, "IPv6"},
	}
	for _, item := range cases {
		executor, run := stackExecutor(t)
		dir := kumaDir(executor)
		service, extra := kumaService(dir), map[string]any{}
		item.change(dir, service, extra)
		run.respond = map[string]string{composeCall(dir, "compose.yaml", "config --format json"): resolved(t, dir, service, extra)}
		result := runRequest(t, executor, createRequest(t, idA, "kuma", kumaText))
		if result.OK || !strings.Contains(result.Output, item.message) {
			t.Fatalf("%s: result %#v", item.name, result)
		}
		if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasSuffix(call, " up -d") || strings.HasSuffix(call, " pull") }) {
			t.Fatalf("%s: nothing may run: %q", item.name, run.calls)
		}
	}
}

func TestAResolvedFileWithoutAProjectNameStillRunsContained(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := kumaDir(executor)
	config := map[string]any{
		"services": map[string]any{"web": kumaService(dir)},
		"networks": map[string]any{"default": map[string]any{"name": "kuma_default"}},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	run.respond = map[string]string{
		composeCall(dir, "compose.yaml", "config --format json"):                                                            string(encoded),
		composeCall(dir, "compose.krynodes.json", "ps --all --format {{.Service}}\t{{.State}}\t{{.Health}}\t{{.ExitCode}}"): "web\trunning\t\t0\n",
	}
	if result := runRequest(t, executor, createRequest(t, idA, "kuma", kumaText)); !result.OK {
		t.Fatalf("the folder names the project when compose leaves it out: %#v", result)
	}
}

func TestAContainedStackKeepsItsLogsSmallOnTheServer(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := kumaDir(executor)
	service := kumaService(dir)
	service["logging"] = map[string]any{"driver": "json-file", "options": map[string]any{"max-size": "10m", "max-file": "3"}}
	run.respond = map[string]string{
		composeCall(dir, "compose.yaml", "config --format json"):                                                            resolved(t, dir, service, nil),
		composeCall(dir, "compose.krynodes.json", "ps --all --format {{.Service}}\t{{.State}}\t{{.Health}}\t{{.ExitCode}}"): "web\trunning\t\t0\n",
	}
	if result := runRequest(t, executor, createRequest(t, idA, "kuma", kumaText)); !result.OK {
		t.Fatalf("a size limit on its own logs is fine: %#v", result)
	}
}

func TestAContainedStackRunsWithTheUsualComposeKeys(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := kumaDir(executor)
	service := kumaService(dir)
	for key, value := range map[string]any{
		"container_name": "kuma", "hostname": "kuma", "restart": "unless-stopped", "environment": map[string]any{"TZ": "UTC"},
		"command": []any{"node", "server"}, "entrypoint": nil, "depends_on": map[string]any{}, "labels": map[string]any{"a": "b"},
		"healthcheck": map[string]any{"test": []any{"CMD", "true"}}, "user": "1000", "working_dir": "/app", "read_only": true,
		"cap_drop": []any{"ALL"}, "security_opt": []any{"no-new-privileges:true"}, "tmpfs": []any{"/tmp"}, "ulimits": map[string]any{},
		"stop_grace_period": "10s", "x-note": "anything", "networks": map[string]any{"default": nil}, "pull_policy": "always",
		"init": true, "extra_hosts": []any{}, "dns": []any{"1.1.1.1"}, "shm_size": "64m", "sysctls": map[string]any{}, "tty": false,
	} {
		service[key] = value
	}
	run.respond = map[string]string{
		composeCall(dir, "compose.yaml", "config --format json"):                                                            resolved(t, dir, service, map[string]any{"x-shared": map[string]any{}}),
		composeCall(dir, "compose.krynodes.json", "ps --all --format {{.Service}}\t{{.State}}\t{{.Health}}\t{{.ExitCode}}"): "web\trunning\t\t0\n",
	}
	if result := runRequest(t, executor, createRequest(t, idA, "kuma", kumaText)); !result.OK {
		t.Fatalf("the usual keys run Contained: %#v", result)
	}
}

func TestAContainedImageFromANameThatPointsAtTheServerIsRefused(t *testing.T) {
	try := func(image string) Result {
		t.Helper()
		executor, run := stackExecutor(t)
		executor.LookupIP = func(_ context.Context, host string) ([]net.IP, error) {
			switch host {
			case "127.0.0.1.nip.io":
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			case "registry.example.com":
				return []net.IP{net.ParseIP("203.0.113.7")}, nil
			}
			return nil, errors.New("no such host")
		}
		dir := kumaDir(executor)
		service := kumaService(dir)
		service["image"] = image
		run.respond = map[string]string{
			composeCall(dir, "compose.yaml", "config --format json"):                                                            resolved(t, dir, service, nil),
			composeCall(dir, "compose.krynodes.json", "ps --all --format {{.Service}}\t{{.State}}\t{{.Health}}\t{{.ExitCode}}"): "web\trunning\t\t0\n",
		}
		return runRequest(t, executor, createRequest(t, idA, "kuma", kumaText))
	}
	if result := try("127.0.0.1.nip.io:5000/app:1"); result.OK || !strings.Contains(result.Output, "127.0.0.1.nip.io") {
		t.Fatalf("result %#v", result)
	}
	if result := try("registry.example.com/app:1"); !result.OK {
		t.Fatalf("a registry elsewhere is fine: %#v", result)
	}
}

func TestANewStackRefusesIncludesBeforeAskingCompose(t *testing.T) {
	for _, text := range []string{
		"include:\n  - /etc/compose.yml\n" + kumaText,
		`{"include": ["/etc/shadow"], "services": {"web": {"image": "nginx"}}}`,
		"{include: [/etc/shadow], services: {web: {image: nginx}}}",
		"'include':\n  - /etc/compose.yml\n" + kumaText,
	} {
		executor, run := stackExecutor(t)
		result := runRequest(t, executor, createRequest(t, idA, "kuma", text))
		if result.OK || len(run.calls) != 0 {
			t.Fatalf("%q: result %#v calls %q", text, result, run.calls)
		}
	}
}

func TestANewStackNeedsAFreeNameComposeAndASignature(t *testing.T) {
	executor, _ := stackExecutor(t, Stack{Project: "kuma", Directory: "/opt/kuma", Running: 1, Total: 1})
	if result := runRequest(t, executor, createRequest(t, idA, "kuma", kumaText)); result.OK || !strings.Contains(result.Output, "already") {
		t.Fatalf("a name in use must be refused: %#v", result)
	}
	executor, _ = stackExecutor(t)
	executor.Collect = func(context.Context, []string) (Snapshot, error) {
		return Snapshot{Docker: "no-compose"}, nil
	}
	if result := runRequest(t, executor, createRequest(t, idA, "kuma", kumaText)); result.OK || !strings.Contains(result.Output, "compose") {
		t.Fatalf("a server without compose must refuse: %#v", result)
	}
	executor, _ = stackExecutor(t)
	unsigned := createRequest(t, idA, "kuma", kumaText)
	unsigned.Signed = nil
	if result := runRequest(t, executor, unsigned); result.OK {
		t.Fatal("an unsigned new stack must be refused")
	}
}

func bare(id, name, action string) Request {
	return Request{ID: id, Kind: "systemd", Name: name, Action: action, ExpiresAt: soon().Format(time.RFC3339Nano)}
}

func listed(t *testing.T, executor Executor) autoRestart {
	t.Helper()
	state, err := readState[autoRestart](executor.StateDir, "autorestart.json")
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestAutoRestartIsTurnedOnOnlyWithASignatureAndNeverForProtectedUnits(t *testing.T) {
	executor, _ := stackExecutor(t)
	if result := runRequest(t, executor, bare(idA, "nginx.service", "autorestart")); result.OK {
		t.Fatal("turning it on needs a signature")
	}
	executor, _ = stackExecutor(t)
	if result := runRequest(t, executor, request(t, idA, "systemd", "ssh.service", "autorestart", soon())); result.OK {
		t.Fatal("a protected unit is never restarted automatically")
	}
	executor, _ = stackExecutor(t)
	if result := runRequest(t, executor, request(t, idA, "systemd", "nginx.service", "autorestart", soon())); !result.OK {
		t.Fatalf("result %#v", result)
	}
	if _, ok := listed(t, executor).Units["nginx.service"]; !ok {
		t.Fatal("the unit must be listed")
	}
	if result := runRequest(t, executor, bare(idB, "nginx.service", "manual")); !result.OK {
		t.Fatalf("turning it off needs no signature: %#v", result)
	}
	if _, ok := listed(t, executor).Units["nginx.service"]; ok {
		t.Fatal("the unit must be taken off the list")
	}
}

func allow(t *testing.T, executor Executor, unit string, heals ...time.Time) {
	t.Helper()
	if heals == nil {
		heals = []time.Time{}
	}
	if err := writeJSON(executor.StateDir, "autorestart.json", autoRestart{Units: map[string][]time.Time{unit: heals}}, 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestAHealRestartsOnlyAListedUnitThatIsDown(t *testing.T) {
	executor, run := stackExecutor(t)
	if result := runRequest(t, executor, bare(idA, "nginx.service", "heal")); result.OK || len(run.calls) != 0 {
		t.Fatalf("a unit that is not listed is left alone: %#v %q", result, run.calls)
	}
	executor, run = stackExecutor(t)
	allow(t, executor, "nginx.service")
	run.failing = map[string]string{"systemctl is-active -- nginx.service": "failed\n"}
	result := runRequest(t, executor, bare(idA, "nginx.service", "heal"))
	if !result.OK || !slices.Contains(run.calls, "systemctl restart -- nginx.service") {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	if heals := listed(t, executor).Units["nginx.service"]; len(heals) != 1 {
		t.Fatalf("the heal must be counted: %#v", heals)
	}
}

func TestAHealLeavesARunningUnitAlone(t *testing.T) {
	executor, run := stackExecutor(t)
	allow(t, executor, "nginx.service")
	run.respond = map[string]string{"systemctl is-active -- nginx.service": "active\n"}
	result := runRequest(t, executor, bare(idA, "nginx.service", "heal"))
	if !result.OK || !strings.Contains(result.Output, "already running") || slices.Contains(run.calls, "systemctl restart -- nginx.service") {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
}

func TestAHealLeavesAUnitStoppedOnPurpose(t *testing.T) {
	executor, run := stackExecutor(t)
	allow(t, executor, "nginx.service")
	if err := writeJSON(executor.StateDir, "stopped.json", []string{"nginx.service"}, 0o640); err != nil {
		t.Fatal(err)
	}
	run.failing = map[string]string{"systemctl is-active -- nginx.service": "inactive\n"}
	result := runRequest(t, executor, bare(idA, "nginx.service", "heal"))
	if result.OK || !strings.Contains(result.Output, "stopped on purpose") {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
}

func TestAHealGivesUpAfterThreeInAnHour(t *testing.T) {
	executor, run := stackExecutor(t)
	allow(t, executor, "nginx.service", executorNow.Add(-50*time.Minute), executorNow.Add(-20*time.Minute), executorNow.Add(-5*time.Minute))
	run.failing = map[string]string{"systemctl is-active -- nginx.service": "failed\n"}
	result := runRequest(t, executor, bare(idA, "nginx.service", "heal"))
	if result.OK || !strings.Contains(result.Output, "3 times") || slices.Contains(run.calls, "systemctl restart -- nginx.service") {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	executor, run = stackExecutor(t)
	allow(t, executor, "nginx.service", executorNow.Add(-90*time.Minute), executorNow.Add(-20*time.Minute), executorNow.Add(-5*time.Minute))
	run.failing = map[string]string{"systemctl is-active -- nginx.service": "failed\n"}
	if result := runRequest(t, executor, bare(idA, "nginx.service", "heal")); !result.OK {
		t.Fatalf("an hour-old heal no longer counts: %#v", result)
	}
}

func TestANewStackRefusesAMountThatLinksOutOfItsFolder(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := kumaDir(executor)
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "data", "escape")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	service := kumaService(dir)
	service["volumes"] = []any{map[string]any{"type": "bind", "source": link, "target": "/host"}}
	run.respond = map[string]string{composeCall(dir, "compose.yaml", "config --format json"): resolved(t, dir, service, nil)}
	result := runRequest(t, executor, createRequest(t, idA, "kuma", kumaText))
	if result.OK || !strings.Contains(result.Output, "mounts") {
		t.Fatalf("result %#v", result)
	}
	service["volumes"] = []any{map[string]any{"type": "bind", "source": filepath.Join(link, "not-yet"), "target": "/host"}}
	run.respond = map[string]string{composeCall(dir, "compose.yaml", "config --format json"): resolved(t, dir, service, nil)}
	result = runRequest(t, executor, createRequest(t, idB, "kuma", kumaText))
	if result.OK || !strings.Contains(result.Output, "mounts") {
		t.Fatalf("a folder that does not exist yet under the link: %#v", result)
	}
}
