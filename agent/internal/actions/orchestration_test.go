package actions

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/seal"
)

const psStates = "ps --all --format {{.Service}}\t{{.State}}\t{{.Health}}\t{{.ExitCode}}"

func composeRequest(t *testing.T, id, name, action string, change func(*Command)) Request {
	t.Helper()
	command := Command{ID: id, Kind: "compose", Name: name, Action: action}
	if change != nil {
		change(&command)
	}
	return signedRequest(t, command)
}

func sealFor(t *testing.T, executor Executor, value any) string {
	t.Helper()
	key, err := executor.sealKey()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := seal.Seal(seal.Public(key), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func kumaReady(t *testing.T, executor Executor, run *fakeRun, service map[string]any, extra map[string]any) string {
	t.Helper()
	dir := kumaDir(executor)
	run.respond = map[string]string{
		composeCall(dir, "compose.yaml", "config --format json"): resolved(t, dir, service, extra),
		composeCall(dir, "compose.krynodes.json", psStates):      "web\trunning\t\t0\n",
		composeCall(dir, "compose.yaml", psStates):               "web\trunning\t\t0\n",
	}
	return dir
}

func krynodesConfig(t *testing.T, dir string) map[string]any {
	t.Helper()
	var config map[string]any
	if err := readJSON(filepath.Join(dir, "compose.krynodes.json"), &config); err != nil {
		t.Fatal(err)
	}
	return config
}

func accessOf(t *testing.T, dir string) string {
	t.Helper()
	var meta struct {
		Access string `json:"access"`
	}
	if err := readJSON(filepath.Join(dir, "krynodes.json"), &meta); err != nil {
		t.Fatal(err)
	}
	return meta.Access
}

func TestAContainedStackGetsLimitsAndItsOwnBridge(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := kumaReady(t, executor, run, kumaService(kumaDir(executor)), nil)
	if result := runRequest(t, executor, createRequest(t, idA, "kuma", kumaText)); !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	config := krynodesConfig(t, dir)
	web := config["services"].(map[string]any)["web"].(map[string]any)
	if web["cpus"] != 1.0 || web["mem_limit"] != float64(1<<30) || web["pids_limit"] != 512.0 {
		t.Fatalf("limits %#v", web)
	}
	network := config["networks"].(map[string]any)["default"].(map[string]any)
	bridge := network["driver_opts"].(map[string]any)["com.docker.network.bridge.name"].(string)
	if !strings.HasPrefix(bridge, "krc") || len(bridge) > 15 || network["name"] != "kuma_default" {
		t.Fatalf("network %#v", network)
	}
	if accessOf(t, dir) != "contained" {
		t.Fatal("the stack must be recorded as contained")
	}
}

func TestAContainedStackAskingForMoreThanItsShareIsRefused(t *testing.T) {
	cases := map[string]map[string]any{
		"memory":    {"mem_limit": "4294967296"},
		"cpus":      {"cpus": 2.5},
		"processes": {"pids_limit": 4096.0},
		"deploy":    {"deploy": map[string]any{"resources": map[string]any{"limits": map[string]any{"memory": "2147483648"}}}},
	}
	for label, extra := range cases {
		t.Run(label, func(t *testing.T) {
			executor, run := stackExecutor(t)
			service := kumaService(kumaDir(executor))
			for key, value := range extra {
				service[key] = value
			}
			kumaReady(t, executor, run, service, nil)
			result := runRequest(t, executor, createRequest(t, idA, "kuma", kumaText))
			if result.OK || !strings.Contains(result.Output, "Full access") {
				t.Fatalf("result %#v", result)
			}
		})
	}
}

func TestAFullAccessStackRunsAsWritten(t *testing.T) {
	executor, run := stackExecutor(t)
	service := kumaService(kumaDir(executor))
	service["privileged"] = true
	service["network_mode"] = "host"
	dir := kumaReady(t, executor, run, service, nil)
	request := composeRequest(t, idA, "kuma", "create", func(c *Command) { c.Compose, c.Access = kumaText, "full" })
	if result := runRequest(t, executor, request); !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	if !slices.Contains(run.calls, composeCall(dir, "compose.yaml", "up -d")) || slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "compose.krynodes.json") }) {
		t.Fatalf("a Full access stack runs its own file: %q", run.calls)
	}
	if accessOf(t, dir) != "full" {
		t.Fatal("the stack must be recorded as Full access")
	}
}

func TestContainedStacksCannotReachTheServerOrTheCloudMetadata(t *testing.T) {
	executor, run := stackExecutor(t)
	kumaReady(t, executor, run, kumaService(kumaDir(executor)), nil)
	run.failing = map[string]string{
		"iptables -C DOCKER-USER -i krc+ -d 169.254.169.254 -j DROP": "",
		"iptables -C INPUT -i krc+ -j DROP":                          "",
	}
	if result := runRequest(t, executor, createRequest(t, idA, "kuma", kumaText)); !result.OK {
		t.Fatalf("result %#v", result)
	}
	for _, call := range []string{"iptables -I DOCKER-USER -i krc+ -d 169.254.169.254 -j DROP", "iptables -I INPUT -i krc+ -j DROP", "ip6tables -C INPUT -i krc+ -j DROP"} {
		if !slices.Contains(run.calls, call) {
			t.Fatalf("missing %q in %q", call, run.calls)
		}
	}
	if slices.Contains(run.calls, "ip6tables -I INPUT -i krc+ -j DROP") {
		t.Fatal("a rule that is already there is not added again")
	}
}

func TestAnOlderContainedStackIsCheckedAgainBeforeItIsRecreated(t *testing.T) {
	for _, verb := range []string{"deploy", "rollback"} {
		executor, run := stackExecutor(t)
		dir, stack := ownKuma(t, executor, "contained", kumaText)
		withStacks(&executor, stack)
		old := `{"name":"kuma","services":{"web":{"image":"louislam/uptime-kuma:1","logging":{"driver":"syslog","options":{"syslog-address":"tcp://127.0.0.1:6379"}}}}}`
		if err := os.WriteFile(filepath.Join(dir, "compose.krynodes.json"), []byte(old), 0o640); err != nil {
			t.Fatal(err)
		}
		result := runRequest(t, executor, composeRequest(t, idA, "kuma", verb, nil))
		if result.OK || !strings.Contains(result.Output, "syslog") || slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasSuffix(call, " up -d") || strings.HasSuffix(call, " pull") }) {
			t.Fatalf("%s: %#v %q", verb, result, run.calls)
		}
	}
}

func TestTheContainmentIsInPlaceBeforeDockerStartsAtBoot(t *testing.T) {
	executor, run := stackExecutor(t)
	kumaReady(t, executor, run, kumaService(kumaDir(executor)), nil)
	if result := runRequest(t, executor, createRequest(t, idA, "kuma", kumaText)); !result.OK {
		t.Fatalf("result %#v", result)
	}
	run.calls = nil
	run.failing = map[string]string{
		"iptables -C DOCKER-USER -i krc+ -d 169.254.169.254 -j DROP": "",
		"iptables -C INPUT -i krc+ -j DROP":                          "",
		"ip6tables -C INPUT -i krc+ -j DROP":                         "",
		"ip6tables -C DOCKER-USER -i krc+ -d fd00:ec2::254 -j DROP":  "",
	}
	executor.Contain(context.Background())
	chain := slices.Index(run.calls, "iptables -N DOCKER-USER")
	chain6 := slices.Index(run.calls, "ip6tables -N DOCKER-USER")
	for _, call := range []string{"iptables -I DOCKER-USER -i krc+ -d 169.254.169.254 -j DROP", "iptables -I INPUT -i krc+ -j DROP", "ip6tables -I INPUT -i krc+ -j DROP", "ip6tables -I DOCKER-USER -i krc+ -d fd00:ec2::254 -j DROP"} {
		if index := slices.Index(run.calls, call); index < 0 || index < chain || chain < 0 || index < chain6 || chain6 < 0 {
			t.Fatalf("missing %q after the chains in %q", call, run.calls)
		}
	}
	quiet, run := stackExecutor(t, listmonk)
	quiet.Contain(context.Background())
	if len(run.calls) != 0 {
		t.Fatalf("no rules without a Contained stack: %q", run.calls)
	}
}

func TestNoGuardRulesWithoutAContainedStack(t *testing.T) {
	executor, run := stackExecutor(t, listmonk)
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "iptables") }) {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestSecretsAreWrittenForTheServerOnly(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := kumaReady(t, executor, run, kumaService(kumaDir(executor)), nil)
	secrets := sealFor(t, executor, map[string]string{"SMTP_PASSWORD": "hunter 2$", "EMPTY": ""})
	request := composeRequest(t, idA, "kuma", "create", func(c *Command) { c.Compose, c.Secrets = kumaText, secrets })
	if result := runRequest(t, executor, request); !result.OK {
		t.Fatalf("result %#v", result)
	}
	env, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil || string(env) != "EMPTY=''\nSMTP_PASSWORD='hunter 2$'\n" {
		t.Fatalf("env %q %v", env, err)
	}
	if info, _ := os.Stat(filepath.Join(dir, ".env")); runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
}

func TestSecretsThatCannotBeWrittenSafelyAreRefused(t *testing.T) {
	other, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	elsewhere, err := seal.Seal(seal.Public(other), []byte(`{"A":"1"}`))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(Executor) string{
		"quote":     func(e Executor) string { return sealFor(t, e, map[string]string{"A": "it's"}) },
		"line":      func(e Executor) string { return sealFor(t, e, map[string]string{"A": "a\nb"}) },
		"name":      func(e Executor) string { return sealFor(t, e, map[string]string{"1A": "x"}) },
		"other key": func(Executor) string { return elsewhere },
	}
	for label, secrets := range cases {
		t.Run(label, func(t *testing.T) {
			executor, run := stackExecutor(t)
			kumaReady(t, executor, run, kumaService(kumaDir(executor)), nil)
			request := composeRequest(t, idA, "kuma", "create", func(c *Command) { c.Compose, c.Secrets = kumaText, secrets(executor) })
			if result := runRequest(t, executor, request); result.OK || slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, " up ") }) {
				t.Fatalf("result %#v calls %q", result, run.calls)
			}
		})
	}
}

func manifest(sizes ...int64) string {
	layers := make([]map[string]any, len(sizes))
	for i, size := range sizes {
		layers[i] = map[string]any{"size": size}
	}
	encoded, _ := json.Marshal(map[string]any{"SchemaV2Manifest": map[string]any{"layers": layers}})
	return string(encoded)
}

func TestAStackThatDoesNotFitOnTheDiskIsRefusedBeforePulling(t *testing.T) {
	for _, free := range []uint64{1 << 30, 10 << 30} {
		executor, run := stackExecutor(t)
		executor.Free = func(path string) (uint64, error) {
			if path != "/var/lib/docker" {
				t.Fatalf("free space of %q", path)
			}
			return free, nil
		}
		dir := kumaReady(t, executor, run, kumaService(kumaDir(executor)), nil)
		run.respond["docker info --format {{.DockerRootDir}}"] = "/var/lib/docker\n"
		run.respond["docker manifest inspect -v louislam/uptime-kuma:1"] = manifest(400_000_000, 200_000_000)
		run.failing = map[string]string{"docker image inspect --format {{.Id}} louislam/uptime-kuma:1": "No such image"}
		result := runRequest(t, executor, createRequest(t, idA, "kuma", kumaText))
		pulled := slices.Contains(run.calls, composeCall(dir, "compose.krynodes.json", "pull"))
		if free == 1<<30 && (result.OK || pulled || !strings.Contains(result.Output, "2.2 GB") || !strings.Contains(result.Output, "1.1 GB free")) {
			t.Fatalf("result %#v pulled %v", result, pulled)
		}
		if free == 10<<30 && (!result.OK || !pulled) {
			t.Fatalf("result %#v calls %q", result, run.calls)
		}
	}
}

func TestImageSizesComeFromTheServersPlatform(t *testing.T) {
	list, _ := json.Marshal([]map[string]any{
		{"Descriptor": map[string]any{"platform": map[string]any{"architecture": "s390x", "os": "linux"}}, "SchemaV2Manifest": map[string]any{"layers": []any{map[string]any{"size": 9}}}},
		{"Descriptor": map[string]any{"platform": map[string]any{"architecture": runtime.GOARCH, "os": "linux"}}, "OCIManifest": map[string]any{"layers": []any{map[string]any{"size": 5}, map[string]any{"size": 6}}}},
	})
	if size, ok := imageSize(list, runtime.GOARCH); !ok || size != 11 {
		t.Fatalf("size %d %v", size, ok)
	}
	if _, ok := imageSize([]byte("not json"), runtime.GOARCH); ok {
		t.Fatal("an unreadable manifest has no size")
	}
}

func ownKuma(t *testing.T, executor Executor, access, text string) (string, Stack) {
	t.Helper()
	dir := kumaDir(executor)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"compose.yaml":          text,
		"compose.krynodes.json": `{"name":"kuma"}`,
		"krynodes.json":         `{"access":"` + access + `"}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	file := "compose.krynodes.json"
	if access == "full" {
		file = "compose.yaml"
	}
	return dir, Stack{Project: "kuma", Directory: dir, Files: []string{filepath.Join(dir, file)}, Running: 1, Total: 1}
}

func withStacks(executor *Executor, stacks ...Stack) {
	executor.Collect = func(context.Context, []string) (Snapshot, error) {
		return Snapshot{Stacks: stacks, Compose: true, Docker: "ready"}, nil
	}
}

const kumaNext = "services:\n  web:\n    image: louislam/uptime-kuma:2\n"

func TestEditReplacesTheComposeFileAndKeepsThePreviousOne(t *testing.T) {
	executor, run := stackExecutor(t)
	dir, stack := ownKuma(t, executor, "contained", kumaText)
	withStacks(&executor, stack)
	kumaReady(t, executor, run, kumaService(kumaDir(executor)), nil)
	request := composeRequest(t, idA, "kuma", "edit", func(c *Command) { c.Compose = kumaNext })
	if result := runRequest(t, executor, request); !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	current, _ := os.ReadFile(filepath.Join(dir, "compose.yaml"))
	previous, _ := os.ReadFile(filepath.Join(dir, "compose.previous.yaml"))
	if string(current) != kumaNext || string(previous) != kumaText || accessOf(t, dir) != "contained" {
		t.Fatalf("current %q previous %q", current, previous)
	}
}

func TestAFailedEditPutsThePreviousComposeBack(t *testing.T) {
	executor, run := stackExecutor(t)
	dir, stack := ownKuma(t, executor, "contained", kumaText)
	withStacks(&executor, stack)
	kumaReady(t, executor, run, kumaService(kumaDir(executor)), nil)
	run.failing = map[string]string{composeCall(dir, "compose.krynodes.json", "pull"): "manifest unknown"}
	request := composeRequest(t, idA, "kuma", "edit", func(c *Command) { c.Compose = kumaNext })
	result := runRequest(t, executor, request)
	current, _ := os.ReadFile(filepath.Join(dir, "compose.yaml"))
	if result.OK || string(current) != kumaText || run.calls[len(run.calls)-1] == composeCall(dir, "compose.krynodes.json", "pull") {
		t.Fatalf("result %#v current %q calls %q", result, current, run.calls)
	}
	if !slices.Contains(run.calls, composeCall(dir, "compose.krynodes.json", "up -d")) {
		t.Fatalf("the previous file must run again: %q", run.calls)
	}
}

func TestEditIsOnlyForStacksKrynodesMade(t *testing.T) {
	executor, run := stackExecutor(t, listmonk)
	request := composeRequest(t, idA, "listmonk", "edit", func(c *Command) { c.Compose = kumaNext })
	if result := runRequest(t, executor, request); result.OK || !strings.Contains(result.Output, "Move into Krynodes") || len(run.calls) != 0 {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
}

func TestReadShowsTheComposeFileItsFilesAndPinnedImages(t *testing.T) {
	executor, run := stackExecutor(t)
	dir, stack := ownKuma(t, executor, "contained", kumaText)
	withStacks(&executor, stack)
	for name, body := range map[string]string{"config.toml": strings.Repeat("x", 100), ".env": "A='1'\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run.respond = map[string]string{
		"docker ps -a --no-trunc --filter label=com.docker.compose.project=kuma --format {{.ID}}": "abc\n",
		"docker inspect --format " + imageFormat + " abc":                                         "web\tlouislam/uptime-kuma:1\tsha256:111\n",
		"docker image inspect --format {{json .RepoDigests}} sha256:111":                          `["louislam/uptime-kuma@sha256:aaa"]`,
	}
	result := runRequest(t, executor, composeRequest(t, idA, "kuma", "read", nil))
	var read struct {
		Compose string            `json:"compose"`
		Access  string            `json:"access"`
		Files   []composeFile     `json:"files"`
		Images  map[string]string `json:"images"`
	}
	if !result.OK || json.Unmarshal([]byte(result.Output), &read) != nil {
		t.Fatalf("result %#v", result)
	}
	if read.Compose != kumaText || read.Access != "contained" || !reflect.DeepEqual(read.Files, []composeFile{{Name: "config.toml", Size: 100}}) || read.Images["web"] != "louislam/uptime-kuma:1@sha256:aaa" {
		t.Fatalf("read %#v", read)
	}
}

func TestExportSealsSecretsAndFilesForTheTarget(t *testing.T) {
	executor, _ := stackExecutor(t)
	dir, stack := ownKuma(t, executor, "contained", kumaText)
	withStacks(&executor, stack)
	for name, body := range map[string]string{"config.toml": "x=1", ".env": "SMTP_PASSWORD='hunter2'\n# note\nPLAIN=yes\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	target, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := composeRequest(t, idA, "kuma", "export", func(c *Command) { c.Args = map[string]string{"key": seal.Public(target)} })
	result := runRequest(t, executor, request)
	if !result.OK {
		t.Fatalf("result %#v", result)
	}
	opened, err := seal.Open(target, result.Output)
	if err != nil {
		t.Fatal(err)
	}
	var bundle moveBundle
	if err := json.Unmarshal(opened, &bundle); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bundle.Env, map[string]string{"SMTP_PASSWORD": "hunter2", "PLAIN": "yes"}) || string(bundle.Files["config.toml"]) != "x=1" {
		t.Fatalf("bundle %#v", bundle)
	}
}

func TestExportRefusesFilesBeyond32KB(t *testing.T) {
	executor, _ := stackExecutor(t)
	dir, stack := ownKuma(t, executor, "contained", kumaText)
	withStacks(&executor, stack)
	if err := os.WriteFile(filepath.Join(dir, "big.bin"), make([]byte, 33<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	target, _ := ecdh.P256().GenerateKey(rand.Reader)
	request := composeRequest(t, idA, "kuma", "export", func(c *Command) { c.Args = map[string]string{"key": seal.Public(target)} })
	if result := runRequest(t, executor, request); result.OK || !strings.Contains(result.Output, "32 KB") {
		t.Fatalf("result %#v", result)
	}
}

func TestANewStackFromAMoveWritesItsFilesAndSecrets(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := kumaReady(t, executor, run, kumaService(kumaDir(executor)), nil)
	request := composeRequest(t, idA, "kuma", "create", func(c *Command) {
		c.Compose, c.Secrets = kumaText, sealFor(t, executor, map[string]string{"A": "2", "B": "3"})
	})
	request.Attachment = sealFor(t, executor, moveBundle{Env: map[string]string{"A": "1", "C": "4"}, Files: map[string][]byte{"config.toml": []byte("x=1")}})
	if result := runRequest(t, executor, request); !result.OK {
		t.Fatalf("result %#v", result)
	}
	env, _ := os.ReadFile(filepath.Join(dir, ".env"))
	config, _ := os.ReadFile(filepath.Join(dir, "config.toml"))
	if string(env) != "A='2'\nB='3'\nC='4'\n" || string(config) != "x=1" {
		t.Fatalf("env %q config %q", env, config)
	}
}

func TestAMoveCannotWriteOutsideItsFolder(t *testing.T) {
	for _, name := range []string{"../escape", "a/b", ".env", "compose.yaml", "krynodes.json", ""} {
		executor, run := stackExecutor(t)
		kumaReady(t, executor, run, kumaService(kumaDir(executor)), nil)
		request := createRequest(t, idA, "kuma", kumaText)
		request.Attachment = sealFor(t, executor, moveBundle{Files: map[string][]byte{name: []byte("x")}})
		if result := runRequest(t, executor, request); result.OK {
			t.Fatalf("%q must be refused", name)
		}
	}
}

func TestAdoptCopiesAStackIntoKrynodesAndKeepsTheOldFolder(t *testing.T) {
	executor, run := stackExecutor(t)
	old := filepath.Join(t.TempDir(), "shop")
	if err := os.MkdirAll(filepath.Join(old, "data"), 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"compose.yaml": "services: {}\n", "data/orders.db": "orders"} {
		if err := os.WriteFile(filepath.Join(old, name), []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	withStacks(&executor, Stack{Project: "shop", Directory: old, Files: []string{filepath.Join(old, "compose.yaml")}, Running: 1, Total: 1})
	next := filepath.Join(executor.StateDir, "compose", "shop")
	call := func(dir, rest string) string {
		return "docker compose --project-name shop --project-directory " + dir + " -f " + filepath.Join(dir, "compose.yaml") + " " + rest
	}
	run.respond = map[string]string{call(next, psStates): "app\trunning\t\t0\n"}
	result := runRequest(t, executor, composeRequest(t, idA, "shop", "adopt", nil))
	if !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	down := slices.Index(run.calls, call(old, "down"))
	up := slices.Index(run.calls, call(next, "up -d"))
	if down < 0 || up < down {
		t.Fatalf("calls %q", run.calls)
	}
	copied, _ := os.ReadFile(filepath.Join(next, "data", "orders.db"))
	kept, _ := os.ReadFile(filepath.Join(old, "data", "orders.db"))
	if string(copied) != "orders" || string(kept) != "orders" || accessOf(t, next) != "full" {
		t.Fatalf("copied %q kept %q", copied, kept)
	}
}

func TestAnAdoptThatCannotCopyInTimeBringsTheOldStackBack(t *testing.T) {
	executor, run := stackExecutor(t)
	old := filepath.Join(t.TempDir(), "shop")
	if err := os.MkdirAll(old, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "compose.yaml"), []byte("services: {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	withStacks(&executor, Stack{Project: "shop", Directory: old, Files: []string{filepath.Join(old, "compose.yaml")}, Running: 1, Total: 1})
	saved := copyTimeout
	copyTimeout = 0
	t.Cleanup(func() { copyTimeout = saved })
	result := runRequest(t, executor, composeRequest(t, idA, "shop", "adopt", nil))
	if result.OK || !strings.Contains(result.Output, "took longer than") {
		t.Fatalf("result %#v", result)
	}
	if _, err := os.Lstat(filepath.Join(executor.StateDir, "compose", "shop")); err == nil {
		t.Fatal("the half-made copy is removed")
	}
	back := "docker compose --project-name shop --project-directory " + old + " -f " + filepath.Join(old, "compose.yaml") + " up -d"
	if run.calls[len(run.calls)-1] != back {
		t.Fatalf("the old stack starts again: %q", run.calls)
	}
}

func TestTheInventoryNamesAccessAndPublicPorts(t *testing.T) {
	executor, _ := stackExecutor(t)
	_, stack := ownKuma(t, executor, "contained", kumaText)
	stack.Public = []string{"3001/tcp"}
	withStacks(&executor, stack)
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	var inventory Inventory
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	if len(inventory.Stacks) != 1 || inventory.Stacks[0].Access != "contained" || !slices.Equal(inventory.Stacks[0].Public, []string{"3001/tcp"}) {
		t.Fatalf("stacks %#v", inventory.Stacks)
	}
}

func TestPublishedPortsOffTheServerAreCountedAsPublic(t *testing.T) {
	_, stacks := parseContainers("kuma-web-1\trunning\tkuma\t/srv/kuma\t/srv/kuma/compose.yaml\t2026-09-25 11:37:02 +0700 WIB\t0.0.0.0:3001->3001/tcp, :::3001->3001/tcp, 127.0.0.1:9000->9000/tcp, [::1]:9001->9001/tcp, 0.0.0.0:53->53/udp, 80/tcp\n")
	if len(stacks) != 1 || !slices.Equal(stacks[0].Public, []string{"3001/tcp", "53/udp"}) {
		t.Fatalf("stacks %#v", stacks)
	}
}

func TestFilesInAStackFolderAreListedWithoutKrynodesOwnFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"compose.yaml", "compose.krynodes.json", "compose.previous.yaml", "krynodes.json", ".env", "notes.md"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "data"), 0o750); err != nil {
		t.Fatal(err)
	}
	files, err := sideFiles(dir, []string{filepath.Join(dir, "compose.yaml")})
	if err != nil || !reflect.DeepEqual(files, []composeFile{{Name: "notes.md", Size: 1}}) {
		t.Fatalf("files %#v %v", files, err)
	}
	_ = base64.StdEncoding
}
