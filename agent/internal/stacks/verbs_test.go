package stacks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/docker"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

const (
	plainCompose = "services:\n  app:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n"
	plainConfig  = `{"name":"web","networks":{"default":{"name":"web_default","ipam":{}}},"services":{"app":{"command":null,"entrypoint":null,"image":"nginx:1.27","networks":{"default":null},"ports":[{"mode":"ingress","target":80,"published":"8080","protocol":"tcp"}]}}}`
	namesOf      = "project=web --format {{.Names}}"
	runningOf    = "status=running --format {{.Names}}"
	healthOf     = " ps --all --format"
	imagesOf     = "inspect --format {{index .Config.Labels"
)

var testNow = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)

type reply struct {
	has    string
	answer func() (string, error)
}

type fake struct {
	mu      sync.Mutex
	calls   []string
	config  string
	broken  int
	replies []reply
}

func newFake() *fake {
	f := &fake{config: plainConfig}
	f.on(healthOf, "app\trunning\t\t0\n")
	f.on("{{.Id}} {{.RestartCount}}", "id-1 0 2026-11-24T10:00:00Z\n")
	return f
}

func (f *fake) when(has string, answer func() (string, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replies = append(f.replies, reply{has, answer})
}

func (f *fake) on(has, output string) {
	f.when(has, func() (string, error) { return output, nil })
}

func (f *fake) fail(has, output string) {
	f.when(has, func() (string, error) { return output, errors.New("exit status 1") })
}

func (f *fake) run(_ context.Context, name string, args ...string) ([]byte, int, error) {
	call := strings.Join(append([]string{name}, args...), " ")
	f.mu.Lock()
	f.calls = append(f.calls, call)
	replies, config := slices.Clone(f.replies), f.config
	at := slices.Index(args, "-o")
	configured := at >= 0 && slices.Contains(args, "config")
	if configured && f.broken > 0 {
		f.broken, config = f.broken-1, ""
	}
	f.mu.Unlock()
	if configured {
		if config == "" {
			return []byte("yaml: line 3: did not find expected key"), 1, errors.New("exit status 1")
		}
		return nil, 0, os.WriteFile(args[at+1], []byte(config), 0o600)
	}
	for index := len(replies) - 1; index >= 0; index-- {
		if strings.Contains(call, replies[index].has) {
			output, err := replies[index].answer()
			if err != nil {
				return []byte(output), 1, err
			}
			return []byte(output), 0, nil
		}
	}
	return nil, 0, nil
}

func (f *fake) called(has string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, call := range f.calls {
		if strings.Contains(call, has) {
			count++
		}
	}
	return count
}

func (f *fake) first(has string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.IndexFunc(f.calls, func(call string) bool { return strings.Contains(call, has) })
}

func (f *fake) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

func quick(t *testing.T) {
	t.Helper()
	timeout, every, settle := healthTimeout, healthEvery, healthSettle
	t.Cleanup(func() { healthTimeout, healthEvery, healthSettle = timeout, every, settle })
	healthTimeout, healthEvery, healthSettle = 150*time.Millisecond, time.Millisecond, 0
}

var sealed = map[string]string{"sealed-1": "TOKEN=first\n", "sealed-2": "PASS=pa$$word\nKEY=a$b\n"}

func testEnv(t *testing.T, f *fake) Env {
	t.Helper()
	quick(t)
	useOwner(t)
	return Env{
		Run:    f.run,
		State:  t.TempDir(),
		Server: "server-1",
		Own:    func() string { return "10.88.37.2" },
		Unseal: func(text string) ([]byte, error) {
			if plain, ok := sealed[text]; ok {
				return []byte(plain), nil
			}
			return nil, errors.New("the sealed message is not for this server")
		},
		Checks: docker.NewChecks(),
		Now:    func() time.Time { return testNow },
	}
}

func command(kind, name, action string, args map[string]string) trust.Command {
	return trust.Command{V: 1, ID: "c-1", Kind: kind, Name: name, Action: action, Args: args}
}

func saving(access, network string) map[string]string {
	return map[string]string{"compose": plainCompose, "access": access, "network": network}
}

func (e Env) do(t *testing.T, cmd trust.Command) (string, error) {
	t.Helper()
	handle := Handlers(e)[cmd.Kind+"/"+cmd.Action]
	if handle == nil {
		t.Fatalf("no handler for %s/%s", cmd.Kind, cmd.Action)
	}
	return handle(context.Background(), cmd, func(string) {})
}

func managed(t *testing.T, e Env, args map[string]string) string {
	t.Helper()
	dir := e.folder("web")
	if err := Write(dir, command("stack", "web", "create", args), e.Unseal); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, runFile), []byte(plainConfig), 0o640); err != nil {
		t.Fatal(err)
	}
	return dir
}

func readText(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestArgsMatchTheSharedFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "protocol", "src", "fixtures", "stack-args.json"))
	if err != nil {
		t.Fatal(err)
	}
	type entry struct {
		Kind   string          `json:"kind"`
		Action string          `json:"action"`
		Args   json.RawMessage `json:"args"`
		Why    string          `json:"why"`
	}
	var fixture struct{ Valid, Invalid []entry }
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	read := func(one entry) (map[string]string, bool) {
		var args map[string]string
		if !bytes.HasPrefix(bytes.TrimSpace(one.Args), []byte("{")) || json.Unmarshal(one.Args, &args) != nil {
			return nil, false
		}
		return args, true
	}
	for _, one := range fixture.Valid {
		args, ok := read(one)
		if !ok || !ArgsValid(one.Kind, one.Action, args) {
			t.Errorf("refused the valid %s/%s %s", one.Kind, one.Action, one.Args)
		}
	}
	for _, one := range fixture.Invalid {
		if args, ok := read(one); ok && ArgsValid(one.Kind, one.Action, args) {
			t.Errorf("accepted %s", one.Why)
		}
	}
}

func TestCreateWritesFilesVetsThenStarts(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	f.when(namesOf, func() (string, error) {
		if f.called(" up -d") > 0 {
			return "proxy-1\n", nil
		}
		return "", nil
	})
	args := saving("contained", "8080")
	args["env"], args["title"], args["names"] = "sealed-1", "Web", "app=proxy-1"
	message, err := e.do(t, command("stack", "web", "create", args))
	if err != nil {
		t.Fatal(err)
	}
	if message != "server-1 runs web: 1 of 1 containers healthy." {
		t.Fatalf("message %q", message)
	}
	dir := e.folder("web")
	if readText(t, filepath.Join(dir, "compose.yaml")) != plainCompose || readText(t, filepath.Join(dir, ".env")) != "TOKEN=first\n" {
		t.Fatal("the files are not what was signed")
	}
	meta, err := ReadMeta(dir)
	if err != nil || meta.Access != "contained" || meta.Title != "Web" || !slices.Equal(meta.Network, []int{8080}) {
		t.Fatalf("meta %+v %v", meta, err)
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(readText(t, filepath.Join(dir, runFile))), &config); err != nil {
		t.Fatal(err)
	}
	app := appOf(config)
	if app["container_name"] != "proxy-1" || app["cpus"] == nil {
		t.Fatalf("the run file was not named or fitted: %v", app)
	}
	var bound []string
	for _, port := range app["ports"].([]any) {
		bound = append(bound, port.(map[string]any)["host_ip"].(string))
	}
	if !slices.Equal(bound, []string{"127.0.0.1", "10.88.37.2"}) {
		t.Fatalf("ports bound on %v", bound)
	}
	normalised, pulled, started, waited := f.first("setpriv"), f.first(" pull"), f.first(" up -d"), f.first(healthOf)
	if normalised < 0 || normalised > pulled || pulled > started || started > waited {
		t.Fatalf("order normalise %d pull %d up %d wait %d", normalised, pulled, started, waited)
	}
	upCall := f.calls[started]
	if !strings.HasPrefix(upCall, "env -i "+searchPath+" docker compose --project-name web --project-directory "+dir+" -f "+filepath.Join(dir, runFile)) {
		t.Fatalf("up ran %q", upCall)
	}
	if f.called("-f "+filepath.Join(dir, "compose.yaml")) > 0 {
		t.Fatal("the raw compose file ran")
	}
	if f.called("iptables -w -C KRY-CONTAINED") == 0 {
		t.Fatal("the Contained guard was not checked before the start")
	}
}

func TestAnEnvValueWithADollarSurvives(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	f.config = strings.Replace(plainConfig, `"image":"nginx:1.27"`, `"environment":{"PASS":"pa$$$$word","KEY":"a$$b"},"image":"nginx:1.27"`, 1)
	var seen string
	original := f.run
	e.Run = func(ctx context.Context, name string, args ...string) ([]byte, int, error) {
		if name == "setpriv" {
			at := slices.Index(args, "--project-directory")
			body, _ := os.ReadFile(filepath.Join(args[at+1], ".env"))
			seen = string(body)
		}
		return original(ctx, name, args...)
	}
	args := saving("contained", "")
	args["env"] = "sealed-2"
	if _, err := e.do(t, command("stack", "web", "create", args)); err != nil {
		t.Fatal(err)
	}
	dir := e.folder("web")
	if written := readText(t, filepath.Join(dir, ".env")); written != sealed["sealed-2"] || seen != sealed["sealed-2"] {
		t.Fatalf("written %q, compose read %q", written, seen)
	}
	if run := readText(t, filepath.Join(dir, runFile)); !strings.Contains(run, `"PASS":"pa$$$$word"`) || !strings.Contains(run, `"KEY":"a$$b"`) {
		t.Fatalf("the run file lost a dollar: %s", run)
	}
}

func TestAContainedEnvLeavesComposeSettingsAlone(t *testing.T) {
	sealed["sealed-3"] = "TZ=UTC\nexport\tCOMPOSE_FILE=/etc/other.yaml\n"
	t.Cleanup(func() { delete(sealed, "sealed-3") })
	for access, want := range map[string]string{"contained": "the .env sets COMPOSE_FILE; a Contained stack leaves COMPOSE_ and DOCKER_ settings alone", "full": ""} {
		f := newFake()
		e := testEnv(t, f)
		args := saving(access, "")
		args["env"] = "sealed-3"
		_, err := e.do(t, command("stack", "web", "create", args))
		if fmt.Sprint(err) != want && !(want == "" && err == nil) {
			t.Fatalf("%s: %v", access, err)
		}
		if want != "" && (f.called(" up ") > 0 || f.called("setpriv") > 0) {
			t.Fatalf("%s: compose ran", access)
		}
	}
}

func TestCreateRefusesAnExistingOrRemovedName(t *testing.T) {
	for _, case_ := range []struct {
		why, want string
		set       func(e Env, f *fake)
	}{
		{"running", "a stack named web already runs on server-1", func(e Env, f *fake) { f.on(namesOf, "web-app-1\n") }},
		{"removed", "a stack named web waits in Removed on server-1; restore it or delete it permanently first", func(e Env, f *fake) {
			os.MkdirAll(e.folder("web"), 0o750)
			e.changeBin(func(bin map[string]removal) { bin["web"] = removal{RemovedAt: testNow} })
		}},
		{"leftover", "files left from an earlier web are still on server-1; delete them permanently first", func(e Env, f *fake) {
			os.MkdirAll(e.folder("web"), 0o750)
		}},
		{"volumes", "files left from an earlier web are still on server-1; delete them permanently first", func(e Env, f *fake) {
			f.on("volume ls -q --filter label=com.docker.compose.project=web", "web_data\n")
		}},
	} {
		f := newFake()
		e := testEnv(t, f)
		case_.set(e, f)
		_, err := e.do(t, command("stack", "web", "create", saving("contained", "")))
		if err == nil || err.Error() != case_.want {
			t.Fatalf("%s: %v", case_.why, err)
		}
		if f.called(" pull") > 0 || f.called(" up ") > 0 || f.called("volume rm") > 0 {
			t.Fatalf("%s: something ran", case_.why)
		}
		if _, err := os.Stat(filepath.Join(e.folder("web"), "compose.yaml")); err == nil {
			t.Fatalf("%s: a compose file was written", case_.why)
		}
	}
}

func imagesAfter(f *fake) {
	f.when(imagesOf, func() (string, error) {
		if f.called(" pull") > 0 && f.called("docker tag sha256:old nginx:1.27") == 0 {
			return "app\tnginx:1.27\tsha256:new\n", nil
		}
		return "app\tnginx:1.27\tsha256:old\n", nil
	})
}

func TestAFailedDeployGoesBackToThePreviousImages(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	dir := managed(t, e, saving("full", ""))
	f.on(namesOf, "web-app-1\n")
	f.on(runningOf, "web-app-1\n")
	imagesAfter(f)
	f.when(healthOf, func() (string, error) {
		if f.called("docker tag sha256:old nginx:1.27") > 0 {
			return "app\trunning\thealthy\t0\n", nil
		}
		return "app\trunning\tunhealthy\t0\n", nil
	})
	_, err := e.do(t, command("stack", "web", "deploy", nil))
	if err == nil || err.Error() != "the health check failed: app running (unhealthy); server-1 went back to the previous images of web, and Rollback is still there" {
		t.Fatalf("err %v", err)
	}
	if f.called(" up -d") != 2 || f.called(" up -d --remove-orphans --pull never") != 1 || f.first("docker tag sha256:old nginx:1.27") < f.first(" up -d") {
		t.Fatal("the stack did not start again on the old images")
	}
	kept, err := load[record](e.recordPath("web"))
	if err != nil || kept.Failed || len(kept.Previous) != 1 || kept.Previous[0].ID != "sha256:old" {
		t.Fatalf("record %+v %v", kept, err)
	}
	if !e.Meta(context.Background()).Stack("web", dir).Rollback {
		t.Fatal("Rollback is gone")
	}
}

func TestADeployOfAStoppedStackStaysStopped(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	managed(t, e, saving("full", ""))
	f.on(namesOf, "web-app-1\n")
	imagesAfter(f)
	message, err := e.do(t, command("stack", "web", "deploy", nil))
	if err != nil || message != "server-1 has the new images of web; it stays stopped." {
		t.Fatalf("message %q err %v", message, err)
	}
	if f.called(" up --no-start --remove-orphans") != 1 || f.called(" up -d") > 0 || f.called(healthOf) > 0 {
		t.Fatal("the stopped stack was started")
	}
	if kept, _ := load[record](e.recordPath("web")); len(kept.Previous) != 1 || kept.Previous[0].ID != "sha256:old" {
		t.Fatalf("record %+v", kept)
	}
}

func TestRollbackIsOneStep(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	dir := managed(t, e, saving("full", ""))
	f.on(namesOf, "web-app-1\n")
	if err := store(e.recordPath("web"), record{Previous: []pinned{{Service: "app", Reference: "nginx:1.27", ID: "sha256:old"}}}); err != nil {
		t.Fatal(err)
	}
	message, err := e.do(t, command("stack", "web", "rollback", nil))
	if err != nil || message != "server-1 runs web: 1 of 1 containers healthy." {
		t.Fatalf("message %q err %v", message, err)
	}
	if f.first("config --format json") < 0 || f.first("config --format json") > f.first("docker tag sha256:old nginx:1.27") || f.first("docker tag") > f.first(" up -d") || f.called(" up -d --remove-orphans --pull never") != 1 {
		t.Fatal("rollback did not vet, tag, then start")
	}
	if e.Meta(context.Background()).Stack("web", dir).Rollback {
		t.Fatal("Rollback is still offered")
	}
	if _, err := e.do(t, command("stack", "web", "rollback", nil)); err == nil || err.Error() != "web has nothing to roll back to" {
		t.Fatalf("second rollback %v", err)
	}
}

func TestEditKeepsTheEnvWhenNoneIsSent(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	args := saving("full", "")
	args["env"] = "sealed-1"
	dir := managed(t, e, args)
	edited := strings.Replace(plainCompose, "nginx:1.27", "nginx:1.28", 1)
	changed := saving("full", "")
	changed["compose"] = edited
	if _, err := e.do(t, command("stack", "web", "edit", changed)); err != nil {
		t.Fatal(err)
	}
	if readText(t, filepath.Join(dir, ".env")) != "TOKEN=first\n" || readText(t, filepath.Join(dir, "compose.yaml")) != edited {
		t.Fatal("the edit changed the .env or lost the compose file")
	}
	if f.called("--env-file "+filepath.Join(dir, ".env")+" config") != 1 {
		t.Fatal("compose did not read the kept .env")
	}
	broken := saving("full", "")
	broken["compose"], broken["env"] = "services: [\n", "sealed-2"
	for _, case_ := range []struct {
		running string
		broken  int
		ends    string
		ups     int
	}{
		{"web-app-1\n", 1, "; the previous file runs again", 1},
		{"", 1, "; the previous file is back", 0},
		{"web-app-1\n", 2, "so it was not started: compose could not read the file: yaml: line 3: did not find expected key", 0},
	} {
		f.reset()
		f.on(runningOf, case_.running)
		f.broken = case_.broken
		_, err := e.do(t, command("stack", "web", "edit", broken))
		if err == nil || !strings.HasSuffix(err.Error(), case_.ends) {
			t.Fatalf("err %v", err)
		}
		if readText(t, filepath.Join(dir, ".env")) != "TOKEN=first\n" || readText(t, filepath.Join(dir, "compose.yaml")) != edited {
			t.Fatal("a failed edit did not put the files back")
		}
		if f.called(" up -d --remove-orphans --pull never") != case_.ups || f.called(" up ") != case_.ups {
			t.Fatalf("%q: calls %q", case_.ends, f.calls)
		}
	}
}

func TestAStackThatNoLongerVetsIsNotRun(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	dir := managed(t, e, saving("contained", ""))
	store(e.recordPath("web"), record{Previous: []pinned{{Service: "app", Reference: "nginx:1.27", ID: "sha256:old"}}})
	f.config = strings.Replace(plainConfig, `"image":"nginx:1.27"`, `"image":"nginx:1.27","privileged":true`, 1)
	f.on(namesOf, "web-app-1\n")
	f.on(runningOf, "web-app-1\n")
	for _, action := range []string{"start", "restart", "deploy", "rollback"} {
		if _, err := e.do(t, command("stack", "web", action, nil)); err == nil {
			t.Fatalf("%s ran a stack that no longer vets", action)
		}
	}
	if f.called("setpriv") != 4 || f.called("-f "+filepath.Join(dir, runFile)) != 0 || f.called("docker tag") != 0 {
		t.Fatalf("calls %q", f.calls)
	}
}

func TestRemoveMovesAsideAndRestoreBringsBack(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	dir := managed(t, e, saving("full", ""))
	f.on(namesOf, "web-app-1\n")
	message, err := e.do(t, command("stack", "web", "remove", nil))
	if err != nil || message != "server-1 moved web to Removed; it is deleted for good after 7 days." {
		t.Fatalf("message %q err %v", message, err)
	}
	if f.called(" down --remove-orphans") != 1 || f.called(" down -v") > 0 {
		t.Fatal("remove did not stop the stack and keep its volumes")
	}
	if _, err := os.Stat(filepath.Join(dir, "compose.yaml")); err != nil {
		t.Fatal("remove deleted the files")
	}
	if listed := e.Meta(context.Background()).Removed(); len(listed) != 1 || listed[0].Project != "web" || listed[0].RemovedAt != "2026-11-24T10:00:00Z" {
		t.Fatalf("removed %+v", listed)
	}
	if _, err := e.do(t, command("stack", "web", "deploy", nil)); err == nil || err.Error() != "web is in Removed on server-1; restore it first" {
		t.Fatalf("deploy of a removed stack: %v", err)
	}
	f.reset()
	message, err = e.do(t, command("stack", "web", "restore", nil))
	if err != nil || message != "server-1 runs web: 1 of 1 containers healthy." {
		t.Fatalf("message %q err %v", message, err)
	}
	if f.first("config --format json") > f.first(" up -d") || e.removed("web") {
		t.Fatal("restore did not vet and start, or left it in Removed")
	}
}

func TestPurgeDeletesFilesAndVolumes(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	dir := managed(t, e, saving("full", ""))
	store(e.recordPath("web"), record{})
	f.on(namesOf, "web-app-1\n")
	f.on("volume ls -q --filter label=com.docker.compose.project=web", "web_data\nweb_cache\n")
	message, err := e.do(t, command("stack", "web", "purge", nil))
	if err != nil || message != "server-1 deleted web and its data for good." {
		t.Fatalf("message %q err %v", message, err)
	}
	if f.called(" down -v --remove-orphans") != 1 || f.called("docker volume rm web_data web_cache") != 1 {
		t.Fatal("the containers or volumes stayed")
	}
	for _, path := range []string{dir, e.recordPath("web")} {
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("%s stayed", path)
		}
	}
	f.on(namesOf, "")
	managed(t, e, saving("full", ""))
	e.changeBin(func(bin map[string]removal) { bin["web"] = removal{RemovedAt: testNow} })
	if _, err := e.do(t, command("stack", "web", "purge", nil)); err != nil || e.removed("web") {
		t.Fatalf("purge of a removed stack: %v", err)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("the removed stack's files stayed")
	}
	f.on("volume ls -q --filter label=com.docker.compose.project=web", "web_data\n")
	f.reset()
	if _, err := e.do(t, command("stack", "web", "purge", nil)); err != nil || f.called("docker volume rm web_data") != 1 {
		t.Fatalf("purge of leftover volumes: %v %q", err, f.calls)
	}
	f.on("volume ls -q --filter label=com.docker.compose.project=web", "")
	if _, err := e.do(t, command("stack", "web", "purge", nil)); err == nil || err.Error() != "web is not on server-1" {
		t.Fatalf("purge of nothing: %v", err)
	}
}

func TestRemovedStacksOlderThanSevenDaysAreSwept(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	for name, age := range map[string]time.Duration{"old": 8 * 24 * time.Hour, "new": 24 * time.Hour} {
		os.MkdirAll(e.folder(name), 0o750)
		e.changeBin(func(bin map[string]removal) { bin[name] = removal{RemovedAt: testNow.Add(-age)} })
	}
	outside := filepath.Join(e.State, "outside")
	os.MkdirAll(outside, 0o750)
	e.changeBin(func(bin map[string]removal) {
		bin["../outside"] = removal{RemovedAt: testNow.Add(-30 * 24 * time.Hour)}
	})
	f.on("timedatectl", "no\n")
	e.sweep(context.Background())
	if listed := e.Meta(context.Background()).Removed(); len(listed) != 2 || listed[0].Project != "new" || listed[1].Project != "old" {
		t.Fatalf("swept with an unsynced clock: %+v", listed)
	}
	f.on("timedatectl", "yes\n")
	f.reset()
	e.Meta(context.Background()).Removed()
	if len(f.calls) != 0 {
		t.Fatalf("the inventory hook ran %q", f.calls)
	}
	e.sweep(context.Background())
	listed := e.Meta(context.Background()).Removed()
	if len(listed) != 1 || listed[0].Project != "new" {
		t.Fatalf("listed %+v", listed)
	}
	if _, err := os.Stat(outside); err != nil || f.called("project=../outside") != 0 {
		t.Fatal("a name that is not a stack's reached a path")
	}
	if _, err := os.Stat(e.folder("old")); err == nil || f.called("volume ls -q --filter label=com.docker.compose.project=old") != 1 {
		t.Fatal("the old stack was not deleted")
	}
	if _, err := os.Stat(e.folder("new")); err != nil {
		t.Fatal("the new stack was deleted")
	}
}

func TestAdoptTakesAStackFromItsLabels(t *testing.T) {
	privileged := strings.Replace(plainConfig, `"image":"nginx:1.27"`, `"image":"nginx:1.27","privileged":true`, 1)
	for _, case_ := range []struct {
		config, access string
	}{
		{plainConfig, "contained"},
		{privileged, "full"},
	} {
		f := newFake()
		e := testEnv(t, f)
		f.config = case_.config
		from := foreignStack(t, f)
		message, err := e.do(t, command("stack", "web", "adopt", map[string]string{"access": case_.access}))
		if err != nil || message != "server-1 runs web: 1 of 1 containers healthy. Krynodes manages it now, with "+strings.ToUpper(case_.access[:1])+case_.access[1:]+" access." {
			t.Fatalf("message %q err %v", message, err)
		}
		dir := e.folder("web")
		if readText(t, filepath.Join(dir, "compose.yaml")) != plainCompose || readText(t, filepath.Join(dir, ".env")) != "TOKEN=old\n" {
			t.Fatal("the files were not taken in")
		}
		described := e.Meta(context.Background()).Stack("web", from)
		if !described.Own || *described.Access != case_.access {
			t.Fatalf("described %+v", described)
		}
		if !strings.Contains(f.calls[f.first(" up -d")], "--project-directory "+from+" -f "+filepath.Join(dir, runFile)) {
			t.Fatal("the adopted stack did not run from its vetted file in its own folder")
		}
		if _, err := e.do(t, command("stack", "web", "adopt", map[string]string{"access": case_.access})); err == nil || err.Error() != "Krynodes already has a stack named web on server-1" {
			t.Fatalf("adopting twice: %v", err)
		}
	}
	f := newFake()
	e := testEnv(t, f)
	f.config = privileged
	foreignStack(t, f)
	if _, err := e.do(t, command("stack", "web", "adopt", map[string]string{"access": "contained"})); err == nil || !strings.Contains(err.Error(), "privileged") {
		t.Fatalf("a privileged stack adopted as Contained: %v", err)
	}
	if _, err := os.Stat(e.folder("web")); err == nil || f.called(" up ") > 0 {
		t.Fatal("a refused adopt left files or ran")
	}
	f.reset()
	if _, err := e.do(t, command("stack", "web", "adopt", nil)); err == nil || f.called("ps -a") > 0 {
		t.Fatalf("an adopt with no signed access: %v", err)
	}
	f.on(homeFormat, t.TempDir()+"\n")
	if _, err := e.do(t, command("stack", "web", "adopt", map[string]string{"access": "full"})); err == nil || !strings.HasSuffix(err.Error(), "holds no compose file Krynodes can adopt") {
		t.Fatalf("a folder without a compose file: %v", err)
	}
	f.on(homeFormat, "/srv/a\n/srv/b\n")
	if _, err := e.do(t, command("stack", "web", "adopt", map[string]string{"access": "full"})); err == nil || err.Error() != "the containers of web do not share one folder" {
		t.Fatalf("two folders: %v", err)
	}
}

func foreignStack(t *testing.T, f *fake) string {
	t.Helper()
	from := t.TempDir()
	os.WriteFile(filepath.Join(from, "docker-compose.yml"), []byte(plainCompose), 0o644)
	os.WriteFile(filepath.Join(from, ".env"), []byte("TOKEN=old\n"), 0o600)
	f.on(homeFormat, from+"\n"+from+"\n")
	f.on(namesOf, "web-app-1\n")
	return from
}

func TestAFailedAdoptNeverRunsTheFoundFile(t *testing.T) {
	for _, case_ := range []struct {
		left, ends string
		starts     int
	}{
		{"id-1\tweb-app-1\n", "; its containers run again as they were, from %s.", 1},
		{"", "; Start it again from %s.", 0},
	} {
		f := newFake()
		e := testEnv(t, f)
		from := foreignStack(t, f)
		f.when("{{.ID}}\t{{.Names}}", func() (string, error) {
			if f.called(" up -d") > 0 {
				return case_.left, nil
			}
			return "id-1\tweb-app-1\n", nil
		})
		f.fail(" up -d", "Error response from daemon: port is already allocated")
		_, err := e.do(t, command("stack", "web", "adopt", map[string]string{"access": "contained"}))
		if err == nil || !strings.HasSuffix(err.Error(), fmt.Sprintf(case_.ends, from)) {
			t.Fatalf("err %v", err)
		}
		if f.called(filepath.Join(from, "docker-compose.yml")) != 0 || f.called(" up ") != 1 || f.called("docker start -- id-1") != case_.starts {
			t.Fatalf("calls %q", f.calls)
		}
		if _, err := os.Stat(e.folder("web")); err == nil {
			t.Fatal("a failed adopt kept the stack")
		}
	}
}

func TestLogsAreCutFromTheStart(t *testing.T) {
	var text strings.Builder
	for index := range 4000 {
		fmt.Fprintf(&text, "%s line %04d\n", strings.Repeat("x", 20), index)
	}
	got := cut([]byte(text.String()))
	if len(got) > maxOutput || !strings.HasPrefix(got, "… earlier lines cut\n") || !strings.HasSuffix(got, "line 3999\n") {
		t.Fatalf("cut to %d bytes, starting %q", len(got), got[:40])
	}
	if first := strings.Split(got, "\n")[1]; !strings.HasPrefix(first, strings.Repeat("x", 20)+" line ") {
		t.Fatalf("the first kept line is cut: %q", first)
	}
	if short := cut([]byte("a\x1b[31mb\n")); short != "a[31mb\n" {
		t.Fatalf("short %q", short)
	}
}

func TestEveryManagedFolderIsOfferedToTheInventory(t *testing.T) {
	e := testEnv(t, newFake())
	dir := managed(t, e, saving("contained", ""))
	for _, name := range []string{"Bad", "bare", "gone"} {
		if err := os.MkdirAll(e.folder(name), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeMeta(e.folder("gone"), Meta{Access: "full", Network: []int{}}); err != nil {
		t.Fatal(err)
	}
	if err := e.changeBin(func(bin map[string]removal) { bin["gone"] = removal{RemovedAt: e.Now().UTC()} }); err != nil {
		t.Fatal(err)
	}
	listed := e.Meta(context.Background()).Managed()
	if len(listed) != 1 || listed["web"] != dir {
		t.Fatalf("managed %v", listed)
	}
	if !e.Meta(context.Background()).Stack("web", listed["web"]).Own {
		t.Fatal("a folder with no containers lost its meta")
	}
}
