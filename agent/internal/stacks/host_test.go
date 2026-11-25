package stacks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/daemon"
	"github.com/Kleavox/krynodes/agent/internal/docker"
	"github.com/Kleavox/krynodes/agent/internal/platform"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

const (
	testNode   = "22222222-2222-4222-8222-222222222222"
	testOrigin = "https://kry.example.test"
	testRPID   = "kry.example.test"
)

type wire struct {
	mu   sync.Mutex
	sent []any
	got  chan reporter.Result
}

func (w *wire) send(message any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sent = append(w.sent, message)
	if result, ok := message.(reporter.Result); ok {
		w.got <- result
	}
	return nil
}

func digestOf(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func signed(t *testing.T, cmd trust.Command) (trust.Trust, reporter.Command) {
	t.Helper()
	b64 := base64.RawURLEncoding
	passkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	session, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&passkey.PublicKey)
	sessionKey, _ := x509.MarshalPKIXPublicKey(&session.PublicKey)
	trusted := trust.Trust{V: 1, NodeID: testNode, Origin: testOrigin, RPID: testRPID, Version: 1,
		Keys: []trust.TrustKey{{ID: "cred-1", Name: "Laptop", Alg: -7, PublicKey: b64.EncodeToString(der)}},
		Core: []string{"cred-1"}, Access: []string{"cred-1"}, RequireUV: true}
	now := time.Now()
	grant, _ := json.Marshal(map[string]any{"v": 1, "rpId": testRPID, "sessionKey": b64.EncodeToString(sessionKey),
		"issuedAt": now.Add(-time.Minute).Format(time.RFC3339Nano), "expiresAt": now.Add(14 * time.Minute).Format(time.RFC3339Nano), "nonce": "bm9uY2U"})
	client, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": b64.EncodeToString(digestOf(grant)), "origin": testOrigin, "crossOrigin": false})
	authData := append(digestOf([]byte(testRPID)), 0x05, 0, 0, 0, 7)
	assertion, err := ecdsa.SignASN1(rand.Reader, passkey, digestOf(append(slices.Clone(authData), digestOf(client)...)))
	if err != nil {
		t.Fatal(err)
	}
	cmd.NodeID, cmd.IssuedAt, cmd.ExpiresAt = testNode, now.Format(time.RFC3339Nano), now.Add(5*time.Minute).Format(time.RFC3339Nano)
	body, _ := json.Marshal(cmd)
	r, s, err := ecdsa.Sign(rand.Reader, session, digestOf(body))
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	wrapped, _ := json.Marshal(trust.SignedCommand{
		Grant:     trust.SignedGrant{Grant: b64.EncodeToString(grant), Assertion: trust.Assertion{CredentialID: "cred-1", AuthenticatorData: b64.EncodeToString(authData), ClientDataJSON: b64.EncodeToString(client), Signature: b64.EncodeToString(assertion)}},
		Command:   b64.EncodeToString(body),
		Signature: b64.EncodeToString(signature),
	})
	return trusted, reporter.Command{Type: "command", ID: cmd.ID, Kind: cmd.Kind, Name: cmd.Name, Action: cmd.Action, Signed: string(wrapped)}
}

func through(t *testing.T, e Env, trusted trust.Trust, message reporter.Command) reporter.Result {
	t.Helper()
	w := &wire{got: make(chan reporter.Result, 1)}
	d := &daemon.Daemon{State: t.TempDir(), Trust: func() trust.Trust { return trusted }, Send: w.send, Now: time.Now, Handlers: Handlers(e)}
	d.Handle(context.Background(), message)
	select {
	case result := <-w.got:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("no result")
	}
	return reporter.Result{}
}

func TestAnUnsignedStackCommandIsRefused(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	managed(t, e, saving("full", ""))
	trusted, message := signed(t, command("stack", "web", "logs", map[string]string{"lines": "5"}))
	unsigned := message
	unsigned.Signed = ""
	if result := through(t, e, trusted, unsigned); result.OK || result.Message != "the command is not signed" || result.Output != "" {
		t.Fatalf("result %+v", result)
	}
	if len(f.calls) != 0 {
		t.Fatalf("an unsigned command ran %q", f.calls)
	}
	f.on(" logs --tail 5", "2026-11-24T10:00:00Z app-1 ready\n")
	result := through(t, e, trusted, message)
	if !result.OK || result.Message != "The last 5 lines of web." || result.Output != "2026-11-24T10:00:00Z app-1 ready\n" {
		t.Fatalf("signed result %+v", result)
	}
}

func TestStackLogsPassTheServiceAfterTheFlags(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	managed(t, e, saving("full", ""))
	trusted, message := signed(t, command("stack", "web", "logs", map[string]string{"lines": "200", "service": "-app"}))
	if result := through(t, e, trusted, message); !result.OK {
		t.Fatalf("result %+v", result)
	}
	if f.called(" logs --tail 200 --timestamps --no-color -- -app") != 1 {
		t.Fatalf("calls %q", f.calls)
	}
	trusted, message = signed(t, command("container", "web-app-1", "logs", map[string]string{"lines": "10"}))
	if result := through(t, e, trusted, message); !result.OK || f.called("docker logs --tail 10 --timestamps -- web-app-1") != 1 {
		t.Fatalf("container logs %+v", result)
	}
}

func TestProtectedUnitsAndContainersAreRefused(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	for _, unit := range []string{"ssh.service", "docker.service", "krynodes.service", "systemd-journald.service"} {
		if _, err := e.do(t, command("unit", unit, "stop", nil)); err == nil || err.Error() != unit+" is protected; Krynodes leaves it alone" {
			t.Fatalf("%s: %v", unit, err)
		}
	}
	if _, err := e.do(t, command("container", "krynodes-tunnel", "restart", nil)); err == nil || !strings.Contains(err.Error(), "is protected") {
		t.Fatalf("tunnel: %v", err)
	}
	for _, refused := range []trust.Command{
		command("unit", "ssh", "stop", nil),
		command("stack", "../etc", "remove", nil),
		command("container", "web-1", "start", map[string]string{"lines": "1"}),
	} {
		if _, err := e.do(t, refused); err == nil {
			t.Fatalf("%s %s ran", refused.Kind, refused.Name)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("a refused command ran %q", f.calls)
	}
	message, err := e.do(t, command("unit", "cron.service", "restart", nil))
	if err != nil || message != "server-1 restarted cron.service." || f.called("systemctl restart -- cron.service") != 1 {
		t.Fatalf("message %q err %v", message, err)
	}
	f.on("{{.State.Paused}}", "true\n")
	message, err = e.do(t, command("container", "web-1", "start", nil))
	if err != nil || message != "server-1 started web-1." || f.called("docker unpause -- web-1") != 1 {
		t.Fatalf("message %q err %v", message, err)
	}
}

func osRelease(t *testing.T, body string, dnf bool) string {
	t.Helper()
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc", "os-release"), []byte(body), 0o644)
	if dnf {
		os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755)
		os.WriteFile(filepath.Join(root, "usr", "bin", "dnf"), nil, 0o755)
	}
	return root
}

func TestInstallDockerUsesThePlatform(t *testing.T) {
	packages := "docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
	for _, case_ := range []struct {
		release string
		dnf     bool
		files   map[string]string
		install string
	}{
		{"ID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\nNAME=\"Debian GNU/Linux\"\n", false,
			map[string]string{"etc/apt/sources.list.d/docker.list": "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable\n", "etc/apt/keyrings/docker.asc": "KEY"},
			"env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -q " + packages},
		{"ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\nNAME=\"Rocky Linux\"\n", true,
			map[string]string{"etc/yum.repos.d/docker-ce.repo": "[docker-ce-stable]\n"},
			"dnf install -y -q " + packages},
	} {
		f := newFake()
		e := testEnv(t, f)
		root := osRelease(t, case_.release, case_.dnf)
		var fetched []string
		e.Platform = platform.Env{Root: root, Run: platform.Runner(f.run), Fetch: func(_ context.Context, url string) ([]byte, error) {
			fetched = append(fetched, url)
			switch {
			case strings.HasSuffix(url, "/Release"):
				return []byte("Architectures: amd64 arm64\n"), nil
			case strings.HasSuffix(url, "/gpg"):
				return []byte("KEY"), nil
			case strings.HasSuffix(url, "/docker-ce.repo"):
				return []byte("[docker-ce-stable]\n"), nil
			}
			return []byte("<repomd/>"), nil
		}}
		f.fail("docker --version", "")
		f.fail("docker compose version", "")
		f.fail("dpkg-query", "")
		f.fail("rpm -q", "")
		f.on("dpkg --print-architecture", "amd64\n")
		f.on("uname -m", "x86_64\n")
		f.on("docker version --format", "28.4.0\n")
		message, err := e.do(t, command("docker", "docker", "install", nil))
		if err != nil || message != "server-1 runs Docker 28.4.0 with Compose now." {
			t.Fatalf("message %q err %v (fetched %q)", message, err, fetched)
		}
		for path, want := range case_.files {
			if got := readText(t, filepath.Join(root, path)); got != want {
				t.Fatalf("%s: %q", path, got)
			}
		}
		if readText(t, filepath.Join(root, "etc", "docker", "daemon.json")) != "{\"log-driver\": \"local\"}\n" {
			t.Fatal("a fresh Docker keeps its logs unbounded")
		}
		if f.called(case_.install) != 1 || f.first(case_.install) > f.first("systemctl enable --now docker") {
			t.Fatalf("calls %q", f.calls)
		}
	}
	f := newFake()
	e := testEnv(t, f)
	e.Platform = platform.Env{Root: osRelease(t, "ID=debian\n", false), Run: platform.Runner(f.run)}
	if message, err := e.do(t, command("docker", "docker", "install", nil)); err != nil || message != "Docker with Compose is already on server-1." {
		t.Fatalf("installed already: %q %v", message, err)
	}
}

type events struct{ io.Reader }

func (events) Close() error { return nil }

func causesAfter(t *testing.T, cmd trust.Command) map[string]*string {
	t.Helper()
	f := newFake()
	e := testEnv(t, f)
	managed(t, e, saving("full", ""))
	f.on(namesOf, "web-app-1\n")
	if _, err := e.do(t, cmd); err != nil {
		t.Fatal(err)
	}
	f.on("docker ps -a --no-trunc --format", "web-app-1\texited\tExited (0) 1 second ago\tnginx:1.27\t\tweb\t/srv/web\tapp\n"+
		"db-1\texited\tExited (1) 1 second ago\tpostgres:17\t\t\t\t\n")
	checks := make(chan reporter.Check, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, _ := io.Pipe()
	watcher := &docker.Watcher{Run: f.run, Checks: e.Checks, Now: e.Now,
		Send: func(message any) error {
			if check, ok := message.(reporter.Check); ok {
				checks <- check
			}
			return nil
		},
		Follow: func(context.Context) (io.ReadCloser, error) { return events{stream}, nil }}
	e.Checks.Choose([]string{"web-app-1", "db-1"})
	go watcher.Watch(ctx)
	causes := map[string]*string{}
	for len(causes) < 2 {
		select {
		case check := <-checks:
			if check.State != "down" {
				t.Fatalf("check %+v", check)
			}
			causes[check.Name] = check.Cause
		case <-time.After(5 * time.Second):
			t.Fatal("no transition")
		}
	}
	if causes["db-1"] != nil {
		t.Fatalf("causes %v", causes)
	}
	return causes
}

func TestStopMarksTheCheckOwner(t *testing.T) {
	for _, cmd := range []trust.Command{command("stack", "web", "stop", nil), command("container", "web-app-1", "stop", nil)} {
		if causes := causesAfter(t, cmd); causes["web-app-1"] == nil || *causes["web-app-1"] != "owner" {
			t.Fatalf("%s %s: causes %v", cmd.Kind, cmd.Action, causes)
		}
	}
}

func TestAContainerThatFailsAfterAStartIsNotTheOwners(t *testing.T) {
	for _, cmd := range []trust.Command{
		command("stack", "web", "start", nil), command("stack", "web", "restart", nil), command("stack", "web", "deploy", nil),
		command("container", "web-app-1", "start", nil), command("container", "web-app-1", "restart", nil),
	} {
		if causes := causesAfter(t, cmd); causes["web-app-1"] != nil {
			t.Fatalf("%s %s: a container that went down after it was started reads %q", cmd.Kind, cmd.Action, *causes["web-app-1"])
		}
	}
}

func TestASignedVerbSendsTheInventoryAtOnce(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	f.on("docker ps -a --no-trunc --format", "web-app-1\trunning\tUp 1 second\tnginx:1.27\t\tweb\t/srv/web\tapp\n")
	sent := make(chan reporter.Inventory, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, _ := io.Pipe()
	watcher := &docker.Watcher{Run: f.run, Checks: e.Checks, Now: e.Now,
		Send: func(message any) error {
			if inventory, ok := message.(reporter.Inventory); ok {
				sent <- inventory
			}
			return nil
		},
		Follow: func(context.Context) (io.ReadCloser, error) { return events{stream}, nil }}
	go watcher.Watch(ctx)
	next := func() reporter.Inventory {
		select {
		case inventory := <-sent:
			return inventory
		case <-time.After(5 * time.Second):
			t.Fatal("no inventory")
		}
		return reporter.Inventory{}
	}
	next()
	f.on("docker ps -a --no-trunc --format", "web-app-1\texited\tExited (0) 1 second ago\tnginx:1.27\t\tweb\t/srv/web\tapp\n")
	if _, err := e.do(t, command("container", "web-app-1", "stop", nil)); err != nil {
		t.Fatal(err)
	}
	if inventory := next(); inventory.Containers[0].State != "stopped" {
		t.Fatalf("inventory %+v", inventory)
	}
}

func TestAKeptContainedStackIsSaidToLoseItsGuard(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	managed(t, e, saving("contained", ""))
	said, problems, _ := Uninstall(context.Background(), f.run, e.State, false)
	t.Cleanup(func() { os.RemoveAll(filepath.Join(filepath.Dir(e.State), "krynodes-stacks")) })
	if len(problems) > 0 || len(said) != 2 || said[1] != "web keeps running without the Contained guard: its containers can now reach this server and its private network" {
		t.Fatalf("said %q problems %q", said, problems)
	}
}

func TestUninstallKeepsTheStacksUnlessAskedToDeleteThem(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	dir := managed(t, e, saving("full", ""))
	os.WriteFile(filepath.Join(dir, runFile), []byte(`{"volumes":["`+dir+`/data"]}`), 0o640)
	said, problems, stayed := Uninstall(context.Background(), f.run, e.State, false)
	target := filepath.Join(filepath.Dir(e.State), "krynodes-stacks", "web")
	t.Cleanup(func() { os.RemoveAll(filepath.Dir(target)) })
	if stayed || len(problems) > 0 || len(said) != 1 || !strings.HasPrefix(said[0], "web stays in "+target) {
		t.Fatalf("said %q problems %q", said, problems)
	}
	if body := readText(t, filepath.Join(target, runFile)); body != `{"volumes":["`+target+`/data"]}` {
		t.Fatalf("run file %s", body)
	}
	if f.called("iptables -w -S DOCKER-USER") == 0 {
		t.Fatal("the guard stayed")
	}
	managed(t, e, saving("full", ""))
	said, problems, stayed = Uninstall(context.Background(), f.run, e.State, true)
	if stayed || len(problems) > 0 || !slices.Equal(said, []string{"web: deleted with its data"}) || f.called(" down -v --remove-orphans") != 1 {
		t.Fatalf("said %q problems %q", said, problems)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("the stack stayed")
	}
}

func TestAPartialUninstallStillRemovesEverythingButTheStacks(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	dir := managed(t, e, saving("full", ""))
	store(e.recordPath("web"), record{})
	for _, file := range []string{"seal.key", "network.json", "trust.json", filepath.Join("ledger", "c-1.json")} {
		os.MkdirAll(filepath.Dir(filepath.Join(e.State, file)), 0o700)
		os.WriteFile(filepath.Join(e.State, file), []byte("{}"), 0o600)
	}
	f.on(namesOf, "web-app-1\n")
	f.fail(" down -v", "Error response from daemon: device or resource busy")
	said, problems, stayed := Uninstall(context.Background(), f.run, e.State, true)
	if !stayed || len(said) != 0 || len(problems) != 1 || !strings.HasPrefix(problems[0], "web stays in "+dir) {
		t.Fatalf("said %q problems %q stayed %v", said, problems, stayed)
	}
	entries, _ := os.ReadDir(e.State)
	if len(entries) != 1 || entries[0].Name() != "compose" {
		t.Fatalf("the state kept %v", entries)
	}
	if _, err := os.Stat(filepath.Join(dir, composeFile)); err != nil {
		t.Fatal("the stack that stayed lost its files")
	}
}
