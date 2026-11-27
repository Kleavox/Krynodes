package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/config"
	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/platform"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/seal"
	"github.com/Kleavox/krynodes/agent/internal/stacks"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

const (
	testOrigin = "https://kry.example.org"
	testToken  = "AAECAwQFBgcICQoLDA0ODw.-7.MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE-PtWtv5mJmKoB5xyNWMR7Y35X3nExwYY-JikK-JBEoMi-YcVwu1KZAed2Kgp8bz5chBIoRR-wGCQlnICVTcp3w"
	testNode   = "11111111-1111-4111-8111-111111111111"
)

func TestVersionPrintsTheBuildVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version exited %d", code)
	}
	if got := stdout.String(); got != version+"\n" {
		t.Fatalf("version printed %q", got)
	}
}

func TestAnythingElseIsRefusedWithExitTwo(t *testing.T) {
	for _, args := range [][]string{nil, {"bogus"}, {"version", "extra"}, {"--version"}, {"install-service", "--config", "x"}, {"self-update", "now"}, {"network"}, {"network", "bogus"}, {"network", "rules", "now"}, {"guard", "now"}, {"guard", "--force"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Errorf("run(%q) exited %d, want 2", args, code)
		}
		if stdout.Len() != 0 || stderr.Len() == 0 {
			t.Errorf("run(%q) wrote stdout %q, stderr %q", args, stdout.String(), stderr.String())
		}
	}
}

type enrollServer struct {
	calls atomic.Int32
	body  map[string]string
	auth  string
	agent string
}

func (s *enrollServer) start(t *testing.T, status int, answer string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/api/agent/enroll" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		s.auth, s.agent = r.Header.Get("Authorization"), r.Header.Get("User-Agent")
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&s.body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(status)
		io.WriteString(w, answer)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func enrollIn(t *testing.T, endpoint string, tokens ...string) (string, string, error) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "etc", "config.json")
	state := filepath.Join(dir, "state")
	_, err := enrollWith(http.DefaultClient, enrollOptions{endpoint: endpoint, token: "code-1", origin: testOrigin, trust: tokens}, facts{"server-1", "Debian GNU/Linux 12", "amd64", "6.1.0-28-amd64"}, configPath, state)
	return configPath, state, err
}

func TestEnrollSendsTheFactsAndKeepsTheTrust(t *testing.T) {
	server := &enrollServer{}
	endpoint := server.start(t, http.StatusOK, `{"nodeId":"`+testNode+`","token":"agent-token"}`)
	configPath, state, err := enrollIn(t, endpoint, testToken)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"hostname": "server-1", "os": "Debian GNU/Linux 12", "arch": "amd64", "kernel": "6.1.0-28-amd64", "version": version}
	if len(server.body) != len(want) {
		t.Fatalf("body %v", server.body)
	}
	for key, value := range want {
		if server.body[key] != value {
			t.Fatalf("body %v", server.body)
		}
	}
	if server.auth != "Bearer code-1" || server.agent != "kry-agent/"+version {
		t.Fatalf("auth %q agent %q", server.auth, server.agent)
	}
	cfg, err := config.Load(configPath)
	if err != nil || cfg.NodeID != testNode || cfg.Token != "agent-token" || cfg.Endpoint != endpoint {
		t.Fatalf("config %+v %v", cfg, err)
	}
	stored, err := trust.Load(state)
	if err != nil || stored.NodeID != testNode || stored.Origin != testOrigin || stored.Version != 1 || len(stored.Core) != 1 || len(stored.Access) != 1 {
		t.Fatalf("trust %+v %v", stored, err)
	}
	if _, err := os.Stat(filepath.Join(state, "seal.key")); err != nil {
		t.Fatalf("no seal key: %v", err)
	}
}

func TestEnrollChecksTheTrustBeforeItSpendsTheCode(t *testing.T) {
	server := &enrollServer{}
	endpoint := server.start(t, http.StatusOK, `{"nodeId":"`+testNode+`","token":"agent-token"}`)
	for _, tokens := range [][]string{nil, {"not-a-token"}, {testToken, testToken}} {
		if _, _, err := enrollIn(t, endpoint, tokens...); err == nil {
			t.Fatalf("%q was accepted", tokens)
		}
	}
	if _, _, err := enrollIn(t, "http://kry.example.org", testToken); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("a plain HTTP endpoint: %v", err)
	}
	if server.calls.Load() != 0 {
		t.Fatalf("the code was sent %d times", server.calls.Load())
	}
}

func TestEnrollLeavesAnEnrolledServerAlone(t *testing.T) {
	server := &enrollServer{}
	endpoint := server.start(t, http.StatusOK, `{"nodeId":"`+testNode+`","token":"agent-token"}`)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := config.Save(configPath, config.Config{Endpoint: endpoint, NodeID: "node-0", Token: "old"}); err != nil {
		t.Fatal(err)
	}
	_, err := enrollWith(http.DefaultClient, enrollOptions{endpoint: endpoint, token: "code-1", origin: testOrigin, trust: []string{testToken}}, facts{}, configPath, filepath.Join(dir, "state"))
	if err == nil || !strings.Contains(err.Error(), "already enrolled as node-0") || server.calls.Load() != 0 {
		t.Fatalf("err %v calls %d", err, server.calls.Load())
	}
}

func TestAnEnrollRefusalShowsTheAnswer(t *testing.T) {
	server := &enrollServer{}
	endpoint := server.start(t, http.StatusUpgradeRequired, `{"code":"AGENT_TOO_OLD"}`)
	configPath, _, err := enrollIn(t, endpoint, testToken)
	if err == nil || !strings.Contains(err.Error(), "HTTP 426") || !strings.Contains(err.Error(), "AGENT_TOO_OLD") {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("a refused enrollment wrote %s", configPath)
	}
	server = &enrollServer{}
	endpoint = server.start(t, http.StatusOK, `{"nodeId":"","token":"agent-token"}`)
	if _, _, err := enrollIn(t, endpoint, testToken); err == nil {
		t.Fatal("an answer without a node id was taken")
	}
}

func TestMissingFactsAreSentAsUnknown(t *testing.T) {
	got := facts{Arch: "arm64"}.known()
	if got != (facts{"unknown", "unknown", "arm64", "unknown"}) {
		t.Fatalf("facts %+v", got)
	}
}

func TestHelloCarriesTheTrustOnlyOnceThereIsOne(t *testing.T) {
	message := hello(facts{"server-1", "Debian GNU/Linux 12", "amd64", "6.1.0"}, "seal", trust.Trust{}, nil)
	if message.Type != "hello" || message.V != 1 || message.Version != version || message.SealKey != "seal" || message.Trust != nil || message.Kind != "server" || message.Network != nil {
		t.Fatalf("hello %+v", message)
	}
	first, err := trust.FirstTrust(testNode, testOrigin, []string{testToken})
	if err != nil {
		t.Fatal(err)
	}
	message = hello(facts{}.known(), "seal", first, nil)
	if message.Trust == nil || message.Trust.Version != 1 || len(message.Trust.Core) != 1 || message.Hostname != "unknown" {
		t.Fatalf("hello %+v", message)
	}
	encoded, _ := json.Marshal(hello(facts{}, "seal", trust.Trust{}, nil))
	if !strings.Contains(string(encoded), `"trust":null`) || !strings.Contains(string(encoded), `"kind":"server"`) || !strings.Contains(string(encoded), `"network":null`) {
		t.Fatalf("hello %s", encoded)
	}
	joined := &reporter.NetworkHello{Version: 2, Key: "k", Signer: "s", Ready: true}
	if message := hello(facts{}, "seal", trust.Trust{}, joined); message.Network != joined {
		t.Fatalf("hello %+v", message)
	}
}

func TestTheUnitRunsTheDaemonAsRootAndComesBack(t *testing.T) {
	for _, line := range []string{"User=root\n", "Restart=always\n", "RestartSec=5\n", "ExecStart=/usr/local/bin/kry run\n", "WantedBy=multi-user.target\n"} {
		if !strings.Contains(unit, line) {
			t.Fatalf("the unit has no %q:\n%s", line, unit)
		}
	}
}

func TestUninstallRemovesEveryPartKrynodesPutThere(t *testing.T) {
	want := []string{"/etc/systemd/system/krynodes.service", "/etc/kry", "/var/lib/kry", "/usr/local/bin/kry", "/usr/local/bin/kry.previous", "/usr/local/bin/kry.new"}
	if strings.Join(removed, " ") != strings.Join(want, " ") {
		t.Fatalf("removes %v", removed)
	}
}

func TestATrustResetSeedsTheTokensAboveTheStoredVersion(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := config.Save(configPath, config.Config{Endpoint: testOrigin, NodeID: testNode, Token: "agent-token"}); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	first, err := trust.FirstTrust(testNode, testOrigin, []string{testToken})
	if err != nil {
		t.Fatal(err)
	}
	first.Version = 7
	if err := trust.Save(state, first); err != nil {
		t.Fatal(err)
	}
	next, err := reseed(configPath, state, testOrigin, []string{testToken})
	if err != nil || next.Version != 8 || next.NodeID != testNode {
		t.Fatalf("next %+v %v", next, err)
	}
	if stored, _ := trust.Load(state); stored.Version != 8 {
		t.Fatalf("stored %+v", stored)
	}
	if err := os.WriteFile(filepath.Join(state, "trust.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if next, err := reseed(configPath, state, testOrigin, []string{testToken}); err != nil || next.Version != 1 {
		t.Fatalf("an unreadable store: %+v %v", next, err)
	}
	if _, err := reseed(configPath, state, testOrigin, []string{"bad"}); err == nil {
		t.Fatal("a bad token was taken")
	}
}

func TestEnrollMakesNetworkKeysAndInstallsNothing(t *testing.T) {
	server := &enrollServer{}
	endpoint := server.start(t, http.StatusOK, `{"nodeId":"`+testNode+`","token":"agent-token"}`)
	_, state, err := enrollIn(t, endpoint, testToken)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := network.Load(filepath.Join(state, "network"), false)
	if err != nil || keys.Public == "" || keys.Signer == "" {
		t.Fatalf("keys %v", err)
	}
	entries, _ := os.ReadDir(state)
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if strings.Join(names, " ") != "network seal.key trust.json" {
		t.Fatalf("enroll left %v", names)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(filepath.Join(state, "network")); info.Mode().Perm() != 0o700 {
			t.Fatalf("the key directory is %v", info.Mode())
		}
	}
}

type fingerprintCase struct {
	Key         string `json:"key"`
	Signer      string `json:"signer"`
	SealKey     string `json:"sealKey"`
	Fingerprint string `json:"fingerprint"`
}

func TestTheFingerprintCommandPrintsTheSameAsTheProtocol(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "protocol", "src", "fixtures", "fingerprint.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []fingerprintCase
	if err := json.Unmarshal(raw, &cases); err != nil || len(cases) == 0 {
		t.Fatalf("fixture %v", err)
	}
	for _, item := range cases {
		if got := network.Fingerprint(item.Key, item.Signer, item.SealKey); got != item.Fingerprint {
			t.Fatalf("got %s want %s", got, item.Fingerprint)
		}
	}
	state := t.TempDir()
	var stdout bytes.Buffer
	if err := networkWith("fingerprint", localMesh(state), &stdout); err == nil || stdout.Len() != 0 {
		t.Fatalf("no keys: %v %q", err, stdout.String())
	}
	keys, err := network.Load(filepath.Join(state, "network"), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := networkWith("fingerprint", localMesh(state), &stdout); err == nil || !strings.Contains(err.Error(), "no seal key") || stdout.Len() != 0 {
		t.Fatalf("no seal key: %v %q", err, stdout.String())
	}
	if _, err := os.Stat(filepath.Join(state, "seal.key")); !os.IsNotExist(err) {
		t.Fatalf("the fingerprint made a seal key: %v", err)
	}
	key, err := seal.Load(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := networkWith("fingerprint", localMesh(state), &stdout); err != nil {
		t.Fatal(err)
	}
	if want := network.Fingerprint(keys.Public, keys.Signer, seal.Public(key)) + "\n"; stdout.String() != want {
		t.Fatalf("printed %q want %q", stdout.String(), want)
	}
}

func TestTheRulesCommandFailsWithoutAnAppliedDocument(t *testing.T) {
	state := t.TempDir()
	m := localMesh(state)
	var calls []string
	m.Run = func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, 0, nil
	}
	var stdout bytes.Buffer
	if err := networkWith("rules", m, &stdout); err == nil || !strings.Contains(err.Error(), "no applied network document") {
		t.Fatalf("rules %v", err)
	}
	if len(calls) != 0 || stdout.Len() != 0 {
		t.Fatalf("calls %v stdout %q", calls, stdout.String())
	}
}

func TestARefreshSendsTheLinksAndADocumentIsApplied(t *testing.T) {
	sent := make(chan any, 4)
	m := localMesh(t.TempDir())
	m.Trust = func() trust.Trust { return trust.Trust{NodeID: testNode} }
	m.Send = func(message any) error { sent <- message; return nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	take := networkWorker(ctx, m)
	take(reporter.Refresh{Type: "refresh"})
	if links, ok := (<-sent).(reporter.Links); !ok || links.Type != "links" || links.Links == nil {
		t.Fatalf("links %+v", links)
	}
	take(reporter.Document{Type: "document", Version: 1, Signed: "{}"})
	if applied, ok := (<-sent).(reporter.Applied); !ok || applied.OK || applied.Version != 1 {
		t.Fatalf("applied %+v", applied)
	}
}

func TestRefreshesDoNotPileUpAndDocumentsAreNeverDropped(t *testing.T) {
	release := make(chan struct{})
	sent := make(chan any, 128)
	m := localMesh(t.TempDir())
	m.Trust = func() trust.Trust { return trust.Trust{NodeID: testNode} }
	m.Send = func(message any) error {
		<-release
		sent <- message
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	take := networkWorker(ctx, m)
	for range 3 {
		take(reporter.Refresh{Type: "refresh"})
	}
	take(reporter.Document{Type: "document", Version: 1, Signed: "{}"})
	for range 40 {
		take(reporter.Hints{Type: "hints"})
	}
	take(reporter.Document{Type: "document", Version: 2, Signed: "{}"})
	take(reporter.Document{Type: "document", Version: 3, Signed: "{}"})
	close(release)
	links, versions := 0, []int{}
	for deadline := time.After(2 * time.Second); len(versions) < 3 || links < 1; {
		select {
		case message := <-sent:
			switch value := message.(type) {
			case reporter.Links:
				links++
			case reporter.Applied:
				versions = append(versions, value.Version)
			}
		case <-deadline:
			t.Fatalf("links %d versions %v", links, versions)
		}
	}
	select {
	case message := <-sent:
		t.Fatalf("more arrived: %+v", message)
	case <-time.After(100 * time.Millisecond):
	}
	if links != 1 || !slices.Equal(versions, []int{1, 2, 3}) {
		t.Fatalf("links %d versions %v", links, versions)
	}
}

func TestTheDocumentQueueKeepsTheLowestVersions(t *testing.T) {
	release, busy := make(chan struct{}), make(chan struct{}, 1)
	sent := make(chan int, 128)
	m := localMesh(t.TempDir())
	m.Trust = func() trust.Trust { return trust.Trust{NodeID: testNode} }
	m.Send = func(message any) error {
		if applied, ok := message.(reporter.Applied); ok {
			busy <- struct{}{}
			<-release
			sent <- applied.Version
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	take := networkWorker(ctx, m)
	take(reporter.Document{Type: "document", Version: 1, Signed: "{}"})
	<-busy
	for version := 71; version >= 2; version-- {
		take(reporter.Document{Type: "document", Version: version, Signed: "{}"})
	}
	close(release)
	go func() {
		for range busy {
		}
	}()
	var versions []int
	for deadline := time.After(5 * time.Second); len(versions) < 65; {
		select {
		case version := <-sent:
			versions = append(versions, version)
		case <-deadline:
			t.Fatalf("versions %v", versions)
		}
	}
	select {
	case version := <-sent:
		t.Fatalf("version %d was kept past the cap", version)
	case <-time.After(100 * time.Millisecond):
	}
	if versions[0] != 1 || versions[1] != 2 || versions[64] != 65 || !slices.IsSorted(versions) {
		t.Fatalf("versions %v", versions)
	}
}

func lockedAway(t *testing.T) {
	t.Helper()
	was := stacks.GuardLock
	t.Cleanup(func() { stacks.GuardLock = was })
	stacks.GuardLock = filepath.Join(t.TempDir(), "guard.lock")
}

func TestGuardCommandFailsWhenTheGuardFails(t *testing.T) {
	lockedAway(t)
	refused := func(context.Context, string, ...string) ([]byte, int, error) {
		return []byte("iptables: Permission denied (you must be root)."), 4, errors.New("exit status 4")
	}
	err := guardWith(refused)
	if err == nil || !strings.HasPrefix(err.Error(), "the guard of Contained stacks: ") || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("a guard that fails says why: %v", err)
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		t.Skip("as root this would change this machine's firewall")
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"guard"}, &stdout, &stderr); code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "kry guard must run as root on Linux") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
}

func TestInstallServiceProvesTheGuardBeforeItWritesTheDropIn(t *testing.T) {
	lockedAway(t)
	const asked = "systemctl show -p LoadState docker.service"
	for name, test := range map[string]struct {
		state   string
		refuse  bool
		written bool
		failure string
	}{
		"the guard holds":           {"loaded", false, true, ""},
		"the guard cannot hold":     {"loaded", true, false, "Permission denied"},
		"this server has no Docker": {"not-found", false, false, ""},
	} {
		root := t.TempDir()
		dropIn := filepath.Join(root, "etc", "systemd", "system", "docker.service.d", "krynodes-guard.conf")
		var calls []string
		firewall := 0
		chains := map[string][]string{}
		run := func(_ context.Context, command string, args ...string) ([]byte, int, error) {
			call := command + " " + strings.Join(args, " ")
			calls = append(calls, call)
			switch {
			case call == asked:
				return []byte("LoadState=" + test.state + "\n"), 0, nil
			case command == "iptables" || command == "ip6tables":
				firewall++
				if _, err := os.Stat(dropIn); err == nil {
					t.Errorf("%s: the drop-in was there before the guard held", name)
				}
				if test.refuse {
					return []byte("iptables: Permission denied (you must be root)."), 4, errors.New("exit status 4")
				}
				key, rest := command+" "+args[2], strings.Join(args[3:], " ")
				switch args[1] {
				case "-C":
					if !slices.Contains(chains[key], rest) {
						return nil, 1, errors.New("exit status 1")
					}
				case "-I":
					chains[key] = slices.Insert(chains[key], 0, strings.TrimPrefix(rest, "1 "))
				case "-D":
					if at := slices.Index(chains[key], rest); at >= 0 {
						chains[key] = slices.Delete(chains[key], at, at+1)
					}
				case "-S":
					listed := "-N DOCKER-USER\n"
					for _, rule := range chains[key] {
						listed += "-A DOCKER-USER " + rule + "\n"
					}
					return []byte(listed), 0, nil
				}
			}
			return nil, 0, nil
		}
		err := guardDocker(context.Background(), platform.Env{Root: root, Run: platform.Runner(run), Executable: "/usr/local/bin/kry", Prove: proveGuard(run)})
		_, missing := os.Stat(dropIn)
		reloaded := slices.Contains(calls, "systemctl daemon-reload")
		switch {
		case test.failure != "" && (err == nil || !strings.HasPrefix(err.Error(), "the guard of Contained stacks: ") || !strings.Contains(err.Error(), test.failure)):
			t.Errorf("%s: install-service fails with the guard's error: %v", name, err)
		case test.failure == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case (missing == nil) != test.written || reloaded != test.written || (firewall > 0) != (test.state == "loaded"):
			t.Errorf("%s: drop-in %v, reloaded %v, firewall calls %d, calls %q", name, missing == nil, reloaded, firewall, calls)
		}
	}
}

func TestUninstallKeepsTheBinaryWhileDockerStillWaitsForIt(t *testing.T) {
	dir := t.TempDir()
	parts := []string{filepath.Join(dir, "kry"), filepath.Join(dir, "kry.previous"), filepath.Join(dir, "state")}
	for _, part := range parts {
		if err := os.WriteFile(part, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	problems := removeParts(parts, map[string]string{parts[0]: "Docker waits for it until the drop-in is removed", parts[2]: ""})
	if len(problems) != 1 || problems[0] != parts[0]+" stays: Docker waits for it until the drop-in is removed" {
		t.Fatalf("problems %q", problems)
	}
	for part, want := range map[string]bool{parts[0]: true, parts[1]: false, parts[2]: true} {
		if _, err := os.Stat(part); (err == nil) != want {
			t.Errorf("%s exists %v, want %v", part, err == nil, want)
		}
	}
}
