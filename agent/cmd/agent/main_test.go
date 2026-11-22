package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/config"
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
	for _, args := range [][]string{nil, {"bogus"}, {"version", "extra"}, {"--version"}, {"install-service", "--config", "x"}, {"self-update", "now"}} {
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
	message := hello(facts{"server-1", "Debian GNU/Linux 12", "amd64", "6.1.0"}, "seal", trust.Trust{})
	if message.Type != "hello" || message.V != 1 || message.Version != version || message.SealKey != "seal" || message.Trust != nil {
		t.Fatalf("hello %+v", message)
	}
	first, err := trust.FirstTrust(testNode, testOrigin, []string{testToken})
	if err != nil {
		t.Fatal(err)
	}
	message = hello(facts{}.known(), "seal", first)
	if message.Trust == nil || message.Trust.Version != 1 || len(message.Trust.Core) != 1 || message.Hostname != "unknown" {
		t.Fatalf("hello %+v", message)
	}
	encoded, _ := json.Marshal(hello(facts{}, "seal", trust.Trust{}))
	if !strings.Contains(string(encoded), `"trust":null`) {
		t.Fatalf("hello %s", encoded)
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
