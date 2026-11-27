package service

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/seal"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

type fakeSystem struct {
	calls        []string
	fail         error
	shortcutFail error
	stopFail     error
	source       string
	program      string
}

func newSystem(t *testing.T) *fakeSystem {
	t.Helper()
	source := filepath.Join(t.TempDir(), "krynodes-windows-amd64.exe")
	if err := os.WriteFile(source, []byte("agent 0.7.24"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &fakeSystem{source: source, program: filepath.Join(t.TempDir(), "Krynodes", "krynodes.exe")}
}

func (f *fakeSystem) Source() (string, error) {
	return f.source, nil
}

func (f *fakeSystem) Program() (string, error) {
	return f.program, nil
}

func (f *fakeSystem) StopService() error {
	f.calls = append(f.calls, "stop")
	return f.stopFail
}

func (f *fakeSystem) StartService() error {
	f.calls = append(f.calls, "start")
	return nil
}

func (f *fakeSystem) Unpack(string) error {
	f.calls = append(f.calls, "unpack")
	return nil
}

func (f *fakeSystem) Folder(dir string) error {
	return os.MkdirAll(dir, 0o755)
}

func (f *fakeSystem) Write(path string, data []byte) error {
	return os.WriteFile(path, data, 0o755)
}

func (f *fakeSystem) Register(executable string) error {
	f.calls = append(f.calls, "register "+filepath.Base(executable))
	return f.fail
}

func (f *fakeSystem) Tray(executable string) error {
	f.calls = append(f.calls, "tray "+filepath.Base(executable))
	return nil
}

func (f *fakeSystem) Shortcut(executable string) error {
	f.calls = append(f.calls, "shortcut "+filepath.Base(executable))
	return f.shortcutFail
}

type enrollServer struct {
	*httptest.Server
	trust []string
	name  string
	body  map[string]json.RawMessage
	calls int

	known        string
	streamStatus int
	redirect     bool
	probes       []*http.Request
}

func newEnrollServer(t *testing.T, tokens ...string) *enrollServer {
	t.Helper()
	server := &enrollServer{trust: tokens, name: "laptop-1"}
	server.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent/stream" {
			server.probes = append(server.probes, r)
			switch {
			case server.redirect:
				http.Redirect(w, r, "/elsewhere", http.StatusFound)
			case server.streamStatus != 0:
				w.WriteHeader(server.streamStatus)
			case server.known != "" && r.Header.Get("Authorization") == "Bearer "+server.known:
				w.WriteHeader(http.StatusUpgradeRequired)
			default:
				w.WriteHeader(http.StatusUnauthorized)
			}
			return
		}
		server.calls++
		if r.URL.Path != "/api/agent/enroll" || r.Header.Get("Authorization") != "Bearer one-time-code" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&server.body); err != nil {
			t.Error(err)
		}
		json.NewEncoder(w).Encode(map[string]any{"nodeId": laptop1, "name": server.name, "token": "agent-token", "trust": server.trust})
	}))
	t.Cleanup(server.Close)
	return server
}

func (s *enrollServer) install(dir string, secrets Secrets, system System, out io.Writer) error {
	return Install(context.Background(), s.Client(), dir, secrets, system, Enrollment{Code: "one-time-code", Origin: testOrigin, Endpoint: s.URL, Version: "0.7.24", Kernel: "10.0.19045"}, out)
}

func TestInstallEnrollsAsALaptopAndStartsTheService(t *testing.T) {
	f := newFixture(t)
	server := newEnrollServer(t, "cred-1.-7."+f.device.PublicKey)
	dir := t.TempDir()
	secrets := memory{}
	system := newSystem(t)
	if err := server.install(dir, secrets, system, io.Discard); err != nil {
		t.Fatal(err)
	}
	service := Service{Dir: dir, Secrets: secrets}
	if _, err := service.keys(); err != nil || len(server.body["hostname"]) < 3 {
		t.Fatalf("sent %s, %v", server.body, err)
	}
	if string(secrets[tokenSecret]) != "agent-token" {
		t.Errorf("token %q", secrets[tokenSecret])
	}
	for _, name := range []string{"wrote trust.json", "wrote state.json"} {
		if _, ok := secrets[name]; !ok {
			t.Errorf("%s was not written through the store", strings.TrimPrefix(name, "wrote "))
		}
	}
	current, err := trust.Load(dir)
	if err != nil || current.NodeID != laptop1 || current.Origin != testOrigin || len(current.Core) != 1 || !slices.Equal(current.Access, []string{"cred-1"}) {
		t.Fatalf("trust %+v, %v", current, err)
	}
	if record, err := service.read(); err != nil || record.NodeID != laptop1 || record.Endpoint != server.URL {
		t.Fatalf("state %+v, %v", record, err)
	}
	want := []string{"stop", "unpack", "tray krynodes.exe", "shortcut krynodes.exe", "register krynodes.exe"}
	if !slices.Equal(system.calls, want) {
		t.Fatalf("calls %v", system.calls)
	}
	if data, err := os.ReadFile(system.program); err != nil || string(data) != "agent 0.7.24" {
		t.Fatalf("placed %q, %v", data, err)
	}
}

func TestEveryEnrolledPasskeyCanSignForANewLaptop(t *testing.T) {
	f := newFixture(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := newEnrollServer(t, "cred-1.-7."+f.device.PublicKey, "cred-2.-7."+spki(t, other))
	dir := t.TempDir()
	secrets := memory{}
	if err := server.install(dir, secrets, newSystem(t), io.Discard); err != nil {
		t.Fatal(err)
	}
	current, err := trust.Load(dir)
	if err != nil || !slices.Equal(current.Access, []string{"cred-1", "cred-2"}) {
		t.Fatalf("trust %+v, %v", current, err)
	}
	f.service.Dir, f.service.Secrets, f.secrets = dir, secrets, secrets
	if f.keys, err = f.service.keys(); err != nil {
		t.Fatal(err)
	}
	sealing, err := ecdh.P256().NewPrivateKey(secrets[sealSecret])
	if err != nil {
		t.Fatal(err)
	}
	f.seal = seal.Public(sealing)
	first := f.document(1, "", true)
	if got := f.deliver(1, f.signWith("cred-1", f.passkey, first)); !got.OK {
		t.Fatalf("signed by the first passkey: %+v", got)
	}
	second := f.document(2, network.BodyHash(first), true)
	if got := f.deliver(2, f.signWith("cred-2", other, second)); !got.OK {
		t.Fatalf("signed by the second passkey: %+v", got)
	}
}

func TestAFailedStartMenuEntryFailsTheInstallBeforeTheServiceAndStartsItAgain(t *testing.T) {
	f := newFixture(t)
	server := newEnrollServer(t, "cred-1.-7."+f.device.PublicKey)
	system := newSystem(t)
	system.shortcutFail = errors.New("access is denied")
	err := server.install(t.TempDir(), memory{}, system, io.Discard)
	if err == nil || !strings.HasPrefix(err.Error(), "make the Start menu entry: access is denied; run install again to finish") {
		t.Fatalf("install = %v", err)
	}
	if want := []string{"stop", "unpack", "tray krynodes.exe", "shortcut krynodes.exe", "start"}; !slices.Equal(system.calls, want) {
		t.Fatalf("calls %v, want %v", system.calls, want)
	}
}

func TestAFailedInstallFinishesOnTheNextRun(t *testing.T) {
	f := newFixture(t)
	server := newEnrollServer(t, "cred-1.-7."+f.device.PublicKey)
	dir := t.TempDir()
	secrets := memory{}
	system := newSystem(t)
	system.fail = errors.New("the service manager is busy")
	if err := server.install(dir, secrets, system, io.Discard); err == nil || !strings.Contains(err.Error(), "run install again") {
		t.Fatalf("first run: %v", err)
	}
	if want := []string{"stop", "unpack", "tray krynodes.exe", "shortcut krynodes.exe", "register krynodes.exe", "start"}; !slices.Equal(system.calls, want) {
		t.Fatalf("first run calls %v, want %v", system.calls, want)
	}
	system.fail, system.calls = nil, nil
	server.known = "agent-token"
	sealed := string(secrets[sealSecret])
	var out strings.Builder
	if err := server.install(dir, secrets, system, &out); err != nil {
		t.Fatal(err)
	}
	if want := "Krynodes is installed.\nThis laptop is already enrolled, so a new code is not needed. Run uninstall first to enroll it again with a new code.\nThe network fingerprint is in the tray menu.\n"; out.String() != want {
		t.Errorf("printed %q, want %q", out.String(), want)
	}
	if len(server.probes) != 1 || server.calls != 1 || string(secrets[tokenSecret]) != "agent-token" || string(secrets[sealSecret]) != sealed {
		t.Fatalf("asked %d times, enrolled %d times, token %q", len(server.probes), server.calls, secrets[tokenSecret])
	}
	if want := []string{"unpack", "tray krynodes.exe", "shortcut krynodes.exe", "register krynodes.exe"}; !slices.Equal(system.calls, want) {
		t.Fatalf("calls %v, want %v", system.calls, want)
	}
}

func storedLaptop(t *testing.T, dir string, secrets memory, token, endpoint string) {
	t.Helper()
	secrets[tokenSecret] = []byte(token)
	secrets[sealSecret] = []byte("old-seal")
	secrets[signerSecret] = []byte("old-signer")
	secrets[wireguardSecret] = []byte("old-wireguard")
	service := Service{Dir: dir, Secrets: secrets}
	if err := service.save(state{Endpoint: endpoint, NodeID: "old-laptop", Joined: true}); err != nil {
		t.Fatal(err)
	}
}

func TestAnInstallWithACodeEnrollsAgainWhenKrynodesForgotTheStoredToken(t *testing.T) {
	f := newFixture(t)
	server := newEnrollServer(t, "cred-1.-7."+f.device.PublicKey)
	dir := t.TempDir()
	secrets := memory{}
	storedLaptop(t, dir, secrets, "dead-token", server.URL)
	system := newSystem(t)
	if err := os.MkdirAll(filepath.Dir(system.program), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(system.program, []byte("agent 0.7.24"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := server.install(dir, secrets, system, &out); err != nil {
		t.Fatal(err)
	}
	if len(server.probes) != 1 {
		t.Fatalf("asked %d times", len(server.probes))
	}
	probe := server.probes[0]
	if probe.Method != http.MethodGet || probe.Header.Get("Authorization") != "Bearer dead-token" || probe.Header.Get("Upgrade") != "" || probe.UserAgent() != "kry-agent/0.7.24" {
		t.Errorf("probe %s %v", probe.Method, probe.Header)
	}
	for _, want := range []string{"Krynodes is installed.", "Network fingerprint: ", "Approve laptop-1 on the Network page of your dashboard."} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output %q lacks %q", out.String(), want)
		}
	}
	if strings.Contains(out.String(), "in the tray menu") {
		t.Errorf("output %q still sends the reader to the tray", out.String())
	}
	if server.calls != 1 || string(secrets[tokenSecret]) != "agent-token" {
		t.Errorf("enrolled %d times, token %q", server.calls, secrets[tokenSecret])
	}
	for _, name := range []string{sealSecret, signerSecret, wireguardSecret} {
		if strings.HasPrefix(string(secrets[name]), "old-") {
			t.Errorf("%s is still the old laptop's", name)
		}
	}
	service := Service{Dir: dir, Secrets: secrets}
	if record, err := service.read(); err != nil || record.NodeID != laptop1 || record.Endpoint != server.URL || record.Joined {
		t.Errorf("state %+v, %v", record, err)
	}
	if current, err := trust.Load(dir); err != nil || current.NodeID != laptop1 {
		t.Errorf("trust %+v, %v", current, err)
	}
	if want := []string{"unpack", "stop", "tray krynodes.exe", "shortcut krynodes.exe", "register krynodes.exe"}; !slices.Equal(system.calls, want) {
		t.Errorf("calls %v, want %v", system.calls, want)
	}
}

func TestAnInstallWithACodeFinishesWithoutUsingItWhenThisLaptopIsStillEnrolled(t *testing.T) {
	f := newFixture(t)
	server := newEnrollServer(t, "cred-1.-7."+f.device.PublicKey)
	server.known = "agent-token"
	dir := t.TempDir()
	secrets := memory{}
	storedLaptop(t, dir, secrets, "agent-token", server.URL)
	system := newSystem(t)
	var out strings.Builder
	if err := server.install(dir, secrets, system, &out); err != nil {
		t.Fatal(err)
	}
	if want := "Krynodes is installed.\nThis laptop is already enrolled, so a new code is not needed. Run uninstall first to enroll it again with a new code.\nThe network fingerprint is in the tray menu.\n"; out.String() != want {
		t.Errorf("printed %q, want %q", out.String(), want)
	}
	if server.calls != 0 || len(server.probes) != 1 {
		t.Errorf("enrolled %d times, asked %d times", server.calls, len(server.probes))
	}
	if want := []string{"stop", "unpack", "tray krynodes.exe", "shortcut krynodes.exe", "register krynodes.exe"}; !slices.Equal(system.calls, want) {
		t.Errorf("calls %v, want %v", system.calls, want)
	}
	for name, want := range map[string]string{tokenSecret: "agent-token", sealSecret: "old-seal", signerSecret: "old-signer", wireguardSecret: "old-wireguard"} {
		if string(secrets[name]) != want {
			t.Errorf("%s became %q", name, secrets[name])
		}
	}
	service := Service{Dir: dir, Secrets: secrets}
	if record, err := service.read(); err != nil || record.NodeID != "old-laptop" || record.Endpoint != server.URL || !record.Joined {
		t.Errorf("state %+v, %v", record, err)
	}
	if current, err := trust.Load(dir); err != nil || current.NodeID != "" {
		t.Errorf("trust %+v, %v", current, err)
	}
}

func TestTheProbeAsksTheKrynodesThatIssuedTheStoredToken(t *testing.T) {
	f := newFixture(t)
	server := newEnrollServer(t, "cred-1.-7."+f.device.PublicKey)
	issuer := newEnrollServer(t)
	dir := t.TempDir()
	secrets := memory{}
	storedLaptop(t, dir, secrets, "dead-token", issuer.URL)
	if err := server.install(dir, secrets, newSystem(t), io.Discard); err != nil {
		t.Fatal(err)
	}
	if len(issuer.probes) != 1 || issuer.probes[0].Header.Get("Authorization") != "Bearer dead-token" || issuer.calls != 0 {
		t.Errorf("the issuer was asked %d times and got %d other requests", len(issuer.probes), issuer.calls)
	}
	if len(server.probes) != 0 || server.calls != 1 {
		t.Errorf("the command line's Krynodes was asked %d times and enrolled %d times", len(server.probes), server.calls)
	}
}

func TestAnInstallWithACodeRefusesWhenTheStoredSettingsCannotBeRead(t *testing.T) {
	server := newEnrollServer(t)
	dir := t.TempDir()
	secrets := memory{}
	storedLaptop(t, dir, secrets, "agent-token", server.URL)
	if err := os.Remove(filepath.Join(dir, stateFile)); err != nil {
		t.Fatal(err)
	}
	system := newSystem(t)
	err := server.install(dir, secrets, system, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "run uninstall first") {
		t.Fatalf("install = %v", err)
	}
	if len(server.probes) != 0 || server.calls != 0 || len(system.calls) != 0 {
		t.Errorf("asked %d times, %d other requests, calls %v", len(server.probes), server.calls, system.calls)
	}
}

func TestAnInstallWithACodeKeepsTheStoredLaptopWhenKrynodesCannotAnswer(t *testing.T) {
	f := newFixture(t)
	server := newEnrollServer(t, "cred-1.-7."+f.device.PublicKey)
	server.streamStatus = http.StatusInternalServerError
	dir := t.TempDir()
	secrets := memory{}
	storedLaptop(t, dir, secrets, "agent-token", server.URL)
	system := newSystem(t)
	err := server.install(dir, secrets, system, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("install = %v", err)
	}
	server.Close()
	if err := server.install(dir, secrets, system, io.Discard); err == nil || !strings.Contains(err.Error(), "reach Krynodes") {
		t.Fatalf("install = %v", err)
	}
	if server.calls != 0 || len(system.calls) != 0 {
		t.Errorf("enrolled %d times, calls %v", server.calls, system.calls)
	}
	if string(secrets[tokenSecret]) != "agent-token" || string(secrets[sealSecret]) != "old-seal" {
		t.Errorf("the stored laptop changed: token %q, seal %q", secrets[tokenSecret], secrets[sealSecret])
	}
}

func TestAnInstallWithACodeKeepsTheStoredLaptopWhenTheProbeIsRedirected(t *testing.T) {
	f := newFixture(t)
	server := newEnrollServer(t, "cred-1.-7."+f.device.PublicKey)
	server.redirect = true
	dir := t.TempDir()
	secrets := memory{}
	storedLaptop(t, dir, secrets, "agent-token", server.URL)
	system := newSystem(t)
	err := server.install(dir, secrets, system, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("install = %v", err)
	}
	if len(server.probes) != 1 || server.calls != 0 || len(system.calls) != 0 {
		t.Errorf("asked %d times, %d other requests, calls %v", len(server.probes), server.calls, system.calls)
	}
	if string(secrets[tokenSecret]) != "agent-token" || string(secrets[sealSecret]) != "old-seal" {
		t.Errorf("the stored laptop changed: token %q, seal %q", secrets[tokenSecret], secrets[sealSecret])
	}
}

func TestARenewTheServerRefusesLeavesTheStoredLaptopAsItWas(t *testing.T) {
	f := newFixture(t)
	server := newEnrollServer(t, "cred-1.-7."+f.device.PublicKey)
	dir := t.TempDir()
	secrets := memory{}
	storedLaptop(t, dir, secrets, "dead-token", server.URL)
	system := newSystem(t)
	if err := os.MkdirAll(filepath.Dir(system.program), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(system.program, []byte("agent 0.7.24"), 0o755); err != nil {
		t.Fatal(err)
	}
	before := maps.Clone(secrets)
	stateBefore, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil {
		t.Fatal(err)
	}
	spent := Enrollment{Code: "spent-code", Origin: testOrigin, Endpoint: server.URL, Version: "0.7.24", Kernel: "10.0.19045"}
	err = Install(context.Background(), server.Client(), dir, secrets, system, spent, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "the code is not valid") {
		t.Fatalf("install = %v", err)
	}
	if want := []string{"unpack", "stop", "start"}; !slices.Equal(system.calls, want) {
		t.Errorf("calls %v, want %v", system.calls, want)
	}
	if !maps.EqualFunc(secrets, before, bytes.Equal) {
		t.Errorf("the stored secrets changed: %v, before %v", secrets, before)
	}
	if stateAfter, err := os.ReadFile(filepath.Join(dir, stateFile)); err != nil || !bytes.Equal(stateAfter, stateBefore) {
		t.Errorf("state %q, %v, before %q", stateAfter, err, stateBefore)
	}
	if _, err := os.Stat(filepath.Join(dir, trustFile)); err == nil {
		t.Error("a trust file was written")
	}
}

func TestAnInstallWithoutTrustOrOverPlainHTTPIsRefused(t *testing.T) {
	server := newEnrollServer(t)
	dir := t.TempDir()
	secrets := memory{}
	system := newSystem(t)
	if err := server.install(dir, secrets, system, io.Discard); err == nil || !strings.Contains(err.Error(), "no trusted passkeys") {
		t.Fatalf("no trust: %v", err)
	}
	if len(secrets) != 0 {
		t.Errorf("a refused first install stored %d secrets", len(secrets))
	}
	if want := []string{"stop", "unpack", "start"}; !slices.Equal(system.calls, want) {
		t.Fatalf("calls %v, want %v", system.calls, want)
	}
	if _, ok := secrets[tokenSecret]; ok {
		t.Fatal("a laptop without trust was set up")
	}
	for _, origin := range []string{"http://kry.example.com", "http://203.0.113.5:8787", "ftp://kry.example.com", "https://kry.example.com/path"} {
		err := Install(context.Background(), server.Client(), dir, secrets, system, Enrollment{Code: "one-time-code", Origin: testOrigin, Endpoint: origin}, io.Discard)
		if err == nil || len(system.calls) != 3 {
			t.Errorf("%s was accepted: %v", origin, err)
		}
	}
	for _, origin := range []string{"http://localhost:8787", "http://127.0.0.1:8787", "http://[::1]:8787", "https://kry.example.com"} {
		if err := checkOrigin(origin); err != nil {
			t.Errorf("%s was refused: %v", origin, err)
		}
	}
}

func TestHelperHoldsTheProgramOpen(t *testing.T) {
	if os.Getenv("KRY_HOLD") != "1" {
		t.Skip("a helper process for the reinstall test")
	}
	time.Sleep(30 * time.Second)
}

func TestReinstallSwapsInBesideARunningTray(t *testing.T) {
	f := newFixture(t)
	server := newEnrollServer(t, "cred-1.-7."+f.device.PublicKey)
	system := newSystem(t)
	if err := os.MkdirAll(filepath.Dir(system.program), 0o755); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	running, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(system.program, running, 0o755); err != nil {
		t.Fatal(err)
	}
	tray := exec.Command(system.program, "-test.run=^TestHelperHoldsTheProgramOpen$")
	tray.Env = append(os.Environ(), "KRY_HOLD=1")
	if err := tray.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		tray.Process.Kill()
		tray.Wait()
	})
	if err := server.install(t.TempDir(), memory{}, system, io.Discard); err != nil {
		t.Fatalf("install over a running program: %v", err)
	}
	if data, _ := os.ReadFile(system.program); string(data) != "agent 0.7.24" {
		t.Errorf("the program in place is %d bytes, want the new agent", len(data))
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(system.program), oldName)); err != nil {
		t.Errorf("the running program was not set aside: %v", err)
	}
	if want := []string{"stop", "unpack", "tray krynodes.exe", "shortcut krynodes.exe", "register krynodes.exe"}; !slices.Equal(system.calls, want) {
		t.Errorf("calls %v, want %v", system.calls, want)
	}
}

func TestAFailedCopyStartsTheServiceAgain(t *testing.T) {
	f := newFixture(t)
	server := newEnrollServer(t, "cred-1.-7."+f.device.PublicKey)
	system := newSystem(t)
	dir := filepath.Dir(system.program)
	if err := os.MkdirAll(filepath.Join(dir, stagedName, "blocked"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(system.program, []byte("agent 0.7.23"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := server.install(t.TempDir(), memory{}, system, io.Discard)
	if err == nil || !strings.HasPrefix(err.Error(), "copy the agent: stage the new agent") {
		t.Fatalf("install = %v, want the copy refused", err)
	}
	if want := []string{"stop", "start"}; !slices.Equal(system.calls, want) {
		t.Errorf("calls %v, want %v", system.calls, want)
	}
	if data, _ := os.ReadFile(system.program); string(data) != "agent 0.7.23" {
		t.Errorf("the installed agent became %q", data)
	}
	if server.calls != 0 {
		t.Errorf("enrolled %d times after a failed copy", server.calls)
	}
}

func TestAStopThatTimesOutStartsTheServiceAgain(t *testing.T) {
	f := newFixture(t)
	server := newEnrollServer(t, "cred-1.-7."+f.device.PublicKey)
	system := newSystem(t)
	system.stopFail = errors.New("the Krynodes service did not stop in 30 seconds")
	dir := filepath.Dir(system.program)
	if err := os.MkdirAll(filepath.Join(dir, stagedName, "blocked"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(system.program, []byte("agent 0.7.23"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := server.install(t.TempDir(), memory{}, system, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "did not stop in 30 seconds") {
		t.Fatalf("install = %v, want the stop failure", err)
	}
	if want := []string{"stop", "start"}; !slices.Equal(system.calls, want) {
		t.Errorf("calls %v, want %v", system.calls, want)
	}
	if data, _ := os.ReadFile(system.program); string(data) != "agent 0.7.23" {
		t.Errorf("the installed agent became %q", data)
	}
	if server.calls != 0 {
		t.Errorf("enrolled %d times after a failed stop", server.calls)
	}
}

func TestTrayErrorsNameTheirStep(t *testing.T) {
	executable := `C:\Program Files\Krynodes\krynodes.exe`
	var events []string
	user := func() userSession {
		return userSession{
			Processes: func() ([]process, error) {
				return []process{{Session: 0, Name: "krynodes.exe"}, {Session: 2, Name: "Krynodes.EXE"}, {Session: 1, Name: "explorer.exe"}}, nil
			},
			Token: func(session uint32) (uintptr, error) {
				events = append(events, fmt.Sprintf("token %d", session))
				return uintptr(session) + 100, nil
			},
			Elevated: func(uintptr) bool { return false },
			Start: func(token uintptr, command string) error {
				events = append(events, fmt.Sprintf("start %d %s", token, command))
				return nil
			},
			Close: func(token uintptr) { events = append(events, fmt.Sprintf("close %d", token)) },
		}
	}
	if err := user().startTray(executable, 1); err != nil {
		t.Fatal(err)
	}
	if want := []string{"token 1", `start 101 "C:\Program Files\Krynodes\krynodes.exe" tray`, "close 101"}; !slices.Equal(events, want) {
		t.Fatalf("events %q, want %q", events, want)
	}

	events = nil
	if err := user().startTray(executable, 2); err != nil || len(events) != 0 {
		t.Fatalf("a session that already runs a tray got another: %v, events %q", err, events)
	}

	denied := errors.New("Access is denied.")
	for _, test := range []struct {
		name    string
		session uint32
		change  func(*userSession)
		want    string
		cause   error
		events  []string
	}{
		{"no console session", noSession, func(*userSession) {}, "start the tray: find the signed-in user: ", errNoUser, nil},
		{"the process list", 1, func(s *userSession) { s.Processes = func() ([]process, error) { return nil, denied } }, "start the tray: find the signed-in user: ", denied, nil},
		{"the token", 1, func(s *userSession) { s.Token = func(uint32) (uintptr, error) { return 0, denied } }, "start the tray: take the user's token: ", denied, nil},
		{"an elevated token", 1, func(s *userSession) { s.Elevated = func(uintptr) bool { return true } }, "start the tray: take the user's token: ", errElevated, []string{"token 1", "close 101"}},
		{"the program", 1, func(s *userSession) { s.Start = func(uintptr, string) error { return denied } }, "start the tray: start the program: ", denied, []string{"token 1", "close 101"}},
	} {
		events = nil
		started := user()
		test.change(&started)
		err := started.startTray(executable, test.session)
		if err == nil || !errors.Is(err, test.cause) || err.Error() != test.want+test.cause.Error() || !slices.Equal(events, test.events) {
			t.Errorf("%s: %v, events %q", test.name, err, events)
		}
	}
}
