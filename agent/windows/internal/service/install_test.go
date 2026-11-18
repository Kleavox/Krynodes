package service

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
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
	calls    []string
	fail     error
	stopFail error
	source   string
	program  string
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

type enrollServer struct {
	*httptest.Server
	trust []string
	sent  struct {
		Hostname string     `json:"hostname"`
		Laptop   laptopKeys `json:"laptop"`
	}
	calls int
}

func newEnrollServer(t *testing.T, tokens ...string) *enrollServer {
	t.Helper()
	server := &enrollServer{trust: tokens}
	server.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.calls++
		if r.URL.Path != "/api/agent/enroll" || r.Header.Get("Authorization") != "Bearer one-time-code" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&server.sent); err != nil {
			t.Error(err)
		}
		json.NewEncoder(w).Encode(map[string]any{"nodeId": laptop1, "token": "agent-token", "intervalSeconds": 60, "trust": server.trust})
	}))
	t.Cleanup(server.Close)
	return server
}

func (s *enrollServer) install(dir string, secrets Secrets, system System) error {
	return Install(context.Background(), s.Client(), dir, secrets, system, Enrollment{Code: "one-time-code", Origin: testOrigin, Endpoint: s.URL, Version: "0.7.24"})
}

func TestInstallEnrollsAsALaptopAndStartsTheService(t *testing.T) {
	f := newFixture(t)
	server := newEnrollServer(t, "cred-1.-7."+f.device.PublicKey)
	dir := t.TempDir()
	secrets := memory{}
	system := newSystem(t)
	if err := server.install(dir, secrets, system); err != nil {
		t.Fatal(err)
	}
	service := Service{Dir: dir, Secrets: secrets}
	keys, err := service.keys()
	sent := server.sent
	if err != nil || sent.Laptop.Key != keys.Public || sent.Laptop.Signer != keys.Signer || sent.Laptop.Port != 51820 || len(sent.Laptop.SealKey) != 87 || sent.Hostname == "" {
		t.Fatalf("sent %+v, keys %+v, %v", sent, keys, err)
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
	if record, err := service.read(); err != nil || record.NodeID != laptop1 || record.Endpoint != server.URL || record.Interval != 60 {
		t.Fatalf("state %+v, %v", record, err)
	}
	want := []string{"stop", "unpack", "register krynodes.exe", "tray krynodes.exe"}
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
	if err := server.install(dir, secrets, newSystem(t)); err != nil {
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
	if err := f.service.applyDocument(f.signWith("cred-1", f.passkey, first)); err != nil {
		t.Fatalf("signed by the first passkey: %v", err)
	}
	second := f.document(2, network.BodyHash(first), true)
	if err := f.service.applyDocument(f.signWith("cred-2", other, second)); err != nil {
		t.Fatalf("signed by the second passkey: %v", err)
	}
}

func TestAFailedInstallFinishesOnTheNextRun(t *testing.T) {
	f := newFixture(t)
	server := newEnrollServer(t, "cred-1.-7."+f.device.PublicKey)
	dir := t.TempDir()
	secrets := memory{}
	system := newSystem(t)
	system.fail = errors.New("the service manager is busy")
	if err := server.install(dir, secrets, system); err == nil || !strings.Contains(err.Error(), "run install again") {
		t.Fatalf("first run: %v", err)
	}
	if want := []string{"stop", "unpack", "register krynodes.exe", "start"}; !slices.Equal(system.calls, want) {
		t.Fatalf("first run calls %v, want %v", system.calls, want)
	}
	system.fail, system.calls = nil, nil
	if err := server.install(dir, secrets, system); err != nil {
		t.Fatal(err)
	}
	if server.calls != 1 || string(secrets[tokenSecret]) != "agent-token" {
		t.Fatalf("enrolled %d times, token %q", server.calls, secrets[tokenSecret])
	}
	if want := []string{"unpack", "register krynodes.exe", "tray krynodes.exe"}; !slices.Equal(system.calls, want) {
		t.Fatalf("calls %v, want %v", system.calls, want)
	}
}

func TestAnInstallWithoutTrustOrOverPlainHTTPIsRefused(t *testing.T) {
	server := newEnrollServer(t)
	dir := t.TempDir()
	secrets := memory{}
	system := newSystem(t)
	if err := server.install(dir, secrets, system); err == nil || !strings.Contains(err.Error(), "no trusted passkeys") {
		t.Fatalf("no trust: %v", err)
	}
	if want := []string{"stop", "unpack", "start"}; !slices.Equal(system.calls, want) {
		t.Fatalf("calls %v, want %v", system.calls, want)
	}
	if _, ok := secrets[tokenSecret]; ok {
		t.Fatal("a laptop without trust was set up")
	}
	for _, origin := range []string{"http://kry.example.com", "http://203.0.113.5:8787", "ftp://kry.example.com", "https://kry.example.com/path"} {
		err := Install(context.Background(), server.Client(), dir, secrets, system, Enrollment{Code: "one-time-code", Origin: testOrigin, Endpoint: origin})
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
	if err := server.install(t.TempDir(), memory{}, system); err != nil {
		t.Fatalf("install over a running program: %v", err)
	}
	if data, _ := os.ReadFile(system.program); string(data) != "agent 0.7.24" {
		t.Errorf("the program in place is %d bytes, want the new agent", len(data))
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(system.program), oldName)); err != nil {
		t.Errorf("the running program was not set aside: %v", err)
	}
	if want := []string{"stop", "unpack", "register krynodes.exe", "tray krynodes.exe"}; !slices.Equal(system.calls, want) {
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
	err := server.install(t.TempDir(), memory{}, system)
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
	err := server.install(t.TempDir(), memory{}, system)
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
