package stacks

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/daemon"
	"github.com/Kleavox/krynodes/agent/internal/docker"
	"github.com/Kleavox/krynodes/agent/internal/platform"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/seal"
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
	_, result := throughWire(t, e, trusted, message)
	return result
}

func throughWire(t *testing.T, e Env, trusted trust.Trust, message reporter.Command) ([]any, reporter.Result) {
	t.Helper()
	w := &wire{got: make(chan reporter.Result, 1)}
	d := &daemon.Daemon{State: t.TempDir(), Trust: func() trust.Trust { return trusted }, Send: w.send, Now: time.Now, Handlers: Handlers(e)}
	d.Handle(context.Background(), message)
	select {
	case result := <-w.got:
		w.mu.Lock()
		defer w.mu.Unlock()
		return slices.Clone(w.sent), result
	case <-time.After(5 * time.Second):
		t.Fatal("no result")
	}
	return nil, reporter.Result{}
}

func browserKey(t *testing.T) (*ecdh.PrivateKey, string) {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key, seal.Public(key)
}

func openFrom(key *ecdh.PrivateKey, node *ecdh.PublicKey, sealed string) ([]byte, error) {
	body, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		return nil, err
	}
	var message struct {
		V   int    `json:"v"`
		EPK string `json:"epk"`
		IV  string `json:"iv"`
		CT  string `json:"ct"`
	}
	if err := json.Unmarshal(body, &message); err != nil {
		return nil, err
	}
	if message.V != 2 {
		return nil, fmt.Errorf("version %d is not sealed by the server", message.V)
	}
	epk, err := base64.RawURLEncoding.DecodeString(message.EPK)
	if err != nil {
		return nil, err
	}
	ephemeral, err := ecdh.P256().NewPublicKey(epk)
	if err != nil {
		return nil, err
	}
	fromEphemeral, err := key.ECDH(ephemeral)
	if err != nil {
		return nil, err
	}
	fromNode, err := key.ECDH(node)
	if err != nil {
		return nil, err
	}
	secret, err := hkdf.Key(sha256.New, slices.Concat(fromEphemeral, fromNode), slices.Concat(epk, node.Bytes(), key.PublicKey().Bytes()), "krynodes-seal-from-node-v1", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv, err := base64.RawURLEncoding.DecodeString(message.IV)
	if err != nil || len(iv) != aead.NonceSize() {
		return nil, fmt.Errorf("the iv is not valid: %v", err)
	}
	ct, err := base64.RawURLEncoding.DecodeString(message.CT)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, iv, ct, nil)
}

func opened(t *testing.T, e Env, key *ecdh.PrivateKey, result reporter.Result) string {
	t.Helper()
	plain, err := openFrom(key, e.Sealing.PublicKey(), result.Output)
	if err != nil {
		t.Fatalf("the output does not open: %v (%q)", err, result.Output)
	}
	return string(plain)
}

func TestAnUnsignedStackCommandIsRefused(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	managed(t, e, saving("full", ""))
	key, to := browserKey(t)
	trusted, message := signed(t, command("stack", "web", "logs", map[string]string{"lines": "5", "to": to}))
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
	if !result.OK || result.Message != "The last 5 lines of web." || opened(t, e, key, result) != "2026-11-24T10:00:00Z app-1 ready\n" {
		t.Fatalf("signed result %+v", result)
	}
}

func TestLogsAreSealedToTheSignedKey(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	managed(t, e, saving("full", ""))
	key, to := browserKey(t)
	other, _ := browserKey(t)
	const stackText = "2026-11-24T10:00:00Z app-1 token=hunter2 ready\n"
	const containerText = "2026-11-24T10:00:01Z app-1 listening on 203.0.113.9\n"
	f.on(" logs --tail 5", stackText)
	f.on("docker logs --tail 10", containerText)
	trusted, message := signed(t, command("stack", "web", "logs", map[string]string{"lines": "5", "to": to}))
	result := through(t, e, trusted, message)
	if !result.OK || result.Output == stackText || strings.Contains(result.Output, "hunter2") || strings.Contains(result.Output, "app-1") {
		t.Fatalf("the stack output is not sealed: %+v", result)
	}
	if opened(t, e, key, result) != stackText {
		t.Fatal("the stack logs do not open with the signed key")
	}
	if _, err := openFrom(other, e.Sealing.PublicKey(), result.Output); err == nil {
		t.Fatal("another key opened the stack logs")
	}
	if _, err := openFrom(key, other.PublicKey(), result.Output); err == nil {
		t.Fatal("the logs opened as if another server had sent them")
	}
	if _, err := seal.Open(key, result.Output); err == nil {
		t.Fatal("the logs opened without the server's key")
	}
	trusted, message = signed(t, command("container", "web-app-1", "logs", map[string]string{"lines": "10", "to": to}))
	result = through(t, e, trusted, message)
	if !result.OK || result.Output == containerText || strings.Contains(result.Output, "203.0.113.9") || opened(t, e, key, result) != containerText {
		t.Fatalf("the container output is not sealed to the signed key: %+v", result)
	}
}

func TestLogsKeepTheirPlaintextLimitBeforeSealing(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	managed(t, e, saving("full", ""))
	key, to := browserKey(t)
	var text strings.Builder
	for index := range 6000 {
		fmt.Fprintf(&text, "%s line %04d\n", strings.Repeat("x", 20), index)
	}
	f.on(" logs --tail 500", text.String())
	trusted, message := signed(t, command("stack", "web", "logs", map[string]string{"lines": "500", "to": to}))
	result := through(t, e, trusted, message)
	plain := opened(t, e, key, result)
	if !result.OK || len(plain) > maxOutput || !strings.HasPrefix(plain, cutLine) || !strings.HasSuffix(plain, "line 5999\n") || len(result.Output) > 128<<10 {
		t.Fatalf("plaintext %d bytes, sealed %d characters", len(plain), len(result.Output))
	}
}

func TestAFailedLogsCommandCarriesNoLogLines(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	managed(t, e, saving("full", ""))
	key, to := browserKey(t)
	const stackText = "2026-11-24T10:00:00Z app-1 token=hunter2 ready\n"
	const containerText = "2026-11-24T10:00:01Z app-1 listening on 203.0.113.9\n"
	f.fail(" logs --tail 5", stackText)
	f.fail("docker logs --tail 10", containerText)
	for _, step := range []struct {
		command trust.Command
		message string
		hidden  []string
	}{
		{command("stack", "web", "logs", map[string]string{"lines": "5", "to": to}), "Logs of web failed.", []string{"hunter2", "app-1", "ready"}},
		{command("container", "web-app-1", "logs", map[string]string{"lines": "10", "to": to}), "Logs of web-app-1 failed.", []string{"203.0.113.9", "listening"}},
	} {
		trusted, message := signed(t, step.command)
		traffic, result := throughWire(t, e, trusted, message)
		if result.OK || result.Message != step.message || opened(t, e, key, result) != "logs failed: exit status 1" {
			t.Fatalf("%s logs: %+v", step.command.Kind, result)
		}
		body, _ := json.Marshal(traffic)
		for _, line := range step.hidden {
			if strings.Contains(string(body), line) {
				t.Fatalf("%s logs: the wire carries %q", step.command.Kind, line)
			}
		}
	}
}

func TestAFailedReadCarriesNoComposeText(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	dir := managed(t, e, saving("full", ""))
	key, to := browserKey(t)
	const secret = "# token=hunter2 registry.example.test/app\n"
	if err := os.WriteFile(filepath.Join(dir, composeFile), []byte(secret+strings.Repeat(`"`, maxComposeBytes-len(secret))), 0o640); err != nil {
		t.Fatal(err)
	}
	trusted, message := signed(t, command("stack", "web", "read", map[string]string{"to": to}))
	result := through(t, e, trusted, message)
	if result.OK || result.Message != "Read of web failed." || opened(t, e, key, result) != "the compose file of web does not fit in one answer" {
		t.Fatalf("result %+v", result)
	}
	if err := os.WriteFile(filepath.Join(dir, composeFile), []byte(secret+strings.Repeat("x", maxComposeBytes)), 0o640); err != nil {
		t.Fatal(err)
	}
	traffic, result := throughWire(t, e, trusted, message)
	body, _ := json.Marshal(traffic)
	if result.OK || result.Message != "Read of web failed." || strings.Contains(string(body), "hunter2") || strings.Contains(string(body), "registry") {
		t.Fatalf("result %+v", result)
	}
	if detail := opened(t, e, key, result); detail != "the compose file is larger than 32 KB" {
		t.Fatalf("detail %q", detail)
	}
}

func TestReadIsSealedToTheSignedKey(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	managed(t, e, saving("full", "8080"))
	key, to := browserKey(t)
	other, _ := browserKey(t)
	trusted, message := signed(t, command("stack", "web", "read", map[string]string{"to": to}))
	result := through(t, e, trusted, message)
	if !result.OK || result.Message != "The compose file of web." || strings.Contains(result.Output, "nginx") || strings.Contains(result.Output, "compose") {
		t.Fatalf("the read output is not sealed: %+v", result)
	}
	var body struct {
		Compose string `json:"compose"`
		Access  string `json:"access"`
		Network []int  `json:"network"`
	}
	if err := json.Unmarshal([]byte(opened(t, e, key, result)), &body); err != nil || body.Compose != plainCompose || body.Access != "full" || !slices.Equal(body.Network, []int{8080}) {
		t.Fatalf("the sealed read: %+v %v", body, err)
	}
	if _, err := openFrom(other, e.Sealing.PublicKey(), result.Output); err == nil {
		t.Fatal("another key opened the compose file")
	}
	if _, err := openFrom(key, other.PublicKey(), result.Output); err == nil {
		t.Fatal("the compose file opened as if another server had sent it")
	}
}

func TestEveryFailureFailsClosedWithoutTheSealKey(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	managed(t, e, saving("full", ""))
	e.Sealing = nil
	_, to := browserKey(t)
	f.on(" logs --tail 5", "token=hunter2 ready\n")
	f.on("docker logs --tail 5", "token=hunter2 ready\n")
	f.fail(" pull", "token=hunter2 denied\n")
	for _, step := range []struct {
		command trust.Command
		message string
	}{
		{command("stack", "web", "logs", map[string]string{"lines": "5", "to": to}), "Logs of web failed. Its details could not be sealed."},
		{command("container", "web-app-1", "logs", map[string]string{"lines": "5", "to": to}), "Logs of web-app-1 failed. Its details could not be sealed."},
		{command("stack", "web", "read", map[string]string{"to": to}), "Read of web failed. Its details could not be sealed."},
		{command("stack", "web", "deploy", map[string]string{"to": to}), "Deploy of web failed. Its details could not be sealed."},
	} {
		trusted, message := signed(t, step.command)
		traffic, result := throughWire(t, e, trusted, message)
		body, _ := json.Marshal(traffic)
		if result.OK || result.Output != "" || result.Message != step.message || strings.Contains(string(body), "hunter2") {
			t.Fatalf("%s %s: %+v", step.command.Kind, step.command.Action, result)
		}
	}
}

func TestABadRecipientIsRefused(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	managed(t, e, saving("full", ""))
	_, good := browserKey(t)
	f.on(" logs --tail 5", "ready\n")
	f.on("docker logs --tail 5", "ready\n")
	bad := []string{"", "x", good[:86], good + "A", strings.Repeat("A", 87), strings.Repeat("-", 87), base64.StdEncoding.EncodeToString(make([]byte, 65))}
	for _, to := range bad {
		for _, refused := range []trust.Command{
			command("stack", "web", "logs", map[string]string{"lines": "5", "to": to}),
			command("container", "web-app-1", "logs", map[string]string{"lines": "5", "to": to}),
			command("stack", "web", "read", map[string]string{"to": to}),
			command("stack", "web", "deploy", map[string]string{"to": to}),
			command("stack", "web", "stop", map[string]string{"to": to}),
			command("stack", "web", "adopt", map[string]string{"access": "full", "to": to}),
			command("container", "web-app-1", "restart", map[string]string{"to": to}),
		} {
			if _, err := e.do(t, refused); err == nil || !strings.Contains(err.Error(), "came with arguments this server does not take") {
				t.Fatalf("%s %s with to %q: %v", refused.Kind, refused.Action, to, err)
			}
		}
	}
	for _, refused := range []trust.Command{
		bare("stack", "web", "logs", map[string]string{"lines": "5"}),
		bare("container", "web-app-1", "logs", map[string]string{"lines": "5"}),
		bare("stack", "web", "read", nil),
		bare("stack", "web", "deploy", nil),
		bare("stack", "web", "remove", nil),
		bare("stack", "web", "purge", nil),
		bare("stack", "web", "adopt", map[string]string{"access": "full"}),
		bare("stack", "web", "create", saving("full", "")),
		bare("container", "web-app-1", "stop", nil),
	} {
		if _, err := e.do(t, refused); err == nil || !strings.Contains(err.Error(), "came with arguments this server does not take") {
			t.Fatalf("%s %s ran without a key: %v", refused.Kind, refused.Action, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("docker ran for a refused recipient: %q", f.calls)
	}
}

func TestStackLogsPassTheServiceAfterTheFlags(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	managed(t, e, saving("full", ""))
	_, to := browserKey(t)
	trusted, message := signed(t, command("stack", "web", "logs", map[string]string{"lines": "200", "service": "-app", "to": to}))
	if result := through(t, e, trusted, message); !result.OK {
		t.Fatalf("result %+v", result)
	}
	if f.called(" logs --tail 200 --timestamps --no-color -- -app") != 1 {
		t.Fatalf("calls %q", f.calls)
	}
	trusted, message = signed(t, command("container", "web-app-1", "logs", map[string]string{"lines": "10", "to": to}))
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

func installable(t *testing.T, release string, dnf bool) (Env, *fake, string) {
	t.Helper()
	f := newFake()
	e := testEnv(t, f)
	root := osRelease(t, release, dnf)
	e.Platform = platform.Env{Root: root, Run: platform.Runner(f.run), Executable: "/usr/local/bin/kry", Prove: proved(f), Fetch: func(_ context.Context, url string) ([]byte, error) {
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
	return e, f, root
}

const debianRelease = "ID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\nNAME=\"Debian GNU/Linux\"\n"

func TestInstallDockerUsesThePlatform(t *testing.T) {
	packages := "docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
	for _, case_ := range []struct {
		release string
		dnf     bool
		files   map[string]string
		install string
	}{
		{debianRelease, false,
			map[string]string{"etc/apt/sources.list.d/docker.list": "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable\n", "etc/apt/keyrings/docker.asc": "KEY"},
			"env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -q " + packages},
		{"ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\nNAME=\"Rocky Linux\"\n", true,
			map[string]string{"etc/yum.repos.d/docker-ce.repo": "[docker-ce-stable]\n"},
			"dnf install -y -q " + packages},
	} {
		e, f, root := installable(t, case_.release, case_.dnf)
		message, err := e.do(t, command("docker", "docker", "install", nil))
		if err != nil || message != "server-1 runs Docker 28.4.0 with Compose now." {
			t.Fatalf("message %q err %v", message, err)
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

func TestInstallDockerWritesTheDropIn(t *testing.T) {
	e, f, root := installable(t, debianRelease, false)
	if _, err := e.do(t, command("docker", "docker", "install", nil)); err != nil {
		t.Fatal(err)
	}
	if got := readText(t, filepath.Join(root, "etc", "systemd", "system", "docker.service.d", "krynodes-guard.conf")); got != "[Service]\nExecStartPre=/usr/local/bin/kry guard\n" {
		t.Fatalf("drop-in %q", got)
	}
	if reload := f.first("systemctl daemon-reload"); reload < 0 || reload < f.first("systemctl enable --now docker") {
		t.Fatalf("systemd is reloaded after Docker is installed: %q", f.calls)
	}

	e, f, root = installable(t, debianRelease, false)
	e.Platform.Executable = ""
	if _, err := e.do(t, command("docker", "docker", "install", nil)); err == nil || !strings.Contains(err.Error(), "does not know where it is installed") {
		t.Fatalf("no path to the guard, no Docker: %v", err)
	}
	if f.called("apt-get") > 0 || f.called("systemctl") > 0 {
		t.Fatalf("nothing was installed: %q", f.calls)
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "systemd")); err == nil {
		t.Fatal("no drop-in was written")
	}

	e, f, root = installable(t, debianRelease, false)
	f.fail("iptables -w -C KRY-CONTAINED", "")
	f.fail("iptables -w -A KRY-CONTAINED", "iptables: Permission denied (you must be root)")
	if _, err := e.do(t, command("docker", "docker", "install", nil)); err == nil || !strings.Contains(err.Error(), "Permission denied") || strings.Count(err.Error(), "the guard of Contained stacks") != 1 {
		t.Fatalf("a guard that cannot hold is the error, said once: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "systemd")); err == nil || f.called("systemctl daemon-reload") > 0 {
		t.Fatalf("no drop-in is written and systemd is not reloaded: %q", f.calls)
	}

	e, f, _ = installable(t, debianRelease, false)
	f.fail("systemctl daemon-reload", "Failed to connect to bus")
	if _, err := e.do(t, command("docker", "docker", "install", nil)); err == nil || !strings.Contains(err.Error(), "guard drop-in was not written") {
		t.Fatalf("a drop-in that did not load is said: %v", err)
	}
}

func proved(f *fake) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := Guard(ctx, f.run); err != nil {
			return fmt.Errorf("the guard of Contained stacks: %w", err)
		}
		return nil
	}
}

func hostOf(t *testing.T, f *fake) platform.Env {
	t.Helper()
	return platform.Env{Root: t.TempDir(), Run: platform.Runner(f.run), Executable: "/usr/local/bin/kry", Prove: proved(f)}
}

func TestUninstallRemovesTheDockerDropIn(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	host := hostOf(t, f)
	if err := host.GuardDocker(context.Background()); err != nil {
		t.Fatal(err)
	}
	dropIn := filepath.Join(host.Root, "etc", "systemd", "system", "docker.service.d", "krynodes-guard.conf")
	readText(t, dropIn)
	f.reset()
	_, problems, _ := Uninstall(context.Background(), host, e.State, false)
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	if _, err := os.Stat(dropIn); err == nil {
		t.Fatal("Docker would wait for a guard that is gone")
	}
	if f.called("systemctl daemon-reload") != 1 || f.first("systemctl daemon-reload") > f.first("iptables -w -S DOCKER-USER") {
		t.Fatalf("systemd is told before the rules go: %q", f.calls)
	}
}

type events struct{ io.Reader }

func (events) Close() error { return nil }

func causesAfter(t *testing.T, cmd trust.Command) map[string]*string {
	t.Helper()
	return causesWith(t, cmd, func(f *fake) {
		f.on(namesOf, "web-app-1\n")
		if cmd.Action == "deploy" {
			f.on(runningOf, "web-app-1\n")
		}
	})
}

func causesWith(t *testing.T, cmd trust.Command, prepare func(f *fake)) map[string]*string {
	t.Helper()
	f := newFake()
	e := testEnv(t, f)
	managed(t, e, saving("full", ""))
	prepare(f)
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

func TestDeployThatStaysStoppedMarksItsChecksAsTheOwners(t *testing.T) {
	deploy := command("stack", "web", "deploy", nil)
	for name, prepare := range map[string]func(f *fake){
		"its containers stopped": func(f *fake) { f.on(namesOf, "web-app-1\n") },
		"its containers gone": func(f *fake) {
			f.when(namesOf, func() (string, error) {
				if f.called(" up --no-start") == 0 {
					return "", nil
				}
				return "web-app-1\n", nil
			})
		},
	} {
		if causes := causesWith(t, deploy, prepare); causes["web-app-1"] == nil || *causes["web-app-1"] != "owner" {
			t.Fatalf("%s: causes %v", name, causes)
		}
	}
}

func TestDeployMarksTheContainersItCreatesBeforeTheyAppear(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	managed(t, e, saving("full", ""))
	var created atomic.Bool
	f.when("docker ps -a --no-trunc --format", func() (string, error) {
		if created.Load() {
			return "web-app-1\texited\tExited (0) 1 second ago\tnginx:1.27\t\tweb\t/srv/web\tapp\n", nil
		}
		return "", nil
	})
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
	go watcher.Watch(ctx)
	var seen reporter.Check
	f.when(" up --no-start", func() (string, error) {
		created.Store(true)
		e.Checks.Choose([]string{"web-app-1"})
		select {
		case seen = <-checks:
		case <-time.After(5 * time.Second):
			t.Error("the watcher saw nothing while up ran")
		}
		return "", nil
	})
	if _, err := e.do(t, command("stack", "web", "deploy", nil)); err != nil {
		t.Fatal(err)
	}
	if seen.Name != "web-app-1" || seen.State != "down" || seen.Cause == nil || *seen.Cause != "owner" {
		t.Fatalf("a container seen while Deploy created it was reported %+v", seen)
	}
}

func TestPlannedNamesFollowComposesNaming(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	if err := os.MkdirAll(e.folder("web"), 0o700); err != nil {
		t.Fatal(err)
	}
	run := `{"services":{"app":{"deploy":{"replicas":2}},"cache":{"scale":3},"db":{"container_name":"web-db"},"job":{},"swarm":{"scale":1000000000}}}`
	if err := os.WriteFile(filepath.Join(e.folder("web"), runFile), []byte(run), 0o600); err != nil {
		t.Fatal(err)
	}
	names := e.planned("web")
	want := []string{"web-app-1", "web-app-2", "web-cache-1", "web-cache-2", "web-cache-3", "web-db", "web-job-1"}
	if len(names) != len(want)+maxCopies || !slices.Equal(names[:len(want)], want) || names[len(names)-1] != fmt.Sprintf("web-swarm-%d", maxCopies) {
		t.Fatalf("names %q", names)
	}
	if none := e.planned("other"); len(none) != 0 {
		t.Fatalf("a stack with no run file plans %q", none)
	}
}

func TestAnUnreadableRunFileIsLogged(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	if err := os.MkdirAll(e.folder("web"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(e.folder("web"), runFile)
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	if names := e.planned("web"); len(names) != 0 || !strings.Contains(logged.String(), path) {
		t.Fatalf("names %q logged %q", names, logged.String())
	}
}

func TestARemovedStackReportsTheNamesOfItsContainers(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	if err := os.MkdirAll(e.folder("web"), 0o700); err != nil {
		t.Fatal(err)
	}
	run := `{"services":{"app":{"scale":2},"cache":{"container_name":"cache-main"}}}`
	if err := os.WriteFile(filepath.Join(e.folder("web"), runFile), []byte(run), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.changeBin(func(bin map[string]removal) { bin["web"] = removal{RemovedAt: e.Now().UTC()} }); err != nil {
		t.Fatal(err)
	}
	listed := e.Meta(context.Background()).Removed()
	if len(listed) != 1 || !slices.Equal(listed[0].Names, []string{"web-app-1", "web-app-2", "cache-main"}) {
		t.Fatalf("removed %+v", listed)
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
	said, problems, _ := Uninstall(context.Background(), hostOf(t, f), e.State, false)
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
	said, problems, stayed := Uninstall(context.Background(), hostOf(t, f), e.State, false)
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
	said, problems, stayed = Uninstall(context.Background(), hostOf(t, f), e.State, true)
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
	said, problems, stayed := Uninstall(context.Background(), hostOf(t, f), e.State, true)
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

func TestTheGuardLoopWritesTheDropInOfADockerInstalledLater(t *testing.T) {
	useResolvers(t, "", "")
	const asked = "systemctl show -p LoadState docker.service"
	f := newFake()
	e := testEnv(t, f)
	e.Platform = hostOf(t, f)
	dropIn := filepath.Join(e.Platform.Root, "etc", "systemd", "system", "docker.service.d", "krynodes-guard.conf")
	want := "[Service]\nExecStartPre=/usr/local/bin/kry guard\n"

	f.on(asked, "LoadState=not-found\n")
	if err := e.keepGuard(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dropIn); err == nil || f.called("daemon-reload") > 0 || f.called("iptables") > 0 {
		t.Fatalf("no Docker, no drop-in, and no Contained stack, no firewall: %q", f.calls)
	}

	f.on(asked, "LoadState=loaded\n")
	if err := e.keepGuard(context.Background()); err != nil {
		t.Fatal(err)
	}
	if readText(t, dropIn) != want || f.called("systemctl daemon-reload") != 1 {
		t.Fatalf("Docker came later and the loop wrote its drop-in: %q", f.calls)
	}

	f.reset()
	if err := e.keepGuard(context.Background()); err != nil || f.called("daemon-reload") > 0 || f.called("systemctl") != 2 {
		t.Fatalf("a drop-in that is right is only checked: %v %q", err, f.calls)
	}

	f.on(guardedDocker, "ExecStartPre=\n")
	f.on("show -p DropInPaths docker.service", "DropInPaths=/etc/systemd/system/docker.service.d/krynodes-guard.conf /etc/systemd/system/docker.service.d/override.conf\n")
	if err := e.keepGuard(context.Background()); err == nil || !strings.HasPrefix(err.Error(), "Docker's guard drop-in: ") || !strings.Contains(err.Error(), "override.conf") {
		t.Fatalf("a drop-in that resets ExecStartPre is named by the loop: %v", err)
	}
	f.on(guardedDocker, guardRuns)

	os.WriteFile(dropIn, []byte("[Service]\nExecStartPre=/old/kry guard\n"), 0o644)
	if err := e.keepGuard(context.Background()); err != nil || readText(t, dropIn) != want || f.called("systemctl daemon-reload") != 1 {
		t.Fatalf("a drop-in that differs is written again: %v %q", err, f.calls)
	}

	managed(t, e, saving("contained", ""))
	f.reset()
	if err := e.keepGuard(context.Background()); err != nil || f.called("iptables -w -C KRY-CONTAINED") == 0 {
		t.Fatalf("a Contained stack is still guarded: %v %q", err, f.calls)
	}

	e.Platform.Executable = ""
	os.Remove(dropIn)
	if err := e.keepGuard(context.Background()); err == nil || !strings.HasPrefix(err.Error(), "Docker's guard drop-in: ") {
		t.Fatalf("a drop-in the loop cannot write is said: %v", err)
	}

	e.Platform.Executable = "/usr/local/bin/kry"
	f.reset()
	f.fail("iptables -w -C KRY-CONTAINED", "")
	f.fail("iptables -w -A KRY-CONTAINED", "iptables: Permission denied (you must be root)")
	err := e.keepGuard(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "the guard of Contained stacks: ") || !strings.Contains(err.Error(), "Permission denied") || strings.Contains(err.Error(), "Docker's guard drop-in") {
		t.Fatalf("a guard that cannot hold is said: %v", err)
	}
	if readText(t, dropIn) != want || f.called("systemctl daemon-reload") != 1 {
		t.Fatalf("with a Contained stack on the server the drop-in is written without the proof: %q", f.calls)
	}
}

func TestTheLoopWritesNoDropInWithoutProofWhenNoStackIsContained(t *testing.T) {
	useResolvers(t, "", "")
	f := newFake()
	e := testEnv(t, f)
	e.Platform = hostOf(t, f)
	dropIn := filepath.Join(e.Platform.Root, "etc", "systemd", "system", "docker.service.d", "krynodes-guard.conf")
	f.on("systemctl show -p LoadState docker.service", "LoadState=loaded\n")
	f.fail("iptables -w -C KRY-CONTAINED", "")
	f.fail("iptables -w -A KRY-CONTAINED", "iptables: Permission denied (you must be root)")
	err := e.keepGuard(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "Docker's guard drop-in: the guard of Contained stacks: ") || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("a guard that cannot hold is said: %v", err)
	}
	if _, err := os.Stat(dropIn); err == nil || f.called("systemctl daemon-reload") > 0 {
		t.Fatalf("without a Contained stack nothing is written while the guard cannot hold: %q", f.calls)
	}
}
