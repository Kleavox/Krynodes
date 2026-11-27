package update

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWriteRequestWritesOnlyWhenTheRequestChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update-request")

	changed, err := WriteRequest(path, "0.5.2", "t1")
	if err != nil || !changed {
		t.Fatalf("first write: changed=%v err=%v", changed, err)
	}
	changed, err = WriteRequest(path, "0.5.2", "t1")
	if err != nil || changed {
		t.Fatalf("repeat write: changed=%v err=%v", changed, err)
	}
	changed, err = WriteRequest(path, "0.5.2", "t2")
	if err != nil || !changed {
		t.Fatalf("retry write: changed=%v err=%v", changed, err)
	}
	content, _ := os.ReadFile(path)
	if string(content) != "0.5.2\nt2\n" {
		t.Fatalf("unexpected request file %q", content)
	}
}

func TestWriteRequestRefusesAnythingButAVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update-request")
	for _, bad := range []string{"../../etc/passwd", "0.5", "v0.5.2", ""} {
		if _, err := WriteRequest(path, bad, "t1"); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

type release struct {
	binary    []byte
	checksum  string
	signature []byte
}

func signedRelease(t *testing.T, private ed25519.PrivateKey, binary []byte) release {
	t.Helper()
	sum := sha256.Sum256(binary)
	return release{
		binary:    binary,
		checksum:  hex.EncodeToString(sum[:]) + "  krynodes-linux-amd64\n",
		signature: ed25519.Sign(private, binary),
	}
}

func gzipped(t *testing.T, data []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

type harness struct {
	options  Options
	mu       sync.Mutex
	runs     []string
	requests []string
	files    map[string][]byte
	serve    func(w http.ResponseWriter, r *http.Request, name string) bool
	health   string
	reported string
	refresh  error
	said     string
}

const asset = "/agent-v0.5.2/krynodes-linux-amd64"

func newHarness(t *testing.T, public ed25519.PublicKey, published release) *harness {
	t.Helper()
	h := &harness{
		files: map[string][]byte{
			asset:             published.binary,
			asset + ".sha256": []byte(published.checksum),
			asset + ".sig":    published.signature,
		},
		health:   "ActiveState=active\nMainPID=42\n",
		reported: "0.5.2\n",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.requests = append(h.requests, r.URL.Path+" "+r.Header.Get("Range"))
		serve := h.serve
		h.mu.Unlock()
		if serve != nil && serve(w, r, r.URL.Path) {
			return
		}
		body, ok := h.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body))
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	binary := filepath.Join(dir, "kry")
	if err := os.WriteFile(binary, []byte("old agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	request := filepath.Join(dir, "update-request")
	if _, err := WriteRequest(request, "0.5.2", "t1"); err != nil {
		t.Fatal(err)
	}
	h.options = Options{
		RequestPath:    request,
		StatusPath:     filepath.Join(dir, "update-status"),
		BinaryPath:     binary,
		Base:           server.URL,
		Arch:           "amd64",
		CurrentVersion: "0.5.1",
		PublicKey:      public,
		Client:         server.Client(),
		Stall:          300 * time.Millisecond,
		Sleep:          func(time.Duration) {},
		Run: func(name string, args ...string) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.runs = append(h.runs, strings.Join(append([]string{filepath.Base(name)}, args...), " "))
			return nil
		},
		Combined: func(name string, args ...string) (string, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.runs = append(h.runs, strings.Join(append([]string{filepath.Base(name)}, args...), " "))
			return h.said, h.refresh
		},
		Output: func(name string, args ...string) (string, error) {
			if filepath.Base(name) == "systemctl" {
				return h.health, nil
			}
			return h.reported, nil
		},
	}
	return h
}

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func contentOf(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(content)
}

func statusOf(t *testing.T, h *harness) Status {
	t.Helper()
	var status Status
	raw, err := os.ReadFile(h.options.StatusPath)
	if err != nil {
		return status
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatal(err)
	}
	return status
}

func TestApplyInstallsASignedReleaseAndRestarts(t *testing.T) {
	public, private := keys(t)
	h := newHarness(t, public, signedRelease(t, private, []byte("new agent")))

	if err := Apply(h.options); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := contentOf(t, h.options.BinaryPath); got != "new agent" {
		t.Fatalf("binary is %q", got)
	}
	if got := contentOf(t, h.options.BinaryPath+".previous"); got != "old agent" {
		t.Fatalf("previous binary is %q", got)
	}
	want := []string{"kry install-service", "systemctl restart krynodes.service"}
	if strings.Join(h.runs, "|") != strings.Join(want, "|") {
		t.Fatalf("ran %#v", h.runs)
	}
	if _, err := os.Stat(h.options.StatusPath); !os.IsNotExist(err) {
		t.Fatalf("a successful update leaves no status: %v", err)
	}
	if leftovers, _ := filepath.Glob(h.options.BinaryPath + ".*.download"); len(leftovers) != 0 {
		t.Fatalf("left %v behind", leftovers)
	}
}

func TestApplyPrefersTheCompressedBinary(t *testing.T) {
	public, private := keys(t)
	h := newHarness(t, public, signedRelease(t, private, []byte("new agent")))
	h.files[asset+".gz"] = gzipped(t, []byte("new agent"))

	if err := Apply(h.options); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := contentOf(t, h.options.BinaryPath); got != "new agent" {
		t.Fatalf("binary is %q", got)
	}
	for _, request := range h.requests {
		if strings.HasPrefix(request, asset+" ") {
			t.Fatalf("downloaded the raw binary too: %v", h.requests)
		}
	}
}

func TestApplyResumesADownloadThatStalls(t *testing.T) {
	public, private := keys(t)
	binary := bytes.Repeat([]byte("new agent "), 4096)
	h := newHarness(t, public, signedRelease(t, private, binary))
	var stalled atomic.Bool
	h.serve = func(w http.ResponseWriter, r *http.Request, name string) bool {
		if name != asset || !stalled.CompareAndSwap(false, true) {
			return false
		}
		w.Header().Set("Content-Length", "40960")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(binary[:10000])
		w.(http.Flusher).Flush()
		time.Sleep(time.Second)
		return true
	}

	if err := Apply(h.options); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := contentOf(t, h.options.BinaryPath); got != string(binary) {
		t.Fatalf("binary has %d bytes", len(got))
	}
	if !strings.Contains(strings.Join(h.requests, "|"), asset+" bytes=10000-") {
		t.Fatalf("did not resume: %v", h.requests)
	}
}

func TestApplyRetriesUntilTheReleaseIsUploaded(t *testing.T) {
	public, private := keys(t)
	h := newHarness(t, public, signedRelease(t, private, []byte("new agent")))
	var missing atomic.Int32
	missing.Store(2)
	h.serve = func(w http.ResponseWriter, r *http.Request, name string) bool {
		if name == asset && missing.Add(-1) >= 0 {
			http.NotFound(w, r)
			return true
		}
		return false
	}

	if err := Apply(h.options); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := contentOf(t, h.options.BinaryPath); got != "new agent" {
		t.Fatalf("binary is %q", got)
	}
}

func TestApplyGivesUpAndSaysWhyAfterItsAttempts(t *testing.T) {
	public, private := keys(t)
	h := newHarness(t, public, signedRelease(t, private, []byte("new agent")))
	delete(h.files, asset)

	if err := Apply(h.options); err == nil {
		t.Fatal("expected a failure")
	}
	status := statusOf(t, h)
	if status.Version != "0.5.2" || !strings.Contains(status.Message, "HTTP 404") {
		t.Fatalf("status %+v", status)
	}
	if got := contentOf(t, h.options.BinaryPath); got != "old agent" {
		t.Fatalf("binary is %q", got)
	}
}

func TestApplyRefusesABinaryThatDoesNotRunHere(t *testing.T) {
	public, private := keys(t)
	h := newHarness(t, public, signedRelease(t, private, []byte("new agent")))
	h.reported = "0.5.1\n"

	if err := Apply(h.options); err == nil {
		t.Fatal("expected a refusal")
	}
	if got := contentOf(t, h.options.BinaryPath); got != "old agent" {
		t.Fatalf("binary is %q", got)
	}
	if len(h.runs) != 0 {
		t.Fatalf("ran %#v", h.runs)
	}
	if status := statusOf(t, h); !strings.Contains(status.Message, "does not run") {
		t.Fatalf("status %+v", status)
	}
}

func TestApplyRollsBackWhenTheNewAgentDoesNotStayUp(t *testing.T) {
	public, private := keys(t)
	h := newHarness(t, public, signedRelease(t, private, []byte("new agent")))
	h.health = "ActiveState=activating\nMainPID=0\n"

	if err := Apply(h.options); err == nil {
		t.Fatal("expected a failure")
	}
	if got := contentOf(t, h.options.BinaryPath); got != "old agent" {
		t.Fatalf("binary is %q", got)
	}
	want := []string{
		"kry install-service", "systemctl restart krynodes.service",
		"kry install-service", "systemctl restart krynodes.service",
	}
	if strings.Join(h.runs, "|") != strings.Join(want, "|") {
		t.Fatalf("ran %#v", h.runs)
	}
	if status := statusOf(t, h); !strings.Contains(status.Message, "rolled back") {
		t.Fatalf("status %+v", status)
	}
}

func TestApplySaysWhyTheServiceUnitsCouldNotBeRefreshed(t *testing.T) {
	public, private := keys(t)
	h := newHarness(t, public, signedRelease(t, private, []byte("new agent")))
	h.refresh = errors.New("exit status 1")
	h.said = "the guard of Contained stacks: iptables DOCKER-USER: iptables: Permission denied" + strings.Repeat("\n", 3)

	err := Apply(h.options)
	if err == nil || !strings.Contains(err.Error(), "refresh service units: exit status 1: the guard of Contained stacks: iptables DOCKER-USER: iptables: Permission denied") || !strings.Contains(err.Error(), "rolled back to 0.5.1") {
		t.Fatalf("the reason of the failure comes with it: %v", err)
	}
	if got := contentOf(t, h.options.BinaryPath); got != "old agent" {
		t.Fatalf("binary is %q", got)
	}
	if status := statusOf(t, h); !strings.Contains(status.Message, "Permission denied") || strings.Contains(status.Message, "\n\n") {
		t.Fatalf("status %+v", status)
	}

	h = newHarness(t, public, signedRelease(t, private, []byte("new agent")))
	h.refresh = errors.New("exit status 1")
	h.said = strings.Repeat("x", 1000) + " END"
	if err := Apply(h.options); err == nil || strings.Contains(err.Error(), strings.Repeat("x", 500)) || !strings.Contains(err.Error(), "END") {
		t.Fatalf("only the tail of a long output is kept: %v", err)
	}

	h = newHarness(t, public, signedRelease(t, private, []byte("new agent")))
	h.refresh = errors.New("exit status 1")
	if err := Apply(h.options); err == nil || !strings.Contains(err.Error(), "refresh service units: exit status 1; rolled back") {
		t.Fatalf("with no output there is nothing to add: %v", err)
	}
}

func TestApplyRefusesAReleaseThatFailsVerification(t *testing.T) {
	public, private := keys(t)
	_, stranger := keys(t)
	good := signedRelease(t, private, []byte("new agent"))

	tampered := good
	tampered.binary = []byte("evil agent")
	foreignKey := signedRelease(t, stranger, []byte("new agent"))
	wrongSum := good
	wrongSum.checksum = strings.Repeat("0", 64) + "  krynodes-linux-amd64\n"

	for name, published := range map[string]release{
		"tampered binary": tampered,
		"foreign key":     foreignKey,
		"wrong checksum":  wrongSum,
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, public, published)
			if err := Apply(h.options); err == nil {
				t.Fatal("expected a refusal")
			}
			if got := contentOf(t, h.options.BinaryPath); got != "old agent" {
				t.Fatalf("binary was replaced with %q", got)
			}
			if len(h.runs) != 0 {
				t.Fatalf("ran %#v", h.runs)
			}
			if leftovers, _ := filepath.Glob(h.options.BinaryPath + ".*.download"); len(leftovers) != 0 {
				t.Fatalf("kept a download that failed verification: %v", leftovers)
			}
		})
	}
}

func TestApplyRefusesDowngradesAndUnknownArchitectures(t *testing.T) {
	public, private := keys(t)
	published := signedRelease(t, private, []byte("new agent"))

	same := newHarness(t, public, published)
	same.options.CurrentVersion = "0.5.2"
	if err := Apply(same.options); err == nil {
		t.Fatal("reinstalled the running version")
	}

	older := newHarness(t, public, published)
	older.options.CurrentVersion = "0.6.0"
	if err := Apply(older.options); err == nil {
		t.Fatal("downgraded the agent")
	}

	arch := newHarness(t, public, published)
	arch.options.Arch = "mips"
	if err := Apply(arch.options); err == nil {
		t.Fatal("accepted an unknown architecture")
	}
}

func TestReadStatusOnlyReportsAFailureForANewerVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update-status")
	if _, ok := ReadStatus(path, "0.5.1"); ok {
		t.Fatal("no file, no status")
	}
	if err := os.WriteFile(path, []byte(`{"version":"0.5.2","message":"download stalled","at":"t"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	status, ok := ReadStatus(path, "0.5.1")
	if !ok || status.Message != "download stalled" {
		t.Fatalf("status %+v %v", status, ok)
	}
	if _, ok := ReadStatus(path, "0.5.2"); ok {
		t.Fatal("a status for the running version is stale")
	}
}

func TestTheEmbeddedReleaseKeyIsUsable(t *testing.T) {
	key, err := PublicKey()
	if err != nil || len(key) != ed25519.PublicKeySize {
		t.Fatalf("release key: %v (%d bytes)", err, len(key))
	}
}
