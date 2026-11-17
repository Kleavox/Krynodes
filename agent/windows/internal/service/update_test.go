package service

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type releaseFixture struct {
	release Release
	files   map[string][]byte
	ran     []string
}

func newRelease(t *testing.T, current, latest string) *releaseFixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(t.TempDir(), "krynodes.exe")
	if err := os.WriteFile(executable, []byte("running agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	binary := []byte("agent " + latest)
	sum := sha256.Sum256(binary)
	url := ReleaseURL(latest, releaseFile)
	fixture := &releaseFixture{files: map[string][]byte{
		url:             binary,
		url + ".sha256": []byte(hex.EncodeToString(sum[:]) + "  " + releaseFile + "\n"),
		url + ".sig":    ed25519.Sign(private, binary),
	}}
	fixture.release = Release{
		Current:    current,
		Key:        public,
		Executable: executable,
		Latest:     func(context.Context) (string, error) { return latest, nil },
		Fetch: func(_ context.Context, url string) ([]byte, error) {
			if data, ok := fixture.files[url]; ok {
				return data, nil
			}
			return nil, errors.New("HTTP 404")
		},
		Run: func(path string) (string, error) {
			fixture.ran = append(fixture.ran, path)
			data, err := os.ReadFile(path)
			return strings.TrimPrefix(string(data), "agent ") + "\n", err
		},
		Write: func(path string, data []byte) error {
			return os.WriteFile(path, data, 0o755)
		},
	}
	return fixture
}

func (f *releaseFixture) untouched(t *testing.T) {
	t.Helper()
	dir := filepath.Dir(f.release.Executable)
	if data, err := os.ReadFile(f.release.Executable); err != nil || string(data) != "running agent" {
		t.Errorf("the running agent was replaced: %q, %v", data, err)
	}
	for _, name := range []string{stagedName, oldName} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s was left behind: %v", name, err)
		}
	}
}

func TestUpdateRefusesAFileWithoutTheReleaseSignature(t *testing.T) {
	fixture := newRelease(t, "0.7.24", "0.7.25")
	delete(fixture.files, ReleaseURL("0.7.25", releaseFile)+".sig")
	if _, err := fixture.release.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "no release signature") {
		t.Fatalf("Update = %v, want a refusal for the missing signature", err)
	}
	if len(fixture.ran) != 0 {
		t.Errorf("an unsigned file was run: %v", fixture.ran)
	}
	fixture.untouched(t)
}

func TestUpdateRefusesAWrongSignatureAndAWrongChecksum(t *testing.T) {
	url := ReleaseURL("0.7.25", releaseFile)
	_, stranger, _ := ed25519.GenerateKey(nil)
	for name, spoil := range map[string]func(map[string][]byte){
		"another key signed it": func(files map[string][]byte) { files[url+".sig"] = ed25519.Sign(stranger, files[url]) },
		"the file was changed":  func(files map[string][]byte) { files[url] = []byte("agent 0.7.25 with something added") },
		"an empty signature":    func(files map[string][]byte) { files[url+".sig"] = nil },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newRelease(t, "0.7.24", "0.7.25")
			spoil(fixture.files)
			if _, err := fixture.release.Update(context.Background()); err == nil || !strings.HasPrefix(err.Error(), "refusing 0.7.25") {
				t.Fatalf("Update = %v, want a refusal", err)
			}
			if len(fixture.ran) != 0 {
				t.Errorf("a refused file was run: %v", fixture.ran)
			}
			fixture.untouched(t)
		})
	}
}

func TestUpdateRefusesAVersionThatIsNotNewer(t *testing.T) {
	for _, latest := range []string{"0.7.24", "0.7.9", "0.6.30"} {
		fixture := newRelease(t, "0.7.24", latest)
		if _, err := fixture.release.Update(context.Background()); !errors.Is(err, ErrUpToDate) {
			t.Errorf("latest %s: Update = %v, want ErrUpToDate", latest, err)
		}
		fixture.untouched(t)
	}
	dev := newRelease(t, "dev", "0.7.25")
	if _, err := dev.release.Update(context.Background()); err == nil || errors.Is(err, ErrUpToDate) {
		t.Errorf("a dev build: Update = %v, want a refusal", err)
	}
	dev.untouched(t)
}

func TestUpdateRefusesANewFileThatReportsAnotherVersion(t *testing.T) {
	fixture := newRelease(t, "0.7.24", "0.7.25")
	fixture.release.Run = func(path string) (string, error) {
		fixture.ran = append(fixture.ran, path)
		return "0.7.26\n", nil
	}
	if _, err := fixture.release.Update(context.Background()); err == nil || !strings.Contains(err.Error(), `reports "0.7.26"`) {
		t.Fatalf("Update = %v, want a refusal of the reported version", err)
	}
	if len(fixture.ran) != 1 || filepath.Base(fixture.ran[0]) != stagedName {
		t.Errorf("ran %v, want the staged file once", fixture.ran)
	}
	fixture.untouched(t)
}

func TestUpdateSwapsInASignedNewerAgentAndKeepsTheOldOne(t *testing.T) {
	fixture := newRelease(t, "0.7.24", "0.7.25")
	got, err := fixture.release.Update(context.Background())
	if err != nil || got != "0.7.25" {
		t.Fatalf("Update = %q, %v", got, err)
	}
	dir := filepath.Dir(fixture.release.Executable)
	if data, _ := os.ReadFile(fixture.release.Executable); string(data) != "agent 0.7.25" {
		t.Errorf("the agent in place is %q", data)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, oldName)); string(data) != "running agent" {
		t.Errorf("the old agent is %q", data)
	}
	Tidy(fixture.release.Executable)
	if _, err := os.Stat(filepath.Join(dir, oldName)); !os.IsNotExist(err) {
		t.Errorf("Tidy left the old agent: %v", err)
	}
}

func TestLatestIsReadFromTheReleaseRedirect(t *testing.T) {
	for location, want := range map[string]string{
		"https://github.com/Kleavox/Krynodes/releases/tag/agent-v0.7.25":   "0.7.25",
		"https://github.com/Kleavox/Krynodes/releases/tag/app-v1.0.0":      "",
		"https://github.com/Kleavox/Krynodes/releases/tag/agent-v0.7.25.1": "",
		"": "",
	} {
		got, ok := LatestFrom(location)
		if got != want || ok != (want != "") {
			t.Errorf("LatestFrom(%q) = %q, %v; want %q", location, got, ok, want)
		}
	}
}

func TestAnOldAgentThatCannotBeDeletedDoesNotBlockTheUpdate(t *testing.T) {
	fixture := newRelease(t, "0.7.24", "0.7.25")
	dir := filepath.Dir(fixture.release.Executable)
	if err := os.MkdirAll(filepath.Join(dir, oldName, "held"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := fixture.release.Update(context.Background()); err != nil || got != "0.7.25" {
		t.Fatalf("Update = %q, %v", got, err)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, oldName)); string(data) != "running agent" {
		t.Errorf("the old agent is %q", data)
	}
	moved, _ := filepath.Glob(filepath.Join(dir, "krynodes.old.*.exe"))
	if len(moved) != 1 {
		t.Fatalf("the held old agent went to %v", moved)
	}
	Tidy(fixture.release.Executable)
	if left, _ := filepath.Glob(filepath.Join(dir, "krynodes.old*.exe")); len(left) != 0 {
		t.Errorf("Tidy left %v", left)
	}
}

func TestAFailedSwapPutsTheRunningAgentBack(t *testing.T) {
	failing := func(fail int) func(string, string) error {
		count := 0
		return func(from, to string) error {
			count++
			if count >= fail {
				return errors.New("access is denied")
			}
			return os.Rename(from, to)
		}
	}
	t.Cleanup(func() { rename = os.Rename })

	fixture := newRelease(t, "0.7.24", "0.7.25")
	rename = failing(2)
	_, err := fixture.release.Update(context.Background())
	if err == nil || !strings.Contains(err.Error(), "putting the previous agent back also failed") {
		t.Fatalf("Update = %v, want both failures named", err)
	}

	fixture = newRelease(t, "0.7.24", "0.7.25")
	count := 0
	rename = func(from, to string) error {
		count++
		if count == 2 {
			return errors.New("access is denied")
		}
		return os.Rename(from, to)
	}
	_, err = fixture.release.Update(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "put the new agent in place") || strings.Contains(err.Error(), "also failed") {
		t.Fatalf("Update = %v, want the swap refused and rolled back", err)
	}
	if data, _ := os.ReadFile(fixture.release.Executable); string(data) != "running agent" {
		t.Errorf("the running agent was not put back: %q", data)
	}
}
