package service

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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

type watchFixture struct {
	watch   Watch
	dir     string
	pids    []uint32
	calls   []string
	slept   time.Duration
	startOK bool
}

func newWatch(t *testing.T, pids ...uint32) *watchFixture {
	t.Helper()
	f := &watchFixture{dir: t.TempDir(), pids: pids, startOK: true}
	for name, data := range map[string]string{"krynodes.exe": "agent 0.7.25", oldName: "agent 0.7.24"} {
		if err := os.WriteFile(filepath.Join(f.dir, name), []byte(data), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.watch = Watch{
		Executable: filepath.Join(f.dir, "krynodes.exe"),
		Previous:   "0.7.24",
		Stop:       func() error { f.calls = append(f.calls, "stop"); return nil },
		Start: func() error {
			f.calls = append(f.calls, "start")
			if !f.startOK {
				return errors.New("the service did not start")
			}
			return nil
		},
		PID: func() (uint32, error) {
			if len(f.pids) == 0 {
				return 0, nil
			}
			pid := f.pids[0]
			f.pids = f.pids[1:]
			return pid, nil
		},
		Sleep: func(d time.Duration) { f.slept += d },
		Note:  func(line string) { f.calls = append(f.calls, "note: "+line) },
	}
	return f
}

func (f *watchFixture) installed(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(f.watch.Executable)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestAnUpdateThatStaysUpIsKept(t *testing.T) {
	f := newWatch(t, 4242, 4242)
	if err := f.watch.Run("0.7.25"); err != nil {
		t.Fatalf("Run = %v", err)
	}
	if got := f.installed(t); got != "agent 0.7.25" {
		t.Errorf("installed %q", got)
	}
	if !slices.Equal(f.calls, []string{"stop", "start"}) || f.slept != settle+5*time.Second {
		t.Errorf("calls %v, slept %v", f.calls, f.slept)
	}
}

func TestAnUpdateThatDoesNotStayUpPutsThePreviousAgentBack(t *testing.T) {
	for name, pids := range map[string][]uint32{
		"never running":  {0},
		"restarted once": {4242, 5151},
		"died later":     {4242, 0},
	} {
		f := newWatch(t, pids...)
		err := f.watch.Run("0.7.25")
		if err == nil || err.Error() != "Krynodes 0.7.25 did not stay up, so 0.7.24 is back." {
			t.Errorf("%s: Run = %v", name, err)
		}
		if got := f.installed(t); got != "agent 0.7.24" {
			t.Errorf("%s: installed %q", name, got)
		}
		if data, _ := os.ReadFile(filepath.Join(f.dir, stagedName)); string(data) != "agent 0.7.25" {
			t.Errorf("%s: the new agent was not set aside for Tidy: %q", name, data)
		}
		if !slices.Equal(f.calls, []string{"stop", "start", "stop", "note: " + err.Error(), "start"}) {
			t.Errorf("%s: calls %v", name, f.calls)
		}
	}
}

func TestAnUpdateThatCannotStartIsRolledBackAndSaysSo(t *testing.T) {
	f := newWatch(t)
	f.startOK = false
	err := f.watch.Run("0.7.25")
	if err == nil || err.Error() != "Krynodes 0.7.25 did not stay up, so 0.7.24 is back. It did not start: the service did not start" {
		t.Fatalf("Run = %v", err)
	}
	if got := f.installed(t); got != "agent 0.7.24" {
		t.Errorf("installed %q", got)
	}
}

func TestARollbackThatCannotPutThePreviousAgentBackKeepsTheNewOne(t *testing.T) {
	t.Cleanup(func() { rename = os.Rename })
	f := newWatch(t, 0)
	count := 0
	rename = func(from, to string) error {
		count++
		if count == 2 {
			return errors.New("access is denied")
		}
		return os.Rename(from, to)
	}
	err := f.watch.Run("0.7.25")
	if err == nil || !strings.Contains(err.Error(), "0.7.24 could not be put back") {
		t.Fatalf("Run = %v", err)
	}
	if got := f.installed(t); got != "agent 0.7.25" {
		t.Errorf("installed %q, want the new agent left in place", got)
	}
	if !slices.Contains(f.calls, "note: "+err.Error()) {
		t.Errorf("the tray is not told: %v", f.calls)
	}
}

func TestANewerReleaseIsOfferedOnce(t *testing.T) {
	f := newFixture(t)
	f.service.Offer("0.7.25", "0.7.24")
	f.service.Offer("0.7.25", "0.7.24")
	if notes := f.service.Status(0).Notes; !slices.Equal(notes, []string{"Krynodes 0.7.25 is available. Settings, Update Agent installs it."}) {
		t.Fatalf("notes %v", notes)
	}
	if got := f.record().Offered; got != "0.7.25" {
		t.Errorf("offered %q", got)
	}
	for _, versions := range [][2]string{{"0.7.24", "0.7.24"}, {"0.7.23", "0.7.24"}, {"0.7.26", "dev"}, {"nope", "0.7.24"}} {
		f.service.Offer(versions[0], versions[1])
	}
	if notes := f.service.Status(0).Notes; len(notes) != 1 {
		t.Errorf("offered more: %v", notes)
	}
}
