package update

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var fakeTools = map[string]string{
	"id":        "echo 0\n",
	"uname":     "if [ \"$1\" = -s ]; then echo Linux; else echo x86_64; fi\n",
	"curl":      "out=\"\"\nwhile [ $# -gt 0 ]; do if [ \"$1\" = -o ]; then out=\"$2\"; fi; shift; done\necho artifact > \"$out\"\n",
	"gzip":      "cat \"$2\"\n",
	"sha256sum": "exit 0\n",
	"openssl":   "exit 0\n",
	"install":   "exit 0\n",
	"systemctl": "echo \"systemctl $*\" >> \"$LOG\"\n",
	"kry":       "echo \"kry $*\" >> \"$LOG\"\nif [ \"$1\" = version ]; then echo 0.6.0; fi\nif [ \"$1\" = setup ] && [ -n \"$FAIL_SETUP\" ]; then exit 1; fi\nexit 0\n",
}

func runInstaller(t *testing.T, failSetup bool, args ...string) (string, string, error) {
	t.Helper()
	return runScript(t, "../../../app/public/install.sh", failSetup, args...)
}

func runScript(t *testing.T, script string, failSetup bool, args ...string) (string, string, error) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the installer runs on Linux")
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range fakeTools {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	log := filepath.Join(dir, "log")
	command := exec.Command(shell, append([]string{script}, args...)...)
	command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "LOG="+log, "KRY_BIN="+filepath.Join(bin, "kry"))
	if failSetup {
		command.Env = append(command.Env, "FAIL_SETUP=1")
	}
	output, err := command.CombinedOutput()
	recorded, _ := os.ReadFile(log)
	return string(recorded), string(output), err
}

func TestTheInstallerPassesSetupAfterTheTrustKeys(t *testing.T) {
	log, output, err := runInstaller(t, false, "https://kry.example", "token-1", "--trust", "https://kry.example", "key1", "key2", "--setup", "recommended,docker", "--reboot-hour", "20")
	if err != nil {
		t.Fatalf("%v\n%s", err, output)
	}
	want := "kry enroll --endpoint https://kry.example --token token-1\n" +
		"kry install-service\n" +
		"kry trust --initial --origin https://kry.example key1 key2\n" +
		"kry setup --recommended --docker --reboot-hour 20\n" +
		"systemctl restart krynodes.service\n" +
		"kry version\n"
	if log != want {
		t.Fatalf("got\n%s\nwant\n%s", log, want)
	}
}

func TestTheInstallerRunsSetupWithoutTrustAndGoesOnWhenItFails(t *testing.T) {
	log, output, err := runInstaller(t, true, "https://kry.example", "token-1", "--setup", "docker")
	if err != nil {
		t.Fatalf("%v\n%s", err, output)
	}
	if !strings.Contains(log, "kry setup --docker\nsystemctl restart krynodes.service\n") || strings.Contains(log, "kry trust") {
		t.Fatalf("log\n%s", log)
	}
	if !strings.Contains(output, "Setup did not finish; turn the rest on from the dashboard.") {
		t.Fatalf("output\n%s", output)
	}
}

func TestTheInstallerRefusesBadSetupFlags(t *testing.T) {
	for _, args := range [][]string{
		{"https://kry.example", "token-1", "--setup", "everything"},
		{"https://kry.example", "token-1", "--setup", "docker", "--reboot-hour", "24"},
		{"https://kry.example", "token-1", "--setup"},
		{"https://kry.example", "token-1", "--trust", "https://kry.example", "--setup", "docker"},
	} {
		log, output, err := runInstaller(t, false, args...)
		if err == nil || strings.Contains(log, "kry enroll") {
			t.Fatalf("%q must stop before enrolling:\n%s\n%s", args, log, output)
		}
	}
}

func TestADownloadCutShortRunsNothing(t *testing.T) {
	script, err := os.ReadFile("../../../app/public/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(strings.TrimSuffix(string(script), "\n"), "\n")
	dir := t.TempDir()
	for cut := 1; cut < len(lines); cut++ {
		path := filepath.Join(dir, "install.sh")
		if err := os.WriteFile(path, []byte(strings.Join(lines[:cut], "")), 0o644); err != nil {
			t.Fatal(err)
		}
		if log, _, _ := runScript(t, path, false, "https://kry.example", "token-1"); log != "" {
			t.Fatalf("a download cut after line %d ran:\n%s", cut, log)
		}
	}
}

func TestTheInstallerLeavesAnEnrolledServerAlone(t *testing.T) {
	config := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(config, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRY_CONFIG", config)
	log, output, err := runInstaller(t, false, "https://kry.example", "token-1")
	if err == nil || log != "" || !strings.Contains(output, "already enrolled") || strings.Contains(output, "Downloading") {
		t.Fatalf("err %v log %q output %q", err, log, output)
	}
}
