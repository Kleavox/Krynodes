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
	command := exec.Command(shell, append([]string{"../../../app/public/install.sh"}, args...)...)
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
