package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestTheInstallerChecksSignaturesWithTheReleaseKey(t *testing.T) {
	script, err := os.ReadFile("../../../app/public/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(script, []byte("-----BEGIN PUBLIC KEY-----"))
	if start < 0 {
		t.Fatal("the installer carries no release key")
	}
	block, _ := pem.Decode(script[start:])
	if block == nil {
		t.Fatal("the installer's release key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	want, err := PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if key, ok := parsed.(ed25519.PublicKey); !ok || !key.Equal(want) {
		t.Fatal("the installer's key must be agent/internal/update/release.pub")
	}
	if !bytes.Contains(script, []byte("openssl pkeyutl -verify")) || !bytes.Contains(script, []byte(".sig")) {
		t.Fatal("the installer must verify the release signature")
	}
}

var fakeTools = map[string]string{
	"id":        "echo 0\n",
	"uname":     "if [ \"$1\" = -s ]; then echo Linux; else echo x86_64; fi\n",
	"curl":      "out=\"\"\nwhile [ $# -gt 0 ]; do if [ \"$1\" = -o ]; then out=\"$2\"; fi; shift; done\necho artifact > \"$out\"\n",
	"gzip":      "cat \"$2\"\n",
	"sha256sum": "exit 0\n",
	"openssl":   "exit 0\n",
	"install":   "echo \"install $*\" >> \"$LOG\"\n",
	"systemctl": "echo \"systemctl $*\" >> \"$LOG\"\n",
	"kry":       "echo \"kry $*\" >> \"$LOG\"\nif [ \"$1\" = version ]; then echo 0.7.90; fi\nif [ \"$1\" = enroll ] && [ -n \"${FAIL_ENROLL:-}\" ]; then exit 1; fi\nexit 0\n",
}

const (
	trustTokens = "AAEC.-7.MFkw,EBES.-257.MIIB"
	installArgs = "--endpoint https://kry.example --token token-1 --origin https://dash.example --trust " + trustTokens
)

func runInstaller(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	return runScript(t, "../../../app/public/install.sh", args...)
}

func runScript(t *testing.T, script string, args ...string) (string, string, error) {
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
	config := os.Getenv("KRY_CONFIG")
	if config == "" {
		config = filepath.Join(dir, "config.json")
	}
	command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "LOG="+log, "KRY_BIN="+filepath.Join(bin, "kry"), "KRY_CONFIG="+config)
	output, err := command.CombinedOutput()
	recorded, _ := os.ReadFile(log)
	return strings.ReplaceAll(string(recorded), bin+"/", ""), string(output), err
}

const wantLog = "install -m 0755 TMP/krynodes-linux-amd64 kry\n" +
	"kry enroll --endpoint https://kry.example --token token-1 --origin https://dash.example --trust " + trustTokens + "\n" +
	"kry install-service\n" +
	"kry version\n"

func normalized(log string) string {
	lines := strings.Split(log, "\n")
	for index, line := range lines {
		if strings.HasPrefix(line, "install -m 0755 ") {
			fields := strings.Fields(line)
			lines[index] = "install -m 0755 TMP/" + filepath.Base(fields[3]) + " " + fields[4]
		}
	}
	return strings.Join(lines, "\n")
}

func TestTheInstallerEnrollsWithTheTrustAndStartsTheService(t *testing.T) {
	log, output, err := runInstaller(t, strings.Fields(installArgs)...)
	if err != nil {
		t.Fatalf("%v\n%s", err, output)
	}
	if got := normalized(log); got != wantLog {
		t.Fatalf("got\n%s\nwant\n%s", got, wantLog)
	}
	if !strings.Contains(output, "Krynodes agent 0.7.90 is running.") {
		t.Fatalf("output\n%s", output)
	}
}

func TestAFailedEnrollmentStartsNothing(t *testing.T) {
	t.Setenv("FAIL_ENROLL", "1")
	log, output, err := runInstaller(t, strings.Fields(installArgs)...)
	if err == nil || strings.Contains(log, "install-service") {
		t.Fatalf("%v\nlog\n%s\noutput\n%s", err, log, output)
	}
}

func servedInstaller(t *testing.T) string {
	t.Helper()
	script, err := os.ReadFile("../../../app/public/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	served := strings.Replace(string(script), "\nmain \"$@\"\n", "\n{\n  kry_args='"+installArgs+"'\n  main $kry_args\n}\n", 1)
	if served == string(script) {
		t.Fatal("install.sh no longer ends with main \"$@\"; the Worker cannot serve it")
	}
	return served
}

func TestTheServedInstallerRunsWithTheArgumentsItCarries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(path, []byte(servedInstaller(t)), 0o644); err != nil {
		t.Fatal(err)
	}
	log, output, err := runScript(t, path)
	if err != nil {
		t.Fatalf("%v\n%s", err, output)
	}
	if got := normalized(log); got != wantLog {
		t.Fatalf("got\n%s\nwant\n%s", got, wantLog)
	}
}

func TestAServedInstallerCutShortRunsNothing(t *testing.T) {
	served := servedInstaller(t)
	start := strings.LastIndex(served, "\n{\n")
	dir := t.TempDir()
	for cut := start; cut < len(served)-1; cut++ {
		path := filepath.Join(dir, "install.sh")
		if err := os.WriteFile(path, []byte(served[:cut]), 0o644); err != nil {
			t.Fatal(err)
		}
		if log, _, _ := runScript(t, path); log != "" {
			t.Fatalf("a download cut at byte %d (%q) ran:\n%s", cut, served[start:cut], log)
		}
	}
}

func TestTheInstallerRefusesBadFlags(t *testing.T) {
	base := strings.Fields(installArgs)
	without := func(flag string) []string {
		var kept []string
		for index := 0; index < len(base); index += 2 {
			if base[index] != flag {
				kept = append(kept, base[index], base[index+1])
			}
		}
		return kept
	}
	for _, args := range [][]string{
		nil,
		without("--endpoint"),
		without("--token"),
		without("--origin"),
		without("--trust"),
		append(without("--trust"), "--trust"),
		append(slices.Clone(base), "--setup", "recommended"),
		append(slices.Clone(base), "extra"),
		append(without("--trust"), "--trust", "AAEC.-7.MFkw;reboot"),
		append(without("--trust"), "--trust", "AAEC.-7.MFkw EBES.-7.MIIB"),
		append(without("--token"), "--token", "token 1"),
		append(without("--endpoint"), "--endpoint", "https://kry.example;id"),
		append(without("--origin"), "--origin", "dash.example"),
	} {
		log, output, err := runInstaller(t, args...)
		if err == nil || log != "" || strings.Contains(output, "Downloading") {
			t.Fatalf("%q must stop before it downloads:\nlog %s\noutput %s", args, log, output)
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
		if log, _, _ := runScript(t, path, strings.Fields(installArgs)...); log != "" {
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
	log, output, err := runInstaller(t, strings.Fields(installArgs)...)
	if err == nil || log != "" || !strings.Contains(output, "already enrolled") || strings.Contains(output, "Downloading") {
		t.Fatalf("err %v log %q output %q", err, log, output)
	}
}
