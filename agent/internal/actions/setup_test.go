package actions

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const trixie = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\nID=debian\n"

func setupServer(t *testing.T) (Executor, *fakeRun) {
	t.Helper()
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	rootFile(t, executor, "/etc/os-release", trixie)
	rootFile(t, executor, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
	run.failing["docker --version"] = ""
	run.respond["dpkg --print-architecture"] = "amd64\n"
	run.respond["docker version --format {{.Client.Version}}"] = "28.4.0\n"
	executor.Fetch = func(context.Context, string) ([]byte, error) { return []byte("KEY"), nil }
	return executor, run
}

func runSetup(t *testing.T, executor Executor, options SetupOptions, answer bool, asked bool) string {
	t.Helper()
	var out strings.Builder
	question := ""
	ask := func(text string) (bool, bool) {
		question = text
		return answer, asked
	}
	if err := executor.Setup(context.Background(), options, &out, ask); err != nil {
		t.Fatal(err)
	}
	if question != "" {
		out.WriteString("asked: " + question + "\n")
	}
	return out.String()
}

func hour(value int) *int { return &value }

func TestSetupRunsTheRecommendedStepsAndDocker(t *testing.T) {
	executor, _ := setupServer(t)
	writeJSON(executor.StateDir, "security.json", securityState{}, 0o640)
	got := runSetup(t, executor, SetupOptions{Recommended: true, Docker: true, RebootHour: hour(20)}, false, false)
	want := "Detected: Debian GNU/Linux 13 (trixie) (apt, ufw)\n" +
		"✓ Automatic security updates\n" +
		"✓ Restart when needed · 20:00 UTC\n" +
		"✓ SSH keys only\n" +
		"✓ Block repeated login failures\n" +
		"– Firewall already on\n" +
		"✓ Docker 28.4.0 with Compose\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if applied := executor.appliedRecipes(); !slices.Equal(applied, []string{"fail2ban", "reboot-window", "security-updates", "ssh-keys-only"}) {
		t.Fatalf("applied %q", applied)
	}
	if window, _ := readState[rebootWindow](executor.StateDir, "reboot.json"); window.Hour == nil || *window.Hour != 20 {
		t.Fatalf("window %#v", window)
	}
	for name, present := range map[string]bool{"security.json": false, "docker.json": true} {
		if _, err := os.Stat(filepath.Join(executor.StateDir, name)); (err == nil) != present {
			t.Fatalf("%s present %v", name, err == nil)
		}
	}
}

func firewallSetup(t *testing.T, answer func(question string) (bool, bool)) (Executor, *fakeRun, string, []string) {
	t.Helper()
	executor, run := setupServer(t)
	rootFile(t, executor, "/etc/ufw/ufw.conf", "ENABLED=no\n")
	run.respond[listening] = manyListeners
	var questions []string
	var out strings.Builder
	ask := func(question string) (bool, bool) {
		questions = append(questions, question)
		return answer(question)
	}
	if err := executor.Setup(context.Background(), SetupOptions{Recommended: true, RebootHour: hour(20)}, &out, ask); err != nil {
		t.Fatal(err)
	}
	return executor, run, out.String(), questions
}

func TestSetupTurnsTheFirewallOnAndAsksAboutEachPublicPort(t *testing.T) {
	executor, run, got, questions := firewallSetup(t, func(question string) (bool, bool) {
		return strings.HasPrefix(question, "Keep 80/tcp "), true
	})
	want := []string{
		"Keep 80/tcp (nginx) open to everyone? [y/N] ",
		"Keep 443/tcp (AdGuardHome) open to everyone? [y/N] ",
		"Keep 3000/tcp (AdGuardHome) open to everyone? [y/N] ",
		"Keep 41641/udp (tailscaled) open to everyone? [y/N] ",
		"Keep 8080/tcp (app) open to everyone? [y/N] ",
		"Keep 9000/tcp (minio) open to everyone? [y/N] ",
		"Keep 5432/tcp (postgres) open to everyone? [y/N] ",
	}
	if !slices.Equal(questions, want) {
		t.Fatalf("questions\n%q", questions)
	}
	if !strings.Contains(got, "✓ Firewall · also open: 80/tcp\n") {
		t.Fatalf("got\n%s", got)
	}
	calls := strings.Join(run.calls, "\n")
	for _, call := range []string{"ufw allow 22/tcp comment krynodes", "ufw allow 80/tcp comment krynodes", "ufw --force enable"} {
		if !strings.Contains(calls, call) {
			t.Fatalf("missing %q in\n%s", call, calls)
		}
	}
	if strings.Contains(calls, "ufw allow 443/tcp") {
		t.Fatalf("443 was not kept:\n%s", calls)
	}
	if !slices.Contains(executor.appliedRecipes(), "firewall") {
		t.Fatalf("applied %q", executor.appliedRecipes())
	}
}

func TestSetupWithoutATerminalKeepsTheOpenPortsOpen(t *testing.T) {
	_, run, got, _ := firewallSetup(t, func(string) (bool, bool) { return false, false })
	open := "80/tcp, 443/tcp, 3000/tcp, 41641/udp, 8080/tcp, 9000/tcp, 5432/tcp"
	if !strings.Contains(got, "No terminal to ask on, so "+open+" stay open.\n") || !strings.Contains(got, "✓ Firewall · also open: "+open+"\n") {
		t.Fatalf("got\n%s", got)
	}
	if !strings.Contains(strings.Join(run.calls, "\n"), "ufw allow 5432/tcp comment krynodes") {
		t.Fatalf("calls\n%s", strings.Join(run.calls, "\n"))
	}
}

func TestSetupSkipsWhatIsOnAndGoesOnAfterAFailure(t *testing.T) {
	executor, run := setupServer(t)
	writeJSON(executor.StateDir, "recipes.json", recipeState{Applied: map[string]appliedRecipe{"fail2ban": {At: executorNow}}}, 0o640)
	os.Remove(executor.path("/root/.ssh/authorized_keys"))
	run.failing["env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -q unattended-upgrades"] = "E: Unable to locate package"
	got := runSetup(t, executor, SetupOptions{Recommended: true}, false, false)
	for _, line := range []string{
		"✗ Automatic security updates: ",
		"– Restart when needed skipped: no restart hour was given\n",
		"– SSH keys only skipped: first let root or a sudo user log in over SSH with a key\n",
		"– Block repeated login failures already on\n",
	} {
		if !strings.Contains(got, line) {
			t.Fatalf("missing %q in\n%s", line, got)
		}
	}
	if strings.Contains(got, "Docker") {
		t.Fatalf("Docker was not asked for:\n%s", got)
	}
}

func TestSetupAsksOnAnUnverifiedVersion(t *testing.T) {
	newer := strings.ReplaceAll(strings.ReplaceAll(trixie, "13", "14"), "trixie", "forky")
	options := SetupOptions{Recommended: true, Docker: true, RebootHour: hour(20), Command: "kry setup --recommended --docker --reboot-hour 20"}
	for _, answer := range []struct {
		yes, asked bool
		held       bool
	}{{true, true, false}, {false, true, true}, {false, false, true}} {
		executor, _ := setupServer(t)
		rootFile(t, executor, "/etc/os-release", newer)
		got := runSetup(t, executor, options, answer.yes, answer.asked)
		if !strings.Contains(got, "Debian GNU/Linux 14 is newer than the versions Krynodes has checked (11 to 13).\n") || !strings.Contains(got, "asked: Run the setup anyway? [y/N] ") {
			t.Fatalf("%+v:\n%s", answer, got)
		}
		held := strings.Contains(got, "Setup held. Run it later with: sudo kry setup --recommended --docker --reboot-hour 20 --anyway\n")
		if held != answer.held || strings.Contains(got, "✓") == answer.held {
			t.Fatalf("%+v:\n%s", answer, got)
		}
	}
	executor, _ := setupServer(t)
	rootFile(t, executor, "/etc/os-release", newer)
	options.Anyway = true
	if got := runSetup(t, executor, options, false, false); strings.Contains(got, "asked:") || !strings.Contains(got, "✓ Automatic security updates") {
		t.Fatalf("--anyway runs without a question:\n%s", got)
	}
}

func TestSetupOnAnUnsupportedOSSkipsEverything(t *testing.T) {
	executor, run := setupServer(t)
	rootFile(t, executor, "/etc/os-release", "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME=\"Alpine Linux v3.20\"\n")
	before := len(run.calls)
	got := runSetup(t, executor, SetupOptions{Recommended: true, Docker: true}, false, false)
	if got != "Detected: Alpine Linux v3.20\nProtections and Docker setup support Debian, Ubuntu and RHEL-family servers; skipped.\n" || len(run.calls) != before {
		t.Fatalf("got\n%s", got)
	}
}
