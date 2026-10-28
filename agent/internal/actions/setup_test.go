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

const upgradesInstall = "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -q unattended-upgrades"

func setupServer(t *testing.T) (Executor, *fakeRun) {
	t.Helper()
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	rootFile(t, executor, "/etc/os-release", trixie)
	rootFile(t, executor, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
	run.failing["docker --version"] = ""
	run.respond["dpkg --print-architecture"] = "amd64\n"
	run.respond["docker version --format {{.Client.Version}}"] = "28.4.0\n"
	executor.Fetch = dockerFetch
	return executor, run
}

func dockerFetch(_ context.Context, url string) ([]byte, error) {
	if strings.HasSuffix(url, "/Release") {
		return []byte("Origin: Docker\nArchitectures: amd64 arm64\n"), nil
	}
	return []byte("KEY"), nil
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

func TestSetupGetsTheServerReadyForThePrivateNetwork(t *testing.T) {
	executor, _ := networkExecutor(t)
	got := runSetup(t, executor, SetupOptions{Network: "10.88.0.0/24"}, false, false)
	if !strings.HasSuffix(got, "✓ Private network ready · it joins when you press Join on the dashboard\n") {
		t.Fatalf("got\n%s", got)
	}
	if record := executor.readNetwork(); record.Prepared == nil || record.Prepared.Port != 51821 || record.Key == "" {
		t.Fatalf("record %+v", record)
	}

	executor, run := networkExecutor(t)
	run.respond["docker network ls -q"] = "n1\n"
	run.respond["docker network inspect --format {{range .IPAM.Config}}{{.Subnet}} {{end}} n1"] = "10.88.0.0/24 \n"
	if got := runSetup(t, executor, SetupOptions{Network: "10.88.0.0/24"}, false, false); !strings.HasSuffix(got, "✗ Private network: 10.88.0.0/24 is already used on this server\n") {
		t.Fatalf("got\n%s", got)
	}
}

func TestSetupTurnsOnRestartWhenNeededAfterSecurityUpdates(t *testing.T) {
	for _, hook := range []bool{true, false} {
		executor, run := setupServer(t)
		if hook {
			run.effects = map[string]func(){upgradesInstall: func() {
				rootFile(t, executor, "/etc/kernel/postinst.d/unattended-upgrades", "")
			}}
		}
		got := runSetup(t, executor, SetupOptions{Recommended: true, RebootHour: hour(20)}, false, false)
		want := []string{"✓ Automatic security updates", "✓ Restart when needed · 20:00 UTC", "✓ SSH keys only"}
		if !hook {
			want = []string{"✓ Automatic security updates", "✗ Restart when needed: Nothing on this server marks when a restart is needed. Turn on Security updates first.", "✓ SSH keys only"}
		}
		for _, line := range want {
			if !strings.Contains(got, line) {
				t.Fatalf("hook %v: missing %q in\n%s", hook, line, got)
			}
		}
	}
}

func TestSetupRunsTheRecommendedStepsAndDocker(t *testing.T) {
	executor, _ := setupServer(t)
	rootFile(t, executor, "/etc/kernel/postinst.d/unattended-upgrades", "")
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
	ufwComesUp(run)
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

func TestSetupRunsOnANewerVersionWithoutAsking(t *testing.T) {
	newer := strings.ReplaceAll(strings.ReplaceAll(trixie, "13", "14"), "trixie", "forky")
	executor, _ := setupServer(t)
	rootFile(t, executor, "/etc/os-release", newer)
	var out strings.Builder
	var questions []string
	ask := func(text string) (bool, bool) {
		questions = append(questions, text)
		return false, true
	}
	if err := executor.Setup(context.Background(), SetupOptions{Recommended: true}, &out, ask); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if slices.ContainsFunc(questions, func(question string) bool { return strings.Contains(question, "anyway") }) {
		t.Fatalf("asked %q", questions)
	}
	if strings.Contains(got, "newer than") || strings.Contains(got, "Setup held") || !strings.Contains(got, "Automatic security updates") {
		t.Fatalf("got\n%s", got)
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
