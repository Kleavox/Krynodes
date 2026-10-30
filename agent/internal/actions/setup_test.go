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

func runSetup(t *testing.T, executor Executor, options SetupOptions) string {
	t.Helper()
	var out strings.Builder
	if err := executor.Setup(context.Background(), options, &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func hour(value int) *int { return &value }

func TestSetupGetsTheServerReadyForThePrivateNetwork(t *testing.T) {
	executor, _ := networkExecutor(t)
	got := runSetup(t, executor, SetupOptions{Network: "10.88.0.0/24"})
	if !strings.HasSuffix(got, "✓ Private network ready · it joins when you press Join on the dashboard\n") {
		t.Fatalf("got\n%s", got)
	}
	if record := executor.readNetwork(); record.Prepared == nil || record.Prepared.Port != 51821 || record.Key == "" {
		t.Fatalf("record %+v", record)
	}

	executor, run := networkExecutor(t)
	run.respond["docker network ls -q"] = "n1\n"
	run.respond["docker network inspect --format {{range .IPAM.Config}}{{.Subnet}} {{end}} n1"] = "10.88.0.0/24 \n"
	if got := runSetup(t, executor, SetupOptions{Network: "10.88.0.0/24"}); !strings.HasSuffix(got, "✗ Private network: 10.88.0.0/24 is already used on this server\n") {
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
		got := runSetup(t, executor, SetupOptions{Recommended: true, RebootHour: hour(20)})
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
	executor, run := setupServer(t)
	run.respond["ufw status"] = "Status: active\n\n22/tcp ALLOW Anywhere # krynodes\n"
	rootFile(t, executor, "/etc/kernel/postinst.d/unattended-upgrades", "")
	writeJSON(executor.StateDir, "security.json", securityState{}, 0o640)
	got := runSetup(t, executor, SetupOptions{Recommended: true, Docker: true, RebootHour: hour(20)})
	want := "Detected: Debian GNU/Linux 13 (trixie) (apt, ufw)\n" +
		"✓ Automatic security updates\n" +
		"✓ Restart when needed · 20:00 UTC\n" +
		"✓ SSH keys only\n" +
		"✓ Block repeated login failures\n" +
		"✓ Firewall · closed\n" +
		"✓ Docker 28.4.0 with Compose\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if applied := executor.appliedRecipes(); !slices.Equal(applied, []string{"fail2ban", "firewall", "reboot-window", "security-updates", "ssh-keys-only"}) {
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

func firewallSetup(t *testing.T, enabled bool) (Executor, *fakeRun) {
	t.Helper()
	executor, run := setupServer(t)
	rootFile(t, executor, "/etc/ufw/ufw.conf", "ENABLED=no\n")
	run.respond[listening] = manyListeners
	ufwComesUp(run)
	if enabled {
		rootFile(t, executor, "/etc/ufw/ufw.conf", "ENABLED=yes\n")
		run.respond["ufw status"] = "Status: active\n\n22/tcp ALLOW Anywhere # krynodes\n"
		run.respond["ufw show added"] = ufwHeader + "ufw allow 22/tcp\nufw allow 80/tcp\nufw allow 443/tcp\nufw allow OpenSSH\n"
	}
	return executor, run
}

func TestSetupClosesTheFirewallWithoutAskingAboutPorts(t *testing.T) {
	executor, run := firewallSetup(t, false)
	got := runSetup(t, executor, SetupOptions{Recommended: true, RebootHour: hour(20)})
	if !strings.Contains(got, "✓ Firewall · closed\n") || strings.Contains(got, "Keep") || strings.Contains(got, "No terminal") {
		t.Fatalf("got\n%s", got)
	}
	calls := strings.Join(run.calls, "\n")
	for _, call := range []string{"ufw allow 22/tcp comment krynodes", "ufw default deny incoming", "ufw --force enable"} {
		if !strings.Contains(calls, call) {
			t.Fatalf("missing %q in\n%s", call, calls)
		}
	}
	for _, port := range []string{"80/tcp", "443/tcp", "5432/tcp"} {
		if strings.Contains(calls, "ufw allow "+port) {
			t.Fatalf("%s was opened:\n%s", port, calls)
		}
	}
	if state := executor.readFirewall(); !state.Closed || len(state.Open) != 0 || !slices.Contains(executor.appliedRecipes(), "firewall") {
		t.Fatalf("state %+v applied %q", state, executor.appliedRecipes())
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "publish.v4")); err != nil {
		t.Fatalf("published ports stay open: %v", err)
	}
}

func TestSetupAdoptsAFirewallAlreadyOn(t *testing.T) {
	executor, run := firewallSetup(t, true)
	got := runSetup(t, executor, SetupOptions{Recommended: true, RebootHour: hour(20)})
	if !strings.Contains(got, "✓ Firewall · closed · kept open: 80/tcp, 443/tcp\n") {
		t.Fatalf("got\n%s", got)
	}
	if slices.Contains(run.calls, "ufw --force enable") {
		t.Fatalf("an active firewall was enabled again: %q", run.calls)
	}
	state := executor.readFirewall()
	if !state.Closed || len(state.Open) != 2 || state.Open[1].Key() != "443/tcp" || !slices.Equal(state.Other, []string{"allow OpenSSH"}) {
		t.Fatalf("state %+v", state)
	}
}

func TestSetupSkipsWhatIsOnAndGoesOnAfterAFailure(t *testing.T) {
	executor, run := setupServer(t)
	writeJSON(executor.StateDir, "recipes.json", recipeState{Applied: map[string]appliedRecipe{"fail2ban": {At: executorNow}}}, 0o640)
	os.Remove(executor.path("/root/.ssh/authorized_keys"))
	run.failing["env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -q unattended-upgrades"] = "E: Unable to locate package"
	got := runSetup(t, executor, SetupOptions{Recommended: true})
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
	got := runSetup(t, executor, SetupOptions{Recommended: true})
	if strings.Contains(got, "newer than") || strings.Contains(got, "Setup held") || !strings.Contains(got, "Automatic security updates") {
		t.Fatalf("got\n%s", got)
	}
}

func TestSetupOnAnUnsupportedOSSkipsEverything(t *testing.T) {
	executor, run := setupServer(t)
	rootFile(t, executor, "/etc/os-release", "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME=\"Alpine Linux v3.20\"\n")
	before := len(run.calls)
	got := runSetup(t, executor, SetupOptions{Recommended: true, Docker: true})
	if got != "Detected: Alpine Linux v3.20\nProtections and Docker setup support Debian, Ubuntu and RHEL-family servers; skipped.\n" || len(run.calls) != before {
		t.Fatalf("got\n%s", got)
	}
}

func TestSetupTurnsOnSELinuxOrAppArmorAndSaysWhatIsLeft(t *testing.T) {
	permissive, run := setupServer(t)
	rootFile(t, permissive, "/etc/os-release", rockyRelease)
	rootFile(t, permissive, "/sys/fs/selinux/enforce", "0")
	rootFile(t, permissive, "/etc/selinux/config", "SELINUX=permissive\n")
	got := runSetup(t, permissive, SetupOptions{Confine: true})
	if !strings.HasSuffix(got, ")\n✓ SELinux · enforcing\n") || !slices.Contains(run.calls, "setenforce 1") {
		t.Fatalf("got\n%s\ncalls %q", got, run.calls)
	}
	if permissive.managedSystem() != "selinux" {
		t.Fatalf("recipes %#v", permissive.readRecipes().Applied)
	}
	if mark, _ := readState[confinementMarkRecord](permissive.StateDir, confinementMark); mark.What != "apply" || !mark.Until.After(executorNow) {
		t.Fatalf("Krynodes' own change must be marked first: %#v", mark)
	}
	if again := runSetup(t, permissive, SetupOptions{Confine: true}); !strings.HasSuffix(again, ")\n– SELinux already on\n") {
		t.Fatalf("again\n%s", again)
	}

	disabled, _ := setupServer(t)
	rootFile(t, disabled, "/etc/os-release", rockyRelease)
	rootFile(t, disabled, "/etc/selinux/config", "SELINUX=disabled\n")
	if got := runSetup(t, disabled, SetupOptions{Confine: true}); !strings.HasSuffix(got, ")\n– SELinux: restart to finish\n") {
		t.Fatalf("got\n%s", got)
	}

	apparmor, run := setupServer(t)
	rootFile(t, apparmor, "/sys/module/apparmor/parameters/enabled", "Y")
	rootFile(t, apparmor, profilesAt, "/usr/bin/man (complain)\n")
	if got := runSetup(t, apparmor, SetupOptions{Confine: true}); !strings.HasSuffix(got, ")\n✓ AppArmor · enforcing\n") || !slices.Contains(run.calls, "aa-enforce /usr/bin/man") {
		t.Fatalf("got\n%s\ncalls %q", got, run.calls)
	}
}

func TestSetupConfinesBeforeDockerSoDockerStartsConfined(t *testing.T) {
	executor, run := setupServer(t)
	rootFile(t, executor, "/etc/os-release", rockyRelease)
	rootFile(t, executor, "/sys/fs/selinux/enforce", "0")
	rootFile(t, executor, "/etc/selinux/config", "SELINUX=permissive\n")
	run.respond["rpm --eval %{?rhel}"] = "9\n"
	run.respond["uname -m"] = "x86_64\n"
	got := runSetup(t, executor, SetupOptions{Confine: true, Docker: true})
	if !strings.Contains(got, "✓ SELinux · enforcing\n✓ Docker") {
		t.Fatalf("got\n%s", got)
	}
	daemon, _ := os.ReadFile(executor.path("/etc/docker/daemon.json"))
	if !strings.Contains(string(daemon), `"selinux-enabled": true`) {
		t.Fatalf("daemon.json %q", daemon)
	}
}
