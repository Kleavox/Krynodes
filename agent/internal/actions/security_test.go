package actions

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Kleavox/krynodes/agent/internal/recipes"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const (
	aptSimulate = "apt-get -s -o Debug::NoLocking=1 -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= upgrade"
	listening   = "ss -H -tulnp"
	riskyFormat = "{{.Name}}\t{{.HostConfig.Privileged}}\t{{range .Mounts}}{{.Source}};{{end}}\t{{index .Config.Labels \"com.docker.compose.project\"}}"
	portsFormat = "{{.Names}}\t{{.Ports}}\t{{.Label \"com.docker.compose.project\"}}"
)

func rootFile(t *testing.T, executor Executor, path, body string) {
	t.Helper()
	full := executor.path(path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func securityExecutor(t *testing.T) (Executor, *fakeRun) {
	t.Helper()
	executor, run := newTrustedExecutor(t)
	executor.Root = t.TempDir()
	executor.Audit = true
	executor.Collect = func(context.Context, []string) (Snapshot, error) {
		return Snapshot{Compose: true, Docker: "ready"}, nil
	}
	run.respond = map[string]string{}
	run.failing = map[string]string{}
	return executor, run
}

func findingsOf(t *testing.T, executor Executor) map[string]reporter.Finding {
	t.Helper()
	var inventory Inventory
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.Security == nil {
		t.Fatal("no security report")
	}
	found := map[string]reporter.Finding{}
	for _, finding := range inventory.Security.Findings {
		found[finding.ID] = finding
	}
	return found
}

func TestASecurityCheckNamesWhatIsWrong(t *testing.T) {
	executor, run := securityExecutor(t)
	rootFile(t, executor, "/etc/os-release", "ID=debian\nVERSION_ID=\"10\"\n")
	rootFile(t, executor, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
	rootFile(t, executor, "/var/run/reboot-required", "*** System restart required ***\n")
	old := executorNow.Add(-8 * 24 * time.Hour)
	os.Chtimes(executor.path("/var/run/reboot-required"), old, old)
	run.respond["sshd -T"] = "passwordauthentication yes\npermitrootlogin yes\nport 22\n"
	run.failing["dpkg-query -W -f ${Status} unattended-upgrades"] = ""
	run.respond[aptSimulate] = "Inst openssl [3.0.1] (3.0.2 Debian-Security:12/stable-security [amd64])\nInst vim [9.0] (9.1 Debian:12/stable [amd64])\n"
	run.respond[listening] = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n" +
		"tcp LISTEN 0 128 0.0.0.0:5432 0.0.0.0:* users:((\"postgres\",pid=2,fd=3))\n" +
		"udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:((\"systemd-resolve\",pid=3,fd=3))\n" +
		"tcp LISTEN 0 128 [::]:80 [::]:* users:((\"nginx\",pid=4,fd=3))\n" +
		"tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:((\"docker-proxy\",pid=5,fd=3))\n"
	run.respond["docker ps -q"] = "c1\n"
	run.respond["docker inspect --format "+riskyFormat+" c1"] = "/portainer\ttrue\t/var/run/docker.sock;\t\n"
	run.respond["docker ps --format "+portsFormat] = "web-1\t0.0.0.0:8080->80/tcp\tshop\n"
	run.failing["ufw status"] = ""
	run.failing["systemctl is-active --quiet fail2ban"] = ""
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	found := findingsOf(t, executor)
	want := map[string]string{
		"ssh-password": "serious", "ssh-root": "serious", "ssh-no-keys": "warning", "os-eol": "serious",
		"updates-off": "warning", "updates-pending": "warning", "reboot-pending": "warning", "risky-container": "serious",
		"public-ports": "warning", "firewall-off": "note", "fail2ban-off": "note", "dns-stub": "note",
		"os-unverified": "note",
	}
	for id, severity := range want {
		if found[id].Severity != severity {
			t.Errorf("%s: %#v", id, found[id])
		}
	}
	if len(found) != len(want) {
		t.Errorf("findings %#v", found)
	}
	if detail := found["public-ports"].Detail; !strings.Contains(detail, "5432/tcp (postgres)") || !strings.Contains(detail, "80/tcp (nginx)") || !strings.Contains(detail, "8080/tcp (web-1)") || strings.Contains(detail, "22/tcp") {
		t.Errorf("public ports %q", detail)
	}
	if detail := found["updates-pending"].Detail; detail != "1 security update is waiting" {
		t.Errorf("updates %q", detail)
	}
	if !strings.Contains(found["risky-container"].Detail, "portainer") {
		t.Errorf("risky %q", found["risky-container"].Detail)
	}
}

func healthyServer(t *testing.T, executor Executor, run *fakeRun) {
	t.Helper()
	rootFile(t, executor, "/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n")
	rootFile(t, executor, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
	rootFile(t, executor, "/root/.ssh/authorized_keys", "ssh-ed25519 AAAA laptop\n")
	rootFile(t, executor, "/etc/apt/apt.conf.d/20auto-upgrades", "APT::Periodic::Unattended-Upgrade \"1\";\n")
	run.respond["sshd -T"] = "passwordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin without-password\nport 22\n"
	run.respond["dpkg-query -W -f ${Status} unattended-upgrades"] = "install ok installed"
	run.respond[listening] = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n"
	rootFile(t, executor, "/etc/ufw/ufw.conf", "# comment\nENABLED=yes\nLOGLEVEL=low\n")
}

func TestUfwIsReadFromItsConfigBecauseTheSandboxCannotTakeItsLock(t *testing.T) {
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	run.failing["ufw status"] = "OSError: [Errno 30] Read-only file system: '/run/ufw.lock'"
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, off := findingsOf(t, executor)["firewall-off"]; off {
		t.Fatal("ufw is enabled in /etc/ufw/ufw.conf")
	}
	executor, run = securityExecutor(t)
	healthyServer(t, executor, run)
	run.respond["ufw status"] = "Status: active\n"
	rootFile(t, executor, "/etc/ufw/ufw.conf", "ENABLED=no\n")
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if found := findingsOf(t, executor); found["firewall-off"].Detail != "No firewall is active (ufw)" {
		t.Fatalf("findings %#v", found)
	}
}

func TestAHealthyServerHasOnlyNotes(t *testing.T) {
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	found := findingsOf(t, executor)
	if len(found) != 1 || found["ssh-keys"].Severity != "note" || found["ssh-keys"].Detail != "SSH keys for root" {
		t.Fatalf("findings %#v", found)
	}
}

func TestFullAccessStacksMayHoldDockerAndPublicPorts(t *testing.T) {
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	dir := filepath.Join(executor.StateDir, "compose", "adguard")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(dir, "krynodes.json", stackMeta{Access: "full"}, 0o640); err != nil {
		t.Fatal(err)
	}
	run.respond["docker ps -q"] = "c1\n"
	run.respond["docker inspect --format "+riskyFormat+" c1"] = "/adguard-dns-1\ttrue\t\tadguard\n"
	run.respond["docker ps --format "+portsFormat] = "adguard-dns-1\t0.0.0.0:53->53/udp\tadguard\n"
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if found := findingsOf(t, executor); len(found) != 1 {
		t.Fatalf("findings %#v", found)
	}
}

func TestThePublicListenersAreReportedWithTheirAddresses(t *testing.T) {
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	run.respond[listening] = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n" +
		"tcp LISTEN 0 4096 100.79.66.29:57969 0.0.0.0:* users:((\"tailscaled\",pid=2,fd=3))\n" +
		"udp UNCONN 0 0 0.0.0.0:41641 0.0.0.0:* users:((\"tailscaled\",pid=2,fd=5))\n" +
		"tcp LISTEN 0 4096 [fd7a:115c:a1e0::1]:63014 [::]:* users:((\"tailscaled\",pid=2,fd=4))\n" +
		"tcp LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:* users:((\"local\",pid=3,fd=3))\n"
	run.respond["docker ps --format "+portsFormat] = "web-1\t192.168.1.5:8080->80/tcp, [::]:8080->80/tcp\tshop\n"
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	var inventory Inventory
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	want := []reporter.Listener{
		{Address: "100.79.66.29", Port: 57969, Protocol: "tcp", Process: "tailscaled"},
		{Address: "0.0.0.0", Port: 41641, Protocol: "udp", Process: "tailscaled"},
		{Address: "fd7a:115c:a1e0::1", Port: 63014, Protocol: "tcp", Process: "tailscaled"},
		{Address: "192.168.1.5", Port: 8080, Protocol: "tcp", Process: "web-1"},
		{Address: "::", Port: 8080, Protocol: "tcp", Process: "web-1"},
	}
	if !slices.Equal(inventory.Security.Listeners, want) {
		t.Fatalf("listeners %#v", inventory.Security.Listeners)
	}
	if detail := findingsOf(t, executor)["public-ports"].Detail; detail != "Listening on public addresses outside Krynodes: 57969/tcp (tailscaled), 41641/udp (tailscaled), 63014/tcp (tailscaled), 8080/tcp (web-1)" {
		t.Fatalf("detail %q", detail)
	}
}

func checks(run *fakeRun) int {
	return strings.Count(strings.Join(run.calls, "\n"), listening)
}

func TestTheCheckRunsEverySixHoursOrWhenAsked(t *testing.T) {
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	now := executorNow
	executor.Now = func() time.Time { return now }
	for range 2 {
		if err := executor.Execute(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if checks(run) != 1 {
		t.Fatalf("one check in six hours, got %d", checks(run))
	}
	now = now.Add(6 * time.Hour)
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	scan := Request{ID: idB, Kind: "host", Name: "server", Action: "scan", ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
	if result := runRequest(t, executor, scan); !result.OK || checks(run) != 3 {
		t.Fatalf("result %#v checks %d", result, checks(run))
	}
}

func hostRequest(t *testing.T, id, name, action string, args map[string]string) Request {
	t.Helper()
	return signedRequest(t, Command{ID: id, Kind: "host", Name: name, Action: action, Args: args})
}

func TestHostRecipesGoToTheHostUnitSigned(t *testing.T) {
	executor, run := securityExecutor(t)
	writeRequest(t, executor.RequestDir, idA+".json", hostRequest(t, idA, "security-updates", "apply", nil))
	unsigned := hostRequest(t, idB, "fail2ban", "apply", nil)
	unsigned.Signed = nil
	writeRequest(t, executor.RequestDir, idB+".json", unsigned)
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "results", idA+".json")); !os.IsNotExist(err) {
		t.Fatal("the host unit writes the result")
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "host", idA+".json")); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, idB); result.OK || slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "apt-get install") }) {
		t.Fatalf("result %#v", result)
	}
}

func TestHostApplyRunsTheRecipeAndReports(t *testing.T) {
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	writeRequest(t, executor.RequestDir, idA+".json", hostRequest(t, idA, "security-updates", "apply", nil))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, idA); !result.OK || !slices.Contains(run.calls, "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -q unattended-upgrades") {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	if entries, _ := os.ReadDir(filepath.Join(executor.StateDir, "host")); len(entries) != 0 {
		t.Fatalf("the request must be claimed: %v", entries)
	}
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	var inventory Inventory
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(inventory.Security.Recipes, []string{"security-updates"}) || checks(run) != 2 {
		t.Fatalf("security %#v checks %d", inventory.Security, checks(run))
	}
	writeRequest(t, executor.RequestDir, idB+".json", hostRequest(t, idB, "security-updates", "undo", nil))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, idB); !result.OK {
		t.Fatalf("undo %#v", result)
	}
}

func TestAProtectionThatIsOnIsNotAppliedAgain(t *testing.T) {
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	for _, id := range []string{idA, idB} {
		writeRequest(t, executor.RequestDir, id+".json", hostRequest(t, id, "security-updates", "apply", nil))
		if err := executor.Execute(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := executor.HostApply(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	installs := 0
	for _, call := range run.calls {
		if strings.Contains(call, "install -y -q unattended-upgrades") {
			installs++
		}
	}
	if first, second := readResult(t, executor, idA), readResult(t, executor, idB); !first.OK || second.OK || installs != 1 {
		t.Fatalf("first %#v second %#v installs %d", first, second, installs)
	}
}

func TestHostApplyRefusesARequestThatWasChanged(t *testing.T) {
	executor, run := securityExecutor(t)
	changed := hostRequest(t, idA, "security-updates", "apply", nil)
	changed.Name = "firewall"
	if err := os.MkdirAll(filepath.Join(executor.StateDir, "host"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeRequest(t, filepath.Join(executor.StateDir, "host"), idA+".json", changed)
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, idA); result.OK || len(run.calls) != 0 {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
}

func TestTheRebootWindowRestartsOnlyWhenNeededAndOnceADay(t *testing.T) {
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	now := executorNow
	executor.Now = func() time.Time { return now }
	window := hostRequest(t, idA, "reboot-window", "apply", map[string]string{"hour": "11"})
	if result := runRequest(t, executor, window); !result.OK {
		t.Fatalf("result %#v", result)
	}
	reboots := func() int { return strings.Count(strings.Join(run.calls, "\n"), "systemctl reboot --no-block") }
	now = now.Add(time.Hour)
	if err := executor.Execute(context.Background()); err != nil || reboots() != 0 {
		t.Fatalf("no restart without need: %v %d", err, reboots())
	}
	rootFile(t, executor, "/var/run/reboot-required", "")
	for range 2 {
		if err := executor.Execute(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if reboots() != 1 {
		t.Fatalf("one restart a day, got %d", reboots())
	}
	now = now.Add(2 * time.Hour)
	executor.Execute(context.Background())
	if reboots() != 1 {
		t.Fatal("only inside the window")
	}
	var inventory Inventory
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.Security.RebootHour == nil || *inventory.Security.RebootHour != 11 || !slices.Contains(inventory.Security.Recipes, "reboot-window") {
		t.Fatalf("security %#v", inventory.Security)
	}
	if result := runRequest(t, executor, hostRequest(t, idB, "reboot-window", "apply", map[string]string{"hour": "25"})); result.OK {
		t.Fatal("an hour is 0 to 23")
	}
}

func TestLockdownSurvivesARestartAndUnlockGivesThePoliciesBack(t *testing.T) {
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	const policy = "docker inspect --format {{.HostConfig.RestartPolicy.Name}}:{{.HostConfig.RestartPolicy.MaximumRetryCount}} "
	run.respond["docker ps --format {{.ID}}\t{{.Names}}\t{{.Ports}}"] = "w1\tweb-1\t0.0.0.0:80->80/tcp\nq1\tqueue-1\t0.0.0.0:5672->5672/tcp\nn1\tnone-1\t0.0.0.0:81->81/tcp\n"
	run.respond[policy+"w1"] = "always:0\n"
	run.respond[policy+"q1"] = "on-failure:5\n"
	run.respond[policy+"n1"] = "no:0\n"
	for _, step := range []struct{ id, action string }{{idA, "lockdown"}, {idB, "unlock"}} {
		writeRequest(t, executor.RequestDir, step.id+".json", hostRequest(t, step.id, "server", step.action, nil))
		if err := executor.Execute(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := executor.HostApply(context.Background()); err != nil {
			t.Fatal(err)
		}
		if result := readResult(t, executor, step.id); !result.OK {
			t.Fatalf("%s %#v", step.action, result)
		}
	}
	stop := slices.Index(run.calls, "docker stop w1 q1 n1")
	start := slices.Index(run.calls, "docker start w1 q1 n1")
	for _, call := range []string{"docker update --restart no w1 q1"} {
		if index := slices.Index(run.calls, call); index < 0 || index > stop {
			t.Fatalf("%q must come before the stop in %q", call, run.calls)
		}
	}
	for _, call := range []string{"docker update --restart always w1", "docker update --restart on-failure:5 q1"} {
		if index := slices.Index(run.calls, call); index < 0 || index > start {
			t.Fatalf("%q must come before the start in %q", call, run.calls)
		}
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasSuffix(call, " n1") && strings.Contains(call, "update") }) {
		t.Fatalf("a container without a policy keeps none: %q", run.calls)
	}
}

func TestAFailedLockdownGivesEverythingBack(t *testing.T) {
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	const policy = "docker inspect --format {{.HostConfig.RestartPolicy.Name}}:{{.HostConfig.RestartPolicy.MaximumRetryCount}} "
	run.respond["docker ps --format {{.ID}}\t{{.Names}}\t{{.Ports}}"] = "w1\tweb-1\t0.0.0.0:80->80/tcp\nq1\tqueue-1\t0.0.0.0:5672->5672/tcp\n"
	run.respond[policy+"w1"] = "always:0\n"
	run.respond[policy+"q1"] = "unless-stopped:0\n"
	run.failing["docker stop w1 q1"] = "Error response from daemon: cannot stop container: q1: permission denied\n"
	writeRequest(t, executor.RequestDir, idA+".json", hostRequest(t, idA, "server", "lockdown", nil))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, idA); result.OK || !strings.Contains(result.Output, "permission denied") {
		t.Fatalf("result %#v", result)
	}
	stop := slices.Index(run.calls, "docker stop w1 q1")
	for _, call := range []string{"docker update --restart always w1", "docker update --restart unless-stopped q1", "docker start w1 q1"} {
		if index := slices.Index(run.calls, call); index < stop {
			t.Fatalf("%q must follow the failed stop in %q", call, run.calls)
		}
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "lockdown.json")); !os.IsNotExist(err) {
		t.Fatal("a failed lockdown leaves the server unlocked")
	}
}

func TestALockdownThatCannotBeRecordedGivesEverythingBack(t *testing.T) {
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	rootFile(t, executor, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
	const policy = "docker inspect --format {{.HostConfig.RestartPolicy.Name}}:{{.HostConfig.RestartPolicy.MaximumRetryCount}} "
	run.respond["docker ps --format {{.ID}}\t{{.Names}}\t{{.Ports}}"] = "w1\tweb-1\t0.0.0.0:80->80/tcp\n"
	run.respond[policy+"w1"] = "always:0\n"
	if err := os.MkdirAll(filepath.Join(executor.StateDir, ".lockdown.json.tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeRequest(t, executor.RequestDir, idA+".json", hostRequest(t, idA, "server", "lockdown", nil))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, idA); result.OK {
		t.Fatalf("result %#v", result)
	}
	stop := slices.Index(run.calls, "docker stop w1")
	for _, call := range []string{"docker update --restart always w1", "docker start w1"} {
		if index := slices.Index(run.calls, call); stop < 0 || index < stop {
			t.Fatalf("%q must follow the stop in %q", call, run.calls)
		}
	}
	if _, err := os.Stat(filepath.Join(executor.Root, "etc/ssh/sshd_config.d/10-krynodes.conf")); !os.IsNotExist(err) {
		t.Fatal("SSH keys only from the failed lockdown is turned off again")
	}
}

func TestAProtectionThatCannotBeRecordedIsTurnedOffAgain(t *testing.T) {
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	rootFile(t, executor, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
	if err := os.MkdirAll(filepath.Join(executor.StateDir, ".recipes.json.tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeRequest(t, executor.RequestDir, idA+".json", hostRequest(t, idA, "ssh-keys-only", "apply", nil))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, idA); result.OK {
		t.Fatalf("result %#v", result)
	}
	if _, err := os.Stat(filepath.Join(executor.Root, "etc/ssh/sshd_config.d/10-krynodes.conf")); !os.IsNotExist(err) {
		t.Fatal("an unrecorded protection could never be turned off")
	}
}

func TestUnlockSkipsContainersThatAreGoneButNotOtherFailures(t *testing.T) {
	executor, run := securityExecutor(t)
	unlock := func(id string) reporter.ActionResult {
		t.Helper()
		if err := writeJSON(executor.StateDir, "lockdown.json", lockdownState{Containers: []string{"w1", "q1"}, Restart: map[string]string{"q1": "always"}, At: executorNow}, 0o640); err != nil {
			t.Fatal(err)
		}
		writeRequest(t, executor.RequestDir, id+".json", hostRequest(t, id, "server", "unlock", nil))
		if err := executor.Execute(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := executor.HostApply(context.Background()); err != nil {
			t.Fatal(err)
		}
		return readResult(t, executor, id)
	}
	run.failing["docker update --restart always q1"] = "Error response from daemon: No such container: q1\n"
	run.failing["docker start w1 q1"] = "Error response from daemon: No such container: q1\nError: failed to start containers: q1\n"
	if result := unlock(idA); !result.OK {
		t.Fatalf("a container that is gone must not keep the server locked: %#v", result)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "lockdown.json")); !os.IsNotExist(err) {
		t.Fatal("the lock is lifted")
	}
	run.failing["docker start w1 q1"] = "Error response from daemon: cannot start: permission denied\n"
	if result := unlock(idB); result.OK {
		t.Fatalf("other failures still count: %#v", result)
	}
}

func TestALockedDownServerStartsNothingUntilItIsUnlocked(t *testing.T) {
	lock := func(executor Executor) {
		if err := writeJSON(executor.StateDir, "lockdown.json", lockdownState{Containers: []string{}, At: executorNow}, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	refused := func(name string, result Result, run *fakeRun) {
		t.Helper()
		if result.OK || !strings.Contains(result.Output, "locked down") || slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "docker") }) {
			t.Fatalf("%s: %#v %q", name, result, run.calls)
		}
	}
	for _, verb := range []string{"deploy", "rollback", "start", "restart", "edit", "adopt", "expose"} {
		executor, run := stackExecutor(t, listmonk)
		lock(executor)
		refused(verb, runRequest(t, executor, request(t, idA, "compose", "listmonk", verb, soon())), run)
	}
	executor, run := stackExecutor(t)
	lock(executor)
	refused("create", runRequest(t, executor, createRequest(t, idA, "kuma", kumaText)), run)
	executor, run = stackExecutor(t)
	lock(executor)
	refused("docker start", runRequest(t, executor, request(t, idA, "docker", "adguard", "start", soon())), run)
	executor, _ = stackExecutor(t, listmonk)
	lock(executor)
	if result := runRequest(t, executor, request(t, idA, "compose", "listmonk", "stop", soon())); !result.OK {
		t.Fatalf("stopping stays allowed: %#v", result)
	}
}

func TestLockdownStopsWhatIsOpenAndUnlockStartsItAgain(t *testing.T) {
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	rootFile(t, executor, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
	run.respond["docker ps --format {{.ID}}\t{{.Names}}\t{{.Ports}}"] = "w1\tweb-1\t0.0.0.0:80->80/tcp\nd1\tdb-1\t5432/tcp\nt1\tkrynodes-tunnel\t\n"
	writeRequest(t, executor.RequestDir, idA+".json", hostRequest(t, idA, "server", "lockdown", nil))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, idA); !result.OK {
		t.Fatalf("result %#v", result)
	}
	for _, call := range []string{"docker stop w1 t1"} {
		if !slices.Contains(run.calls, call) {
			t.Fatalf("missing %q in %q", call, run.calls)
		}
	}
	if _, err := os.Stat(executor.path("/etc/ssh/sshd_config.d/10-krynodes.conf")); err != nil {
		t.Fatal("lockdown turns SSH passwords off")
	}
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if found := findingsOf(t, executor); found["lockdown"].Severity != "warning" {
		t.Fatalf("findings %#v", found)
	}
	writeRequest(t, executor.RequestDir, idB+".json", hostRequest(t, idB, "server", "unlock", nil))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, idB); !result.OK || !slices.Contains(run.calls, "docker start w1 t1") {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	if _, err := os.Stat(executor.path("/etc/ssh/sshd_config.d/10-krynodes.conf")); !os.IsNotExist(err) {
		t.Fatal("unlock gives SSH back as it was")
	}
}

const rockyRelease = "NAME=\"Rocky Linux\"\nVERSION_ID=\"9.4\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nPRETTY_NAME=\"Rocky Linux 9.4 (Blue Onyx)\"\n"

func rhelServer(t *testing.T, executor Executor, run *fakeRun) {
	t.Helper()
	rootFile(t, executor, "/etc/os-release", rockyRelease)
	rootFile(t, executor, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
	rootFile(t, executor, "/root/.ssh/authorized_keys", "ssh-ed25519 AAAA laptop\n")
	run.respond["sshd -T"] = "passwordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin without-password\nport 22\n"
	run.respond[listening] = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n"
	run.respond["firewall-cmd --state"] = "running\n"
	run.respond["dnf needs-restarting -r"] = "No core libraries or services have been updated since boot-up.\nReboot should not be necessary.\n"
}

func TestARHELServerIsCheckedWithItsOwnTools(t *testing.T) {
	executor, run := securityExecutor(t)
	rhelServer(t, executor, run)
	for _, timer := range []string{"krynodes-security-updates.timer", "dnf-automatic-install.timer", "dnf-automatic.timer", "dnf5-automatic.timer"} {
		run.failing["systemctl is-enabled --quiet "+timer] = ""
	}
	run.failing["ufw status"] = ""
	run.respond["dnf -q updateinfo list --security --cacheonly"] = "RHSA-2026:1 Important/Sec. openssl-3.0.7-1.el9.x86_64\nRHSA-2026:2 Moderate/Sec. vim-9.0-1.el9.x86_64\n"
	run.respond["dnf needs-restarting -r"] = "Core libraries or services have been updated since boot-up:\n  * kernel\n\nReboot is required to fully utilize these updates.\n"
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	found := findingsOf(t, executor)
	if found["updates-off"].Severity != "warning" || found["updates-pending"].Detail != "2 security updates are waiting" || found["reboot-pending"].Detail != "A restart is waiting" {
		t.Fatalf("findings %#v", found)
	}
	if _, off := found["firewall-off"]; off {
		t.Fatalf("firewalld is running: %#v", found)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool {
		return strings.Contains(call, "dpkg-query") || strings.Contains(call, "apt-get")
	}) {
		t.Fatalf("no Debian tools on RHEL: %q", run.calls)
	}
	executor, run = securityExecutor(t)
	rhelServer(t, executor, run)
	delete(run.respond, "firewall-cmd --state")
	run.failing["firewall-cmd --state"] = "not running"
	run.failing["ufw status"] = ""
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	found = findingsOf(t, executor)
	if _, off := found["updates-off"]; off || found["firewall-off"].Detail != "No firewall is active (firewalld)" {
		t.Fatalf("findings %#v", found)
	}
}

func TestTheReportNamesThePlatformAndAnUnverifiedVersion(t *testing.T) {
	executor, run := securityExecutor(t)
	rhelServer(t, executor, run)
	rootFile(t, executor, "/etc/os-release", strings.ReplaceAll(rockyRelease, "9.4", "11.0"))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	var inventory Inventory
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	platform := inventory.Security.Platform
	if platform == nil || platform.Family == nil || *platform.Family != "rhel" || platform.Name != "Rocky Linux 11.0" || platform.Verified || platform.Checked != "8 to 10" {
		t.Fatalf("platform %#v", platform)
	}
	if found := findingsOf(t, executor)["os-unverified"]; found.Severity != "note" || found.Detail != "Rocky Linux 11 is newer than the versions Krynodes has checked (8 to 10)." {
		t.Fatalf("finding %#v", found)
	}
	executor, run = securityExecutor(t)
	healthyServer(t, executor, run)
	rootFile(t, executor, "/etc/os-release", "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\n")
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	if platform := inventory.Security.Platform; platform == nil || platform.Family != nil || platform.Name != "Alpine Linux 3.20.3" {
		t.Fatalf("platform %#v", platform)
	}
}

func TestEndOfLifeComesFromTheSharedTable(t *testing.T) {
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	rootFile(t, executor, "/etc/os-release", "NAME=\"Ubuntu\"\nVERSION_ID=\"25.10\"\nID=ubuntu\nID_LIKE=debian\n")
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if found := findingsOf(t, executor)["os-eol"]; found.Severity != "serious" || found.Detail != "Ubuntu 25.10 no longer gets security updates (since 1 Jul 2026)" {
		t.Fatalf("finding %#v", found)
	}
}

func TestRebootWindowUsesTheFamilyCheck(t *testing.T) {
	executor, run := securityExecutor(t)
	rhelServer(t, executor, run)
	now := executorNow
	executor.Now = func() time.Time { return now }
	if result := runRequest(t, executor, hostRequest(t, idA, "reboot-window", "apply", map[string]string{"hour": "11"})); !result.OK {
		t.Fatalf("result %#v", result)
	}
	now = now.Add(time.Hour)
	reboots := func() int { return strings.Count(strings.Join(run.calls, "\n"), "systemctl reboot --no-block") }
	if err := executor.Execute(context.Background()); err != nil || reboots() != 0 {
		t.Fatalf("no restart without need: %v %d", err, reboots())
	}
	run.respond["dnf needs-restarting -r"] = "Reboot is required to fully utilize these updates.\n"
	if err := executor.Execute(context.Background()); err != nil || reboots() != 1 {
		t.Fatalf("restart when dnf asks: %v %d", err, reboots())
	}
}

func TestAnUnsyncedClockIsNoted(t *testing.T) {
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, found := findingsOf(t, executor)["clock-unsynced"]; found {
		t.Fatal("no finding when timedatectl says nothing")
	}
	executor, run = securityExecutor(t)
	healthyServer(t, executor, run)
	run.respond["timedatectl show -p NTPSynchronized --value"] = "no\n"
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if found := findingsOf(t, executor)["clock-unsynced"]; found.Severity != "warning" || found.Detail != "The clock is not synchronized with a time server; signed actions can be refused" {
		t.Fatalf("finding %#v", found)
	}
}

func TestAPlatformNameFitsTheReport(t *testing.T) {
	for _, long := range []string{strings.Repeat("Ü", 200), strings.Repeat("🐧", 100)} {
		report := platformReport(recipes.Platform{Name: long})
		if len(report.Name) > 120 || len(report.Name) < 116 || !utf8.ValidString(report.Name) || !strings.HasPrefix(long, report.Name) {
			t.Fatalf("name of %d bytes", len(report.Name))
		}
	}
}

func TestRebootWindowWaitsForHostWork(t *testing.T) {
	executor, run := securityExecutor(t)
	rhelServer(t, executor, run)
	now := executorNow
	executor.Now = func() time.Time { return now }
	if result := runRequest(t, executor, hostRequest(t, idA, "reboot-window", "apply", map[string]string{"hour": "11"})); !result.OK {
		t.Fatalf("result %#v", result)
	}
	now = now.Add(time.Hour)
	run.respond["dnf needs-restarting -r"] = "Reboot is required to fully utilize these updates.\n"
	reboots := func() int { return strings.Count(strings.Join(run.calls, "\n"), "systemctl reboot --no-block") }
	queued := filepath.Join(executor.StateDir, "host", idB+".json")
	if err := writeJSON(filepath.Dir(queued), idB+".json", hostRequest(t, idB, "docker", "install", nil), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := executor.Execute(context.Background()); err != nil || reboots() != 0 {
		t.Fatalf("no restart while host work is queued: %v %d", err, reboots())
	}
	if err := os.Remove(queued); err != nil {
		t.Fatal(err)
	}
	run.respond["systemctl is-active krynodes-host.service"] = "activating\n"
	if err := executor.Execute(context.Background()); err != nil || reboots() != 0 {
		t.Fatalf("no restart while host work runs: %v %d", err, reboots())
	}
	run.respond["systemctl is-active krynodes-host.service"] = "inactive\n"
	if err := executor.Execute(context.Background()); err != nil || reboots() != 1 {
		t.Fatalf("restart once host work is done: %v %d", err, reboots())
	}
}

func TestInstallDockerGoesToTheHostUnitSigned(t *testing.T) {
	executor, _ := securityExecutor(t)
	writeRequest(t, executor.RequestDir, idA+".json", hostRequest(t, idA, "docker", "install", nil))
	unsigned := hostRequest(t, idB, "docker", "install", nil)
	unsigned.Signed = nil
	writeRequest(t, executor.RequestDir, idB+".json", unsigned)
	writeRequest(t, executor.RequestDir, idC+".json", hostRequest(t, idC, "fail2ban", "install", nil))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "host", idA+".json")); err != nil {
		t.Fatal("install docker waits for the host unit")
	}
	for _, id := range []string{idB, idC} {
		if result := readResult(t, executor, id); result.OK {
			t.Fatalf("%s %#v", id, result)
		}
	}
}

func TestInstallDockerRunsInTheHostUnit(t *testing.T) {
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	rootFile(t, executor, "/etc/os-release", "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\nID=debian\n")
	run.failing["docker --version"] = ""
	run.respond["dpkg --print-architecture"] = "amd64\n"
	run.respond["docker version --format {{.Client.Version}}"] = "28.4.0\n"
	executor.Fetch = func(context.Context, string) ([]byte, error) { return []byte("KEY"), nil }
	writeRequest(t, executor.RequestDir, idA+".json", hostRequest(t, idA, "docker", "install", nil))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, idA); !result.OK || result.Output != "Docker 28.4.0 with Compose" {
		t.Fatalf("result %#v", result)
	}
	if !slices.Contains(run.calls, "systemctl enable --now docker") {
		t.Fatalf("calls %q", run.calls)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "docker.json")); err != nil {
		t.Fatal("Krynodes remembers it installed Docker")
	}
}
