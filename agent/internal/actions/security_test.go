package actions

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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
	run.respond["ufw status"] = "Status: active\n"
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

func checks(run *fakeRun) int {
	return strings.Count(strings.Join(run.calls, "\n"), "sshd -T")
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
	if result := readResult(t, executor, idA); !result.OK || !slices.Contains(run.calls, "env DEBIAN_FRONTEND=noninteractive apt-get install -y -q unattended-upgrades") {
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
		if strings.Contains(call, "apt-get install -y -q unattended-upgrades") {
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
