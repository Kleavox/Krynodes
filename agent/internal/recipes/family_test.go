package recipes

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func mustCall(t *testing.T, run *fakeRun, calls ...string) {
	t.Helper()
	for _, call := range calls {
		if !slices.Contains(run.calls, call) {
			t.Fatalf("missing %q in %q", call, run.calls)
		}
	}
}

func TestSecurityUpdatesOnRHELUseTheirOwnTimer(t *testing.T) {
	ctx := context.Background()
	for _, key := range []string{"rocky", "almalinux"} {
		env, run := onRelease(t, key)
		write(t, env, "/etc/dnf/automatic.conf", "owner's file")
		run.respond[securityNotices] = "RLSA-2024:3501 Important/Sec. openssl-1:3.0.7-27.el9.x86_64\n"
		run.failing["rpm -q dnf-plugins-core"] = true
		saved, err := Apply(ctx, env, "security-updates", nil)
		if err != nil || saved != nil {
			t.Fatalf("%s: saved %v err %v", key, saved, err)
		}
		mustCall(t, run, "dnf install -y -q dnf-plugins-core", "systemctl daemon-reload", "systemctl enable --now krynodes-security-updates.timer")
		if slices.Index(run.calls, "dnf install -y -q dnf-plugins-core") > slices.Index(run.calls, "systemctl daemon-reload") {
			t.Fatalf("%s: the plugin comes first: %q", key, run.calls)
		}
		if service := read(env, "/etc/systemd/system/krynodes-security-updates.service"); !strings.Contains(service, "ExecStart=/usr/bin/dnf -y upgrade --security\n") || !strings.Contains(service, "Type=oneshot\n") {
			t.Fatalf("%s: service:\n%s", key, service)
		}
		timer := read(env, "/etc/systemd/system/krynodes-security-updates.timer")
		for _, want := range []string{"OnCalendar=daily\n", "RandomizedDelaySec=1h\n", "Persistent=true\n", "WantedBy=timers.target\n"} {
			if !strings.Contains(timer, want) {
				t.Fatalf("%s: timer misses %q:\n%s", key, want, timer)
			}
		}
		if read(env, "/etc/dnf/automatic.conf") != "owner's file" || exists(env, "/etc/dnf/krynodes-automatic.conf") || exists(env, "/etc/apt/apt.conf.d/52krynodes-auto-upgrades") {
			t.Fatalf("%s: only Krynodes' own units change", key)
		}
		if err := Undo(ctx, env, "security-updates", saved); err != nil {
			t.Fatal(err)
		}
		mustCall(t, run, "systemctl disable --now krynodes-security-updates.timer")
		for _, gone := range []string{"/etc/systemd/system/krynodes-security-updates.service", "/etc/systemd/system/krynodes-security-updates.timer"} {
			if exists(env, gone) {
				t.Fatalf("%s: %s stays", key, gone)
			}
		}
	}
}

const securityNotices = "dnf -q updateinfo list --security --all"

func TestSecurityUpdatesNeedSecurityNoticesOnRHEL(t *testing.T) {
	env, run := onRelease(t, "centos")
	_, err := Apply(context.Background(), env, "security-updates", nil)
	if err == nil || err.Error() != "CentOS Stream 9's repositories publish no security notices, so dnf cannot pick out security updates." {
		t.Fatalf("err %v", err)
	}
	if exists(env, "/etc/systemd/system/krynodes-security-updates.timer") {
		t.Fatal("no timer without notices")
	}
	if slices.ContainsFunc(run.calls, func(call string) bool {
		return call == "systemctl daemon-reload" || strings.HasPrefix(call, "dnf install")
	}) {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestAFailedSecurityUpdatesTimerOnRHELLeavesNoUnits(t *testing.T) {
	env, run := onRelease(t, "rocky")
	run.respond[securityNotices] = "RLSA-2024:3501 Important/Sec. openssl-1:3.0.7-27.el9.x86_64\n"
	run.failing["systemctl enable --now krynodes-security-updates.timer"] = true
	if _, err := Apply(context.Background(), env, "security-updates", nil); err == nil {
		t.Fatal("the failure is reported")
	}
	for _, gone := range []string{"/etc/systemd/system/krynodes-security-updates.service", "/etc/systemd/system/krynodes-security-updates.timer"} {
		if exists(env, gone) {
			t.Fatalf("%s stays", gone)
		}
	}
}

func TestSSHOnRHELReloadsSshd(t *testing.T) {
	env, run := onRelease(t, "rocky")
	usersWithKeys(t, env, true)
	write(t, env, "/etc/group", "wheel:x:10:budi\n")
	write(t, env, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
	passwordsOffFor(run, "budi")
	if _, err := Apply(context.Background(), env, "ssh-keys-only", nil); err != nil {
		t.Fatal(err)
	}
	mustCall(t, run, "systemctl reload sshd")
	if slices.Contains(run.calls, "systemctl reload ssh") {
		t.Fatalf("RHEL has no ssh unit: %q", run.calls)
	}
}

func TestFail2banOnRHELBringsEPEL(t *testing.T) {
	ctx := context.Background()
	for key, epel := range map[string]string{
		"rocky":     "dnf install -y -q epel-release",
		"almalinux": "dnf install -y -q epel-release",
		"centos":    "dnf install -y -q epel-release",
		"oracle":    "dnf install -y -q oracle-epel-release-el9",
		"rhel":      "dnf install -y -q https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm",
	} {
		env, run := onRelease(t, key)
		for _, name := range []string{"epel-release", "oracle-epel-release-el9", "fail2ban", "fail2ban-systemd"} {
			run.failing["rpm -q "+name] = true
		}
		saved, err := Apply(ctx, env, "fail2ban", nil)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		mustCall(t, run, epel, "dnf install -y -q fail2ban fail2ban-systemd", "systemctl enable --now fail2ban")
		if !strings.Contains(read(env, "/etc/fail2ban/jail.d/krynodes.local"), "[sshd]\nenabled = true") {
			t.Fatalf("%s: jail", key)
		}
		want := "fail2ban fail2ban-systemd"
		if key == "oracle" {
			want = "oracle-epel-release-el9 " + want
		} else {
			want = "epel-release " + want
		}
		if saved["installed"] != want {
			t.Fatalf("%s: saved %v", key, saved)
		}
	}
}

func TestRebootNeededPerFamily(t *testing.T) {
	ctx := context.Background()
	env, _ := newEnv(t)
	if needed, _ := RebootNeeded(ctx, env); needed {
		t.Fatal("no file, no restart")
	}
	write(t, env, "/var/run/reboot-required", "")
	stamp := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	if err := os.Chtimes(env.path("/var/run/reboot-required"), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if needed, since := RebootNeeded(ctx, env); !needed || !since.Equal(stamp) {
		t.Fatalf("needed %v since %v", needed, since)
	}
	env, run := onRelease(t, "rocky")
	run.respond["dnf needs-restarting -r"] = "Core libraries or services have been updated since boot-up:\n  * kernel\n\nReboot is required to fully utilize these updates.\n"
	if needed, _ := RebootNeeded(ctx, env); !needed {
		t.Fatal("dnf says a restart is needed")
	}
	run.respond["dnf needs-restarting -r"] = "No core libraries or services have been updated since boot-up.\nReboot should not be necessary.\n"
	if needed, _ := RebootNeeded(ctx, env); needed {
		t.Fatal("dnf says none is needed")
	}
	delete(run.respond, "dnf needs-restarting -r")
	run.failing["dnf needs-restarting -r"] = true
	if needed, _ := RebootNeeded(ctx, env); needed {
		t.Fatal("a failing check never restarts the server")
	}
}

func TestFirewalldKeepsSSHAndTheChosenPortsOpen(t *testing.T) {
	env, run := onRelease(t, "rocky")
	run.failing["firewall-cmd --state"] = true
	run.failing["rpm -q firewalld"] = true
	for _, port := range []string{"22/tcp", "443/tcp"} {
		run.failing["firewall-offline-cmd --query-port="+port] = true
	}
	saved, err := Apply(context.Background(), env, "firewall", map[string]string{"ports": "443/tcp,53/udp"})
	if err != nil {
		t.Fatal(err)
	}
	mustCall(t, run, "dnf install -y -q firewalld", "firewall-offline-cmd --add-port=22/tcp", "firewall-offline-cmd --add-port=443/tcp", "systemctl enable --now firewalld")
	start := slices.Index(run.calls, "systemctl enable --now firewalld")
	for _, port := range []string{"22/tcp", "443/tcp"} {
		if slices.Index(run.calls, "firewall-offline-cmd --add-port="+port) > start {
			t.Fatalf("%s must be open before firewalld starts: %q", port, run.calls)
		}
	}
	if slices.Contains(run.calls, "firewall-offline-cmd --add-port=53/udp") {
		t.Fatal("a port that is already open is left alone")
	}
	if saved["ports"] != "22/tcp,443/tcp" || saved["wasRunning"] != "false" || saved["installed"] != "firewalld" {
		t.Fatalf("saved %v", saved)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "ufw") }) {
		t.Fatalf("no ufw on RHEL: %q", run.calls)
	}
}

func TestFirewalldWithoutSSHIsTurnedBackOff(t *testing.T) {
	env, run := onRelease(t, "rocky")
	run.failing["firewall-cmd --state"] = true
	run.failing["firewall-cmd --query-port=22/tcp"] = true
	_, err := Apply(context.Background(), env, "firewall", nil)
	if err == nil || err.Error() != "The firewall came up without SSH allowed, so Krynodes turned it back off." {
		t.Fatalf("err %v", err)
	}
	mustCall(t, run, "systemctl disable --now firewalld")
}

func TestFirewalldNeverStartsWithoutSSH(t *testing.T) {
	env, run := onRelease(t, "rocky")
	run.failing["firewall-cmd --state"] = true
	run.failing["firewall-offline-cmd --query-port=22/tcp"] = true
	run.failing["firewall-offline-cmd --add-port=22/tcp"] = true
	if _, err := Apply(context.Background(), env, "firewall", nil); err == nil {
		t.Fatal("the failure is reported")
	}
	if slices.Contains(run.calls, "systemctl enable --now firewalld") {
		t.Fatalf("firewalld must not start when SSH could not be let in: %q", run.calls)
	}
}

func TestARunningFirewalldGetsThePortsLive(t *testing.T) {
	env, run := onRelease(t, "rocky")
	run.respond["firewall-cmd --state"] = "running\n"
	run.failing["firewall-cmd --permanent --query-port=22/tcp"] = true
	saved, err := Apply(context.Background(), env, "firewall", nil)
	if err != nil {
		t.Fatal(err)
	}
	mustCall(t, run, "firewall-cmd --permanent --add-port=22/tcp", "firewall-cmd --reload")
	if slices.Contains(run.calls, "systemctl enable --now firewalld") || saved["wasRunning"] != "true" {
		t.Fatalf("calls %q saved %v", run.calls, saved)
	}
}

func TestFirewalldUndoRemovesOnlyItsPortsAndStopsItIfItWasOff(t *testing.T) {
	ctx := context.Background()
	env, run := onRelease(t, "rocky")
	if err := Undo(ctx, env, "firewall", map[string]string{"ports": "22/tcp,443/tcp", "wasRunning": "false"}); err != nil {
		t.Fatal(err)
	}
	mustCall(t, run, "firewall-cmd --permanent --remove-port=22/tcp", "firewall-cmd --permanent --remove-port=443/tcp", "firewall-cmd --reload", "systemctl disable --now firewalld")
	env, run = onRelease(t, "rocky")
	if err := Undo(ctx, env, "firewall", map[string]string{"ports": "443/tcp", "wasRunning": "true"}); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(run.calls, "systemctl disable --now firewalld") {
		t.Fatalf("a firewall that was on stays on: %q", run.calls)
	}
}
