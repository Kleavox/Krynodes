package recipes

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

type fakeRun struct {
	calls   []string
	respond map[string]string
	failing map[string]bool
	effects map[string]func()
}

func (f *fakeRun) run(_ context.Context, name string, args ...string) ([]byte, int, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if effect := f.effects[call]; effect != nil {
		effect()
	}
	if f.failing[call] {
		return []byte("failed"), 1, errors.New("exit status 1")
	}
	return []byte(f.respond[call]), 0, nil
}

func newEnv(t *testing.T) (Env, *fakeRun) {
	t.Helper()
	run := &fakeRun{respond: map[string]string{}, failing: map[string]bool{}, effects: map[string]func(){}}
	env := Env{Root: t.TempDir(), Run: run.run}
	write(t, env, "/etc/os-release", "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\nID=debian\n")
	return env, run
}

func write(t *testing.T, env Env, path, body string) {
	t.Helper()
	full := env.path(path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(env Env, path string) string {
	body, _ := os.ReadFile(env.path(path))
	return string(body)
}

func exists(env Env, path string) bool {
	_, err := os.Lstat(env.path(path))
	return err == nil
}

const (
	budiProbe = "sshd -T -C user=budi,host=krynodes.invalid,addr=192.0.2.1"
	rootProbe = "sshd -T -C user=root,host=krynodes.invalid,addr=192.0.2.1"
)

func afterSSHCheck(run *fakeRun, answers map[string]string) {
	run.effects["sshd -t"] = func() {
		for call, answer := range answers {
			run.respond[call] = answer
		}
	}
}

func passwordsOffFor(run *fakeRun, users ...string) {
	answers := map[string]string{"sshd -T": "passwordauthentication no\nkbdinteractiveauthentication no\n"}
	for _, user := range users {
		answers["sshd -T -C user="+user+",host=krynodes.invalid,addr=192.0.2.1"] = "passwordauthentication no\nkbdinteractiveauthentication no\n"
	}
	afterSSHCheck(run, answers)
}

func usersWithKeys(t *testing.T, env Env, keyed bool) {
	t.Helper()
	write(t, env, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nbudi:x:1000:1000::/home/budi:/bin/bash\nwww:x:33:33::/var/www:/usr/sbin/nologin\n")
	write(t, env, "/etc/group", "sudo:x:27:budi\n")
	if keyed {
		write(t, env, "/home/budi/.ssh/authorized_keys", "# laptop\nssh-ed25519 AAAAC3Nza budi@laptop\n")
	}
	write(t, env, "/var/www/.ssh/authorized_keys", "ssh-ed25519 AAAA www\n")
}

const unattendedProbe = "apt-config shell UU APT::Periodic::Unattended-Upgrade"

func TestSecurityUpdatesStayOffWhenAnotherFileTurnsThemOff(t *testing.T) {
	env, run := newEnv(t)
	run.failing["dpkg-query -W -f ${Status} unattended-upgrades"] = true
	run.respond[unattendedProbe] = "UU='0'\n"
	_, err := Apply(context.Background(), env, "security-updates", nil)
	if err == nil || err.Error() != "Another file in /etc/apt/apt.conf.d turns unattended upgrades off." {
		t.Fatalf("err %v", err)
	}
	if exists(env, "/etc/apt/apt.conf.d/52krynodes-auto-upgrades") {
		t.Fatal("the drop-in is taken back")
	}
	if !slices.Contains(run.calls, "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 purge -y -q unattended-upgrades") {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestSecurityUpdatesNeedTheDailyUpgradeTimer(t *testing.T) {
	env, run := newEnv(t)
	run.respond[unattendedProbe] = "UU='1'\n"
	run.failing["systemctl is-enabled --quiet apt-daily-upgrade.timer"] = true
	_, err := Apply(context.Background(), env, "security-updates", nil)
	if err == nil || err.Error() != "apt-daily-upgrade.timer is off, so updates would never run." {
		t.Fatalf("err %v", err)
	}
	if exists(env, "/etc/apt/apt.conf.d/52krynodes-auto-upgrades") {
		t.Fatal("the drop-in is taken back")
	}
}

func TestRestartIsMarkedPerFamily(t *testing.T) {
	ctx := context.Background()
	const none = "Nothing on this server marks when a restart is needed. Turn on Security updates first."
	env, _ := newEnv(t)
	if err := RestartMarked(ctx, env); err == nil || err.Error() != none {
		t.Fatalf("debian without a marker: %v", err)
	}
	write(t, env, "/etc/kernel/postinst.d/unattended-upgrades", "")
	if err := RestartMarked(ctx, env); err != nil {
		t.Fatal(err)
	}
	env, _ = onRelease(t, "ubuntu")
	write(t, env, "/usr/share/update-notifier/notify-reboot-required", "")
	if err := RestartMarked(ctx, env); err != nil {
		t.Fatal(err)
	}
	env, run := onRelease(t, "rocky")
	run.respond["dnf needs-restarting -r"] = "No core libraries or services have been updated since boot-up.\nReboot should not be necessary.\n"
	if err := RestartMarked(ctx, env); err != nil {
		t.Fatal(err)
	}
	run.respond["dnf needs-restarting -r"] = "No such command: needs-restarting."
	run.failing["dnf needs-restarting -r"] = true
	if err := RestartMarked(ctx, env); err == nil || err.Error() != none {
		t.Fatalf("rocky without the plugin: %v", err)
	}
}

func TestAutomaticSecurityUpdates(t *testing.T) {
	env, run := newEnv(t)
	run.respond[unattendedProbe] = "UU='1'\n"
	if _, err := Apply(context.Background(), env, "security-updates", nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(run.calls, "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -q unattended-upgrades") {
		t.Fatalf("calls %q", run.calls)
	}
	if !strings.Contains(read(env, "/etc/apt/apt.conf.d/52krynodes-auto-upgrades"), `APT::Periodic::Unattended-Upgrade "1";`) {
		t.Fatal("the drop-in turns unattended upgrades on")
	}
	if err := Undo(context.Background(), env, "security-updates", nil); err != nil || exists(env, "/etc/apt/apt.conf.d/52krynodes-auto-upgrades") {
		t.Fatalf("undo %v", err)
	}
}

func TestKeysOnlyNeedsAKeyForRootOrASudoUser(t *testing.T) {
	env, run := newEnv(t)
	usersWithKeys(t, env, false)
	write(t, env, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
	if _, err := Apply(context.Background(), env, "ssh-keys-only", nil); err == nil || !strings.Contains(err.Error(), "SSH key") {
		t.Fatalf("err %v", err)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return !strings.HasPrefix(call, "sshd -T") }) || exists(env, "/etc/ssh/sshd_config.d/10-krynodes.conf") {
		t.Fatalf("calls %q", run.calls)
	}
	if users := SSHLogins(context.Background(), env); len(users) != 0 {
		t.Fatalf("a nologin account does not count: %v", users)
	}
}

func TestKeysOnlyNeedsSSHToReadTheDropInFolder(t *testing.T) {
	env, _ := newEnv(t)
	usersWithKeys(t, env, true)
	write(t, env, "/etc/ssh/sshd_config", "PasswordAuthentication yes\n")
	if _, err := Apply(context.Background(), env, "ssh-keys-only", nil); err == nil || !strings.Contains(err.Error(), "sshd_config.d") {
		t.Fatalf("err %v", err)
	}
}

func TestKeysOnlyTurnsPasswordsOffAndCanBeUndone(t *testing.T) {
	env, run := newEnv(t)
	usersWithKeys(t, env, true)
	passwordsOffFor(run, "budi")
	write(t, env, "/etc/ssh/sshd_config", "include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n")
	run.failing["systemctl reload ssh"] = true
	if _, err := Apply(context.Background(), env, "ssh-keys-only", nil); err != nil {
		t.Fatal(err)
	}
	dropIn := read(env, "/etc/ssh/sshd_config.d/10-krynodes.conf")
	if !strings.Contains(dropIn, "PasswordAuthentication no") || !strings.Contains(dropIn, "KbdInteractiveAuthentication no") || strings.Contains(dropIn, "PermitRootLogin") {
		t.Fatalf("drop-in %q", dropIn)
	}
	if !slices.Contains(run.calls, "sshd -t") || !slices.Contains(run.calls, "systemctl reload sshd") {
		t.Fatalf("calls %q", run.calls)
	}
	if err := Undo(context.Background(), env, "ssh-keys-only", nil); err != nil || exists(env, "/etc/ssh/sshd_config.d/10-krynodes.conf") {
		t.Fatalf("undo %v", err)
	}
	if SSHLogins(context.Background(), env)[0] != "budi" {
		t.Fatalf("users %v", SSHLogins(context.Background(), env))
	}
}

func TestKeysOnlyLeavesNothingBehindWhenSSHRefusesTheChange(t *testing.T) {
	env, run := newEnv(t)
	usersWithKeys(t, env, true)
	write(t, env, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
	run.failing["sshd -t"] = true
	if _, err := Apply(context.Background(), env, "ssh-keys-only", nil); err == nil {
		t.Fatal("a refused change must fail")
	}
	if exists(env, "/etc/ssh/sshd_config.d/10-krynodes.conf") || slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "reload") }) {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestKeysOnlyStaysOffWhenAnEarlierSettingWins(t *testing.T) {
	env, run := newEnv(t)
	usersWithKeys(t, env, true)
	write(t, env, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
	afterSSHCheck(run, map[string]string{"sshd -T": "passwordauthentication no\n", budiProbe: "passwordauthentication yes\n"})
	_, err := Apply(context.Background(), env, "ssh-keys-only", nil)
	if err == nil || err.Error() != "SSH still accepts passwords for budi: a setting read before Krynodes' wins (a file in /etc/ssh/sshd_config.d or a Match block). Change it by hand." {
		t.Fatalf("err %v", err)
	}
	if exists(env, "/etc/ssh/sshd_config.d/10-krynodes.conf") || slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "reload") }) {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestFail2banIsTakenBackWhenItsJailDoesNotStart(t *testing.T) {
	env, run := newEnv(t)
	run.failing["fail2ban-client status sshd"] = true
	_, err := Apply(context.Background(), env, "fail2ban", nil)
	if err == nil || !strings.HasPrefix(err.Error(), "fail2ban started, but its SSH jail did not: ") {
		t.Fatalf("err %v", err)
	}
	if exists(env, "/etc/fail2ban/jail.d/krynodes.local") {
		t.Fatal("the jail is taken back")
	}
	if !slices.Contains(run.calls, "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 purge -y -q fail2ban python3-systemd") {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestAFirewallWithoutSSHIsTurnedBackOff(t *testing.T) {
	env, run := newEnv(t)
	run.respond["sshd -T"] = "port 22\n"
	run.respond["ufw status"] = "Status: inactive\n"
	run.effects["ufw --force enable"] = func() { run.respond["ufw status"] = "Status: active\n" }
	_, err := Apply(context.Background(), env, "firewall", nil)
	if err == nil || err.Error() != "The firewall came up without SSH allowed, so Krynodes turned it back off." {
		t.Fatalf("err %v", err)
	}
	if enable, disable := slices.Index(run.calls, "ufw --force enable"), slices.Index(run.calls, "ufw --force disable"); enable < 0 || disable < enable {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestAFirewallThatWasOnIsNotCheckedAgain(t *testing.T) {
	env, run := newEnv(t)
	run.respond["sshd -T"] = "port 22\n"
	run.respond["ufw status"] = "Status: active\n"
	if _, err := Apply(context.Background(), env, "firewall", nil); err != nil {
		t.Fatal(err)
	}
}

func TestRepeatedLoginFailuresAreBlocked(t *testing.T) {
	env, run := newEnv(t)
	if _, err := Apply(context.Background(), env, "fail2ban", nil); err != nil {
		t.Fatal(err)
	}
	for _, call := range []string{"env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -q fail2ban python3-systemd", "systemctl enable --now fail2ban", "systemctl restart fail2ban"} {
		if !slices.Contains(run.calls, call) {
			t.Fatalf("missing %q in %q", call, run.calls)
		}
	}
	if !strings.Contains(read(env, "/etc/fail2ban/jail.d/krynodes.local"), "[sshd]\nenabled = true") {
		t.Fatal("the sshd jail is on")
	}
	if err := Undo(context.Background(), env, "fail2ban", nil); err != nil || exists(env, "/etc/fail2ban/jail.d/krynodes.local") || !slices.Contains(run.calls, "systemctl disable --now fail2ban") {
		t.Fatalf("undo %v calls %q", err, run.calls)
	}
}

func TestTheFirewallKeepsSSHAndTheChosenPortsOpen(t *testing.T) {
	env, run := newEnv(t)
	run.respond["sshd -T"] = "port 2222\npasswordauthentication no\n"
	run.respond["ufw status"] = "Status: inactive\n"
	run.effects["ufw --force enable"] = func() {
		run.respond["ufw status"] = "Status: active\n\nTo Action From\n2222/tcp ALLOW Anywhere # krynodes\n"
	}
	saved, err := Apply(context.Background(), env, "firewall", map[string]string{"ports": "80/tcp,53/udp"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ufw allow 2222/tcp comment krynodes", "ufw allow 80/tcp comment krynodes", "ufw allow 53/udp comment krynodes", "ufw default deny incoming", "ufw default allow outgoing", "ufw --force enable"}
	for _, call := range want {
		if !slices.Contains(run.calls, call) {
			t.Fatalf("missing %q in %q", call, run.calls)
		}
	}
	if slices.Index(run.calls, "ufw allow 2222/tcp comment krynodes") > slices.Index(run.calls, "ufw --force enable") {
		t.Fatal("SSH is allowed before the firewall turns on")
	}
	run.calls = nil
	if err := Undo(context.Background(), env, "firewall", saved); err != nil {
		t.Fatal(err)
	}
	for _, call := range []string{"ufw --force delete allow 2222/tcp", "ufw --force delete allow 80/tcp", "ufw --force delete allow 53/udp", "ufw --force disable"} {
		if !slices.Contains(run.calls, call) {
			t.Fatalf("missing %q in %q", call, run.calls)
		}
	}
}

func TestTheFirewallKeepsEveryPortSSHReallyListensOn(t *testing.T) {
	env, run := newEnv(t)
	run.respond["sshd -T"] = "port 22\n"
	run.respond["systemctl show ssh.socket -p Listen --value"] = "[::]:2200 (Stream)\n"
	run.respond["ss -H -tulnp"] = "tcp LISTEN 0 128 0.0.0.0:2022 0.0.0.0:* users:((\"sshd\",pid=9,fd=3))\n" +
		"tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:((\"nginx\",pid=7,fd=3))\n"
	run.respond["ufw status"] = "Status: inactive\n"
	run.effects["ufw --force enable"] = func() {
		run.respond["ufw status"] = "Status: active\n\n22/tcp ALLOW Anywhere # krynodes\n2200/tcp ALLOW Anywhere # krynodes\n2022/tcp ALLOW Anywhere # krynodes\n"
	}
	if _, err := Apply(context.Background(), env, "firewall", nil); err != nil {
		t.Fatal(err)
	}
	enable := slices.Index(run.calls, "ufw --force enable")
	for _, port := range []string{"22", "2200", "2022"} {
		allow := slices.Index(run.calls, "ufw allow "+port+"/tcp comment krynodes")
		if allow < 0 || allow > enable {
			t.Fatalf("SSH on %s is not kept open before the firewall turns on: %q", port, run.calls)
		}
	}
	if slices.Contains(run.calls, "ufw allow 8080/tcp comment krynodes") {
		t.Fatalf("only SSH and the chosen ports: %q", run.calls)
	}
}

func TestAFirewallThatWasOnStaysOnAfterUndo(t *testing.T) {
	env, run := newEnv(t)
	run.respond["sshd -T"] = "port 22\n"
	run.respond["ufw status"] = "Status: active\n"
	saved, err := Apply(context.Background(), env, "firewall", nil)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(run.calls, "ufw --force enable") || slices.Contains(run.calls, "ufw default deny incoming") {
		t.Fatalf("an active firewall keeps its own defaults: %q", run.calls)
	}
	if err := Undo(context.Background(), env, "firewall", saved); err != nil || slices.Contains(run.calls, "ufw --force disable") {
		t.Fatalf("undo %v calls %q", err, run.calls)
	}
	if _, err := Apply(context.Background(), env, "firewall", map[string]string{"ports": "80;rm -rf /"}); err == nil {
		t.Fatal("a port must look like 80/tcp")
	}
}

func TestPort53IsFreedFromSystemdResolved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privilege on Windows")
	}
	env, run := newEnv(t)
	run.failing["systemctl is-active --quiet systemd-resolved"] = true
	if _, err := Apply(context.Background(), env, "free-port-53", nil); err == nil {
		t.Fatal("nothing to free without systemd-resolved")
	}
	delete(run.failing, "systemctl is-active --quiet systemd-resolved")
	write(t, env, "/run/systemd/resolve/stub-resolv.conf", "nameserver 127.0.0.53\n")
	write(t, env, "/run/systemd/resolve/resolv.conf", "nameserver 1.1.1.1\n")
	if err := os.MkdirAll(env.path("/etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../run/systemd/resolve/stub-resolv.conf", env.path("/etc/resolv.conf")); err != nil {
		t.Fatal(err)
	}
	saved, err := Apply(context.Background(), env, "free-port-53", nil)
	if err != nil {
		t.Fatal(err)
	}
	link, _ := os.Readlink(env.path("/etc/resolv.conf"))
	if link != "/run/systemd/resolve/resolv.conf" || !strings.Contains(read(env, "/etc/systemd/resolved.conf.d/krynodes-no-stub.conf"), "DNSStubListener=no") || !slices.Contains(run.calls, "systemctl restart systemd-resolved") {
		t.Fatalf("link %q calls %q", link, run.calls)
	}
	if err := Undo(context.Background(), env, "free-port-53", saved); err != nil {
		t.Fatal(err)
	}
	link, _ = os.Readlink(env.path("/etc/resolv.conf"))
	if link != "../run/systemd/resolve/stub-resolv.conf" || exists(env, "/etc/systemd/resolved.conf.d/krynodes-no-stub.conf") {
		t.Fatalf("link %q", link)
	}
}

func TestPort53StaysWhenResolvedKnowsNoUpstreamServer(t *testing.T) {
	env, run := newEnv(t)
	write(t, env, "/run/systemd/resolve/resolv.conf", "# no servers yet\nsearch example\n")
	if _, err := Apply(context.Background(), env, "free-port-53", nil); err == nil || !strings.Contains(err.Error(), "no DNS server") {
		t.Fatalf("err %v", err)
	}
	if exists(env, "/etc/systemd/resolved.conf.d/krynodes-no-stub.conf") || slices.Contains(run.calls, "systemctl restart systemd-resolved") {
		t.Fatalf("nothing changes: %q", run.calls)
	}
}

func TestAFailedPort53ChangeGivesDNSBack(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privilege on Windows")
	}
	env, run := newEnv(t)
	write(t, env, "/run/systemd/resolve/stub-resolv.conf", "nameserver 127.0.0.53\n")
	write(t, env, "/run/systemd/resolve/resolv.conf", "nameserver 1.1.1.1\n")
	if err := os.MkdirAll(env.path("/etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../run/systemd/resolve/stub-resolv.conf", env.path("/etc/resolv.conf")); err != nil {
		t.Fatal(err)
	}
	run.failing["systemctl restart systemd-resolved"] = true
	if _, err := Apply(context.Background(), env, "free-port-53", nil); err == nil {
		t.Fatal("the failed restart is reported")
	}
	link, _ := os.Readlink(env.path("/etc/resolv.conf"))
	if link != "../run/systemd/resolve/stub-resolv.conf" || exists(env, "/etc/systemd/resolved.conf.d/krynodes-no-stub.conf") {
		t.Fatalf("DNS is not as it was: link %q", link)
	}
}

func TestKeysOnlyLeavesRootLoginAsStrictAsItWas(t *testing.T) {
	for setting, want := range map[string]bool{"permitrootlogin no\n": false, "permitrootlogin yes\n": false} {
		env, run := newEnv(t)
		usersWithKeys(t, env, true)
		write(t, env, "/etc/ssh/sshd_config", "include /etc/ssh/sshd_config.d/*.conf\n")
		run.respond["sshd -T"] = setting
		passwordsOffFor(run, "budi")
		if _, err := Apply(context.Background(), env, "ssh-keys-only", nil); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(read(env, "/etc/ssh/sshd_config.d/10-krynodes.conf"), "PermitRootLogin"); got != want {
			t.Fatalf("%q: root line %v", setting, got)
		}
	}
}

func TestOnlyAccountsSSHLetsInCountAsKeyedLogins(t *testing.T) {
	for setting, want := range map[string][]string{
		"":                                           {"budi", "root"},
		"permitrootlogin no\n":                       {"budi"},
		"permitrootlogin forced-commands-only\n":     {"budi"},
		"allowusers admin\n":                         {},
		"allowusers budi@10.0.0.*\n":                 {"budi"},
		"denyusers bud*\n":                           {"root"},
		"allowgroups sudo\n":                         {"budi"},
		"denygroups sudo\n":                          {"root"},
		"pubkeyauthentication no\n":                  {},
		"authenticationmethods any\n":                {"budi", "root"},
		"authenticationmethods publickey,password\n": {},
		"authenticationmethods publickey,keyboard-interactive:pam\n":      {},
		"authenticationmethods publickey,password publickey\n":            {"budi", "root"},
		"authorizedkeysfile /etc/ssh/keys/%u\n":                           {},
		"authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n": {"budi", "root"},
	} {
		env, run := newEnv(t)
		usersWithKeys(t, env, true)
		write(t, env, "/root/.ssh/authorized_keys", "ssh-ed25519 AAAA root@laptop\n")
		run.respond["sshd -T"] = setting
		if got := SSHLogins(context.Background(), env); !slices.Equal(got, want) && !(len(got) == 0 && len(want) == 0) {
			t.Fatalf("%q: logins %v, want %v", setting, got, want)
		}
	}
	env, run := newEnv(t)
	usersWithKeys(t, env, false)
	write(t, env, "/root/.ssh/authorized_keys", "ssh-ed25519 AAAA root@laptop\n")
	write(t, env, "/etc/ssh/sshd_config", "include /etc/ssh/sshd_config.d/*.conf\n")
	run.respond["sshd -T"] = "permitrootlogin no\n"
	if _, err := Apply(context.Background(), env, "ssh-keys-only", nil); err == nil || exists(env, "/etc/ssh/sshd_config.d/10-krynodes.conf") {
		t.Fatalf("a key root may not use keeps nobody in: %v", err)
	}
}

func TestAMatchBlockForOneAccountIsCounted(t *testing.T) {
	env, run := newEnv(t)
	usersWithKeys(t, env, true)
	write(t, env, "/root/.ssh/authorized_keys", "ssh-ed25519 AAAA root@laptop\n")
	run.respond["sshd -T"] = ""
	run.respond["sshd -T -C user=budi,host=krynodes.invalid,addr=192.0.2.1"] = "pubkeyauthentication no\n"
	run.respond["sshd -T -C user=root,host=krynodes.invalid,addr=192.0.2.1"] = "permitrootlogin prohibit-password\npubkeyauthentication yes\n"
	if got := SSHLogins(context.Background(), env); !slices.Equal(got, []string{"root"}) {
		t.Fatalf("logins %v", got)
	}
}

func TestKeysInTheFileSSHReadsCount(t *testing.T) {
	env, run := newEnv(t)
	usersWithKeys(t, env, true)
	write(t, env, "/etc/ssh/keys/root", "ssh-ed25519 AAAA root@laptop\n")
	run.respond["sshd -T"] = "authorizedkeysfile /etc/ssh/keys/%u %h/.ssh/none\n"
	if got := SSHLogins(context.Background(), env); !slices.Equal(got, []string{"root"}) {
		t.Fatalf("logins %v", got)
	}
}

func TestKeysOnlyLeavesNothingWhenSSHCannotReload(t *testing.T) {
	env, run := newEnv(t)
	usersWithKeys(t, env, true)
	write(t, env, "/etc/ssh/sshd_config", "include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n")
	run.failing["systemctl reload ssh"] = true
	run.failing["systemctl reload sshd"] = true
	passwordsOffFor(run, "budi")
	if _, err := Apply(context.Background(), env, "ssh-keys-only", nil); err == nil {
		t.Fatal("the failed reload is reported")
	}
	if exists(env, "/etc/ssh/sshd_config.d/10-krynodes.conf") {
		t.Fatal("a drop-in that never took effect would turn passwords off at the next SSH restart")
	}
}

func TestUnknownRecipesAreRefused(t *testing.T) {
	env, run := newEnv(t)
	if _, err := Apply(context.Background(), env, "rm-rf", nil); err == nil || len(run.calls) != 0 {
		t.Fatal("unknown recipes must be refused")
	}
	if err := Undo(context.Background(), env, "reboot-window", nil); err == nil {
		t.Fatal("the reboot window is not a host recipe")
	}
}

func TestAFailedProtectionTakesBackThePackagesItInstalled(t *testing.T) {
	env, run := newEnv(t)
	run.respond["dpkg-query -W -f ${Status} python3-systemd"] = "install ok installed"
	run.failing["systemctl enable --now fail2ban"] = true
	if _, err := Apply(context.Background(), env, "fail2ban", nil); err == nil {
		t.Fatal("the failure is reported")
	}
	purge := "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 purge -y -q fail2ban"
	if exists(env, "/etc/fail2ban/jail.d/krynodes.local") || !slices.Contains(run.calls, purge) {
		t.Fatalf("calls %q", run.calls)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool {
		return strings.Contains(call, "purge") && strings.Contains(call, "python3-systemd")
	}) {
		t.Fatal("a package that was there before stays")
	}
}

func TestUndoRemovesOnlyThePackagesItInstalled(t *testing.T) {
	env, run := newEnv(t)
	run.respond["dpkg-query -W -f ${Status} python3-systemd"] = "install ok installed"
	run.respond["dpkg-query -W -f ${Status} unattended-upgrades"] = "install ok installed"
	run.respond[unattendedProbe] = "UU='1'"
	saved, err := Apply(context.Background(), env, "fail2ban", nil)
	if err != nil || saved["installed"] != "fail2ban" {
		t.Fatalf("saved %v err %v", saved, err)
	}
	if err := Undo(context.Background(), env, "fail2ban", saved); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(run.calls, "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 purge -y -q fail2ban") {
		t.Fatalf("calls %q", run.calls)
	}
	kept, err := Apply(context.Background(), env, "security-updates", nil)
	if err != nil || kept["installed"] != "" {
		t.Fatalf("saved %v err %v", kept, err)
	}
	before := len(run.calls)
	if err := Undo(context.Background(), env, "security-updates", kept); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(run.calls[before:], func(call string) bool { return strings.Contains(call, "purge") }) {
		t.Fatalf("a package that was there before stays: %q", run.calls[before:])
	}
}
