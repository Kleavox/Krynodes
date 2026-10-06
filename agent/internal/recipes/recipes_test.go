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
}

func (f *fakeRun) run(_ context.Context, name string, args ...string) ([]byte, int, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if f.failing[call] {
		return []byte("failed"), 1, errors.New("exit status 1")
	}
	return []byte(f.respond[call]), 0, nil
}

func newEnv(t *testing.T) (Env, *fakeRun) {
	t.Helper()
	run := &fakeRun{respond: map[string]string{}, failing: map[string]bool{}}
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

func usersWithKeys(t *testing.T, env Env, keyed bool) {
	t.Helper()
	write(t, env, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nbudi:x:1000:1000::/home/budi:/bin/bash\nwww:x:33:33::/var/www:/usr/sbin/nologin\n")
	write(t, env, "/etc/group", "sudo:x:27:budi\n")
	if keyed {
		write(t, env, "/home/budi/.ssh/authorized_keys", "# laptop\nssh-ed25519 AAAAC3Nza budi@laptop\n")
	}
	write(t, env, "/var/www/.ssh/authorized_keys", "ssh-ed25519 AAAA www\n")
}

func TestAutomaticSecurityUpdates(t *testing.T) {
	env, run := newEnv(t)
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
	if len(run.calls) != 0 || exists(env, "/etc/ssh/sshd_config.d/10-krynodes.conf") {
		t.Fatalf("calls %q", run.calls)
	}
	if users := KeyedUsers(env); len(users) != 0 {
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
	write(t, env, "/etc/ssh/sshd_config", "include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n")
	run.failing["systemctl reload ssh"] = true
	if _, err := Apply(context.Background(), env, "ssh-keys-only", nil); err != nil {
		t.Fatal(err)
	}
	dropIn := read(env, "/etc/ssh/sshd_config.d/10-krynodes.conf")
	if !strings.Contains(dropIn, "PasswordAuthentication no") || !strings.Contains(dropIn, "KbdInteractiveAuthentication no") || !strings.Contains(dropIn, "PermitRootLogin prohibit-password") {
		t.Fatalf("drop-in %q", dropIn)
	}
	if !slices.Contains(run.calls, "sshd -t") || !slices.Contains(run.calls, "systemctl reload sshd") {
		t.Fatalf("calls %q", run.calls)
	}
	if err := Undo(context.Background(), env, "ssh-keys-only", nil); err != nil || exists(env, "/etc/ssh/sshd_config.d/10-krynodes.conf") {
		t.Fatalf("undo %v", err)
	}
	if KeyedUsers(env)[0] != "budi" {
		t.Fatalf("users %v", KeyedUsers(env))
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

func TestUnknownRecipesAreRefused(t *testing.T) {
	env, run := newEnv(t)
	if _, err := Apply(context.Background(), env, "rm-rf", nil); err == nil || len(run.calls) != 0 {
		t.Fatal("unknown recipes must be refused")
	}
	if err := Undo(context.Background(), env, "reboot-window", nil); err == nil {
		t.Fatal("the reboot window is not a host recipe")
	}
}

func TestUndoRemovesOnlyThePackagesItInstalled(t *testing.T) {
	env, run := newEnv(t)
	run.respond["dpkg-query -W -f ${Status} python3-systemd"] = "install ok installed"
	run.respond["dpkg-query -W -f ${Status} unattended-upgrades"] = "install ok installed"
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
