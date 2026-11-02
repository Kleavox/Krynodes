package recipes

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func selinuxServer(t *testing.T, enforce, config string) (Env, *fakeRun) {
	t.Helper()
	env, run := onRelease(t, "rocky")
	if enforce != "" {
		write(t, env, "/sys/fs/selinux/enforce", enforce)
	}
	write(t, env, "/etc/selinux/config", "# SELinux\n"+config+"SELINUXTYPE=targeted\n")
	write(t, env, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/srv/user:/bin/bash\nother:x:1001:1001::/home/other:/bin/bash\n")
	write(t, env, "/etc/group", "wheel:x:10:user,other\n")
	write(t, env, "/srv/user/.ssh/authorized_keys", "ssh-ed25519 AAAA user\n")
	write(t, env, "/home/other/.ssh/authorized_keys", "ssh-ed25519 AAAA other\n")
	run.respond["sshd -T"] = "port 22\nport 2222\n"
	return env, run
}

func calledInOrder(t *testing.T, run *fakeRun, calls ...string) {
	t.Helper()
	at := 0
	for _, call := range run.calls {
		if at < len(calls) && strings.TrimSpace(call) == calls[at] {
			at++
		}
	}
	if at < len(calls) {
		t.Fatalf("missing %q in order, calls %q", calls[at], run.calls)
	}
}

func TestSELinuxPermissiveGoesEnforcingAfterTheSSHPortAndHomeLabels(t *testing.T) {
	env, run := selinuxServer(t, "0", "SELINUX=permissive\n")
	saved, err := Apply(context.Background(), env, "confinement", nil)
	if err != nil {
		t.Fatal(err)
	}
	calledInOrder(t, run,
		"semanage port -a -t ssh_port_t -p tcp 2222",
		`semanage fcontext -a -t ssh_home_t /srv/user/\.ssh(/.*)?`,
		"restorecon -R /srv/user/.ssh",
		"setenforce 1",
	)
	if slices.ContainsFunc(run.calls, func(call string) bool {
		return strings.Contains(call, "/home/other") || strings.HasSuffix(call, "tcp 22") || strings.Contains(call, " -e ") || call == "restorecon -R /srv/user"
	}) {
		t.Fatalf("labelled what needs none: %q", run.calls)
	}
	if got := read(env, "/etc/selinux/config"); got != "# SELinux\nSELINUX=enforcing\nSELINUXTYPE=targeted\n" {
		t.Fatalf("config %q", got)
	}
	if saved["system"] != "selinux" || saved["mode"] != "permissive" || saved["config"] != "permissive" || saved["restart"] != "" {
		t.Fatalf("saved %v", saved)
	}
	run.calls = nil
	if err := Undo(context.Background(), env, "confinement", saved); err != nil {
		t.Fatal(err)
	}
	calledInOrder(t, run, "setenforce 0")
	if got := read(env, "/etc/selinux/config"); got != "# SELinux\nSELINUX=permissive\nSELINUXTYPE=targeted\n" {
		t.Fatalf("config after undo %q", got)
	}
}

func TestSELinuxDisabledIsTurnedOnAtTheNextRestart(t *testing.T) {
	env, run := selinuxServer(t, "", "SELINUX=disabled\n")
	saved, err := Apply(context.Background(), env, "confinement", nil)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(run.calls, "setenforce 1") || !exists(env, "/.autorelabel") || saved["restart"] != "1" || !strings.Contains(read(env, "/etc/selinux/config"), "SELINUX=enforcing\n") {
		t.Fatalf("calls %q saved %v", run.calls, saved)
	}
	if err := Undo(context.Background(), env, "confinement", saved); err != nil {
		t.Fatal(err)
	}
	if exists(env, "/.autorelabel") || !strings.Contains(read(env, "/etc/selinux/config"), "SELINUX=disabled\n") || slices.Contains(run.calls, "setenforce 0") {
		t.Fatalf("before the restart Undo puts back what was there: calls %q", run.calls)
	}

	saved, err = Apply(context.Background(), env, "confinement", nil)
	if err != nil {
		t.Fatal(err)
	}
	write(t, env, "/sys/fs/selinux/enforce", "1")
	env.remove("/.autorelabel")
	if err := Undo(context.Background(), env, "confinement", saved); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(run.calls, "setenforce 0") || !strings.Contains(read(env, "/etc/selinux/config"), "SELINUX=permissive\n") {
		t.Fatalf("after the restart a disabled start comes back permissive: calls %q config %q", run.calls, read(env, "/etc/selinux/config"))
	}
}

func TestSELinuxOffInTheKernelIsTurnedOnInTheBootSettings(t *testing.T) {
	env, run := selinuxServer(t, "", "SELINUX=disabled\n")
	write(t, env, "/proc/cmdline", "BOOT_IMAGE=/vmlinuz ro selinux=0 quiet\n")
	saved, err := Apply(context.Background(), env, "confinement", nil)
	if err != nil {
		t.Fatal(err)
	}
	calledInOrder(t, run, `semanage fcontext -a -t ssh_home_t /srv/user/\.ssh(/.*)?`, "grubby --update-kernel ALL --remove-args selinux")
	if !exists(env, "/.autorelabel") || saved["restart"] != "1" || saved["kernel"] != "1" || saved["mode"] != "kernel-off" || !strings.Contains(read(env, "/etc/selinux/config"), "SELINUX=enforcing\n") {
		t.Fatalf("calls %q saved %v", run.calls, saved)
	}
	run.calls = nil
	if err := Undo(context.Background(), env, "confinement", saved); err != nil {
		t.Fatal(err)
	}
	calledInOrder(t, run, "grubby --update-kernel ALL --args selinux=0")
	if exists(env, "/.autorelabel") || !strings.Contains(read(env, "/etc/selinux/config"), "SELINUX=disabled\n") || slices.Contains(run.calls, "setenforce 0") {
		t.Fatalf("before the restart Undo puts back what was there: calls %q", run.calls)
	}

	saved, err = Apply(context.Background(), env, "confinement", nil)
	if err != nil {
		t.Fatal(err)
	}
	write(t, env, "/proc/cmdline", "BOOT_IMAGE=/vmlinuz ro quiet\n")
	write(t, env, "/sys/fs/selinux/enforce", "1")
	env.remove("/.autorelabel")
	run.calls = nil
	if err := Undo(context.Background(), env, "confinement", saved); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(run.calls, "setenforce 0") || slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "grubby") }) || !strings.Contains(read(env, "/etc/selinux/config"), "SELINUX=permissive\n") {
		t.Fatalf("after the restart it comes back permissive and the boot stays as it is: calls %q config %q", run.calls, read(env, "/etc/selinux/config"))
	}
}

func TestSELinuxOffInTheKernelRefusesWhenTheBootSettingsCannotChange(t *testing.T) {
	env, run := selinuxServer(t, "", "SELINUX=disabled\n")
	write(t, env, "/proc/cmdline", "ro selinux=0\n")
	run.failing["grubby --update-kernel ALL --remove-args selinux"] = true
	if _, err := Apply(context.Background(), env, "confinement", nil); err == nil {
		t.Fatal("applied without the boot setting")
	}
	if exists(env, "/.autorelabel") || !strings.Contains(read(env, "/etc/selinux/config"), "SELINUX=disabled\n") {
		t.Fatalf("changed anyway: calls %q config %q", run.calls, read(env, "/etc/selinux/config"))
	}
}

func TestSELinuxAlreadyEnforcingIsTakenOverWithoutAChange(t *testing.T) {
	env, run := selinuxServer(t, "1", "SELINUX=enforcing\n")
	saved, err := Apply(context.Background(), env, "confinement", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Undo(context.Background(), env, "confinement", saved); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool {
		return strings.HasPrefix(call, "setenforce") || strings.HasPrefix(call, "semanage")
	}) || !strings.Contains(read(env, "/etc/selinux/config"), "SELINUX=enforcing\n") {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestSELinuxRefusesWhenItCannotLabelACustomSSHPort(t *testing.T) {
	env, run := selinuxServer(t, "0", "SELINUX=permissive\n")
	run.failing["rpm -q policycoreutils-python-utils"] = true
	run.failing["dnf install -y -q policycoreutils-python-utils"] = true
	_, err := Apply(context.Background(), env, "confinement", nil)
	if err == nil || !strings.Contains(err.Error(), "2222") {
		t.Fatalf("err %v", err)
	}
	if slices.Contains(run.calls, "setenforce 1") || !strings.Contains(read(env, "/etc/selinux/config"), "SELINUX=permissive\n") {
		t.Fatalf("switched anyway: %q", run.calls)
	}
}

func TestSELinuxPutsBackWhatItInstalled(t *testing.T) {
	env, run := selinuxServer(t, "0", "SELINUX=permissive\n")
	run.failing["rpm -q policycoreutils-python-utils"] = true
	saved, err := Apply(context.Background(), env, "confinement", nil)
	if err != nil || saved["installed"] != "policycoreutils-python-utils" {
		t.Fatalf("saved %v err %v", saved, err)
	}
	if err := Undo(context.Background(), env, "confinement", saved); err != nil {
		t.Fatal(err)
	}
	calledInOrder(t, run, "setenforce 0", "dnf remove -y -q policycoreutils-python-utils")
}

func apparmorServer(t *testing.T, enabled, profiles string) (Env, *fakeRun) {
	t.Helper()
	env, run := newEnv(t)
	if enabled != "" {
		write(t, env, "/sys/module/apparmor/parameters/enabled", enabled)
	}
	if profiles != "" {
		write(t, env, "/sys/kernel/security/apparmor/profiles", profiles)
	}
	return env, run
}

func TestAppArmorEnforcesTheProfilesInComplainAndUndoPutsThemBack(t *testing.T) {
	env, run := apparmorServer(t, "Y\n", "docker-default (enforce)\n/usr/bin/man (complain)\n/usr/sbin/tool (complain)\n")
	saved, err := Apply(context.Background(), env, "confinement", nil)
	if err != nil {
		t.Fatal(err)
	}
	calledInOrder(t, run, "aa-enforce /usr/bin/man", "aa-enforce /usr/sbin/tool")
	if saved["system"] != "apparmor" || saved["complain"] != "/usr/bin/man\n/usr/sbin/tool" || saved["installed"] != "apparmor-utils" {
		t.Fatalf("saved %v", saved)
	}
	run.calls = nil
	if err := Undo(context.Background(), env, "confinement", saved); err != nil {
		t.Fatal(err)
	}
	calledInOrder(t, run, "aa-complain /usr/bin/man", "aa-complain /usr/sbin/tool")
	if slices.ContainsFunc(run.calls, func(call string) bool {
		return strings.Contains(call, "disable") || strings.Contains(call, "purge -y -q apparmor ")
	}) {
		t.Fatalf("AppArmor is never turned off: %q", run.calls)
	}
}

func TestAppArmorNotRunningIsInstalledAndStarted(t *testing.T) {
	env, run := apparmorServer(t, "Y\n", "")
	saved, err := Apply(context.Background(), env, "confinement", nil)
	if err != nil {
		t.Fatal(err)
	}
	calledInOrder(t, run, "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -q apparmor apparmor-utils", "systemctl enable --now apparmor")
	if strings.Contains(saved["installed"], "apparmor ") || saved["installed"] == "apparmor" {
		t.Fatalf("apparmor itself is never purged: %v", saved)
	}
}

func TestAppArmorOffAtBootOnAPiGoesInTheCmdlineAndUndoTakesItOut(t *testing.T) {
	for _, original := range []string{"console=tty1 root=PARTUUID=x rootwait\n", "console=tty1 root=PARTUUID=x rootwait"} {
		env, run := apparmorServer(t, "N\n", "")
		write(t, env, "/boot/firmware/cmdline.txt", original)
		write(t, env, "/boot/cmdline.txt", "DO NOT EDIT THIS FILE\n\nThe file you are looking for has moved to /boot/firmware/cmdline.txt\n")
		saved, err := Apply(context.Background(), env, "confinement", nil)
		if err != nil {
			t.Fatal(err)
		}
		want := strings.Replace(original, "rootwait", "rootwait apparmor=1 security=apparmor", 1)
		if got := read(env, "/boot/firmware/cmdline.txt"); got != want || saved["cmdline"] != "/boot/firmware/cmdline.txt" || saved["restart"] != "1" {
			t.Fatalf("cmdline %q saved %v", got, saved)
		}
		if slices.Contains(run.calls, "update-grub") || exists(env, grubAppArmor) || !strings.HasPrefix(read(env, "/boot/cmdline.txt"), "DO NOT EDIT") {
			t.Fatalf("touched grub or the stub: %q", run.calls)
		}
		if err := Undo(context.Background(), env, "confinement", saved); err != nil {
			t.Fatal(err)
		}
		if got := read(env, "/boot/firmware/cmdline.txt"); got != original {
			t.Fatalf("after Undo %q, want %q", got, original)
		}
	}
}

func TestAppArmorOffAtBootSkipsThePiStubAndRefusesWithNoBootSettings(t *testing.T) {
	env, run := apparmorServer(t, "N\n", "")
	stub := "DO NOT EDIT THIS FILE\n\nThe file you are looking for has moved to /boot/firmware/cmdline.txt\n"
	write(t, env, "/boot/cmdline.txt", stub)
	if _, err := Apply(context.Background(), env, "confinement", nil); err == nil || !strings.Contains(err.Error(), "boot") {
		t.Fatalf("err %v", err)
	}
	if read(env, "/boot/cmdline.txt") != stub || slices.Contains(run.calls, "update-grub") {
		t.Fatalf("changed something: %q", run.calls)
	}

	env, _ = apparmorServer(t, "N\n", "")
	write(t, env, "/boot/cmdline.txt", "root=/dev/mmcblk0p2 rootwait\n")
	saved, err := Apply(context.Background(), env, "confinement", nil)
	if err != nil || read(env, "/boot/cmdline.txt") != "root=/dev/mmcblk0p2 rootwait apparmor=1 security=apparmor\n" || saved["cmdline"] != "/boot/cmdline.txt" {
		t.Fatalf("an older Pi keeps its line in /boot: err %v saved %v", err, saved)
	}
}

func TestAppArmorOffAtBootGetsABootSettingAndARestart(t *testing.T) {
	env, run := apparmorServer(t, "N\n", "")
	write(t, env, "/etc/default/grub", "GRUB_CMDLINE_LINUX=\"\"\n")
	saved, err := Apply(context.Background(), env, "confinement", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := read(env, grubAppArmor); !strings.Contains(got, "apparmor=1 security=apparmor") || saved["restart"] != "1" {
		t.Fatalf("drop-in %q saved %v", got, saved)
	}
	calledInOrder(t, run, "update-grub")
	if err := Undo(context.Background(), env, "confinement", saved); err != nil {
		t.Fatal(err)
	}
	if exists(env, grubAppArmor) {
		t.Fatal("the boot setting stays after Undo")
	}
}

func TestTheCheckBeforeEnrollSaysWhyItCannotTurnOn(t *testing.T) {
	ctx := context.Background()
	env, _ := onRelease(t, "rocky")
	write(t, env, "/etc/os-release", "ID=alpine\n")
	if err := CheckConfine(ctx, env); err == nil || err.Error() != "this server has neither SELinux nor AppArmor, which Krynodes needs on every server" {
		t.Fatalf("neither: %v", err)
	}

	env, run := selinuxServer(t, "", "SELINUX=disabled\n")
	write(t, env, "/proc/cmdline", "ro selinux=0\n")
	run.failing["sh -c command -v grubby"] = true
	if err := CheckConfine(ctx, env); err == nil || err.Error() != "SELinux is off when this server boots, and Krynodes found no grubby to turn it on" {
		t.Fatalf("no grubby: %v", err)
	}
	delete(run.failing, "sh -c command -v grubby")
	if err := CheckConfine(ctx, env); err != nil {
		t.Fatalf("with grubby: %v", err)
	}

	env, _ = selinuxServer(t, "0", "SELINUX=permissive\n")
	if err := CheckConfine(ctx, env); err != nil {
		t.Fatalf("a key home with .ssh: %v", err)
	}

	env, _ = apparmorServer(t, "N\n", "")
	if err := CheckConfine(ctx, env); err == nil || err.Error() != "AppArmor is off when this server boots, and Krynodes found no grub or cmdline.txt to turn it on" {
		t.Fatalf("no boot file: %v", err)
	}
	write(t, env, "/boot/firmware/cmdline.txt", "root=PARTUUID=x rootwait\n")
	if err := CheckConfine(ctx, env); err != nil {
		t.Fatalf("a Pi: %v", err)
	}
	if got := read(env, "/boot/firmware/cmdline.txt"); got != "root=PARTUUID=x rootwait\n" {
		t.Fatalf("the check changed %q", got)
	}
}

func TestTheCheckBeforeEnrollRefusesAKeyHomeWithoutSSHFolder(t *testing.T) {
	env, run := selinuxServer(t, "0", "SELINUX=permissive\n")
	write(t, env, "/srv/user/.config/keys", "ssh-ed25519 AAAA user\n")
	if err := os.RemoveAll(env.path("/srv/user/.ssh")); err != nil {
		t.Fatal(err)
	}
	run.respond["sshd -T"] = "port 22\nauthorizedkeysfile .config/keys\n"
	if err := CheckConfine(context.Background(), env); err == nil || err.Error() != "SELinux would block key logins into /srv/user: its keys are not in /srv/user/.ssh" {
		t.Fatalf("err %v", err)
	}
}

func TestConfinementNeedsSELinuxOrAppArmor(t *testing.T) {
	env, _ := onRelease(t, "rocky")
	write(t, env, "/etc/os-release", "ID=alpine\n")
	if _, err := Apply(context.Background(), env, "confinement", nil); err == nil {
		t.Fatal("applied on a server with neither")
	}
}

func TestSELinuxLabelsTheHomeOfEveryKeyLoginNotOnlyAdmins(t *testing.T) {
	env, run := selinuxServer(t, "0", "SELINUX=permissive\n")
	write(t, env, "/etc/passwd", read(env, "/etc/passwd")+"deploy:x:1002:1002::/srv/deploy:/bin/bash\n")
	write(t, env, "/srv/deploy/.ssh/authorized_keys", "ssh-ed25519 AAAA deploy\n")
	if _, err := Apply(context.Background(), env, "confinement", nil); err != nil {
		t.Fatal(err)
	}
	calledInOrder(t, run, `semanage fcontext -a -t ssh_home_t /srv/deploy/\.ssh(/.*)?`, "restorecon -R /srv/deploy/.ssh", "setenforce 1")
}

func TestSELinuxLabelsTheRealFolderOfAHomeBehindALink(t *testing.T) {
	env, run := selinuxServer(t, "0", "SELINUX=permissive\n")
	if err := os.MkdirAll(env.path("/data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(env.path("/home"), env.path("/data/home")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(env.path("/data/home"), env.path("/home")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	if _, err := Apply(context.Background(), env, "confinement", nil); err != nil {
		t.Fatal(err)
	}
	calledInOrder(t, run, `semanage fcontext -a -t ssh_home_t /data/home/other/\.ssh(/.*)?`, "restorecon -R /data/home/other/.ssh", "setenforce 1")
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, filepath.Base(env.Root)) }) {
		t.Fatalf("labelled a path outside the server: %q", run.calls)
	}
}
