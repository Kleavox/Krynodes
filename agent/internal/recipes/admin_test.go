package recipes

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
)

const (
	laptopBlob     = "AAAAC3NzaC1lZDI1NTE5AAAAINgR/LmOeWesWGV4gX2RBfBT5TKbBcKMCk+GVyMOWScy"
	laptopPrint    = "SHA256:lMKB0LebO8arH9OP7OBxvLF0veMl7Of0UHgkPdafFtQ"
	phoneBlob      = "AAAAC3NzaC1lZDI1NTE5AAAAIDVFg4Wx2NViu9ZffqPwSTCUsSzH60Im/4s1noczsx+q"
	passwordMarker = "pw-marker-5f3a"
	sudoList       = "User user1 may run the following commands on server-2:\n    (ALL : ALL) ALL\n"
)

type fakeTerminal struct {
	run      *fakeRun
	answer   bool
	asked    bool
	fails    int
	printed  strings.Builder
	askedAt  int
	password string
}

func (f *fakeTerminal) Ask(question string) (bool, bool) {
	f.printed.WriteString(question)
	f.askedAt = len(f.run.calls)
	return f.answer, f.asked
}

func (f *fakeTerminal) Passwd(_ context.Context, name string) error {
	f.run.calls = append(f.run.calls, "tty passwd "+name)
	if f.fails > 0 {
		f.fails--
		return errors.New("passwd: Authentication token manipulation error")
	}
	return nil
}

func (f *fakeTerminal) Printf(format string, args ...any) {
	fmt.Fprintf(&f.printed, format, args...)
}

func adminKeys(t *testing.T) []AdminKey {
	t.Helper()
	var keys []AdminKey
	for _, arg := range []string{laptopBlob + ":laptop", phoneBlob + ":phone"} {
		key, err := ParseAdminKey(arg)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	return keys
}

func adminServer(t *testing.T, release string) (Env, *fakeRun, *fakeTerminal) {
	t.Helper()
	env, run := newEnv(t)
	if release != "" {
		write(t, env, "/etc/os-release", releases[release])
	}
	write(t, env, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nwww:x:33:33::/var/www:/usr/sbin/nologin\n")
	write(t, env, "/etc/group", "sudo:x:27:\nwheel:x:10:\n")
	run.effects = map[string]func(){
		"useradd -m -s /bin/bash user1": func() {
			write(t, env, "/etc/passwd", read(env, "/etc/passwd")+"user1:x:1001:1001::/home/user1:/bin/bash\n")
		},
	}
	run.respond["sudo -l -U user1"] = sudoList
	return env, run, &fakeTerminal{run: run, answer: true, asked: true, password: passwordMarker}
}

func adminCalls(run *fakeRun) []string {
	return slices.DeleteFunc(slices.Clone(run.calls), func(call string) bool {
		return !strings.HasPrefix(call, "useradd") && !strings.HasPrefix(call, "usermod") && !strings.HasPrefix(call, "tty passwd") && !strings.HasPrefix(call, "sudo -l")
	})
}

func TestAnAdminKeyIsReadFromItsBlob(t *testing.T) {
	key, err := ParseAdminKey(laptopBlob + ":laptop")
	if err != nil || key.Type != "ssh-ed25519" || key.Fingerprint() != laptopPrint || key.Line() != "ssh-ed25519 "+laptopBlob+" laptop" {
		t.Fatalf("key %+v %v", key, err)
	}
	inner := binary.BigEndian.AppendUint32(nil, 7)
	inner = append(append(inner, "ssh-dss"...), 0, 0, 0, 1, 1)
	for _, arg := range []string{base64.StdEncoding.EncodeToString(inner) + ":old", laptopBlob, laptopBlob + ":bad label", "!!!:x"} {
		if _, err := ParseAdminKey(arg); err == nil {
			t.Fatalf("%q was accepted", arg)
		}
	}
}

func TestAnAdminUserIsMadeWithSudoAndTheKeys(t *testing.T) {
	for release, group := range map[string]string{"": "sudo", "rocky": "wheel"} {
		env, run, tty := adminServer(t, release)
		result, err := AddAdmin(context.Background(), env, "user1", adminKeys(t), tty)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"useradd -m -s /bin/bash user1", "usermod -aG " + group + " user1", "tty passwd user1", "sudo -l -U user1"}
		if calls := adminCalls(run); !slices.Equal(calls, want) {
			t.Fatalf("%s calls %q", release, calls)
		}
		if tty.askedAt != 0 || !strings.Contains(tty.printed.String(), laptopPrint) || !strings.Contains(tty.printed.String(), "Add them? [y/N] ") {
			t.Fatalf("the keys come before any command: %d %q", tty.askedAt, tty.printed.String())
		}
		if result.Group != group || !result.Created || !slices.Equal(result.KeyFiles, []string{"/home/user1/.ssh/authorized_keys"}) {
			t.Fatalf("result %+v", result)
		}
		keys := read(env, "/home/user1/.ssh/authorized_keys")
		if keys != "ssh-ed25519 "+laptopBlob+" laptop\nssh-ed25519 "+phoneBlob+" phone\n" {
			t.Fatalf("keys %q", keys)
		}
		if !slices.Contains(run.calls, "chown -R user1: "+env.path("/home/user1/.ssh")) {
			t.Fatalf("calls %q", run.calls)
		}
		if runtime.GOOS != "windows" {
			if info, _ := os.Stat(env.path("/home/user1/.ssh/authorized_keys")); info.Mode().Perm() != 0o600 {
				t.Fatalf("mode %v", info.Mode())
			}
			if info, _ := os.Stat(env.path("/home/user1/.ssh")); info.Mode().Perm() != 0o700 {
				t.Fatalf("mode %v", info.Mode())
			}
		}
		for _, call := range run.calls {
			if strings.Contains(call, passwordMarker) {
				t.Fatalf("a password reached a command: %q", call)
			}
		}
		if strings.Contains(tty.printed.String(), passwordMarker) || strings.Contains(strings.ToLower(tty.printed.String()), "new password") {
			t.Fatalf("output %q", tty.printed.String())
		}
	}
}

func TestAnExistingUserKeepsItsKeys(t *testing.T) {
	env, run, tty := adminServer(t, "")
	write(t, env, "/etc/passwd", read(env, "/etc/passwd")+"user1:x:1001:1001::/home/user1:/bin/bash\n")
	write(t, env, "/home/user1/.ssh/authorized_keys", "ssh-rsa AAAAold desk\nssh-ed25519 "+laptopBlob+" laptop\n")
	result, err := AddAdmin(context.Background(), env, "user1", adminKeys(t), tty)
	if err != nil || result.Created || slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "useradd") }) {
		t.Fatalf("result %+v %v %q", result, err, run.calls)
	}
	if keys := read(env, "/home/user1/.ssh/authorized_keys"); keys != "ssh-rsa AAAAold desk\nssh-ed25519 "+laptopBlob+" laptop\nssh-ed25519 "+phoneBlob+" phone\n" {
		t.Fatalf("keys %q", keys)
	}
}

func TestAnAdminUserIsSkippedWithoutAYes(t *testing.T) {
	for asked, sentence := range map[bool]string{true: "the keys were not confirmed", false: "no terminal to type user1's password on"} {
		env, run, tty := adminServer(t, "")
		tty.answer, tty.asked = false, asked
		_, err := AddAdmin(context.Background(), env, "user1", adminKeys(t), tty)
		var skipped AdminSkipped
		if !errors.As(err, &skipped) || err.Error() != sentence || len(run.calls) != 0 {
			t.Fatalf("asked %v: %v %q", asked, err, run.calls)
		}
	}
}

func TestThreeFailedPasswordsLeaveTheUserLocked(t *testing.T) {
	env, run, tty := adminServer(t, "")
	tty.fails = 3
	result, err := AddAdmin(context.Background(), env, "user1", adminKeys(t), tty)
	if err == nil || err.Error() != "the password was not set. Run sudo kry admin-user user1 later." {
		t.Fatalf("err %v", err)
	}
	if calls := adminCalls(run); !slices.Equal(calls, []string{"useradd -m -s /bin/bash user1", "usermod -aG sudo user1", "tty passwd user1", "tty passwd user1", "tty passwd user1"}) {
		t.Fatalf("calls %q", calls)
	}
	if result.Group != "sudo" {
		t.Fatalf("the user and keys are there: %+v", result)
	}
}

func TestSudoMustLetTheAdminIn(t *testing.T) {
	env, run, tty := adminServer(t, "")
	run.respond["sudo -l -U user1"] = "User user1 is not allowed to run sudo on server-2.\n"
	if _, err := AddAdmin(context.Background(), env, "user1", adminKeys(t), tty); err == nil || err.Error() != "it is in the sudo group but sudo does not let it in. Check /etc/sudoers." {
		t.Fatalf("err %v", err)
	}
}

func TestRootAndSystemAccountsAreNotAdminUsers(t *testing.T) {
	for name, sentence := range map[string]string{"root": "root cannot be the admin user", "www": "www is a system account on this server.", "Bad": "Bad is not a user name"} {
		env, run, tty := adminServer(t, "")
		if _, err := AddAdmin(context.Background(), env, name, adminKeys(t), tty); err == nil || err.Error() != sentence || len(run.calls) != 0 {
			t.Fatalf("%s: %v %q", name, err, run.calls)
		}
	}
}

func TestNoRootLoginNeedsAnotherUserWithAKey(t *testing.T) {
	env, run := newEnv(t)
	write(t, env, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
	write(t, env, "/root/.ssh/authorized_keys", "ssh-ed25519 AAAA laptop\n")
	write(t, env, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
	if _, err := Apply(context.Background(), env, "no-root-login", nil); err == nil || err.Error() != "no SSH key lets a sudo user other than root log in; add one before turning root login off" {
		t.Fatalf("err %v", err)
	}
	if exists(env, rootDropIn) || slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "reload") }) {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestNoRootLoginStaysOffWhenAnEarlierSettingWins(t *testing.T) {
	env, run := newEnv(t)
	usersWithKeys(t, env, true)
	write(t, env, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
	afterSSHCheck(run, map[string]string{rootProbe: "permitrootlogin yes\n"})
	_, err := Apply(context.Background(), env, "no-root-login", nil)
	if err == nil || err.Error() != "SSH still lets root log in: a setting read before Krynodes' wins (a file in /etc/ssh/sshd_config.d or a Match block). Change it by hand." {
		t.Fatalf("err %v", err)
	}
	if exists(env, rootDropIn) || slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "reload") }) {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestNoRootLoginTurnsRootOffAndCanBeUndone(t *testing.T) {
	env, run := newEnv(t)
	usersWithKeys(t, env, true)
	write(t, env, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
	afterSSHCheck(run, map[string]string{rootProbe: "permitrootlogin no\n"})
	if _, err := Apply(context.Background(), env, "no-root-login", nil); err != nil {
		t.Fatal(err)
	}
	if read(env, rootDropIn) != "PermitRootLogin no\n" || !slices.Contains(run.calls, "sshd -t") || !slices.Contains(run.calls, "systemctl reload ssh") {
		t.Fatalf("file %q calls %q", read(env, rootDropIn), run.calls)
	}
	if err := Undo(context.Background(), env, "no-root-login", nil); err != nil || exists(env, rootDropIn) {
		t.Fatalf("undo %v", err)
	}
	env, run = newEnv(t)
	usersWithKeys(t, env, true)
	write(t, env, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
	run.failing["sshd -t"] = true
	if _, err := Apply(context.Background(), env, "no-root-login", nil); err == nil || exists(env, rootDropIn) {
		t.Fatalf("a refused change leaves nothing: %v", err)
	}
}
