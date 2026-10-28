package actions

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/recipes"
	"github.com/Kleavox/krynodes/agent/internal/watch"
)

const (
	adminBlob  = "AAAAC3NzaC1lZDI1NTE5AAAAIDVFg4Wx2NViu9ZffqPwSTCUsSzH60Im/4s1noczsx+q"
	adminAgain = "Open this server in Krynodes, choose Actions → Add Admin User and run the command it gives within 30 minutes."
)

type adminTerminal struct {
	out    *strings.Builder
	answer bool
	during func()
}

func (a *adminTerminal) Ask(question string) (bool, bool) {
	a.out.WriteString(question + "\n")
	return a.answer, true
}

func (a *adminTerminal) Passwd(context.Context, string) error {
	if a.during != nil {
		a.during()
	}
	return nil
}

func (a *adminTerminal) Printf(format string, args ...any) {
	fmt.Fprintf(a.out, format, args...)
}

func joinGroup(t *testing.T, executor Executor, group, name string) {
	t.Helper()
	body, _ := os.ReadFile(executor.path("/etc/group"))
	lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
	for index, line := range lines {
		if strings.HasPrefix(line, group+":") {
			if strings.HasSuffix(line, ":") {
				lines[index] = line + name
			} else {
				lines[index] = line + "," + name
			}
		}
	}
	rootFile(t, executor, "/etc/group", strings.Join(lines, "\n")+"\n")
}

func adminRunner(t *testing.T, executor *Executor, run *fakeRun) {
	t.Helper()
	run.respond["sudo -l -U musyaf"] = "    (ALL : ALL) ALL\n"
	if _, err := os.Stat(executor.path("/etc/group")); err != nil {
		rootFile(t, *executor, "/etc/group", "sudo:x:27:\n")
	}
	inner := executor.Run
	executor.Run = func(ctx context.Context, name string, args ...string) ([]byte, int, error) {
		switch name + " " + strings.Join(args, " ") {
		case "useradd -m -s /bin/bash musyaf":
			body, _ := os.ReadFile(executor.path("/etc/passwd"))
			rootFile(t, *executor, "/etc/passwd", string(body)+"musyaf:x:1001:1001::/home/musyaf:/bin/bash\n")
		case "usermod -aG sudo musyaf":
			joinGroup(t, *executor, "sudo", "musyaf")
		}
		return inner(ctx, name, args...)
	}
}

func adminKey(t *testing.T) recipes.AdminKey {
	t.Helper()
	key, err := recipes.ParseAdminKey(adminBlob + ":laptop")
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func stateFileGone(t *testing.T, executor Executor, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(executor.StateDir, name)); err == nil {
			t.Fatalf("%s is still there", name)
		}
	}
}

func TestAnAdminUserCommandIsMadeReadyBySignature(t *testing.T) {
	executor, _ := securityExecutor(t)
	args := map[string]string{"name": "musyaf", "keys": adminBlob + ":laptop"}
	unsigned := hostRequest(t, idA, "server", "admin", args)
	unsigned.Signed = nil
	if result := runRequest(t, executor, unsigned); result.OK {
		t.Fatalf("unsigned: %+v", result)
	}
	for id, bad := range map[string]map[string]string{
		idB: {"name": "musyaf", "keys": "AAAA:laptop"},
		idC: {"name": "root", "keys": adminBlob + ":laptop"},
		idD: {"name": "musyaf", "keys": strings.Repeat(adminBlob+":laptop,", 4) + adminBlob + ":phone"},
	} {
		if result := runRequest(t, executor, hostRequest(t, id, "server", "admin", bad)); result.OK {
			t.Fatalf("%v: %+v", bad, result)
		}
	}
	stateFileGone(t, executor, adminFile)
	id := "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a05"
	result := runRequest(t, executor, hostRequest(t, id, "server", "admin", args))
	if !result.OK || result.Output != "ready: run sudo kry admin-user musyaf on this server within 30 minutes" {
		t.Fatalf("result %+v", result)
	}
	ticket, err := readState[adminTicket](executor.StateDir, adminFile)
	if err != nil || ticket.ID != id || ticket.Name != "musyaf" || !slices.Equal(ticket.Keys, []string{adminBlob + ":laptop"}) || !ticket.Until.Equal(executorNow.Add(30*time.Minute)) {
		t.Fatalf("ticket %+v %v", ticket, err)
	}
	if info, _ := os.Stat(filepath.Join(executor.StateDir, adminFile)); runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}
}

func TestAdminUserNeedsAFreshCommandForThatName(t *testing.T) {
	for _, ticket := range []*adminTicket{nil, {Name: "musyaf", Keys: []string{adminBlob + ":laptop"}, Until: executorNow.Add(-time.Minute)}, {Name: "budi", Keys: []string{adminBlob + ":laptop"}, Until: executorNow.Add(time.Minute)}} {
		executor, run := watchedServer(t)
		if ticket != nil {
			writeJSON(executor.StateDir, adminFile, *ticket, 0o600)
		}
		var out strings.Builder
		err := executor.AdminUser(context.Background(), "musyaf", &out, &adminTerminal{out: &out, answer: true})
		if err == nil || err.Error() != adminAgain || len(run.calls) != 0 {
			t.Fatalf("ticket %+v: %v %q", ticket, err, run.calls)
		}
	}
}

func TestAdminUserMakesTheUserAndQuietsOnlyItsOwnItems(t *testing.T) {
	executor, run := watchedServer(t)
	rootFile(t, executor, "/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n")
	rootFile(t, executor, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
	run.respond["sshd -T"] = "passwordauthentication yes\npermitrootlogin yes\nport 22\n"
	adminRunner(t, &executor, run)
	executor.watchServer(context.Background())
	writeJSON(executor.StateDir, adminFile, adminTicket{ID: idA, Name: "musyaf", Keys: []string{adminBlob + ":laptop"}, Until: executorNow.Add(10 * time.Minute)}, 0o600)
	writeJSON(executor.StateDir, "security.json", securityState{}, 0o640)
	var out strings.Builder
	if err := executor.AdminUser(context.Background(), "musyaf", &out, &adminTerminal{out: &out, answer: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out.String(), "✓ Admin user musyaf · sudo with its password\n✓ SSH keys only\n✓ No root login · log in as musyaf from now on\n") {
		t.Fatalf("out\n%s", out.String())
	}
	if applied := executor.appliedRecipes(); !slices.Equal(applied, []string{"no-root-login", "ssh-keys-only"}) {
		t.Fatalf("applied %q", applied)
	}
	stateFileGone(t, executor, adminFile, "security.json", setupLock)
	executor.watchServer(context.Background())
	if events := readEvents(t, executor); len(events) != 0 {
		t.Fatalf("the admin user warned: %+v", events)
	}
	body, _ := os.ReadFile(executor.path("/etc/passwd"))
	rootFile(t, executor, "/etc/passwd", string(body)+"eve:x:1002:1002::/home/eve:/bin/bash\n")
	executor.watchServer(context.Background())
	if events := readEvents(t, executor); len(events) != 1 || events[0].Kind != "user" || !strings.Contains(fmt.Sprint(events[0].Detail), "eve") {
		t.Fatalf("another user must still warn: %+v", events)
	}
}

func TestSetupMakesTheAdminUserFirstAndTurnsRootLoginOffLast(t *testing.T) {
	executor, run := setupServer(t)
	rootFile(t, executor, "/sys/module/wireguard/version", "1.0.0\n")
	rootFile(t, executor, "/usr/bin/wg", "")
	rootFile(t, executor, "/etc/hosts", "127.0.0.1 localhost\n")
	run.respond["ip -d -j addr show"] = `[{"ifname":"eth0","mtu":1500,"addr_info":[{"family":"inet","local":"141.95.0.30","prefixlen":24}]},` + wg0Address + `]`
	run.respond["ip -j route show default"] = `[{"dev":"eth0"}]`
	run.respond["wg show all listen-port"] = "wg0\t51820\n"
	adminRunner(t, &executor, run)
	executor.watchServer(context.Background())
	var out strings.Builder
	tty := &adminTerminal{out: &out, answer: true}
	tty.during = func() { executor.watchServer(context.Background()) }
	options := SetupOptions{Recommended: true, Docker: true, RebootHour: hour(20), Network: "10.88.0.0/24", Admin: "musyaf", AdminKeys: []recipes.AdminKey{adminKey(t)}, Terminal: tty}
	if err := executor.Setup(context.Background(), options, &out, func(string) (bool, bool) { return false, false }); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	last := -1
	for _, line := range []string{"Admin user musyaf gets these SSH keys:", "✓ Admin user musyaf · sudo with its password", "✓ Automatic security updates", "✓ SSH keys only", "✓ Docker", "✓ Private network ready", "✓ No root login · log in as musyaf from now on"} {
		at := strings.Index(got, line)
		if at <= last {
			t.Fatalf("%q out of order in\n%s", line, got)
		}
		last = at
	}
	if events := readEvents(t, executor); len(events) != 0 {
		t.Fatalf("the watch warned during setup: %+v", events)
	}
	start, _ := readState[watch.State](executor.StateDir, watchFile)
	if !slices.Contains(start.Users, "musyaf") || !slices.Contains(start.Sudo, "group:sudo:musyaf") {
		t.Fatalf("start %+v", start)
	}
	stateFileGone(t, executor, setupLock)
}

func TestSetupSkipsTheAdminUserAndRootLoginWithoutAYes(t *testing.T) {
	executor, run := setupServer(t)
	adminRunner(t, &executor, run)
	var out strings.Builder
	options := SetupOptions{Recommended: true, Admin: "musyaf", AdminKeys: []recipes.AdminKey{adminKey(t)}, Terminal: &adminTerminal{out: &out}}
	if err := executor.Setup(context.Background(), options, &out, func(string) (bool, bool) { return false, false }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "– Admin user skipped: the keys were not confirmed\n") || strings.Contains(out.String(), "No root login") {
		t.Fatalf("out\n%s", out.String())
	}
	if slices.Contains(executor.appliedRecipes(), "no-root-login") {
		t.Fatal("root login stays on")
	}
}

func TestTheWatchWaitsWhileSetupRuns(t *testing.T) {
	executor, _ := watchedServer(t)
	executor.watchServer(context.Background())
	body, _ := os.ReadFile(executor.path("/etc/passwd"))
	rootFile(t, executor, "/etc/passwd", string(body)+"eve:x:1002:1002::/home/eve:/bin/bash\n")
	writeJSON(executor.StateDir, setupLock, setupMark{At: executorNow.Add(-59 * time.Minute)}, 0o600)
	executor.watchServer(context.Background())
	if events := readEvents(t, executor); len(events) != 0 {
		t.Fatalf("warned while setup runs: %+v", events)
	}
	writeJSON(executor.StateDir, setupLock, setupMark{At: executorNow.Add(-61 * time.Minute)}, 0o600)
	executor.watchServer(context.Background())
	if events := readEvents(t, executor); len(events) != 1 {
		t.Fatalf("an old marker does not hold the watch: %+v", events)
	}
}

func TestRootLoginIsAFinding(t *testing.T) {
	for setting, want := range map[string]bool{"without-password": true, "no": false} {
		executor, run := securityExecutor(t)
		healthyServer(t, executor, run)
		run.respond["sshd -T"] = "passwordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin " + setting + "\nport 22\n"
		if err := executor.Execute(context.Background()); err != nil {
			t.Fatal(err)
		}
		finding, found := findingsOf(t, executor)["root-login"]
		if found != want || (found && (finding.Severity != "note" || finding.Detail != "Root can log in over SSH.")) {
			t.Fatalf("%s: %+v %v", setting, finding, found)
		}
	}
}
