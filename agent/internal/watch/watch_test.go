package watch

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	ownerKey   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINgR/LmOeWesWGV4gX2RBfBT5TKbBcKMCk+GVyMOWScy budi@laptop"
	ownerPrint = "SHA256:lMKB0LebO8arH9OP7OBxvLF0veMl7Of0UHgkPdafFtQ"
	otherKey   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDVFg4Wx2NViu9ZffqPwSTCUsSzH60Im/4s1noczsx+q evil"
	otherPrint = "SHA256:1s+YW4SIoq6rDRmD1o/df0ZH56AiCmAMwmKR+Drp/v4"
)

func write(t *testing.T, root, name, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func server(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\nbudi:x:1000:1000::/home/budi:/bin/bash\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n")
	write(t, root, "/etc/group", "root:x:0:\nsudo:x:27:budi\nbudi:x:1000:\n")
	write(t, root, "/etc/sudoers", "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n")
	write(t, root, "/etc/sudoers.d/README", "# read me\n")
	write(t, root, "/etc/sudoers.d/old.dpkg-old", "ignored\n")
	write(t, root, "/root/.ssh/authorized_keys", "# the owner's laptop\n"+ownerKey+"\n")
	write(t, root, "/home/budi/.ssh/authorized_keys", `command="/bin/true",no-pty `+ownerKey+"\n")
	return root
}

func read(t *testing.T, root string, ports ...string) State {
	t.Helper()
	state, err := Read(root)
	if err != nil {
		t.Fatal(err)
	}
	state.Ports = append(state.Ports, ports...)
	return state
}

func kinds(changes []Change) []string {
	var found []string
	for _, change := range changes {
		found = append(found, change.Kind)
	}
	return found
}

func TestTheStartingPointNamesKeysUsersSudoAndPorts(t *testing.T) {
	state := read(t, server(t), "8080/tcp nginx")
	if !slices.Equal(state.Users, []string{"budi", "root"}) {
		t.Fatalf("users %v", state.Users)
	}
	if len(state.Keys) != 2 || state.Keys[0] != (Key{User: "budi", File: "/home/budi/.ssh/authorized_keys", Fingerprint: ownerPrint, Type: "ED25519", Comment: "budi@laptop"}) || state.Keys[1].User != "root" || state.Keys[1].Fingerprint != ownerPrint {
		t.Fatalf("keys %+v", state.Keys)
	}
	if len(state.Sudo) != 3 || !slices.Contains(state.Sudo, "group:sudo:budi") || slices.ContainsFunc(state.Sudo, func(item string) bool { return strings.Contains(item, "dpkg-old") }) {
		t.Fatalf("sudo %v", state.Sudo)
	}
	if !slices.Equal(state.Ports, []string{"8080/tcp nginx"}) {
		t.Fatalf("ports %v", state.Ports)
	}
	if _, err := Read(t.TempDir()); err == nil {
		t.Fatal("read a server with no /etc/passwd")
	}
}

func TestEachNewThingMakesOneChangeAndNothingElseDoes(t *testing.T) {
	root := server(t)
	start := read(t, root, "8080/tcp nginx")
	if changes := Compare(start, read(t, root, "8080/tcp nginx")); len(changes) != 0 {
		t.Fatalf("unchanged server: %+v", changes)
	}
	write(t, root, "/root/.ssh/authorized_keys", ownerKey+"\n"+otherKey+"\n")
	write(t, root, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nbudi:x:1000:1000::/home/budi:/bin/bash\nmallory:x:1001:1001::/home/mallory:/bin/sh\n")
	write(t, root, "/etc/sudoers.d/90-mallory", "mallory ALL=(ALL) NOPASSWD:ALL\n")
	changes := Compare(start, read(t, root, "4444/tcp nc"))
	if !slices.Equal(kinds(changes), []string{"ssh-key", "user", "sudo", "port"}) {
		t.Fatalf("changes %+v", changes)
	}
	key := changes[0]
	if key.Item != "root:/root/.ssh/authorized_keys:"+otherPrint || key.Detail["user"] != "root" || key.Detail["file"] != "/root/.ssh/authorized_keys" || key.Detail["key"] != "ED25519 "+otherPrint+" evil" {
		t.Fatalf("key change %+v", key)
	}
	if changes[1].Detail["user"] != "mallory" || changes[2].Detail["rule"] != "/etc/sudoers.d/90-mallory" || changes[3].Detail["port"] != "4444/tcp" || changes[3].Detail["process"] != "nc" {
		t.Fatalf("details %+v", changes)
	}
}

func TestANewSudoMemberIsASudoChange(t *testing.T) {
	root := server(t)
	start := read(t, root)
	write(t, root, "/etc/group", "root:x:0:\nsudo:x:27:budi,www\nbudi:x:1000:\n")
	changes := Compare(start, read(t, root))
	if len(changes) != 1 || changes[0].Kind != "sudo" || changes[0].Item != "group:sudo:www" || changes[0].Detail["rule"] != "www in sudo" {
		t.Fatalf("changes %+v", changes)
	}
}

func TestTheOwnersKnownKeySigningInIsNotALogin(t *testing.T) {
	root := server(t)
	start := read(t, root)
	journal := "1790000000.123456 vps-1 sshd[901]: Accepted publickey for root from 198.51.100.4 port 50000 ssh2: ED25519 " + ownerPrint + "\n" +
		"1790000010.000000 vps-1 sshd-session[902]: Accepted publickey for root from 203.0.113.9 port 51515 ssh2: ED25519 " + otherPrint + "\n" +
		"1790000020.000000 vps-1 sshd[903]: Accepted publickey for daemon from 203.0.113.9 port 51516 ssh2: ED25519 " + otherPrint + "\n" +
		"1790000030.000000 vps-1 sshd[904]: Accepted password for budi from 203.0.113.9 port 51517 ssh2\n"
	logins := Logins(journal, start, start)
	if len(logins) != 1 || logins[0].Kind != "ssh-login" || logins[0].Item != otherPrint || logins[0].Detail["user"] != "root" || logins[0].Detail["from"] != "203.0.113.9" || logins[0].Detail["at"] != "2026-09-21T14:13:30Z" {
		t.Fatalf("logins %+v", logins)
	}
}

func TestItWasMeAcceptsThatOneItem(t *testing.T) {
	root := server(t)
	start := read(t, root)
	write(t, root, "/root/.ssh/authorized_keys", ownerKey+"\n"+otherKey+"\n")
	now := read(t, root)
	change := Compare(start, now)[0]
	if !start.Accept(change.Kind, change.Item) || start.Accept(change.Kind, change.Item) {
		t.Fatal("accepted twice")
	}
	if changes := Compare(start, now); len(changes) != 0 {
		t.Fatalf("still warns: %+v", changes)
	}
	write(t, root, "/home/budi/.ssh/authorized_keys", ownerKey+"\n"+otherKey+"\n")
	if changes := Compare(start, read(t, root)); len(changes) != 1 || changes[0].Detail["user"] != "budi" {
		t.Fatalf("a second new key: %+v", changes)
	}
	login := "1790000010.000000 vps-1 sshd[902]: Accepted publickey for root from 203.0.113.9 port 51515 ssh2: ED25519 " + otherPrint + "\n"
	if len(Logins(login, start, now)) != 0 {
		t.Fatal("a login with an accepted key still warns")
	}
	fresh := read(t, server(t))
	if !fresh.Accept("ssh-login", otherPrint) || fresh.Accept("ssh-login", otherPrint) || len(Logins(login, fresh, fresh)) != 0 {
		t.Fatal("an accepted login still warns")
	}
	if start.Accept("rule", "x") || start.Accept("port", "") {
		t.Fatal("accepted what has no starting point")
	}
}
