package confine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	avcFile   = `type=AVC msg=audit(1700000000.123:456): avc:  denied  { read } for  pid=1234 comm="cat" name="shadow" dev="vda1" ino=42 scontext=system_u:system_r:container_t:s0:c12,c34 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0`
	avcBind   = `audit: type=1400 audit(1700000001.000:457): avc:  denied  { name_bind } for  pid=99 comm="nginx" src=8081 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:unreserved_port_t:s0 tclass=tcp_socket permissive=0`
	armorLine = `type=AVC msg=audit(1700000002.500:458): apparmor="DENIED" operation="open" class="file" profile="docker-default" name="/etc/shadow" pid=4321 comm="cat" requested_mask="r" denied_mask="r" fsuid=0 ouid=0`
	statusOff = `type=MAC_STATUS msg=audit(1700000003.000:459): enforcing=0 old_enforcing=1 auid=1000 ses=3 enabled=1 old-enabled=1 lsm=selinux res=1`
	policy    = `audit: type=1403 audit(1700000004.000:460): auid=4294967295 ses=4294967295 lsm=selinux res=1`
)

func TestParseReadsDenialsStatusAndPolicyLines(t *testing.T) {
	found := Parse(avcFile + "\n" + avcBind + "\n" + armorLine + "\n" + statusOff + "\n" + policy + "\nsomething else\n")
	if len(found) != 5 {
		t.Fatalf("found %+v", found)
	}
	file := found[0]
	if file.Kind != Denied || file.System != SELinux || file.Program != "cat" || file.Pid != 1234 || file.Type != "container_t" || file.Level != "s0:c12,c34" || file.Wanted != "read shadow" || !file.At.Equal(time.Unix(1700000000, 0)) {
		t.Fatalf("file %+v", file)
	}
	if bind := found[1]; bind.Program != "nginx" || bind.Type != "httpd_t" || bind.Level != "s0" || bind.Wanted != "name_bind 8081/tcp" {
		t.Fatalf("bind %+v", bind)
	}
	if armor := found[2]; armor.Kind != Denied || armor.System != AppArmor || armor.Type != "docker-default" || armor.Pid != 4321 || armor.Wanted != "open /etc/shadow" {
		t.Fatalf("apparmor %+v", armor)
	}
	if status := found[3]; status.Kind != Status || status.Enforcing != "0" {
		t.Fatalf("status %+v", status)
	}
	if load := found[4]; load.Kind != Policy || !load.At.Equal(time.Unix(1700000004, 0)) {
		t.Fatalf("policy %+v", load)
	}
}

func TestParseKeepsEachFieldWithinWhatTheReportTakes(t *testing.T) {
	long := strings.Repeat("a", 400)
	found := Parse(`type=AVC msg=audit(1700000000.123:456): apparmor="DENIED" operation="open" profile="` + long + `" name="/` + long + `" pid=1 comm="` + long + `"`)
	if len(found) != 1 || len(found[0].Wanted) > 200 || len(found[0].Type) > 200 || len(found[0].Program) > 64 {
		t.Fatalf("found %+v", found)
	}
}

func TestReadNewFinishesTheRotatedLogBeforeTheNewOne(t *testing.T) {
	root := t.TempDir()
	log := filepath.Join(root, filepath.FromSlash(AuditLog))
	if err := os.MkdirAll(filepath.Dir(log), 0o755); err != nil {
		t.Fatal(err)
	}
	previous := fileID
	defer func() { fileID = previous }()
	rotated := false
	fileID = func(info os.FileInfo) uint64 {
		if info.Name() == "audit.log" && rotated {
			return 8
		}
		return 7
	}
	if err := os.WriteFile(log, []byte(avcFile+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cursor := Cursor{}
	if _, err := ReadNew(root, &cursor); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(log, []byte(avcFile+"\n"+armorLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(log, log+".1"); err != nil {
		t.Fatal(err)
	}
	rotated = true
	if err := os.WriteFile(log, []byte(policy+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if text, err := ReadNew(root, &cursor); err != nil || text != armorLine+"\n"+policy+"\n" {
		t.Fatalf("read %q %v", text, err)
	}
}

func TestReadNewStartsAtTheEndAndFollowsRotation(t *testing.T) {
	root := t.TempDir()
	log := filepath.Join(root, filepath.FromSlash(AuditLog))
	if err := os.MkdirAll(filepath.Dir(log), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(body string) {
		if err := os.WriteFile(log, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	appendLine := func(line string) {
		file, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		file.WriteString(line)
	}
	write(avcFile + "\n")
	cursor := Cursor{}
	if text, err := ReadNew(root, &cursor); err != nil || text != "" || !cursor.Started {
		t.Fatalf("first read %q %v %+v", text, err, cursor)
	}
	appendLine(armorLine + "\n" + statusOff)
	if text, _ := ReadNew(root, &cursor); text != armorLine+"\n" {
		t.Fatalf("second read %q", text)
	}
	appendLine("\n")
	if text, _ := ReadNew(root, &cursor); text != statusOff+"\n" {
		t.Fatalf("a line is read once it is whole: %q", text)
	}
	write(policy + "\n")
	if text, _ := ReadNew(root, &cursor); text != policy+"\n" {
		t.Fatalf("a shorter new log starts from 0: %q", text)
	}
	previous := fileID
	defer func() { fileID = previous }()
	fileID = func(os.FileInfo) uint64 { return cursor.Inode + 1 }
	write(policy + "\n" + avcFile + "\n")
	if text, _ := ReadNew(root, &cursor); text != policy+"\n"+avcFile+"\n" {
		t.Fatalf("a new inode starts from 0: %q", text)
	}
}

func TestProfilesReadsEachProfileAndItsMode(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, filepath.FromSlash(profilesFile))
	os.MkdirAll(filepath.Dir(path), 0o755)
	os.WriteFile(path, []byte("/usr/sbin/cupsd (enforce)\nsnap-update-ns.some app (complain)\ndocker-default (enforce)\n"), 0o644)
	profiles := Profiles(root)
	if len(profiles) != 3 || profiles["/usr/sbin/cupsd"] != "enforce" || profiles["snap-update-ns.some app"] != "complain" {
		t.Fatalf("profiles %v", profiles)
	}
}
