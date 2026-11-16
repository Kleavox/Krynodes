//go:build windows

package store

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func readBack(t *testing.T, path string) (string, string) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("%s inherits its DACL", path)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	text := descriptor.String()
	return owner.String(), text[strings.Index(text, "("):]
}

func me(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid.String()
}

func TestStoredSecretsOpenOnlyForThisMachine(t *testing.T) {
	secret := []byte("wireguard private key bytes")
	sealed, err := protect(secret)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(sealed[40:44])&windows.CRYPTPROTECT_LOCAL_MACHINE == 0 {
		t.Fatal("the blob is not sealed for the machine, so the service could not open what install wrote")
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("the stored blob carries the secret in the clear")
	}
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := unprotect(tampered); err == nil {
		t.Fatal("a tampered blob opened")
	}

	user := me(t)
	dir := filepath.Join(t.TempDir(), "Krynodes")
	folder := "O:" + user + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user + ")"
	if err := create(dir, folder); err != nil {
		t.Fatal(err)
	}
	store := Store{Dir: dir, file: "O:" + user + "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user + ")"}
	if err := store.Put("token", secret); err != nil {
		t.Fatal(err)
	}
	opened, err := store.Get("token")
	if err != nil || !bytes.Equal(opened, secret) {
		t.Fatalf("opened %q, %v", opened, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "token.dpapi"))
	if err != nil || bytes.Contains(raw, secret) {
		t.Fatalf("the file carries the secret in the clear: %v", err)
	}
	for path, want := range map[string]string{
		dir:                               "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user + ")",
		filepath.Join(dir, "token.dpapi"): "(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user + ")",
	} {
		owner, dacl := readBack(t, path)
		if owner != user || dacl != want {
			t.Errorf("%s owner %s DACL %s, want %s %s", path, owner, dacl, user, want)
		}
	}
}

func TestTheProductionFolderBelongsToSystemAndAdministrators(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token to make Administrators the owner")
	}
	dir := filepath.Join(t.TempDir(), "Krynodes")
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put("token", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		dir:                               "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
		filepath.Join(dir, "token.dpapi"): "(A;;FA;;;SY)(A;;FA;;;BA)",
	} {
		owner, dacl := readBack(t, path)
		if owner != "S-1-5-32-544" || dacl != want {
			t.Errorf("%s owner %s DACL %s", path, owner, dacl)
		}
	}
	if _, err := Open(dir); err != nil {
		t.Errorf("our own folder was refused: %v", err)
	}
}

func TestAFolderSomeoneElseMadeIsRefused(t *testing.T) {
	parent := t.TempDir()
	squatted := filepath.Join(parent, "Krynodes")
	if err := os.Mkdir(squatted, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := create(squatted, folderSDDL); err == nil || !strings.Contains(err.Error(), "delete it as an administrator and run install again") {
		t.Fatalf("a folder owned by the user was accepted: %v", err)
	}
	user := me(t)
	mine := "O:" + user + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user + ")"
	data, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(parent, "Junction")
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", junction, data).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, output)
	}
	if err := create(junction, mine); err == nil || !strings.Contains(err.Error(), "delete it as an administrator") {
		t.Fatalf("a junction to a folder SYSTEM owns was accepted: %v", err)
	}
	file := filepath.Join(parent, "token.dpapi")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := create(file, mine); err == nil || !strings.Contains(err.Error(), "delete it as an administrator") {
		t.Fatalf("a file was taken for the folder: %v", err)
	}
	if err := os.Link(file, filepath.Join(parent, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := lock(file, "O:"+user+"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;"+user+")", false); err == nil {
		t.Fatal("a hard-linked file was locked")
	}
}

func TestTheLogIsLockedAndCapped(t *testing.T) {
	user := me(t)
	dir := t.TempDir()
	log := &Log{path: filepath.Join(dir, "service.log"), sddl: "O:" + user + "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user + ")", limit: 100}
	line := []byte(strings.Repeat("x", 39) + "\n")
	for range 10 {
		if _, err := log.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	log.file.Close()
	for _, name := range []string{"service.log", "service.log.1"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Size() > 100 {
			t.Fatalf("%s: %v %v", name, info, err)
		}
		owner, dacl := readBack(t, filepath.Join(dir, name))
		if owner != user || !strings.HasPrefix(dacl, "(A;;FA;;;SY)(A;;FA;;;BA)") {
			t.Errorf("%s owner %s DACL %s", name, owner, dacl)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("log files %v", entries)
	}
}
