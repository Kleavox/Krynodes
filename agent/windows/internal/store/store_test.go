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
	"unsafe"

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

func elevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token to make Administrators the owner; live-test G runs it")
	}
}

func refused(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "delete it as an administrator and run install again") {
		t.Fatalf("%s was accepted: %v", what, err)
	}
}

type tokenOwner struct {
	Owner *windows.SID
}

func setOwner(token windows.Token, sid *windows.SID) error {
	value := tokenOwner{Owner: sid}
	return windows.SetTokenInformation(token, windows.TokenOwner, (*byte)(unsafe.Pointer(&value)), uint32(unsafe.Sizeof(value)))
}

func defaultOwner(t *testing.T, sid *windows.SID) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT, &token); err != nil {
		t.Fatal(err)
	}
	var size uint32
	_ = windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &size)
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &buffer[0], size, &size); err != nil {
		token.Close()
		t.Fatal(err)
	}
	before, err := (*tokenOwner)(unsafe.Pointer(&buffer[0])).Owner.Copy()
	if err != nil {
		token.Close()
		t.Fatal(err)
	}
	if err := setOwner(token, sid); err != nil {
		token.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		defer token.Close()
		if err := setOwner(token, before); err != nil {
			t.Error(err)
		}
	})
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
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "token.dpapi"), sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := Store{Dir: dir}.Get("token")
	if err != nil || !bytes.Equal(opened, secret) {
		t.Fatalf("opened %q, %v", opened, err)
	}
}

func TestTheDescriptorReachesWindowsAsBuilt(t *testing.T) {
	for _, c := range []struct {
		owner, sid       string
		folder, readable bool
		aces             string
	}{
		{administrators, "S-1-5-32-544", true, false, "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"},
		{administrators, "S-1-5-32-544", false, true, "(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"},
		{localSystem, "S-1-5-18", false, false, "(A;;FA;;;SY)(A;;FA;;;BA)"},
		{localSystem, "S-1-5-18", true, true, "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"},
	} {
		parsed, err := windows.SecurityDescriptorFromString(descriptor(c.owner, c.folder, c.readable))
		if err != nil {
			t.Fatal(err)
		}
		owner, _, err := parsed.Owner()
		if err != nil || owner.String() != c.sid {
			t.Errorf("owner %v, %v; want %s", owner, err, c.sid)
		}
		control, _, err := parsed.Control()
		if err != nil || control&windows.SE_DACL_PROTECTED == 0 || control&windows.SE_DACL_PRESENT == 0 {
			t.Errorf("control %#x, %v: the DACL is not present and protected", control, err)
		}
		text := parsed.String()
		if got := text[strings.Index(text, "("):]; got != c.aces {
			t.Errorf("ACEs %s, want %s", got, c.aces)
		}
	}
}

func TestAFileNamesItsOwnerAndTheInteractiveUserIsRefused(t *testing.T) {
	user := me(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	for _, body := range []string{"first", "second"} {
		refused(t, write(path, []byte(body), descriptor(user, false, false)+"(A;;FA;;;"+user+")"), "a file the interactive user owns")
		if data, err := os.ReadFile(path); err != nil || string(data) != body {
			t.Fatalf("read %q, %v; want %q", data, err, body)
		}
		owner, dacl := readBack(t, path)
		if owner != user || dacl != "(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;"+user+")" {
			t.Errorf("owner %s DACL %s", owner, dacl)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("left behind %v", entries)
	}
	refused(t, lock(path, descriptor(administrators, false, false), false), "a file the interactive user owns")
	if err := write(filepath.Join(dir, "missing", "state.json"), []byte("x"), descriptor(user, false, false)+"(A;;FA;;;"+user+")"); err == nil {
		t.Error("a file was written into a folder that does not exist")
	}
}

func TestAFolderSomeoneElseMadeIsRefused(t *testing.T) {
	squatted := filepath.Join(t.TempDir(), "Krynodes")
	if err := os.Mkdir(squatted, 0o700); err != nil {
		t.Fatal(err)
	}
	refused(t, create(squatted, descriptor(administrators, true, false)), "a folder the interactive user owns")
	refused(t, create(squatted, descriptor(administrators, true, true)), "a program folder the interactive user owns")
	user := me(t)
	mine := filepath.Join(t.TempDir(), "Krynodes")
	refused(t, create(mine, descriptor(user, true, false)+"(A;OICI;FA;;;"+user+")"), "a folder made for the interactive user")
	owner, dacl := readBack(t, mine)
	if owner != user || dacl != "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;"+user+")" {
		t.Errorf("owner %s DACL %s", owner, dacl)
	}
}

func TestEverythingKrynodesMakesBelongsToAdministrators(t *testing.T) {
	elevated(t)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	defaultOwner(t, user.User.Sid)
	parent := t.TempDir()
	plain := filepath.Join(parent, "plain.txt")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if owner, err := ownerOf(plain); err != nil || owner != me(t) {
		t.Fatalf("a plain file is owned by %s, %v, so the token does not stand in for nodefaultadminowner", owner, err)
	}
	refused(t, lock(plain, descriptor(administrators, false, false), false), "a file the interactive user owns")

	dir := filepath.Join(parent, "Krynodes")
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"one", "two"} {
		if err := store.Put("token", []byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	if opened, err := store.Get("token"); err != nil || string(opened) != "two" {
		t.Fatalf("opened %q, %v", opened, err)
	}
	if err := store.Write(filepath.Join(dir, "state.json"), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	log := &Log{path: filepath.Join(dir, "service.log"), sddl: descriptor(administrators, false, false), limit: 100}
	for range 10 {
		if _, err := log.Write([]byte(strings.Repeat("x", 39) + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	log.file.Close()
	program := filepath.Join(parent, "Program")
	if err := ProgramFolder(program); err != nil {
		t.Fatal(err)
	}
	if err := ProgramFolder(filepath.Join(program, "licenses")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"krynodes.exe", "krynodes.exe", filepath.Join("licenses", "wintun.txt")} {
		if err := ProgramFile(filepath.Join(program, name), []byte(name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Rename(filepath.Join(program, "krynodes.exe"), filepath.Join(program, "krynodes.old.exe")); err != nil {
		t.Fatal(err)
	}
	secret := "(A;;FA;;;SY)(A;;FA;;;BA)"
	readable := "(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
	folder := "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	for path, want := range map[string]string{
		dir:                                              "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
		filepath.Join(dir, "token.dpapi"):                secret,
		filepath.Join(dir, "state.json"):                 secret,
		filepath.Join(dir, "service.log"):                secret,
		filepath.Join(dir, "service.log.1"):              secret,
		program:                                          folder,
		filepath.Join(program, "licenses"):               folder,
		filepath.Join(program, "krynodes.old.exe"):       readable,
		filepath.Join(program, "licenses", "wintun.txt"): readable,
	} {
		owner, dacl := readBack(t, path)
		if owner != "S-1-5-32-544" || dacl != want {
			t.Errorf("%s owner %s DACL %s, want S-1-5-32-544 %s", path, owner, dacl, want)
		}
	}
	for _, folder := range []string{dir, program} {
		if found, _ := filepath.Glob(filepath.Join(folder, "*.tmp")); len(found) != 0 {
			t.Errorf("left behind %v", found)
		}
	}
	if _, err := Open(dir); err != nil {
		t.Errorf("our own folder was refused: %v", err)
	}
	if err := ProgramFolder(program); err != nil {
		t.Errorf("our own program folder was refused: %v", err)
	}
}

func TestLinksAreRefusedEvenWhenAdministratorsOwnThem(t *testing.T) {
	elevated(t)
	parent := t.TempDir()
	data, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(parent, "Junction")
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", junction, data).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, output)
	}
	refused(t, create(junction, descriptor(administrators, true, false)), "a junction to a folder SYSTEM owns")
	file := filepath.Join(parent, "token.dpapi")
	if err := ProgramFile(file, []byte("x")); err != nil {
		t.Fatal(err)
	}
	refused(t, create(file, descriptor(administrators, true, false)), "a file taken for the folder")
	if err := os.Link(file, filepath.Join(parent, "linked")); err != nil {
		t.Fatal(err)
	}
	refused(t, lock(file, descriptor(administrators, false, false), false), "a hard-linked file")
}

func ownerOf(path string) (string, error) {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return "", err
	}
	return owner.String(), nil
}
