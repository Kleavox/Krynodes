//go:build windows

package service

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

func TestALogonTraysTheConsoleSessionWithoutReadingTheEvent(t *testing.T) {
	previous := consoleSession
	t.Cleanup(func() { consoleSession = previous })
	consoleSession = func() uint32 { return 7 }
	notification := &windows.WTSSESSION_NOTIFICATION{Size: uint32(unsafe.Sizeof(windows.WTSSESSION_NOTIFICATION{})), SessionID: 3}
	request := svc.ChangeRequest{Cmd: svc.SessionChange, EventType: windows.WTS_SESSION_LOGON, EventData: uintptr(unsafe.Pointer(notification))}
	if session, logon := loggedOn(request); !logon || session != 7 {
		t.Fatalf("session %d logon %v", session, logon)
	}
	for _, other := range []svc.ChangeRequest{
		{Cmd: svc.SessionChange, EventType: windows.WTS_SESSION_LOGOFF},
		{Cmd: svc.Interrogate},
	} {
		if _, logon := loggedOn(other); logon {
			t.Fatalf("%+v trays", other)
		}
	}
}

func TestTheStartMenuEntryOpensTheTrayWhateverTheFolderIsCalled(t *testing.T) {
	folder := filepath.Join(t.TempDir(), "Krynodes $(exit 7) 'q' & more; (x)")
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	program := filepath.Join(folder, "krynodes.exe")
	if err := os.WriteFile(program, []byte("agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(folder, "Krynodes.lnk")
	for range 2 {
		if err := makeShortcut(link, program); err != nil {
			t.Fatal(err)
		}
	}
	read := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:KRY_LINK); $s.TargetPath; $s.Arguments; $s.WorkingDirectory`)
	read.Env = append(os.Environ(), "KRY_LINK="+link)
	output, err := read.CombinedOutput()
	if err != nil {
		t.Fatalf("read the entry back: %v: %s", err, output)
	}
	want := []string{program, "tray", folder}
	if got := strings.Split(strings.TrimSpace(string(output)), "\r\n"); !slices.Equal(got, want) {
		t.Errorf("the entry says %q, want %q", got, want)
	}
	if regexp.MustCompile(`[A-Za-z]+-[A-Za-z]+`).MatchString(shortcutScript) || strings.Contains(shortcutScript, folder) {
		t.Errorf("the script calls a cmdlet or names a path: %s", shortcutScript)
	}
}

func TestAStartMenuEntryThatCannotBeMadeNamesWhy(t *testing.T) {
	folder := t.TempDir()
	err := makeShortcut(filepath.Join(folder, "missing", "Krynodes.lnk"), filepath.Join(folder, "krynodes.exe"))
	if err == nil {
		t.Fatal("an entry in a folder that is not there was made")
	}
}

func TestRemovingAStartMenuEntryThatIsNotThereIsNotAnError(t *testing.T) {
	link := filepath.Join(t.TempDir(), "Krynodes.lnk")
	if err := removeShortcut(link); err != nil {
		t.Fatalf("a missing entry: %v", err)
	}
	if err := os.WriteFile(link, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeShortcut(link); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(link); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the entry is still there: %v", err)
	}
}
