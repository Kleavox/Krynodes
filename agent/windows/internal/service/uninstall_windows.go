//go:build windows

package service

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/Kleavox/krynodes/agent/windows/internal/bundle"
	"github.com/Kleavox/krynodes/agent/windows/internal/store"
	"github.com/Kleavox/krynodes/agent/windows/internal/tunnel"
)

type remover struct {
	program string
}

func UninstallCommand(out io.Writer) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("run uninstall as Administrator")
	}
	program, err := bundle.Program()
	if err != nil {
		return err
	}
	return Uninstall(remover{program: program}, out)
}

func (remover) StopService() error {
	return stopService()
}

func (remover) DeleteService() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	switch {
	case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
	case err != nil:
		return err
	default:
		err = service.Delete()
		service.Close()
		if err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			return err
		}
	}
	if err := eventlog.Remove(serviceName); err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return err
	}
	return nil
}

func (r remover) CloseTrays() error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	dir := filepath.Dir(r.program)
	own := windows.GetCurrentProcessId()
	var failed []error
	if err := debugPrivilege(); err != nil {
		failed = append(failed, err)
	}
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		name := strings.ToLower(windows.UTF16ToString(entry.ExeFile[:]))
		if entry.ProcessID == own || !slices.Contains([]string{"krynodes.exe", oldName, stagedName}, name) {
			continue
		}
		process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, entry.ProcessID)
		if err != nil {
			failed = append(failed, fmt.Errorf("a Krynodes program (process %d) could not be closed: %w; sign out the account that runs it", entry.ProcessID, err))
			continue
		}
		buffer := make([]uint16, windows.MAX_LONG_PATH)
		size := uint32(len(buffer))
		if windows.QueryFullProcessImageName(process, 0, &buffer[0], &size) == nil && strings.EqualFold(filepath.Dir(windows.UTF16ToString(buffer[:size])), dir) {
			if err := windows.TerminateProcess(process, 0); err != nil {
				failed = append(failed, err)
			} else {
				windows.WaitForSingleObject(process, 5000)
			}
		}
		windows.CloseHandle(process)
	}
	return errors.Join(failed...)
}

func debugPrivilege() error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	name, err := windows.UTF16PtrFromString("SeDebugPrivilege")
	if err != nil {
		return err
	}
	privileges := windows.Tokenprivileges{PrivilegeCount: 1}
	if err := windows.LookupPrivilegeValue(nil, name, &privileges.Privileges[0].Luid); err != nil {
		return err
	}
	privileges.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	return windows.AdjustTokenPrivileges(token, false, &privileges, 0, nil, nil)
}

func (remover) RemoveAdapter() error {
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		if _, err := net.InterfaceByName(serviceName); err != nil {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("the Krynodes network adapter is still there; restart Windows to remove it")
		}
	}
}

func (remover) RemoveFirewall() error {
	return tunnel.RemoveFirewall()
}

func (remover) RemoveNRPT() error {
	return tunnel.RemoveNRPT()
}

func (remover) RemoveRunEntry() error {
	return startWithWindows("", false)
}

func (remover) RemoveShortcut() error {
	link, err := shortcutPath()
	if err != nil {
		return err
	}
	return removeShortcut(link)
}

func removeShortcut(link string) error {
	if err := os.Remove(link); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (remover) RemoveData() error {
	dir, err := store.Dir()
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

func (r remover) RemoveProgram() (bool, error) {
	dir := filepath.Dir(r.program)
	if os.RemoveAll(dir) == nil {
		return false, nil
	}
	var left []string
	if err := filepath.WalkDir(dir, func(path string, _ fs.DirEntry, err error) error {
		if err == nil {
			left = append(left, path)
		}
		return nil
	}); err != nil {
		return false, err
	}
	slices.Reverse(left)
	for _, path := range left {
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return false, err
		}
		if err := windows.MoveFileEx(name, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); err != nil {
			return false, err
		}
	}
	return len(left) > 0, nil
}
