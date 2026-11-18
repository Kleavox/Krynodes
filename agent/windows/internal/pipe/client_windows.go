//go:build windows

package pipe

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const serviceName = "Krynodes"

var errNotService = errors.New("the pipe is not served by the Krynodes service")

func Ask(request Request) (Reply, error) {
	file, err := dial()
	if err != nil {
		return Reply{}, err
	}
	defer file.Close()
	wait := 30 * time.Second
	if request.Request == "status" {
		wait = 5 * time.Second
	}
	if err := file.SetDeadline(time.Now().Add(wait)); err != nil {
		return Reply{}, err
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return Reply{}, err
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return Reply{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxReply+1))
	if err != nil {
		return Reply{}, err
	}
	line, rest, found := bytes.Cut(raw, []byte("\n"))
	if !found || len(rest) != 0 || len(raw) > MaxReply {
		return Reply{}, errors.New("the Krynodes service answered with something else")
	}
	var reply Reply
	return reply, json.Unmarshal(line, &reply)
}

func dial() (*os.File, error) {
	path, err := windows.UTF16PtrFromString(Path)
	if err != nil {
		return nil, err
	}
	var handle windows.Handle
	for attempt := 0; ; attempt++ {
		handle, err = windows.CreateFile(path, windows.GENERIC_READ|windows.FILE_WRITE_DATA, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_ANONYMOUS, 0)
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) || attempt == 50 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		return nil, err
	}
	if err := genuine(handle); err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}
	return os.NewFile(uintptr(handle), Path), nil
}

func genuine(pipe windows.Handle) error {
	security, err := windows.GetSecurityInfo(pipe, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := security.Owner()
	if err != nil {
		return err
	}
	if !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return errNotService
	}
	var server uint32
	if err := windows.GetNamedPipeServerProcessId(pipe, &server); err != nil {
		return err
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(manager)
	name, err := windows.UTF16PtrFromString(serviceName)
	if err != nil {
		return err
	}
	service, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if err := windows.QueryServiceStatusEx(service, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed); err != nil {
		return err
	}
	if status.ProcessId == 0 || status.ProcessId != server {
		return errNotService
	}
	return nil
}
