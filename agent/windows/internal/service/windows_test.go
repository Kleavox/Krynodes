//go:build windows

package service

import (
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
