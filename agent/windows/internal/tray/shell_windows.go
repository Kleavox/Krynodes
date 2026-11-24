//go:build windows

package tray

import (
	"errors"
	"net/url"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	trayID          = 100
	nimModify       = 0x1
	nifInfo         = 0x10
	niifInfo        = 0x1
	cfUnicodeText   = 13
	gmemMoveable    = 0x2
	clipboardFailed = "The address could not be copied."
)

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	kernel32         = windows.NewLazySystemDLL("kernel32.dll")
	shell32          = windows.NewLazySystemDLL("shell32.dll")
	findWindowEx     = user32.NewProc("FindWindowExW")
	openClipboard    = user32.NewProc("OpenClipboard")
	emptyClipboard   = user32.NewProc("EmptyClipboard")
	setClipboardData = user32.NewProc("SetClipboardData")
	closeClipboard   = user32.NewProc("CloseClipboard")
	globalAlloc      = kernel32.NewProc("GlobalAlloc")
	globalLock       = kernel32.NewProc("GlobalLock")
	globalUnlock     = kernel32.NewProc("GlobalUnlock")
	globalFree       = kernel32.NewProc("GlobalFree")
	moveMemory       = kernel32.NewProc("RtlMoveMemory")
	freeConsole      = kernel32.NewProc("FreeConsole")
	shellNotifyIcon  = shell32.NewProc("Shell_NotifyIconW")
)

func trayWindow() windows.Handle {
	class, err := windows.UTF16PtrFromString("SystrayClass")
	if err != nil {
		return 0
	}
	own := windows.GetCurrentProcessId()
	var after uintptr
	for {
		found, _, _ := findWindowEx.Call(0, after, uintptr(unsafe.Pointer(class)), 0)
		if found == 0 {
			return 0
		}
		var pid uint32
		if _, err := windows.GetWindowThreadProcessId(windows.HWND(found), &pid); err == nil && pid == own {
			return windows.Handle(found)
		}
		after = found
	}
}

func balloon(line string) {
	window := trayWindow()
	if window == 0 {
		return
	}
	data := notifyIconData{Wnd: uintptr(window), ID: trayID, Flags: nifInfo, InfoFlags: niifInfo}
	data.Size = uint32(unsafe.Sizeof(data))
	info, err := windows.UTF16FromString(line)
	if err != nil {
		return
	}
	title, _ := windows.UTF16FromString("Krynodes")
	copy(data.Info[:len(data.Info)-1], info)
	copy(data.InfoTitle[:len(data.InfoTitle)-1], title)
	shellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&data)))
}

func copyText(value string) error {
	text, err := windows.UTF16FromString(value)
	if err != nil {
		return err
	}
	if ok, _, _ := openClipboard.Call(0); ok == 0 {
		return errors.New(clipboardFailed)
	}
	defer closeClipboard.Call()
	emptyClipboard.Call()
	size := uintptr(len(text)) * 2
	memory, _, _ := globalAlloc.Call(gmemMoveable, size)
	if memory == 0 {
		return errors.New(clipboardFailed)
	}
	target, _, _ := globalLock.Call(memory)
	if target == 0 {
		globalFree.Call(memory)
		return errors.New(clipboardFailed)
	}
	moveMemory.Call(target, uintptr(unsafe.Pointer(&text[0])), size)
	globalUnlock.Call(memory)
	if placed, _, _ := setClipboardData.Call(cfUnicodeText, memory); placed == 0 {
		globalFree.Call(memory)
		return errors.New(clipboardFailed)
	}
	return nil
}

func show(text string) {
	message, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	title, _ := windows.UTF16PtrFromString("Krynodes")
	_, _ = windows.MessageBox(0, message, title, windows.MB_OK|windows.MB_ICONINFORMATION|windows.MB_SETFOREGROUND)
}

func open(address string) error {
	parsed, err := url.Parse(address)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return errors.New("The dashboard's address is not a web address.")
	}
	verb, _ := windows.UTF16PtrFromString("open")
	target, err := windows.UTF16PtrFromString(parsed.String())
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, target, nil, nil, windows.SW_SHOWNORMAL)
}

var instance windows.Handle

func single() bool {
	name, err := windows.UTF16PtrFromString(`Local\Krynodes tray`)
	if err != nil {
		return false
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		handle, err := windows.CreateMutex(nil, false, name)
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			instance = handle
			return true
		}
		if handle != 0 {
			windows.CloseHandle(handle)
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

func release() {
	if instance != 0 {
		windows.CloseHandle(instance)
		instance = 0
	}
}

func detach() {
	freeConsole.Call()
}
