package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/windows"

	"github.com/Kleavox/krynodes/agent/windows/internal/service"
	"github.com/Kleavox/krynodes/agent/windows/internal/tray"
)

const uninstalled = "Krynodes is removed from this laptop. It stays a member of the private network until you choose Remove from Network on the Network page."

var attachConsole = windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")

var terminal bool

var inTerminal = func() bool { return terminal }

func console(command string) {
	if command == "tray" || command == "service" {
		return
	}
	terminal = usable(os.Stdout)
	if terminal && usable(os.Stderr) {
		return
	}
	if attached, _, _ := attachConsole.Call(uintptr(^uint32(0))); attached == 0 {
		return
	}
	out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		return
	}
	if !usable(os.Stdout) {
		os.Stdout = out
	}
	if !usable(os.Stderr) {
		os.Stderr = out
	}
	terminal = true
}

var notice = func(text string) {
	message, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	title, _ := windows.UTF16PtrFromString("Krynodes")
	_, _ = windows.MessageBox(0, message, title, windows.MB_OK|windows.MB_ICONINFORMATION|windows.MB_SETFOREGROUND)
}

func usable(file *os.File) bool {
	if file == nil {
		return false
	}
	kind, err := windows.GetFileType(windows.Handle(file.Fd()))
	return err == nil && (kind == windows.FILE_TYPE_DISK || kind == windows.FILE_TYPE_PIPE)
}

func system(command string, args []string, stdout, stderr io.Writer) int {
	var err error
	done := ""
	switch command {
	case "install":
		err = service.InstallCommand(args, version, stdout)
	case "uninstall":
		if len(args) > 0 {
			err = errors.New("use uninstall with no arguments")
		} else {
			err = service.UninstallCommand()
			done = uninstalled
		}
	case "service":
		err = service.RunService(version)
	case "after-update":
		err = service.AfterUpdate(args, version)
	case "tray":
		if len(args) > 0 {
			err = errors.New("use tray with no arguments")
		} else {
			tray.Run(version)
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "krynodes %s: %v\n", command, err)
		return 1
	}
	if done != "" {
		fmt.Fprintln(stdout, done)
	}
	return 0
}
