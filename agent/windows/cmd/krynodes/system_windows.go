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

const (
	installed   = "Krynodes is installed. Approve this laptop on the Network page of your dashboard."
	uninstalled = "Krynodes is removed from this laptop. It stays a member of the private network until you choose Remove Laptop on the Network page."
)

var attachConsole = windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")

func console(command string) {
	if command == "tray" || command == "service" || (usable(os.Stdout) && usable(os.Stderr)) {
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
		err = service.InstallCommand(args, version)
		done = installed
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
