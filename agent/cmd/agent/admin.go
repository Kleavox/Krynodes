package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/actions"
)

type terminal struct{}

func (terminal) Ask(question string) (bool, bool) {
	return askTerminal(question)
}

func (terminal) Printf(format string, args ...any) {
	fmt.Printf(format, args...)
}

func (terminal) Passwd(ctx context.Context, name string) error {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer tty.Close()
	command := exec.CommandContext(ctx, "passwd", name)
	command.Stdin, command.Stdout, command.Stderr = tty, tty, tty
	return command.Run()
}

func adminUserCommand(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: kry admin-user <name>")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("admin-user must run as root on Linux")
	}
	executor := actions.Executor{StateDir: actions.StateDir, Now: time.Now, Run: actions.RunCommand}
	return executor.AdminUser(context.Background(), args[0], os.Stdout, terminal{})
}
