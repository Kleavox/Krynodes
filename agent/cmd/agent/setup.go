package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/actions"
)

func setupCommand(args []string) error {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	recommended := flags.Bool("recommended", false, "apply the recommended protections")
	docker := flags.Bool("docker", false, "install Docker with Compose")
	anyway := flags.Bool("anyway", false, "run on a version Krynodes has not checked")
	hour := flags.Int("reboot-hour", -1, "restart hour in UTC, 0 to 23")
	if err := flags.Parse(args); err != nil {
		return err
	}
	switch {
	case flags.NArg() > 0:
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	case !*recommended && !*docker:
		return errors.New("choose --recommended, --docker or both")
	case *hour < -1 || *hour > 23:
		return errors.New("--reboot-hour is 0 to 23")
	case runtime.GOOS != "linux" || os.Geteuid() != 0:
		return errors.New("setup must run as root on Linux")
	}
	options := actions.SetupOptions{Recommended: *recommended, Docker: *docker, Anyway: *anyway, Command: setupCommandLine(*recommended, *docker, *hour)}
	if *hour >= 0 {
		options.RebootHour = hour
	}
	executor := actions.Executor{StateDir: actions.StateDir, Now: time.Now, Run: actions.RunCommand}
	return executor.Setup(context.Background(), options, os.Stdout, askTerminal)
}

func setupCommandLine(recommended, docker bool, hour int) string {
	parts := []string{"kry setup"}
	if recommended {
		parts = append(parts, "--recommended")
	}
	if docker {
		parts = append(parts, "--docker")
	}
	if recommended && hour >= 0 {
		parts = append(parts, fmt.Sprintf("--reboot-hour %d", hour))
	}
	return strings.Join(parts, " ")
}

func askTerminal(question string) (bool, bool) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, false
	}
	defer tty.Close()
	fmt.Fprint(tty, question)
	line, _ := bufio.NewReader(tty).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", true
}
