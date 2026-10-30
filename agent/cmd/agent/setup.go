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
	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/recipes"
)

func setupCommand(args []string) error {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	recommended := flags.Bool("recommended", false, "apply the recommended protections")
	confine := flags.Bool("confine", false, "turn on SELinux or AppArmor")
	docker := flags.Bool("docker", false, "install Docker with Compose")
	hour := flags.Int("reboot-hour", -1, "restart hour in UTC, 0 to 23")
	join := flags.String("network", "", "get ready to join the private network in this range")
	admin := flags.String("admin", "", "make this sudo user with the --admin-key keys")
	var adminKeys []recipes.AdminKey
	flags.Func("admin-key", "an SSH key for the admin user, <blob>:<label>", func(value string) error {
		key, err := recipes.ParseAdminKey(value)
		adminKeys = append(adminKeys, key)
		return err
	})
	if err := flags.Parse(args); err != nil {
		return err
	}
	switch {
	case flags.NArg() > 0:
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	case !*recommended && !*confine && !*docker && *join == "" && *admin == "" && len(adminKeys) == 0:
		return errors.New("choose --recommended, --confine, --docker, --network or more")
	case *admin != "" && !recipes.ValidAdminName(*admin):
		return errors.New("--admin takes your user name, not root")
	case *admin != "" && (len(adminKeys) == 0 || len(adminKeys) > 4):
		return errors.New("--admin needs one to four --admin-key")
	case *admin == "" && len(adminKeys) > 0:
		return errors.New("--admin-key needs --admin")
	case *join != "" && !network.ValidRange(*join):
		return errors.New("--network takes a /24 of 10.88.0.0/16")
	case *hour < -1 || *hour > 23:
		return errors.New("--reboot-hour is 0 to 23")
	case runtime.GOOS != "linux" || os.Geteuid() != 0:
		return errors.New("setup must run as root on Linux")
	}
	options := actions.SetupOptions{Recommended: *recommended, Confine: *confine, Docker: *docker, Network: *join, Admin: *admin, AdminKeys: adminKeys, Terminal: terminal{}}
	if *hour >= 0 {
		options.RebootHour = hour
	}
	executor := actions.Executor{StateDir: actions.StateDir, Now: time.Now, Run: actions.RunCommand}
	return executor.Setup(context.Background(), options, os.Stdout)
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
