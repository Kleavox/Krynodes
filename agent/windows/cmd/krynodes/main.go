package main

import (
	"fmt"
	"io"
	"os"
)

var version = "dev"

const (
	usage = "usage: krynodes <install|uninstall|service|tray|version>"
	hint  = "Krynodes is installed from your dashboard: Network, Add Laptop."
)

func main() {
	command := ""
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	console(command)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		if inTerminal() {
			fmt.Fprintln(stdout, hint)
		} else {
			notice(hint)
		}
		return 0
	}
	switch args[0] {
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "install", "uninstall", "service", "tray", "after-update":
		return system(args[0], args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "krynodes: unknown command %q\n%s\n", args[0], usage)
	return 2
}
