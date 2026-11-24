//go:build !windows

package main

import (
	"fmt"
	"io"
)

func console(string) {}

var inTerminal = func() bool { return true }

var notice = func(text string) {
	fmt.Println(text)
}

func system(command string, _ []string, _, stderr io.Writer) int {
	fmt.Fprintf(stderr, "krynodes %s: Windows only\n", command)
	return 1
}
