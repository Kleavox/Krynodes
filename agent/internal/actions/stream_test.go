package actions

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestStreamHelper(t *testing.T) {
	if os.Getenv("KRY_STREAM_HELPER") != "1" {
		t.Skip("run by TestAStreamedCommandHandsOverEachLineAsItComes")
	}
	fmt.Print("Waiting for cache lock... 1s\rWaiting for cache lock... 2s\rpmstatus:x:50:Unpacking x\n")
	fmt.Fprint(os.Stderr, strings.Repeat("y", 70<<10)+"\n")
	fmt.Print("done\n")
	os.Exit(3)
}

func TestAStreamedCommandHandsOverEachLineAsItComes(t *testing.T) {
	t.Setenv("KRY_STREAM_HELPER", "1")
	var lines []string
	err := StreamCommand(context.Background(), func(line string) { lines = append(lines, line) }, os.Args[0], "-test.run=^TestStreamHelper$")
	if err == nil {
		t.Fatal("the exit status was lost")
	}
	if !slices.Contains(lines, "Waiting for cache lock... 2s") || !slices.Contains(lines, "pmstatus:x:50:Unpacking x") || !slices.Contains(lines, "done") {
		t.Fatalf("lines %q", lines)
	}
}
