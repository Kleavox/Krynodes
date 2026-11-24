package main

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

func TestVersionPrintsTheLinkerValue(t *testing.T) {
	name := "krynodes"
	flags := []string{"-X main.version=1.2.3"}
	if runtime.GOOS == "windows" {
		name += ".exe"
		flags = append(flags, "-H windowsgui -X main.version=1.2.3")
	}
	for _, ldflags := range flags {
		binary := filepath.Join(t.TempDir(), name)
		build := exec.Command("go", "build", "-ldflags", ldflags, "-o", binary, ".")
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("go build %s: %v\n%s", ldflags, err, output)
		}
		output, err := exec.Command(binary, "version").Output()
		if err != nil {
			t.Fatalf("%s version: %v", ldflags, err)
		}
		if got := strings.TrimSpace(string(output)); got != "1.2.3" {
			t.Errorf("%s: version printed %q, want 1.2.3", ldflags, got)
		}
	}
}

func TestEverySubcommandIsKnownAndAnythingElseIsRefused(t *testing.T) {
	for _, test := range []struct {
		args []string
		want int
	}{
		{[]string{"version"}, 0},
		{[]string{"install"}, 1},
		{[]string{"uninstall", "now"}, 1},
		{[]string{"service"}, 1},
		{[]string{"tray", "now"}, 1},
		{[]string{"after-update"}, 1},
		{[]string{"nope"}, 2},
	} {
		var stdout, stderr bytes.Buffer
		if got := run(test.args, &stdout, &stderr); got != test.want {
			t.Errorf("run(%v) = %d, want %d (stderr %q)", test.args, got, test.want, stderr.String())
		}
	}
}

func TestNoArgumentsShowsTheDashboardHint(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		shown := []string{}
		before, attached := notice, inTerminal
		notice = func(text string) { shown = append(shown, text) }
		inTerminal = func() bool { return terminal }
		var stdout, stderr bytes.Buffer
		got := run(nil, &stdout, &stderr)
		notice, inTerminal = before, attached
		if got != 0 {
			t.Fatalf("terminal %v: run() = %d, want 0", terminal, got)
		}
		want, printed := []string{hint}, ""
		if terminal {
			want, printed = []string{}, hint+"\n"
		}
		if hint != "Krynodes is installed from your dashboard: Network, Add Laptop." || !slices.Equal(shown, want) || stdout.String() != printed || stderr.Len() != 0 {
			t.Errorf("terminal %v: shown %q, printed %q and %q", terminal, shown, stdout.String(), stderr.String())
		}
	}
}

func TestParentInternalPackagesImport(t *testing.T) {
	if got := network.DNSName("Laptop 1"); got != "laptop-1" {
		t.Errorf("DNSName = %q, want laptop-1", got)
	}
}
