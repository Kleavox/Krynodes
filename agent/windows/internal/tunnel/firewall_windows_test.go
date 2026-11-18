//go:build windows

package tunnel

import (
	"os/exec"
	"strings"
	"testing"
)

func TestTheFirewallIsSeenRunningWithoutFullRightsOnItsService(t *testing.T) {
	output, err := exec.Command("sc.exe", "query", "MpsSvc").Output()
	if err != nil {
		t.Skipf("sc query MpsSvc: %v", err)
	}
	if want := strings.Contains(string(output), "RUNNING"); firewallRunning() != want {
		t.Fatalf("firewallRunning() = %v, sc.exe says running = %v", !want, want)
	}
}
