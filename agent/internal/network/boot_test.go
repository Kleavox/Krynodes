package network

import "testing"

func TestTheBootDropInRestoresRulesBeforeTheTunnel(t *testing.T) {
	if RulesDropInPath != "/etc/systemd/system/wg-quick@kry0.service.d/krynodes-rules.conf" {
		t.Fatalf("path %q", RulesDropInPath)
	}
	if got := RulesDropIn("/usr/local/bin/kry"); got != "[Service]\nExecStartPre=/usr/local/bin/kry network rules\n" {
		t.Fatalf("body %q", got)
	}
	if DropInPath != "/etc/systemd/system/docker.service.d/krynodes-network.conf" || DropInBody != "[Unit]\nAfter=wg-quick@kry0.service\nWants=wg-quick@kry0.service\n" {
		t.Fatalf("docker drop-in %q %q", DropInPath, DropInBody)
	}
}
