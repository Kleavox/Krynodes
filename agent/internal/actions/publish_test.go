package actions

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

func closedServer(t *testing.T, ports string) (Executor, *fakeRun, []network.Opening) {
	t.Helper()
	executor, run := securityExecutor(t)
	open, err := network.ParseOpenings(ports)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(executor.StateDir, firewallFile, closedFirewall{Closed: true, Tool: "ufw", Open: open}, 0o640); err != nil {
		t.Fatal(err)
	}
	return executor, run, open
}

func mustRun(t *testing.T, run *fakeRun, calls ...string) {
	t.Helper()
	for _, call := range calls {
		if !slices.Contains(run.calls, call) {
			t.Fatalf("missing %q in %q", call, run.calls)
		}
	}
}

func publishRestore(open []network.Opening, ipv6 bool) string {
	return "*filter\n:KRY-PUBLISH - [0:0]\n" + strings.Join(network.Publish(open, ipv6), "\n") + "\nCOMMIT\n"
}

func TestAClosedFirewallClosesDockersPublishedPortsFromBoot(t *testing.T) {
	executor, run, open := closedServer(t, "443/tcp@everyone,8443/tcp@tailscale")
	run.failing["iptables -C DOCKER-USER -j KRY-PUBLISH"] = ""
	run.failing["ip6tables -C DOCKER-USER -j KRY-PUBLISH"] = ""
	executor.Contain(context.Background())
	for _, family := range []struct {
		tool, file string
		ipv6       bool
	}{{"iptables", "publish.v4", false}, {"ip6tables", "publish.v6", true}} {
		path := filepath.Join(executor.StateDir, family.file)
		body, err := os.ReadFile(path)
		if err != nil || string(body) != publishRestore(open, family.ipv6) {
			t.Fatalf("%s rules %q %v", family.tool, body, err)
		}
		mustRun(t, run, family.tool+"-restore --noflush "+path, family.tool+" -I DOCKER-USER 1 -j KRY-PUBLISH")
	}
	if !strings.Contains(publishRestore(open, false), "-A KRY-PUBLISH -i tailscale0 -p tcp -m conntrack --ctorigdstport 8443 -j RETURN\n-A KRY-PUBLISH -j DROP\n") {
		t.Fatal("the chain does not end in a drop after the open ports")
	}
}

func TestPublishedPortsInPlaceAreLeftAlone(t *testing.T) {
	executor, run, open := closedServer(t, "443/tcp@everyone")
	run.respond["iptables -S KRY-PUBLISH"] = "-N KRY-PUBLISH\n" + strings.Join(network.Publish(open, false), "\n") + "\n"
	run.respond["ip6tables -S KRY-PUBLISH"] = "-N KRY-PUBLISH\n" + strings.Join(network.Publish(open, true), "\n") + "\n"
	if err := executor.syncPublish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool {
		return strings.Contains(call, "-restore") || strings.Contains(call, "-I DOCKER-USER")
	}) {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestADropTakenOutOfThePublishChainIsReportedAndPutBack(t *testing.T) {
	executor, run, open := closedServer(t, "443/tcp@everyone")
	wanted := network.Publish(open, false)
	if err := writeWhole(executor.StateDir, "publish.v4", []byte(publishRestore(open, false)), 0o600); err != nil {
		t.Fatal(err)
	}
	run.respond["iptables -S KRY-PUBLISH"] = "-N KRY-PUBLISH\n" + strings.Join(wanted[:len(wanted)-1], "\n") + "\n"
	if err := executor.syncPublish(context.Background()); err != nil {
		t.Fatal(err)
	}
	log, _ := readState[eventLog](executor.StateDir, eventsFile)
	if len(log.Events) != 1 || log.Events[0].Kind != "rule" || log.Events[0].Detail["chain"] != "KRY-PUBLISH" || log.Events[0].Detail["rule"] != "-A KRY-PUBLISH -j DROP" {
		t.Fatalf("events %+v", log.Events)
	}
	mustRun(t, run, "iptables-restore --noflush "+filepath.Join(executor.StateDir, "publish.v4"))
}

func TestAnOpenFirewallHasNoPublishChain(t *testing.T) {
	executor, run := securityExecutor(t)
	run.respond["iptables -S KRY-PUBLISH"] = "-N KRY-PUBLISH\n-A KRY-PUBLISH -j DROP\n"
	if err := writeWhole(executor.StateDir, "publish.v4", []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := executor.syncPublish(context.Background()); err != nil {
		t.Fatal(err)
	}
	mustRun(t, run, "iptables -D DOCKER-USER -j KRY-PUBLISH", "iptables -F KRY-PUBLISH", "iptables -X KRY-PUBLISH")
	if slices.ContainsFunc(run.calls, func(call string) bool {
		return strings.HasPrefix(call, "ip6tables -D") || strings.Contains(call, "-restore")
	}) {
		t.Fatalf("calls %q", run.calls)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "publish.v4")); !os.IsNotExist(err) {
		t.Fatal("the last rules file stays behind")
	}
	run.calls = nil
	if err := executor.syncPublish(context.Background()); err != nil || len(run.calls) != 0 {
		t.Fatalf("a firewall never closed costs no commands: %v %q", err, run.calls)
	}
}
