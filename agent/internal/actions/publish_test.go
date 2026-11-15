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
	executor, run, open := closedServer(t, "443/tcp@everyone,8443/tcp@203.0.113.0/24")
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
	if !strings.Contains(publishRestore(open, false), "-A KRY-PUBLISH -s 203.0.113.0/24 -p tcp -m conntrack --ctorigdstport 8443 -j RETURN\n-A KRY-PUBLISH -j DROP\n") {
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

func TestTailscaleOpeningsKeepTheirWayThroughThePublishChain(t *testing.T) {
	executor, run, open := closedServer(t, "443/tcp@everyone")
	open = append(open, network.Opening{Port: 8443, Protocol: "tcp", From: "tailscale"})
	if err := writeJSON(executor.StateDir, firewallFile, closedFirewall{Closed: true, Tool: "ufw", Open: open}, 0o640); err != nil {
		t.Fatal(err)
	}
	through := "-A KRY-PUBLISH -i tailscale0 -p tcp -m conntrack --ctorigdstport 8443 -j RETURN\n"
	for _, step := range []string{"before filing", "after filing"} {
		if step == "after filing" {
			if err := executor.fileTailscaleOpenings(context.Background()); err != nil {
				t.Fatal(err)
			}
			if state := executor.readFirewall(); len(state.Open) != 1 || len(state.Filed) != 1 {
				t.Fatalf("state %+v", state)
			}
		}
		if err := executor.syncPublish(context.Background()); err != nil {
			t.Fatal(err)
		}
		for _, file := range []string{"publish.v4", "publish.v6"} {
			body, err := os.ReadFile(filepath.Join(executor.StateDir, file))
			if err != nil || !strings.Contains(string(body), through) || !strings.HasSuffix(string(body), "-A KRY-PUBLISH -j DROP\nCOMMIT\n") {
				t.Fatalf("%s %s: %q %v", step, file, body, err)
			}
		}
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "KRY-TAILSCALE") }) {
		t.Fatalf("a guard was made: %q", run.calls)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "tailscale.v4")); !os.IsNotExist(err) {
		t.Fatal("a guard file was made")
	}
}

func TestALeftoverGuardWithAnotherRuleIsNotRestored(t *testing.T) {
	executor, run, _ := closedServer(t, "443/tcp@everyone")
	guard := "*filter\n:KRY-TAILSCALE - [0:0]\n-A KRY-TAILSCALE -i tailscale0 -j RETURN\n-A INPUT -j ACCEPT\nCOMMIT\n"
	if err := writeWhole(executor.StateDir, "tailscale.v4", []byte(guard), 0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(executor.StateDir, "tailscale.v4")
	run.failing["iptables -C INPUT -j KRY-TAILSCALE"] = ""
	if err := executor.syncPublish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "KRY-TAILSCALE") || strings.Contains(call, file) }) {
		t.Fatalf("the file was used: %q", run.calls)
	}
	if body, err := os.ReadFile(file); err != nil || string(body) != guard {
		t.Fatalf("the file changed: %q %v", body, err)
	}
}

func TestALeftoverTailscaleGuardIsRestoredAsItIs(t *testing.T) {
	executor, run, _ := closedServer(t, "443/tcp@everyone")
	guard := "*filter\n:KRY-TAILSCALE - [0:0]\n-A KRY-TAILSCALE -i tailscale0 -j RETURN\n-A KRY-TAILSCALE -m conntrack ! --ctstate NEW -j RETURN\n-A KRY-TAILSCALE -s 100.64.0.0/10 -p tcp -m tcp --dport 8443 -j DROP\nCOMMIT\n"
	if err := writeWhole(executor.StateDir, "tailscale.v4", []byte(guard), 0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(executor.StateDir, "tailscale.v4")
	run.failing["iptables -C INPUT -j KRY-TAILSCALE"] = ""
	if err := executor.syncPublish(context.Background()); err != nil {
		t.Fatal(err)
	}
	mustRun(t, run, "iptables-restore --noflush "+file, "iptables -I INPUT 1 -j KRY-TAILSCALE")
	if slices.ContainsFunc(run.calls, func(call string) bool {
		return strings.HasPrefix(call, "ip6tables") && strings.Contains(call, "KRY-TAILSCALE")
	}) {
		t.Fatalf("a guard was made for IPv6: %q", run.calls)
	}
	if body, err := os.ReadFile(file); err != nil || string(body) != guard {
		t.Fatalf("the guard's file changed: %q %v", body, err)
	}
	run.calls = nil
	delete(run.failing, "iptables -C INPUT -j KRY-TAILSCALE")
	run.respond["iptables -S KRY-TAILSCALE"] = "-N KRY-TAILSCALE\n-A KRY-TAILSCALE -i tailscale0 -j RETURN\n-A KRY-TAILSCALE -m conntrack ! --ctstate NEW -j RETURN\n-A KRY-TAILSCALE -s 100.64.0.0/10 -p tcp -m tcp --dport 8443 -j DROP\n"
	if err := executor.syncPublish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(run.calls, "iptables-restore --noflush "+file) || slices.Contains(run.calls, "iptables -I INPUT 1 -j KRY-TAILSCALE") {
		t.Fatalf("a guard in place was rewritten: %q", run.calls)
	}
}
