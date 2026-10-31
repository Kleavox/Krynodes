package actions

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const ufwHeader = "Added user rules (see 'ufw status' for running firewall):\n"

func ufwServer(t *testing.T) (Executor, *fakeRun) {
	t.Helper()
	executor, run := securityExecutor(t)
	rootFile(t, executor, "/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n")
	run.respond["sshd -T"] = "port 22\n"
	run.respond["ufw status"] = "Status: inactive\n"
	run.respond["ufw show added"] = ufwHeader + "ufw allow 22/tcp comment 'krynodes'\nufw allow 80/tcp\nufw allow OpenSSH\n"
	ufwComesUp(run)
	return executor, run
}

func handAdds(run *fakeRun, call, line string) {
	run.effects[call] = func() { run.respond["ufw show added"] += "ufw " + line + "\n" }
}

func handRemoves(run *fakeRun, call, line string) {
	run.effects[call] = func() {
		run.respond["ufw show added"] = strings.Replace(run.respond["ufw show added"], "ufw "+line+"\n", "", 1)
	}
}

func closedUfwServer(t *testing.T) (Executor, *fakeRun) {
	t.Helper()
	executor, run := ufwServer(t)
	if result := hostRun(t, executor, hostRequest(t, idA, "firewall", "apply", map[string]string{"closed": "1", "ports": "80/tcp@everyone"})); !result.OK {
		t.Fatalf("close %#v calls %q", result, run.calls)
	}
	return executor, run
}

func firewallEvents(t *testing.T, executor Executor) []reporter.Event {
	t.Helper()
	log, _ := readState[eventLog](executor.StateDir, eventsFile)
	return slices.DeleteFunc(log.Events, func(event reporter.Event) bool { return event.Kind != "firewall" })
}

func TestClosingTheFirewallRemembersWhatIsOpenAndUndoForgetsIt(t *testing.T) {
	executor, run := closedUfwServer(t)
	state := executor.readFirewall()
	everyone, _ := network.ParseOpening("80", "tcp", "everyone")
	if !state.Closed || state.Tool != "ufw" || !reflect.DeepEqual(state.Open, []network.Opening{everyone}) || !reflect.DeepEqual(state.Other, []string{"allow OpenSSH"}) || !slices.Contains(state.Known, "allow 80/tcp") {
		t.Fatalf("state %+v", state)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "publish.v4")); err != nil {
		t.Fatalf("published ports stay open: %v", err)
	}
	run.respond["iptables -S KRY-PUBLISH"] = "-N KRY-PUBLISH\n-A KRY-PUBLISH -j DROP\n"
	if result := hostRun(t, executor, hostRequest(t, idB, "firewall", "undo", nil)); !result.OK {
		t.Fatalf("undo %#v", result)
	}
	if executor.readFirewall().Closed {
		t.Fatal("still closed after Turn Off")
	}
	mustRun(t, run, "iptables -X KRY-PUBLISH")
}

func TestClosingOverKrynodesOldFirewallTurnsOffBackToIt(t *testing.T) {
	executor, run := ufwServer(t)
	if result := hostRun(t, executor, hostRequest(t, idA, "firewall", "apply", map[string]string{"ports": "80/tcp"})); !result.OK {
		t.Fatalf("old apply %#v", result)
	}
	if result := hostRun(t, executor, hostRequest(t, idB, "firewall", "apply", map[string]string{"closed": "1", "ports": "80/tcp@everyone"})); !result.OK {
		t.Fatalf("close everything else %#v calls %q", result, run.calls)
	}
	if !executor.readFirewall().Closed {
		t.Fatal("not closed")
	}
	if result := hostRun(t, executor, hostRequest(t, idC, "firewall", "apply", map[string]string{"closed": "1", "ports": ""})); result.OK {
		t.Fatal("a closed firewall was closed twice")
	}
	run.respond["iptables -S KRY-PUBLISH"] = "-N KRY-PUBLISH\n-A KRY-PUBLISH -j DROP\n"
	if result := hostRun(t, executor, hostRequest(t, idC, "firewall", "undo", nil)); !result.OK {
		t.Fatalf("turn off %#v", result)
	}
	saved := executor.readRecipes().Applied["firewall"].Saved
	if executor.readFirewall().Closed || saved == nil || saved["closed"] == "1" {
		t.Fatalf("closed %v saved %v", executor.readFirewall().Closed, saved)
	}
	if result := hostRun(t, executor, hostRequest(t, idD, "firewall", "undo", nil)); !result.OK {
		t.Fatalf("old turn off %#v", result)
	}
	if slices.Contains(executor.appliedRecipes(), "firewall") {
		t.Fatalf("still applied: %q", executor.appliedRecipes())
	}
}

func TestTurningOffKeepsThePrivateNetworkJoinedWhileClosedReachable(t *testing.T) {
	executor, run := closedUfwServer(t)
	if err := executor.saveNetwork(networkRecord{Joined: true, Firewall: "ufw", Port: 51821}); err != nil {
		t.Fatal(err)
	}
	run.respond["iptables -S KRY-PUBLISH"] = "-N KRY-PUBLISH\n-A KRY-PUBLISH -j DROP\n"
	run.calls = nil
	if result := hostRun(t, executor, hostRequest(t, idB, "firewall", "undo", nil)); !result.OK {
		t.Fatalf("turn off %#v", result)
	}
	if !ranInOrder(run.calls, "ufw allow 51821/udp comment krynodes-network", "ufw allow in on kry0 comment krynodes-network") {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestCloseEverythingElseKeepsARuleTheDialogNeverShowed(t *testing.T) {
	executor, run := ufwServer(t)
	run.respond["ufw status"] = "Status: active\n\n22/tcp ALLOW Anywhere # krynodes\n"
	shown, _ := network.ParseOpening("80", "tcp", "everyone")
	if err := writeJSON(executor.StateDir, "security.json", securityState{CheckedAt: executorNow, Firewall: &reporter.Firewall{Open: []network.Opening{shown}}}, 0o640); err != nil {
		t.Fatal(err)
	}
	run.respond["ufw show added"] += "ufw allow 9090/tcp\n"
	if result := hostRun(t, executor, hostRequest(t, idA, "firewall", "apply", map[string]string{"closed": "1", "ports": ""})); !result.OK {
		t.Fatalf("close %#v calls %q", result, run.calls)
	}
	if !slices.Contains(run.calls, "ufw --force delete allow 80/tcp") || slices.Contains(run.calls, "ufw --force delete allow 9090/tcp") {
		t.Fatalf("calls %q", run.calls)
	}
	unseen, _ := network.ParseOpening("9090", "tcp", "everyone")
	if state := executor.readFirewall(); !reflect.DeepEqual(state.Open, []network.Opening{unseen}) {
		t.Fatalf("open %+v", state.Open)
	}
}

func TestOpenAndCloseChangeTheFirewallAndItsState(t *testing.T) {
	executor, run := closedUfwServer(t)
	handAdds(run, "ufw allow in on tailscale0 to any port 8443 proto tcp comment krynodes", "allow in on tailscale0 to any port 8443 proto tcp comment 'krynodes'")
	if result := hostRun(t, executor, hostRequest(t, idB, "firewall", "open", map[string]string{"port": "8443", "protocol": "tcp", "from": "tailscale"})); !result.OK || result.Output != "8443/tcp is open to Tailscale" {
		t.Fatalf("open %#v", result)
	}
	if state := executor.readFirewall(); len(state.Open) != 2 || state.Open[1].From != "tailscale" || !slices.Contains(state.Known, "allow in on tailscale0 to any port 8443 proto tcp") {
		t.Fatalf("state %+v", state)
	}
	run.calls = nil
	if result := hostRun(t, executor, hostRequest(t, idC, "firewall", "open", map[string]string{"port": "8443", "protocol": "tcp", "from": "203.0.113.0/24"})); !result.OK || result.Output != "8443/tcp is open to 203.0.113.0/24" {
		t.Fatalf("change from %#v", result)
	}
	if !ranInOrder(run.calls, "ufw allow from 203.0.113.0/24 to any port 8443 proto tcp comment krynodes", "ufw --force delete allow in on tailscale0 to any port 8443 proto tcp") {
		t.Fatalf("calls %q", run.calls)
	}
	if result := hostRun(t, executor, hostRequest(t, idD, "firewall", "close", map[string]string{"port": "8443", "protocol": "tcp"})); !result.OK || result.Output != "8443/tcp is closed" {
		t.Fatalf("close %#v", result)
	}
	if state := executor.readFirewall(); len(state.Open) != 1 || state.Open[0].Port != 80 {
		t.Fatalf("state %+v", state)
	}
	mustRun(t, run, "ufw --force delete allow from 203.0.113.0/24 to any port 8443 proto tcp")
	for i, args := range []map[string]string{
		{"port": "8443", "protocol": "tcp"},
		{"port": "22", "protocol": "tcp"},
	} {
		if result := hostRun(t, executor, hostRequest(t, []string{idB, idC}[i], "firewall", "close", args)); result.OK {
			t.Fatalf("%v must be refused: %#v", args, result)
		}
	}
	if result := hostRun(t, executor, hostRequest(t, idD, "firewall", "open", map[string]string{"port": "22", "protocol": "tcp", "from": "tailscale"})); result.OK || !strings.Contains(result.Output, "SSH stays open") {
		t.Fatalf("ssh %#v", result)
	}
}

func TestOpenPortNeedsAClosedFirewall(t *testing.T) {
	executor, run := ufwServer(t)
	if result := hostRun(t, executor, hostRequest(t, idA, "firewall", "open", map[string]string{"port": "8443", "protocol": "tcp", "from": "everyone"})); result.OK {
		t.Fatalf("open %#v", result)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "ufw allow") }) {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestARuleAddedByHandWarnsOncePerHourAndAnOpenByKrynodesDoesNot(t *testing.T) {
	executor, run := closedUfwServer(t)
	run.respond["ufw show added"] += "ufw allow 9999/tcp\n"
	for range 2 {
		if err := executor.Execute(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	events := firewallEvents(t, executor)
	if len(events) != 1 || events[0].Detail["rule"] != "allow 9999/tcp" {
		t.Fatalf("events %+v", events)
	}
	var inventory Inventory
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	if report := inventory.Security.Firewall; report == nil || !report.Closed || len(report.Open) != 1 || !reflect.DeepEqual(report.Drift, []string{"allow 9999/tcp"}) || !reflect.DeepEqual(report.Other, []string{"allow OpenSSH"}) {
		t.Fatalf("report %+v", inventory.Security.Firewall)
	}
	handAdds(run, "ufw allow 7000/udp comment krynodes", "allow 7000/udp comment 'krynodes'")
	if result := hostRun(t, executor, hostRequest(t, idB, "firewall", "open", map[string]string{"port": "7000", "protocol": "udp", "from": "everyone"})); !result.OK {
		t.Fatalf("open %#v", result)
	}
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if events := firewallEvents(t, executor); len(events) != 1 {
		t.Fatalf("an open by Krynodes warned: %+v", events)
	}
	if state := executor.readFirewall(); !reflect.DeepEqual(state.Drift, []string{"allow 9999/tcp"}) {
		t.Fatalf("the hand-added rule is no longer drift: %+v", state)
	}
}

func TestDriftIsOnlyARuleThatLetsSomethingInFromOutsideKrynodes(t *testing.T) {
	executor, run := closedUfwServer(t)
	if err := executor.saveNetwork(networkRecord{Joined: true, Port: 51821}); err != nil {
		t.Fatal(err)
	}
	run.respond["ufw show added"] += "ufw allow 51821/udp comment 'krynodes-network'\nufw allow in on kry0 comment 'krynodes-network'\nufw allow 22/tcp\nufw deny from 192.0.2.7\nufw reject 25/tcp\nufw allow 8080/tcp\n"
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	events := firewallEvents(t, executor)
	if len(events) != 1 || events[0].Detail["rule"] != "allow 8080/tcp" {
		t.Fatalf("events %+v", events)
	}
	if state := executor.readFirewall(); !reflect.DeepEqual(state.Drift, []string{"allow 8080/tcp"}) {
		t.Fatalf("drift %+v", state.Drift)
	}
	rocky, run := securityExecutor(t)
	rootFile(t, rocky, "/etc/os-release", "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\n")
	run.respond["sshd -T"] = "port 22\n"
	run.respond["firewall-cmd --state"] = "running\n"
	run.respond["firewall-cmd --get-default-zone"] = "public\n"
	if err := writeJSON(rocky.StateDir, firewallFile, closedFirewall{Closed: true, Tool: "firewalld", Open: []network.Opening{}, Known: []string{"service:ssh"}}, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := rocky.saveNetwork(networkRecord{Joined: true, Port: 51821}); err != nil {
		t.Fatal(err)
	}
	run.respond["firewall-cmd --zone=public --list-ports"] = "51821/udp 22/tcp\n"
	run.respond["firewall-cmd --zone=public --list-services"] = "ssh\n"
	run.respond["firewall-cmd --zone=public --list-rich-rules"] = "rule family=\"ipv4\" source address=\"192.0.2.7\" port port=\"ssh\" protocol=\"tcp\" reject type=\"icmp-port-unreachable\"\nrule family=\"ipv4\" source address=\"192.0.2.8\" drop\n"
	if err := rocky.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if events := firewallEvents(t, rocky); len(events) != 0 {
		t.Fatalf("events %+v", events)
	}
}

func TestPutBackRemovesAHandAddedRule(t *testing.T) {
	executor, run := closedUfwServer(t)
	run.respond["ufw show added"] += "ufw allow 9999/tcp\n"
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	handRemoves(run, "ufw --force delete allow 9999/tcp", "allow 9999/tcp")
	if result := hostRun(t, executor, hostRequest(t, idB, "firewall", "putback", map[string]string{"rule": "allow 9999/tcp"})); !result.OK {
		t.Fatalf("put back %#v", result)
	}
	if state := executor.readFirewall(); len(state.Drift) != 0 || slices.Contains(state.Known, "allow 9999/tcp") {
		t.Fatalf("state %+v", state)
	}
	if result := hostRun(t, executor, hostRequest(t, idC, "firewall", "putback", map[string]string{"rule": "allow 22/tcp"})); result.OK {
		t.Fatalf("ssh %#v", result)
	}
}

func TestItWasMeKeepsAHandAddedRule(t *testing.T) {
	executor, run := closedUfwServer(t)
	run.respond["ufw show added"] += "ufw allow 9999/tcp\nufw allow 6000:6010/tcp\n"
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i, item := range []string{"allow 9999/tcp", "allow 6000:6010/tcp"} {
		writeRequest(t, executor.RequestDir, []string{idB, idC}[i]+".json", hostRequest(t, []string{idB, idC}[i], "server", "accept", map[string]string{"kind": "firewall", "item": item}))
	}
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, idB); !result.OK {
		t.Fatalf("accept %#v", result)
	}
	state := executor.readFirewall()
	if len(state.Drift) != 0 || len(state.Open) != 2 || state.Open[1].Key() != "9999/tcp" || !slices.Contains(state.Other, "allow 6000:6010/tcp") {
		t.Fatalf("state %+v", state)
	}
}

func TestAFirewallThatIsOnButNotClosedReportsWhatWouldBeAdopted(t *testing.T) {
	executor, run := ufwServer(t)
	run.respond["ufw status"] = "Status: active\n"
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	var inventory Inventory
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	everyone, _ := network.ParseOpening("80", "tcp", "everyone")
	if report := inventory.Security.Firewall; report == nil || report.Closed || !reflect.DeepEqual(report.Open, []network.Opening{everyone}) || !reflect.DeepEqual(report.Other, []string{"allow OpenSSH"}) {
		t.Fatalf("report %+v", inventory.Security.Firewall)
	}
	off, _ := ufwServer(t)
	if err := off.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	var quiet Inventory
	if err := readJSON(filepath.Join(off.StateDir, "inventory.json"), &quiet); err != nil || quiet.Security.Firewall != nil {
		t.Fatalf("an inactive firewall reports %+v %v", quiet.Security.Firewall, err)
	}
}

func TestAnExitNodeBehindFirewalldMasqueradesUntilItStops(t *testing.T) {
	executor, run := tailnetServer(t)
	rootFile(t, executor, "/etc/os-release", "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\n")
	rootFile(t, executor, "/proc/net/route", "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\nens3\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\n")
	run.respond["firewall-cmd --state"] = "running\n"
	run.respond["firewall-cmd --get-zone-of-interface=ens3"] = "public\n"
	run.failing["firewall-cmd --permanent --zone=public --query-masquerade"] = "no\n"
	if result := hostRun(t, executor, hostRequest(t, idA, "tailscale", "exitnode", map[string]string{"on": "1"})); !result.OK {
		t.Fatalf("on %#v", result)
	}
	if !ranInOrder(run.calls, "firewall-cmd --permanent --zone=public --add-masquerade", "firewall-cmd --reload", "tailscale set --advertise-exit-node=true") {
		t.Fatalf("calls %q", run.calls)
	}
	run.calls = nil
	if result := hostRun(t, executor, hostRequest(t, idB, "tailscale", "exitnode", map[string]string{"on": "0"})); !result.OK {
		t.Fatalf("off %#v", result)
	}
	if !ranInOrder(run.calls, "tailscale set --advertise-exit-node=false", "firewall-cmd --permanent --zone=public --remove-masquerade", "firewall-cmd --reload") {
		t.Fatalf("calls %q", run.calls)
	}
	already, run := tailnetServer(t)
	rootFile(t, already, "/etc/os-release", "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\n")
	run.respond["firewall-cmd --state"] = "running\n"
	for i, on := range []string{"1", "0"} {
		if result := hostRun(t, already, hostRequest(t, []string{idA, idB}[i], "tailscale", "exitnode", map[string]string{"on": on})); !result.OK {
			t.Fatalf("%s %#v", on, result)
		}
	}
	if slices.ContainsFunc(run.calls, func(call string) bool {
		return strings.Contains(call, "-masquerade") && !strings.Contains(call, "--query")
	}) {
		t.Fatalf("a masquerade the owner set is left alone: %q", run.calls)
	}
}

func TestTheFirewallReportStaysWithinWhatTheDashboardTakes(t *testing.T) {
	executor, _ := securityExecutor(t)
	state := closedFirewall{Closed: true, Tool: "ufw", Open: []network.Opening{}}
	state.Drift = append(state.Drift, "allow "+strings.Repeat("9", 400))
	for port := 1000; port < 1150; port++ {
		state.Drift = append(state.Drift, fmt.Sprintf("allow %d/tcp", port))
		state.Open = append(state.Open, network.Opening{Port: port, Protocol: "tcp", From: "everyone"})
	}
	for port := 2000; port < 2200; port++ {
		state.Open = append(state.Open, network.Opening{Port: port, Protocol: "tcp", From: "everyone"})
	}
	if err := writeJSON(executor.StateDir, firewallFile, state, 0o640); err != nil {
		t.Fatal(err)
	}
	report := executor.firewallReport(nil)
	if len(report.Open) != 256 || len(report.Drift) != 100 || report.Drift[0] != "allow 1000/tcp" || len(report.Other) != 0 {
		t.Fatalf("open %d drift %d first %q", len(report.Open), len(report.Drift), report.Drift[0])
	}
}

func TestAClosedFirewallFollowsSSHToANewPortAndShowsTheOldOne(t *testing.T) {
	executor, run := closedUfwServer(t)
	run.respond["sshd -T"] = "port 2222\n"
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(executor.StateDir, "host", "ssh-ports")
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the exec unit left nothing for the host unit: %v", err)
	}
	handAdds(run, "ufw allow 2222/tcp comment krynodes", "allow 2222/tcp comment 'krynodes'")
	run.calls = nil
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	mustRun(t, run, "ufw allow 2222/tcp comment krynodes")
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("the marker stays")
	}
	if state := executor.readFirewall(); !slices.Contains(state.Known, "allow 2222/tcp") {
		t.Fatalf("the new SSH rule is not Krynodes' own: %+v", state)
	}
	run.respond["sshd -T"] = "port 2223\n"
	run.calls = nil
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	os.Remove(marker)
	if events := firewallEvents(t, executor); len(events) != 0 {
		t.Fatalf("a port Krynodes opened for SSH warned: %+v", events)
	}
	state := executor.readFirewall()
	keys := []string{}
	for _, opening := range state.Open {
		keys = append(keys, opening.String())
	}
	if !reflect.DeepEqual(keys, []string{"80/tcp@everyone", "22/tcp@everyone", "2222/tcp@everyone"}) || len(state.Drift) != 0 {
		t.Fatalf("ports SSH left are not shown as open ports: %q %+v", keys, state)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "ufw --force delete") }) {
		t.Fatalf("a port was closed without the owner: %q", run.calls)
	}

	rocky, run := securityExecutor(t)
	rootFile(t, rocky, "/etc/os-release", "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\n")
	run.respond["sshd -T"] = "port 2222\n"
	run.respond["firewall-cmd --state"] = "running\n"
	run.respond["firewall-cmd --get-default-zone"] = "public\n"
	run.respond["firewall-cmd --zone=public --list-ports"] = "22/tcp\n"
	run.respond["firewall-cmd --permanent --zone=public --list-ports"] = "22/tcp\n"
	if err := writeJSON(rocky.StateDir, firewallFile, closedFirewall{Closed: true, Tool: "firewalld", Open: []network.Opening{}, Known: []string{"port:22/tcp"}}, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := rocky.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	run.calls = nil
	if err := rocky.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	mustRun(t, run, "firewall-cmd --permanent --zone=public --add-port=2222/tcp", "firewall-cmd --reload")
}
