package recipes

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

const ufwAdded = "Added user rules (see 'ufw status' for running firewall):\n" +
	"ufw allow 22/tcp comment 'krynodes'\n" +
	"ufw allow 51821/udp comment 'krynodes-network'\n" +
	"ufw allow in on kry0 comment 'krynodes-network'\n" +
	"ufw allow 80\n" +
	"ufw allow from 203.0.113.0/24 to any port 9000 proto tcp\n" +
	"ufw allow OpenSSH\n" +
	"ufw deny 25/tcp\n"

func closedUfw(t *testing.T, active bool) (Env, *fakeRun) {
	t.Helper()
	env, run := newEnv(t)
	run.respond["sshd -T"] = "port 22\n"
	run.respond["ufw show added"] = ufwAdded
	status := "Status: inactive\n"
	if active {
		status = "Status: active\n\nTo Action From\n22/tcp ALLOW Anywhere # krynodes\n"
	}
	run.respond["ufw status"] = status
	run.effects["ufw --force enable"] = func() {
		run.respond["ufw status"] = "Status: active\n\nTo Action From\n22/tcp ALLOW Anywhere # krynodes\n"
	}
	write(t, env, "/etc/ufw/user.rules", "*filter\n### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in\nCOMMIT\n")
	write(t, env, "/etc/default/ufw", "DEFAULT_INPUT_POLICY=\"ACCEPT\"\n")
	return env, run
}

func TestTheRulesOfAFirewallAreReadAsOpenPortsAndKeptLines(t *testing.T) {
	env, run := closedUfw(t, true)
	rules := ReadRules(context.Background(), env)
	if rules.Tool != "ufw" || !rules.Active || !slices.Contains(rules.Lines, "allow 80") || slices.Contains(rules.Lines, "allow 22/tcp comment 'krynodes'") {
		t.Fatalf("rules %+v", rules)
	}
	adopted := Adopt(context.Background(), env, rules, "51821")
	want := []network.Opening{
		{Port: 80, Protocol: "tcp", From: "everyone"},
		{Port: 80, Protocol: "udp", From: "everyone"},
		{Port: 9000, Protocol: "tcp", From: "addresses", Addresses: []string{"203.0.113.0/24"}},
	}
	if !reflect.DeepEqual(adopted.Open, want) || !reflect.DeepEqual(adopted.Other, []string{"allow OpenSSH"}) {
		t.Fatalf("adopted %+v", adopted)
	}
	run.respond["ufw version"] = ""
	run.failing["ufw version"] = true
	if rules := ReadRules(context.Background(), env); rules.Tool != "" {
		t.Fatalf("no ufw %+v", rules)
	}
}

func TestAClosedFirewallKeepsOnlySSHThePrivateNetworkAndTheChosenPorts(t *testing.T) {
	env, run := closedUfw(t, false)
	saved, err := Apply(context.Background(), env, "firewall", map[string]string{"closed": "1", "ports": "80/tcp@everyone,8443/tcp@tailscale", NetworkPort: "51821"})
	if err != nil {
		t.Fatal(err)
	}
	mustCall(t, run,
		"ufw allow in on tailscale0 to any port 8443 proto tcp comment krynodes",
		"ufw --force delete allow 80",
		"ufw allow 80/tcp comment krynodes",
		"ufw --force delete allow from 203.0.113.0/24 to any port 9000 proto tcp",
		"ufw default deny incoming",
		"ufw --force enable",
	)
	for _, kept := range []string{"ufw --force delete allow OpenSSH", "ufw --force delete allow 22/tcp", "ufw --force delete deny 25/tcp", "ufw --force delete allow in on kry0", "ufw allow 22/tcp comment krynodes"} {
		if slices.Contains(run.calls, kept) {
			t.Fatalf("%q must stay: %q", kept, run.calls)
		}
	}
	if slices.Index(run.calls, "ufw allow 80/tcp comment krynodes") > slices.Index(run.calls, "ufw --force delete allow 80") {
		t.Fatal("a port closed between its old rule and its new one")
	}
	if saved["closed"] != "1" || saved["wasActive"] != "false" || !strings.Contains(saved["file:/etc/ufw/user.rules"], "tuple") || saved["gone:/etc/ufw/user6.rules"] != "1" {
		t.Fatalf("saved %v", saved)
	}
	write(t, env, "/etc/ufw/user.rules", "changed")
	write(t, env, "/etc/ufw/user6.rules", "changed")
	write(t, env, "/etc/default/ufw", "DEFAULT_INPUT_POLICY=\"DROP\"\n")
	run.calls = nil
	if err := Undo(context.Background(), env, "firewall", saved); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(env, "/etc/ufw/user.rules"), "tuple") || exists(env, "/etc/ufw/user6.rules") || !strings.Contains(read(env, "/etc/default/ufw"), "ACCEPT") || !slices.Contains(run.calls, "ufw --force disable") {
		t.Fatalf("undo calls %q", run.calls)
	}
}

func TestAClosedFirewallThatWasOnIsReloadedOnUndo(t *testing.T) {
	env, run := closedUfw(t, true)
	saved, err := Apply(context.Background(), env, "firewall", map[string]string{"closed": "1"})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(run.calls, "ufw --force enable") {
		t.Fatalf("an active firewall is not enabled again: %q", run.calls)
	}
	run.calls = nil
	if err := Undo(context.Background(), env, "firewall", saved); err != nil || !slices.Contains(run.calls, "ufw reload") || slices.Contains(run.calls, "ufw --force disable") {
		t.Fatalf("undo %v calls %q", err, run.calls)
	}
}

func TestAClosedFirewallWithoutSSHIsTurnedBackOff(t *testing.T) {
	env, run := closedUfw(t, false)
	run.effects["ufw --force enable"] = func() { run.respond["ufw status"] = "Status: active\n" }
	if _, err := Apply(context.Background(), env, "firewall", map[string]string{"closed": "1"}); err == nil || !strings.HasPrefix(err.Error(), "The firewall came up without SSH allowed") {
		t.Fatalf("err %v", err)
	}
	if !slices.Contains(run.calls, "ufw --force disable") {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestBrokenPortsAreRefusedBeforeAnythingChanges(t *testing.T) {
	env, run := closedUfw(t, false)
	if _, err := Apply(context.Background(), env, "firewall", map[string]string{"closed": "1", "ports": "80/tcp@everyone;rm"}); err == nil || len(run.calls) != 0 {
		t.Fatalf("err %v calls %q", err, run.calls)
	}
}

func closedFirewalld(t *testing.T) (Env, *fakeRun) {
	t.Helper()
	env, run := onRelease(t, "rocky")
	write(t, env, "/proc/net/route", "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\nens3\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\n")
	run.respond["firewall-cmd --state"] = "running\n"
	run.respond["sshd -T"] = "port 2222\n"
	run.respond["firewall-cmd --get-zone-of-interface=ens3"] = "public\n"
	run.respond["firewall-cmd --permanent --zone=public --list-ports"] = "2222/tcp 51821/udp 3000/tcp 6000-6010/tcp\n"
	run.respond["firewall-cmd --permanent --zone=public --list-services"] = "cockpit dhcpv6-client ssh\n"
	run.respond["firewall-cmd --permanent --zone=public --list-rich-rules"] = "rule family=\"ipv4\" source address=\"100.64.0.0/10\" port port=\"8443\" protocol=\"tcp\" accept\nrule family=\"ipv4\" source address=\"192.0.2.0/24\" drop\n"
	run.respond["firewall-cmd --info-service=cockpit"] = "cockpit\n  ports: 9090/tcp\n  protocols: \n"
	write(t, env, "/etc/firewalld/zones/public.xml", "<zone/>\n")
	return env, run
}

func TestFirewalldClosesInTheZoneOfTheDefaultRoute(t *testing.T) {
	env, run := closedFirewalld(t)
	adopted := Adopt(context.Background(), env, ReadRules(context.Background(), env), "51821")
	if got := fmtOpenings(adopted.Open); got != "3000/tcp@everyone,9090/tcp@everyone,8443/tcp@tailscale" || !reflect.DeepEqual(adopted.Other, []string{"port:6000-6010/tcp"}) {
		t.Fatalf("adopted %s %q", got, adopted.Other)
	}
	saved, err := Apply(context.Background(), env, "firewall", map[string]string{"closed": "1", "ports": "9090/tcp@everyone,443/tcp@203.0.113.0/24", NetworkPort: "51821"})
	if err != nil {
		t.Fatal(err)
	}
	mustCall(t, run,
		"firewall-cmd --permanent --zone=public --add-port=9090/tcp",
		`firewall-cmd --permanent --zone=public --add-rich-rule=rule family="ipv4" source address="203.0.113.0/24" port port="443" protocol="tcp" accept`,
		"firewall-cmd --permanent --zone=public --remove-service=cockpit",
		"firewall-cmd --permanent --zone=public --remove-port=3000/tcp",
		`firewall-cmd --permanent --zone=public --remove-rich-rule=rule family="ipv4" source address="100.64.0.0/10" port port="8443" protocol="tcp" accept`,
		"firewall-cmd --reload",
	)
	for _, kept := range []string{"--remove-service=ssh", "--remove-service=dhcpv6-client", "--remove-port=2222/tcp", "--remove-port=51821/udp", "--remove-port=6000-6010/tcp", "drop"} {
		if slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "--remove") && strings.Contains(call, kept) }) {
			t.Fatalf("%q must stay: %q", kept, run.calls)
		}
	}
	if saved["zone"] != "public" || saved["file:/etc/firewalld/zones/public.xml"] != "<zone/>\n" || saved["wasRunning"] != "true" {
		t.Fatalf("saved %v", saved)
	}
	write(t, env, "/etc/firewalld/zones/public.xml", "<zone>changed</zone>\n")
	run.calls = nil
	if err := Undo(context.Background(), env, "firewall", saved); err != nil || read(env, "/etc/firewalld/zones/public.xml") != "<zone/>\n" || !slices.Contains(run.calls, "firewall-cmd --reload") {
		t.Fatalf("undo %v calls %q", err, run.calls)
	}
}

func TestOneOpenPortChangesAlone(t *testing.T) {
	env, run := closedUfw(t, true)
	before, _ := network.ParseOpening("8443", "tcp", "everyone")
	after, _ := network.ParseOpening("8443", "tcp", "tailscale")
	if err := OpenPort(context.Background(), env, &before, after, "51821"); err != nil {
		t.Fatal(err)
	}
	add, remove := slices.Index(run.calls, "ufw allow in on tailscale0 to any port 8443 proto tcp comment krynodes"), slices.Index(run.calls, "ufw --force delete allow 8443/tcp")
	if add < 0 || remove < add {
		t.Fatalf("calls %q", run.calls)
	}
	run.calls = nil
	if err := ClosePort(context.Background(), env, after, "51821"); err != nil || !slices.Contains(run.calls, "ufw --force delete allow in on tailscale0 to any port 8443 proto tcp") || slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "ufw allow") }) {
		t.Fatalf("close %v calls %q", err, run.calls)
	}
	ssh, _ := network.ParseOpening("22", "tcp", "tailscale")
	private, _ := network.ParseOpening("51821", "udp", "tailscale")
	for _, kept := range []network.Opening{ssh, private} {
		run.calls = nil
		if OpenPort(context.Background(), env, nil, kept, "51821") == nil || ClosePort(context.Background(), env, kept, "51821") == nil || slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "ufw ") }) {
			t.Fatalf("%s must stay open to everyone: %q", kept, run.calls)
		}
	}
	run.calls = nil
	if err := RemoveRule(context.Background(), env, "allow 80", "51821"); err != nil || !slices.Contains(run.calls, "ufw --force delete allow 80") {
		t.Fatalf("remove %v calls %q", err, run.calls)
	}
	for _, refused := range []string{"allow 22/tcp", "allow in on kry0", "allow 7000/tcp"} {
		if err := RemoveRule(context.Background(), env, refused, "51821"); err == nil {
			t.Fatalf("%q must be refused", refused)
		}
	}
}

func TestDriftOnFirewalldReadsTheRunningRules(t *testing.T) {
	env, run := closedFirewalld(t)
	run.respond["firewall-cmd --zone=public --list-ports"] = "2222/tcp 4444/tcp\n"
	live := LiveRules(context.Background(), env)
	if !slices.Contains(live.Lines, "port:4444/tcp") || slices.Contains(live.Lines, "port:3000/tcp") {
		t.Fatalf("live %q", live.Lines)
	}
	run.calls = nil
	if err := RemoveRule(context.Background(), env, "port:4444/tcp", "51821"); err != nil || !slices.Equal(run.calls[len(run.calls)-1:], []string{"firewall-cmd --reload"}) || slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "--remove-port") }) {
		t.Fatalf("a rule only in the running firewall goes with a reload: %v %q", err, run.calls)
	}
}

func TestOnlyACanonicalLineIsAnOpenPort(t *testing.T) {
	for line, want := range map[string]string{
		"allow 9999/tcp": "9999/tcp@everyone",
		"allow in on tailscale0 to any port 8443 proto tcp":  "8443/tcp@tailscale",
		"allow from 203.0.113.0/24 to any port 53 proto udp": "53/udp@203.0.113.0/24",
		"allow 80":            "",
		"allow 6000:6010/tcp": "",
		"allow OpenSSH":       "",
	} {
		opening, ok := OpeningOf("ufw", line)
		if (want == "") == ok || ok && opening.String() != want {
			t.Fatalf("%q: %v %s", line, ok, opening)
		}
	}
	if _, ok := OpeningOf("firewalld", `rich:rule family="ipv4" source address="100.64.0.0/10" port port="8443" protocol="tcp" accept`); ok {
		t.Fatal("half of a Tailscale row is not a row")
	}
	if opening, ok := OpeningOf("firewalld", "port:3000/tcp"); !ok || opening.String() != "3000/tcp@everyone" {
		t.Fatalf("port %v %s", ok, opening)
	}
}

func fmtOpenings(openings []network.Opening) string {
	texts := []string{}
	for _, opening := range openings {
		texts = append(texts, opening.String())
	}
	return strings.Join(texts, ",")
}
