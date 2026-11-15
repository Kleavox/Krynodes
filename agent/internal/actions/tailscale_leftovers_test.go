package actions

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/recipes"
)

func ufwLeftover(t *testing.T) (Executor, *fakeRun, []string) {
	t.Helper()
	executor, run := ufwServer(t)
	run.respond["ufw status"] = "Status: active\n"
	run.respond["ufw show added"] = ufwHeader + "ufw allow 22/tcp comment 'krynodes'\nufw allow 443/tcp comment 'krynodes'\nufw allow in on tailscale0 to any port 8443 proto tcp comment 'krynodes'\n"
	return executor, run, []string{"allow in on tailscale0 to any port 8443 proto tcp"}
}

func firewalldLeftover(t *testing.T) (Executor, *fakeRun, []string) {
	t.Helper()
	executor, run := securityExecutor(t)
	rootFile(t, executor, "/etc/os-release", "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\n")
	run.respond["sshd -T"] = "port 22\n"
	run.respond["firewall-cmd --state"] = "running\n"
	run.respond["firewall-cmd --get-default-zone"] = "public\n"
	rich := "rule family=\"ipv4\" source address=\"100.64.0.0/10\" port port=\"8443\" protocol=\"tcp\" accept\nrule family=\"ipv6\" source address=\"fd7a:115c:a1e0::/48\" port port=\"8443\" protocol=\"tcp\" accept\n"
	for _, permanent := range []string{"", "--permanent "} {
		run.respond["firewall-cmd "+permanent+"--zone=public --list-ports"] = "22/tcp 443/tcp\n"
		run.respond["firewall-cmd "+permanent+"--zone=public --list-rich-rules"] = rich
	}
	return executor, run, []string{
		`rich:rule family="ipv4" source address="100.64.0.0/10" port port="8443" protocol="tcp" accept`,
		`rich:rule family="ipv6" source address="fd7a:115c:a1e0::/48" port port="8443" protocol="tcp" accept`,
	}
}

func changesTheServer(call string) bool {
	for _, change := range []string{"ufw allow", "ufw delete", "ufw --force", "--add-", "--remove-", "KRY-TAILSCALE", "KRY-TAILNET", "tailscale ", "sysctl", "tables-restore", "systemctl start", "systemctl stop", "systemctl restart", "systemctl reload", "systemctl enable", "systemctl disable", "systemctl daemon-reload"} {
		if strings.Contains(call, change) {
			return true
		}
	}
	return false
}

func TestFromTailscaleOpeningsBecomeTheOwnersLines(t *testing.T) {
	for _, c := range []struct {
		tool   string
		server func(*testing.T) (Executor, *fakeRun, []string)
	}{{"ufw", ufwLeftover}, {"firewalld", firewalldLeftover}} {
		executor, run, filed := c.server(t)
		env := executor.recipeEnv()
		everyone, _ := network.ParseOpening("443", "tcp", "everyone")
		known := recipes.LiveRules(context.Background(), env).Lines
		if len(known) != 2+len(filed) {
			t.Fatalf("%s reads %q", c.tool, known)
		}
		before := closedFirewall{Closed: true, Tool: c.tool, Open: []network.Opening{{Port: 8443, Protocol: "tcp", From: "tailscale"}, everyone}, Known: known}
		if err := writeJSON(executor.StateDir, firewallFile, before, 0o640); err != nil {
			t.Fatal(err)
		}
		run.calls = nil
		if err := executor.fileTailscaleOpenings(context.Background()); err != nil {
			t.Fatal(err)
		}
		if slices.ContainsFunc(run.calls, changesTheServer) {
			t.Fatalf("%s filing ran %q", c.tool, run.calls)
		}
		state := executor.readFirewall()
		if !reflect.DeepEqual(state.Open, []network.Opening{everyone}) || !reflect.DeepEqual(state.Filed, before.Open[:1]) || !slices.Equal(state.Other, filed) || !slices.Equal(state.Known, known) {
			t.Fatalf("%s state %+v", c.tool, state)
		}
		watched := recipes.WatchRules(context.Background(), env, recipes.LiveRules(context.Background(), env), state.Known, state.Other, state.Open, "")
		if len(watched.Drift)+len(watched.Unlisted)+len(watched.Missing) != 0 {
			t.Fatalf("%s watch %+v", c.tool, watched)
		}
		if err := executor.Execute(context.Background()); err != nil {
			t.Fatal(err)
		}
		if events := firewallEvents(t, executor); len(events) != 0 {
			t.Fatalf("%s warned %+v", c.tool, events)
		}
		if after := executor.readFirewall(); !reflect.DeepEqual(after, state) {
			t.Fatalf("%s the drift check changed the record: %+v", c.tool, after)
		}
		if slices.ContainsFunc(run.calls, changesTheServer) {
			t.Fatalf("%s changed the server: %q", c.tool, run.calls)
		}
	}
}

func TestFilingTwiceFilesOnce(t *testing.T) {
	executor, _ := securityExecutor(t)
	record := filepath.Join(executor.StateDir, firewallFile)
	if err := writeWhole(executor.StateDir, firewallFile, []byte("{broken"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := executor.fileTailscaleOpenings(context.Background()); err == nil {
		t.Fatal("an unreadable record was filed")
	}
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	if err := executor.fileTailscaleOpenings(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatal("an open firewall gets a record")
	}
	before := closedFirewall{Closed: true, Tool: "ufw", Open: []network.Opening{{Port: 8443, Protocol: "tcp", From: "tailscale"}}}
	if err := writeJSON(executor.StateDir, firewallFile, before, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := executor.fileTailscaleOpenings(context.Background()); err != nil {
		t.Fatal(err)
	}
	once, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if state := executor.readFirewall(); len(state.Open) != 0 || len(state.Filed) != 1 || len(state.Other) != 1 {
		t.Fatalf("filed %+v", state)
	}
	if err := executor.fileTailscaleOpenings(context.Background()); err != nil {
		t.Fatal(err)
	}
	if twice, err := os.ReadFile(record); err != nil || string(twice) != string(once) {
		t.Fatalf("filed twice: %s %v", twice, err)
	}
}

func TestFilingWaitsForTheHostUnit(t *testing.T) {
	executor, run := securityExecutor(t)
	run.respond["systemctl is-active krynodes-host.service"] = "active\n"
	before := closedFirewall{Closed: true, Tool: "ufw", Open: []network.Opening{{Port: 8443, Protocol: "tcp", From: "tailscale"}}}
	if err := writeJSON(executor.StateDir, firewallFile, before, 0o640); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(executor.StateDir, firewallFile)
	written, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.fileTailscaleOpenings(context.Background()); err != nil {
		t.Fatal(err)
	}
	if after, err := os.ReadFile(record); err != nil || string(after) != string(written) {
		t.Fatalf("filed while the host unit runs: %s %v", after, err)
	}
	delete(run.respond, "systemctl is-active krynodes-host.service")
	if err := executor.fileTailscaleOpenings(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := executor.readFirewall(); len(state.Open) != 0 || !reflect.DeepEqual(state.Filed, before.Open) {
		t.Fatalf("not filed once the host unit is done: %+v", state)
	}
}

func TestTheDriftCheckWaitsForTheHostUnit(t *testing.T) {
	executor, run, _ := ufwLeftover(t)
	run.respond["systemctl is-active krynodes-host.service"] = "active\n"
	if err := writeJSON(executor.StateDir, firewallFile, closedFirewall{Closed: true, Tool: "ufw", Known: []string{"allow 22/tcp"}}, 0o640); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(executor.StateDir, firewallFile)
	written, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	executor.firewallDrift(context.Background())
	if after, err := os.ReadFile(record); err != nil || string(after) != string(written) {
		t.Fatalf("checked while the host unit runs: %s %v", after, err)
	}
	if events := firewallEvents(t, executor); len(events) != 0 {
		t.Fatalf("warned while the host unit runs: %+v", events)
	}
	delete(run.respond, "systemctl is-active krynodes-host.service")
	executor.firewallDrift(context.Background())
	after, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) == string(written) && len(firewallEvents(t, executor)) == 0 {
		t.Fatal("the drift check saw nothing once the host unit was done")
	}
}

func TestUninstallRemovesLeftoverTailscaleChains(t *testing.T) {
	executor, run := securityExecutor(t)
	rootFile(t, executor, "/etc/sysctl.d/99-krynodes-exit-node.conf", "net.ipv4.ip_forward = 1\n")
	for _, name := range []string{"tailnet.json", "vault-tailscale.json", "exit-node.json", "tailscale.v4"} {
		if err := writeWhole(executor.StateDir, name, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	removal := executor.Uninstall(context.Background(), false)
	for _, tool := range []string{"iptables", "ip6tables"} {
		mustRun(t, run,
			tool+" -D INPUT -j KRY-TAILSCALE", tool+" -F KRY-TAILSCALE", tool+" -X KRY-TAILSCALE",
			tool+" -D INPUT -i tailscale0 -j KRY-TAILNET", tool+" -D FORWARD -i tailscale0 -j KRY-TAILNET", tool+" -F KRY-TAILNET", tool+" -X KRY-TAILNET",
		)
	}
	if _, err := os.Stat(executor.path("/etc/sysctl.d/99-krynodes-exit-node.conf")); !os.IsNotExist(err) {
		t.Fatal("the exit node's forwarding file stays")
	}
	if _, err := os.Stat(executor.StateDir); !os.IsNotExist(err) {
		t.Fatal("the state directory stays")
	}
	if len(removal.Problems) != 0 || strings.Contains(removal.Token, "Tailscale") {
		t.Fatalf("removal %#v", removal)
	}
}

func TestTailscaleVerbsAreUnknown(t *testing.T) {
	executor, run := securityExecutor(t)
	requests := []Request{
		attached(t, hostRequest(t, fresh(1), "tailscale", "block", nil), map[string]string{"addresses": "100.101.7.10"}),
		signedRequest(t, Command{ID: fresh(10), Kind: "vault", Name: "tailscale", Action: "policy", Args: map[string]string{"client": "k1"}}),
		signedRequest(t, Command{ID: fresh(11), Kind: "vault", Name: "tailscale", Action: "store", Args: map[string]string{"set": "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a01", "holders": "1"}}),
		aptRequest(t, fresh(12), "tailscale", "signin", nil),
	}
	for index, action := range []string{"unblock", "inspect", "signin", "join", "exitnode", "dns"} {
		requests = append(requests, hostRequest(t, fresh(2+index), "tailscale", action, map[string]string{"on": "1"}))
	}
	for _, request := range requests {
		writeRequest(t, executor.RequestDir, request.ID+".json", request)
	}
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, request := range requests {
		if result := readResult(t, executor, request.ID); result.OK || result.Output != `refused: unknown action "`+request.Action+`"` {
			t.Fatalf("%s %s %s: %+v", request.Kind, request.Name, request.Action, result)
		}
	}
	if slices.ContainsFunc(run.calls, changesTheServer) {
		t.Fatalf("calls %q", run.calls)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "vault.json")); !os.IsNotExist(err) {
		t.Fatal("a Tailscale piece was stored")
	}
}
