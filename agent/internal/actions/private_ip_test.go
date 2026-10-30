package actions

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const (
	withOwnIP   = "env KRY_PRIVATE_IP=10.88.0.2 "
	kry0Listed  = "ip -o -4 addr show dev kry0 up"
	privateText = "services:\n  web:\n    image: grafana/grafana:11\n    ports:\n      - \"${KRY_PRIVATE_IP}:3000:3000\"\n"
)

func onMember(run *fakeRun) {
	for call, answer := range run.respond {
		if strings.HasPrefix(call, "docker compose") {
			run.respond[withOwnIP+call] = answer
		}
	}
	run.respond[kry0Listed] = "7: kry0    inet 10.88.0.2/24 scope global kry0\\       valid_lft forever preferred_lft forever\n"
}

func bothFiles(dir, rest string) string {
	return "docker compose --project-name panel --project-directory " + dir + " -f " + filepath.Join(dir, "compose.yaml") + " -f " + filepath.Join(dir, "compose.krynodes-hosts.json") + " " + rest
}

func fullGrafana(t *testing.T, member, up bool) (Executor, *fakeRun, Result) {
	t.Helper()
	executor, run := stackExecutor(t)
	dir := panelDir(executor)
	panelReady(t, executor, run, map[string]any{"image": "grafana/grafana:11", "ports": []any{map[string]any{"host_ip": "10.88.0.2", "target": 3000, "published": "3000", "protocol": "tcp"}}}, nil)
	run.respond[bothFiles(dir, psStates)] = "web\trunning\t\t0\n"
	if member {
		inNetwork(t, executor)
		onMember(run)
	}
	if !up {
		delete(run.respond, kry0Listed)
	}
	result := runRequest(t, executor, composeRequest(t, idA, "panel", "create", func(command *Command) {
		command.Compose = privateText
		command.Access = "full"
	}))
	return executor, run, result
}

func startedAny(calls []string) bool {
	return slices.ContainsFunc(calls, func(call string) bool { return strings.HasSuffix(call, " up -d") })
}

func TestAComposeCallOnAMemberCarriesThePrivateAddress(t *testing.T) {
	executor, run, result := servingPanel(t, true, "", nil)
	if !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	dir := panelDir(executor)
	if !slices.Contains(run.calls, withOwnIP+composeCall(dir, "compose.krynodes.json", "up -d")) || slices.Contains(run.calls, composeCall(dir, "compose.krynodes.json", "up -d")) {
		t.Fatalf("calls %q", run.calls)
	}
	_, run, result = servingPanel(t, false, "", nil)
	if !result.OK || slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "env ") }) {
		t.Fatalf("off the network nothing is added: %#v %q", result, run.calls)
	}
}

func TestAFullAccessStackOnAMemberGetsTheNamesBeside(t *testing.T) {
	executor, run, result := fullGrafana(t, true, true)
	dir := panelDir(executor)
	if !result.OK || !slices.Contains(run.calls, withOwnIP+bothFiles(dir, "up -d")) {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	var hosts map[string]any
	if err := readJSON(filepath.Join(dir, "compose.krynodes-hosts.json"), &hosts); err != nil {
		t.Fatal(err)
	}
	listed := asList(asMap(asMap(hosts["services"])["web"])["extra_hosts"])
	if len(listed) != 2 || listed[0] != "server-2.kry:10.88.0.1" || listed[1] != "vps-2.kry:10.88.0.2" {
		t.Fatalf("hosts %#v", hosts)
	}
}

func TestOffTheNetworkAFileThatUsesThePrivateAddressDoesNotStart(t *testing.T) {
	executor, run, result := fullGrafana(t, false, false)
	if result.OK || !strings.Contains(result.Output, "this server is not in the private network, so KRY_PRIVATE_IP has no value") || startedAny(run.calls) {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	if _, err := os.Stat(filepath.Join(panelDir(executor), "compose.krynodes-hosts.json")); !os.IsNotExist(err) {
		t.Fatalf("no names off the network: %v", err)
	}
	executor, run = stackExecutor(t)
	_, stack := ownPanel(t, executor, "full", privateText)
	withStacks(&executor, stack)
	panelReady(t, executor, run, map[string]any{"image": "grafana/grafana:11"}, nil)
	edited := runRequest(t, executor, composeRequest(t, idB, "panel", "edit", func(command *Command) { command.Compose = privateText }))
	if edited.OK || !strings.Contains(edited.Output, "KRY_PRIVATE_IP has no value") || startedAny(run.calls) {
		t.Fatalf("an edit and its way back start nothing: %#v %q", edited, run.calls)
	}
}

func TestWithKry0DownAStackOnThePrivateAddressWaits(t *testing.T) {
	_, run, result := fullGrafana(t, true, false)
	if result.OK || !strings.Contains(result.Output, "kry0 is down on vps-2") || startedAny(run.calls) {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
}

func TestLeavingPutsAServedStackBackOnTheServerOnly(t *testing.T) {
	executor, run, result := servingPanel(t, true, "", map[string]string{"serves": "3001/tcp=all", "reaches": "10.88.0.1:5432/tcp"})
	if !result.OK {
		t.Fatalf("result %#v", result)
	}
	executor.Root = t.TempDir()
	run.calls = nil
	run.respond["iptables -S KRY-SERVE"] = "-N KRY-SERVE\n"
	left := executor.leaveNetwork(context.Background(), Request{ID: idC}, onNetwork, "", executor.readNetwork())
	if !left.OK {
		t.Fatalf("leave %#v calls %q", left, run.calls)
	}
	dir := panelDir(executor)
	web := krynodesConfig(t, dir)["services"].(map[string]any)["web"].(map[string]any)
	if ports := web["ports"].([]any); len(ports) != 1 || ports[0].(map[string]any)["host_ip"] != "127.0.0.1" {
		t.Fatalf("ports %#v", ports)
	}
	if meta := executor.metaOf(dir); len(meta.Serves) != 0 || len(meta.Reaches) != 0 || meta.Access != "contained" {
		t.Fatalf("meta %#v", meta)
	}
	if !slices.Contains(run.calls, composeCall(dir, "compose.krynodes.json", "up -d")) || !slices.Contains(run.calls, "iptables -X KRY-SERVE") {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestFullAccessContainersAreNamedAndWireGuardIsOnThePrivateAddress(t *testing.T) {
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	rootFile(t, executor, "/etc/ufw/ufw.conf", "ENABLED=no\n")
	inNetwork(t, executor)
	dir := filepath.Join(executor.StateDir, "compose", "grafana")
	if err := writeJSON(dir, "krynodes.json", stackMeta{Access: "full"}, 0o640); err != nil {
		t.Fatal(err)
	}
	run.respond[listening] += "udp UNCONN 0 0 0.0.0.0:51821 0.0.0.0:*\n"
	run.respond["docker ps --format "+portsFormat] = "grafana-grafana-1\t0.0.0.0:3000->3000/tcp\tgrafana\n"
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := publicPortsOf(t, executor); !strings.Contains(got, "3000/tcp (grafana-grafana-1)") {
		t.Fatalf("public ports %q", got)
	}
	var inventory Inventory
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(inventory.Security.Listeners, reporter.Listener{Address: "10.88.0.2", Port: 51821, Protocol: "udp", Process: "WireGuard"}) {
		t.Fatalf("listeners %+v", inventory.Security.Listeners)
	}
}

func TestTurningOnTheFirewallOnAMemberKeepsTheNetworkOpen(t *testing.T) {
	executor, run := securityExecutor(t)
	rootFile(t, executor, "/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n")
	run.respond["sshd -T"] = "port 22\n"
	ufwComesUp(run)
	document := onNetwork
	if err := executor.saveNetwork(networkRecord{Joined: true, Document: &document, Applied: network.Applied{Version: 1}, Port: 51821}); err != nil {
		t.Fatal(err)
	}
	if result := hostRun(t, executor, hostRequest(t, idA, "firewall", "apply", nil)); !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	for _, open := range []string{"ufw allow 51821/udp comment krynodes-network", "ufw allow in on kry0 comment krynodes-network"} {
		before(t, run.calls, open, "ufw --force enable")
	}
	if executor.readNetwork().Firewall != "ufw" {
		t.Fatal("leaving must know to close them")
	}
}
