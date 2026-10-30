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
)

const innerID = "9f2c00000000000000000000"

var inner = sharedBridgeName("apps-inner")

func sharedRecord(t *testing.T, executor Executor, kind string, pins map[string]string) {
	t.Helper()
	if err := executor.saveBridges(map[string]bridgeRecord{"apps-inner": {ID: innerID, Kind: kind, Subnet: "172.24.0.0/24", Bridge: inner, Pins: pins}}); err != nil {
		t.Fatal(err)
	}
}

func sharedPanel(t *testing.T, executor Executor, run *fakeRun, change func(map[string]any)) string {
	t.Helper()
	service := panelService(panelDir(executor))
	service["networks"] = map[string]any{"default": nil, "inner": nil}
	if change != nil {
		change(service)
	}
	dir := panelReady(t, executor, run, service, map[string]any{"networks": map[string]any{
		"default": map[string]any{"name": "panel_default"},
		"inner":   map[string]any{"name": "apps-inner", "external": true},
	}})
	run.respond["docker network inspect -f {{.Id}} apps-inner"] = innerID + "\n"
	run.respond[composeCall(dir, "compose.yaml -f "+filepath.Join(dir, hostsFile), "ps --all --format {{.Service}}\t{{.State}}\t{{.Health}}\t{{.ExitCode}}")] = "web\trunning\t\t0\n"
	return dir
}

func createPanel(t *testing.T, executor Executor, access string, args map[string]string) Result {
	t.Helper()
	return runRequest(t, executor, composeRequest(t, idA, "panel", "create", func(c *Command) {
		c.Compose, c.Access, c.Args = panelText, access, args
	}))
}

func TestAContainedStackJoinsAKrynodesContainedNetworkWithAFixedAddress(t *testing.T) {
	executor, run := bridgeExecutor(t, "1")
	sharedRecord(t, executor, "contained", nil)
	dir := sharedPanel(t, executor, run, nil)
	if result := createPanel(t, executor, "contained", map[string]string{"offers": "apps-inner/web=3001/tcp", "hostPorts": "3000/tcp"}); !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	config := krynodesConfig(t, dir)
	web := config["services"].(map[string]any)["web"].(map[string]any)
	joined := web["networks"].(map[string]any)["inner"].(map[string]any)
	if joined["ipv4_address"] != "172.24.0.2" || !reflect.DeepEqual(joined["aliases"], []any{"web.panel"}) || !reflect.DeepEqual(web["cap_drop"], []any{"NET_RAW"}) {
		t.Fatalf("web %#v", web)
	}
	if shared := config["networks"].(map[string]any)["inner"].(map[string]any); shared["driver_opts"] != nil {
		t.Fatalf("an external network keeps its own options: %#v", shared)
	}
	if !slices.Equal(bridgesOf(config), []string{bridgeName("panel", "default")}) {
		t.Fatalf("bridges %q", bridgesOf(config))
	}
	if slices.ContainsFunc(run.calls, func(call string) bool {
		return strings.Contains(call, "-i "+inner) && strings.Contains(call, "--dport")
	}) {
		t.Fatalf("a shared bridge gets no host-port rule: %q", run.calls)
	}
	if pins := executor.readBridges()["apps-inner"].Pins; pins["panel/web"] != "172.24.0.2" {
		t.Fatalf("pins %#v", pins)
	}
	if meta := executor.metaOf(dir); !slices.Equal(meta.Offers, []string{"apps-inner/web=3001/tcp"}) {
		t.Fatalf("meta %#v", meta)
	}
}

func TestAFullAccessStackJoinsAContainedNetworkAsAGuest(t *testing.T) {
	executor, run := bridgeExecutor(t, "1")
	sharedRecord(t, executor, "contained", map[string]string{"adns/dns": "172.24.0.2"})
	dir := sharedPanel(t, executor, run, nil)
	if result := createPanel(t, executor, "full", nil); !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	var override map[string]any
	if err := readJSON(filepath.Join(dir, hostsFile), &override); err != nil {
		t.Fatal(err)
	}
	web := override["services"].(map[string]any)["web"].(map[string]any)
	joined := web["networks"].(map[string]any)["inner"].(map[string]any)
	if joined["ipv4_address"] != "172.24.0.3" || !reflect.DeepEqual(joined["aliases"], []any{"web.panel"}) || !reflect.DeepEqual(web["cap_drop"], []any{"NET_RAW"}) {
		t.Fatalf("override %#v", override)
	}
	if !slices.Contains(run.calls, composeCall(dir, "compose.yaml -f "+filepath.Join(dir, hostsFile), "up -d")) {
		t.Fatalf("the guest's settings must be used: %q", run.calls)
	}
}

func TestJoiningASharedNetworkIsRefusedWhenItCannotBeKeptClosed(t *testing.T) {
	cases := []struct {
		label, access, kind, refusal string
		change                       func(map[string]any)
		missing                      bool
	}{
		{label: "full network", access: "contained", kind: "full", refusal: "A Contained stack cannot join apps-inner, a Full Access network."},
		{label: "not Krynodes'", access: "contained", refusal: "apps-inner on this server was not made by Krynodes as a Contained network. Create one under Docker Networks."},
		{label: "missing", access: "contained", missing: true, refusal: "apps-inner is not on this server. Create it under Docker Networks first."},
		{label: "copies", access: "contained", kind: "contained", change: func(s map[string]any) { s["deploy"] = map[string]any{"replicas": 2.0} }, refusal: "web runs 2 copies; a service on a Contained network runs one, so its address stays fixed."},
		{label: "guest privileged", access: "full", kind: "contained", change: func(s map[string]any) { s["privileged"] = true }, refusal: "web is privileged, so it cannot join apps-inner, a Contained network."},
		{label: "guest capability", access: "full", kind: "contained", change: func(s map[string]any) { s["cap_add"] = []any{"NET_ADMIN"} }, refusal: "web adds NET_ADMIN, so it cannot join apps-inner, a Contained network."},
		{label: "guest copies", access: "full", kind: "contained", change: func(s map[string]any) { s["scale"] = 3.0 }, refusal: "web runs 3 copies; a service on a Contained network runs one, so its address stays fixed."},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			executor, run := bridgeExecutor(t, "1")
			if c.kind != "" {
				sharedRecord(t, executor, c.kind, nil)
			}
			sharedPanel(t, executor, run, c.change)
			if c.missing {
				delete(run.respond, "docker network inspect -f {{.Id}} apps-inner")
				run.failing = map[string]string{"docker network inspect -f {{.Id}} apps-inner": "Error: No such network: apps-inner"}
			}
			result := createPanel(t, executor, c.access, nil)
			if result.OK || result.Output != "refused: "+c.refusal {
				t.Fatalf("result %#v", result)
			}
			if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasSuffix(call, " up -d") }) {
				t.Fatalf("calls %q", run.calls)
			}
		})
	}
}

func TestAStackReachesOnlyWhatAnotherStackOffers(t *testing.T) {
	executor, run := bridgeExecutor(t, "1")
	sharedRecord(t, executor, "contained", map[string]string{"db/postgres": "172.24.0.2"})
	dir := sharedPanel(t, executor, run, nil)
	peers := map[string]string{"peers": "apps-inner/postgres.db:5432/tcp"}
	if result := createPanel(t, executor, "contained", peers); result.OK || result.Output != "refused: postgres.db does not offer 5432/tcp on apps-inner." {
		t.Fatalf("result %#v", result)
	}
	writeStack(t, executor, "db", stackMeta{Access: "full", Offers: []string{"apps-inner/postgres=5432/tcp"}}, "")
	again := composeRequest(t, idB, "panel", "create", func(c *Command) { c.Compose, c.Access, c.Args = panelText, "contained", peers })
	if result := runRequest(t, executor, again); !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	if meta := executor.metaOf(dir); !slices.Equal(meta.Peers, []string{"apps-inner/postgres.db:5432/tcp"}) {
		t.Fatalf("meta %#v", meta)
	}
	if _, err := executor.choicesFrom(Command{Args: map[string]string{"peers": "apps-inner/postgres:5432/tcp"}}, "contained", stackMeta{}); err == nil || err.Error() != "apps-inner/postgres:5432/tcp is not a port of another stack written as stack/name:number/tcp" {
		t.Fatalf("err %v", err)
	}
	if _, err := executor.choicesFrom(Command{Args: map[string]string{"peers": "apps-inner/postgres.db:5432/tcp"}}, "full", stackMeta{}); err == nil {
		t.Fatal("a Full Access stack only answers on a Contained network")
	}
	if _, err := executor.choicesFrom(Command{Args: map[string]string{"offers": "apps-inner/web=70000/tcp"}}, "contained", stackMeta{}); err == nil {
		t.Fatal("a port must be one a server has")
	}
}

func TestAnOfferMustNameANetworkAndServiceTheStackHas(t *testing.T) {
	for offers, refusal := range map[string]string{
		"other-net/web=3001/tcp":  "panel does not join other-net, a Contained network on this server.",
		"apps-inner/api=3001/tcp": "api is not on apps-inner.",
	} {
		executor, run := bridgeExecutor(t, "1")
		sharedRecord(t, executor, "contained", nil)
		sharedPanel(t, executor, run, nil)
		if result := createPanel(t, executor, "contained", map[string]string{"offers": offers}); result.OK || result.Output != "refused: "+refusal {
			t.Fatalf("%s: %#v", offers, result)
		}
	}
}

func peersExecutor(t *testing.T, filter string) (Executor, *fakeRun) {
	t.Helper()
	executor, run := bridgeExecutor(t, filter)
	sharedRecord(t, executor, "contained", map[string]string{"panel/web": "172.24.0.2", "db/postgres": "172.24.0.3", "adns/dns": "172.24.0.4"})
	writeStack(t, executor, "panel", stackMeta{Access: "contained", Peers: []string{"apps-inner/postgres.db:5432/tcp", "apps-inner/dns.adns:53/udp"}}, "")
	writeStack(t, executor, "db", stackMeta{Access: "full", Offers: []string{"apps-inner/postgres=5432/tcp"}}, "")
	writeStack(t, executor, "adns", stackMeta{Access: "contained"}, "")
	run.failing = map[string]string{"iptables -C DOCKER-USER -i " + inner + " -o " + inner + " -j KRY-PEERS": ""}
	return executor, run
}

func TestPeersRulesOnAServerWithNoPrivateNetwork(t *testing.T) {
	executor, run := peersExecutor(t, "1")
	if err := executor.syncRules(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(executor.networkDir(), "peers.v4")
	text, err := os.ReadFile(path)
	want := network.PeersRestore(network.Peers([]network.PeerNetwork{{Bridge: inner, Allow: []network.PeerRule{{From: "172.24.0.2", To: "172.24.0.3", Proto: "tcp", Port: 5432}}}}))
	if err != nil || string(text) != want {
		t.Fatalf("peers %q err %v", text, err)
	}
	for _, call := range []string{"iptables-restore --noflush " + path, "iptables -I DOCKER-USER 1 -i " + inner + " -o " + inner + " -j KRY-PEERS"} {
		if !slices.Contains(run.calls, call) {
			t.Fatalf("missing %q in %q", call, run.calls)
		}
	}
	run.calls = nil
	run.respond = map[string]string{"iptables -S KRY-PEERS": "-N KRY-PEERS\n" + strings.Join(network.Peers([]network.PeerNetwork{{Bridge: inner, Allow: []network.PeerRule{{From: "172.24.0.2", To: "172.24.0.3", Proto: "tcp", Port: 5432}}}}), "\n") + "\n"}
	if err := executor.syncRules(context.Background()); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "iptables-restore") }) {
		t.Fatalf("rules already in place are not written again: %q", run.calls)
	}
}

func TestPeersFailClosedWithoutBridgeFiltering(t *testing.T) {
	executor, _ := peersExecutor(t, "0")
	if err := executor.syncRules(context.Background()); err != nil {
		t.Fatal(err)
	}
	text, _ := os.ReadFile(filepath.Join(executor.networkDir(), "peers.v4"))
	if strings.Contains(string(text), "ACCEPT\n-A KRY-PEERS -s") || strings.Contains(string(text), "--dport") {
		t.Fatalf("peers %s", text)
	}
	if events := readEvents(t, executor); len(events) != 1 || events[0].Kind != "rule" || events[0].Detail["chain"] != "KRY-PEERS" {
		t.Fatalf("events %+v", events)
	}
}

func TestGuardClosesPortsOtherStacksPublish(t *testing.T) {
	executor, run, result := reachingPanel(t, "3000/tcp")
	if !result.OK {
		t.Fatalf("result %#v", result)
	}
	bridge := bridgeName("panel", "default")
	ret := "-i " + bridge + " -p tcp -m conntrack --ctorigdstport 3000 -j RETURN"
	logged := "-m limit --limit 600/min -j LOG --log-prefix kry-reach  --log-level 6"
	stale := "-i krcdeadbeef0000 -p tcp -m conntrack --ctorigdstport 9 -j RETURN"
	jump := "-i krc+ -m conntrack --ctstate DNAT --ctdir ORIGINAL -j KRY-PORTS"
	run.calls = nil
	missing(run, "iptables -C KRY-PORTS "+ret, "iptables -C KRY-PORTS "+logged, "iptables -C KRY-PORTS -j DROP", "iptables -C DOCKER-USER "+jump)
	run.respond = map[string]string{"iptables -S KRY-PORTS": "-N KRY-PORTS\n-A KRY-PORTS " + stale + "\n-A KRY-PORTS " + ret + "\n"}
	executor.Contain(context.Background())
	order := []string{"iptables -N KRY-PORTS", "iptables -I KRY-PORTS 1 " + ret, "iptables -A KRY-PORTS " + logged, "iptables -A KRY-PORTS -j DROP", "iptables -I DOCKER-USER 1 " + jump}
	last := -1
	for _, call := range order {
		index := slices.Index(run.calls, call)
		if index < last {
			t.Fatalf("missing or out of order %q in %q", call, run.calls)
		}
		last = index
	}
	if !slices.Contains(run.calls, "iptables -D KRY-PORTS "+stale) || slices.Contains(run.calls, "iptables -D KRY-PORTS "+ret) {
		t.Fatalf("only a stale rule is deleted: %q", run.calls)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool {
		return strings.HasPrefix(call, "ip6tables") && strings.Contains(call, "KRY-PORTS")
	}) {
		t.Fatalf("KRY-PORTS is IPv4 only: %q", run.calls)
	}
}

func TestOffThePrivateNetworkAStackThatKnocksIsStopped(t *testing.T) {
	executor, run := newTrustedExecutor(t)
	knockingStack(t, executor)
	run.respond = map[string]string{
		journalCall(): knockLines(network.ReachPrefix, "krc111111111111", "172.30.0.2", 10, func(index int) string { return fmt.Sprintf("192.168.1.%d:6379", index+1) }),
		"docker ps -a --filter label=com.docker.compose.project=app --format {{.ID}}": "c1\n",
	}
	executor.watchKnocks(context.Background())
	if !slices.Contains(run.calls, "docker compose --project-name app stop") {
		t.Fatalf("calls %q", run.calls)
	}
	if events := readEvents(t, executor); len(events) != 1 || events[0].Kind != "stack" || events[0].Detail["stopped"] != "true" {
		t.Fatalf("events %+v", events)
	}
	quiet, run := newTrustedExecutor(t)
	quiet.watchKnocks(context.Background())
	if len(run.calls) != 0 {
		t.Fatalf("nothing to watch, nothing read: %q", run.calls)
	}
}

func TestRemovingAStackFreesItsAddresses(t *testing.T) {
	executor, run := bridgeExecutor(t, "1")
	sharedRecord(t, executor, "contained", nil)
	sharedPanel(t, executor, run, nil)
	if result := createPanel(t, executor, "contained", nil); !result.OK {
		t.Fatalf("result %#v", result)
	}
	dir := panelDir(executor)
	withStacks(&executor, Stack{Project: "panel", Directory: dir, Files: []string{filepath.Join(dir, "compose.krynodes.json")}})
	if result := runRequest(t, executor, composeRequest(t, idB, "panel", "remove", nil)); !result.OK {
		t.Fatalf("result %#v", result)
	}
	if record := executor.readBridges()["apps-inner"]; len(record.Pins) != 0 || !slices.Equal(record.Freed, []string{"172.24.0.2"}) {
		t.Fatalf("record %#v", record)
	}
}
