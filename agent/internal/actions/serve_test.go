package actions

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

var onNetwork = network.Document{V: 1, Version: 1, Range: "10.88.0.0/24", Port: 51820, MTU: 1420, Blocked: []string{}, Members: []network.Member{
	{Node: peerNode, Name: "io", Address: "10.88.0.1", Port: 51820},
	{Node: testNode, Name: "vps-2", Address: "10.88.0.2", Port: 51821},
}}

func inNetwork(t *testing.T, executor Executor) {
	t.Helper()
	document := onNetwork
	if err := writeJSON(executor.StateDir, "network.json", networkRecord{Joined: true, Document: &document, Applied: network.Applied{Version: 1}}, 0o640); err != nil {
		t.Fatal(err)
	}
}

func servingKuma(t *testing.T, member bool, access string, args map[string]string) (Executor, *fakeRun, Result) {
	t.Helper()
	executor, run := stackExecutor(t)
	if member {
		inNetwork(t, executor)
	}
	kumaReady(t, executor, run, kumaService(kumaDir(executor)), nil)
	if member {
		onMember(run)
	}
	run.failing = map[string]string{
		"iptables -C DOCKER-USER -i kry0 -j KRY-SERVE":                 "",
		"iptables -C DOCKER-USER -d 10.88.0.0/24 -i krc+ -j KRY-REACH": "",
	}
	result := runRequest(t, executor, composeRequest(t, idA, "kuma", "create", func(command *Command) {
		command.Compose = kumaText
		command.Access = access
		command.Args = args
	}))
	return executor, run, result
}

func restored(t *testing.T, executor Executor) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(executor.networkDir(), "rules.v4"))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestAServedPortIsBoundOnThePrivateAddressAndStaysOnTheServer(t *testing.T) {
	executor, run, result := servingKuma(t, true, "", map[string]string{"serves": "3001/tcp=all"})
	if !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	web := krynodesConfig(t, kumaDir(executor))["services"].(map[string]any)["web"].(map[string]any)
	var hosts []string
	for _, raw := range web["ports"].([]any) {
		hosts = append(hosts, raw.(map[string]any)["host_ip"].(string))
	}
	if !slices.Equal(hosts, []string{"127.0.0.1", "10.88.0.2"}) {
		t.Fatalf("ports %#v", web["ports"])
	}
	var meta stackMeta
	if err := readJSON(filepath.Join(kumaDir(executor), "krynodes.json"), &meta); err != nil || len(meta.Serves) != 1 || !meta.Serves[0].All {
		t.Fatalf("meta %#v err %v", meta, err)
	}
}

func TestChosenServersAndPlacesAreRuledBeforeTheStackStarts(t *testing.T) {
	executor, run, result := servingKuma(t, true, "", map[string]string{"serves": "3001/tcp=" + peerNode, "reaches": "10.88.0.1:5432/tcp"})
	if !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	dir := kumaDir(executor)
	restore := "iptables-restore --noflush " + filepath.Join(executor.networkDir(), "rules.v4")
	before(t, run.calls, restore, withOwnIP+composeCall(dir, "compose.krynodes.json", "up -d"))
	before(t, run.calls, restore, "iptables -I DOCKER-USER 1 -i kry0 -j KRY-SERVE")
	bridge := bridgeName("kuma", "default")
	text := restored(t, executor)
	for _, line := range []string{
		"-A KRY-SERVE -s 10.88.0.1/32 -p tcp -m conntrack --ctorigdst 10.88.0.2/32 --ctorigdstport 3001 -j RETURN",
		"-A KRY-REACH -d 10.88.0.1/32 -i " + bridge + " -p tcp -m tcp --dport 5432 -j RETURN",
		"-A KRY-REACH -i " + bridge + " -m comment --comment kry-reach:kuma -j DROP",
	} {
		if !strings.Contains(text, line+"\n") {
			t.Fatalf("missing %q in\n%s", line, text)
		}
	}
	if !slices.Contains(run.calls, "iptables -I DOCKER-USER 1 -d 10.88.0.0/24 -i krc+ -j KRY-REACH") {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestServingAndReachingNeedTheNetworkAndAContainedStack(t *testing.T) {
	for _, attempt := range []struct {
		member bool
		access string
		args   map[string]string
		says   string
	}{
		{false, "", map[string]string{"serves": "3001/tcp=all"}, "this server is not in the private network"},
		{false, "", map[string]string{"reaches": "10.88.0.1:5432/tcp"}, "this server is not in the private network"},
		{true, "full", map[string]string{"serves": "3001/tcp=all"}, "for Contained stacks"},
		{true, "", map[string]string{"reaches": "10.88.0.2:5432/tcp"}, "is this server"},
		{true, "", map[string]string{"serves": "3001=all"}, "is not a port such as"},
	} {
		_, run, result := servingKuma(t, attempt.member, attempt.access, attempt.args)
		if result.OK || !strings.Contains(result.Output, attempt.says) {
			t.Fatalf("%+v: %#v", attempt, result)
		}
		if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasSuffix(call, " up -d") }) {
			t.Fatalf("%+v started: %q", attempt, run.calls)
		}
	}
	if _, _, result := servingKuma(t, false, "", map[string]string{"serves": "", "reaches": ""}); !result.OK {
		t.Fatalf("empty choices off the network are fine: %#v", result)
	}
}

func TestTheChainsAreRewrittenOnlyWhenTheyDiffer(t *testing.T) {
	executor, run, result := servingKuma(t, true, "", map[string]string{"reaches": "10.88.0.1:5432/tcp"})
	if !result.OK {
		t.Fatalf("result %#v", result)
	}
	bridge := bridgeName("kuma", "default")
	run.calls = nil
	run.respond["iptables -S KRY-SERVE"] = "-N KRY-SERVE\n"
	run.respond["iptables -S KRY-REACH"] = "-N KRY-REACH\n" +
		"-A KRY-REACH -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN\n" +
		"-A KRY-REACH -d 10.88.0.1/32 -i " + bridge + " -p tcp -m tcp --dport 5432 -j RETURN\n" +
		"-A KRY-REACH -i " + bridge + " -m comment --comment kry-reach:kuma -j DROP\n" +
		"-A KRY-REACH -j DROP\n"
	executor.syncRules(context.Background())
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "iptables-restore") }) {
		t.Fatalf("nothing to rewrite: %q", run.calls)
	}
	run.respond["iptables -S KRY-REACH"] = "-N KRY-REACH\n-A KRY-REACH -j DROP\n"
	executor.syncRules(context.Background())
	if !slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "iptables-restore --noflush") }) {
		t.Fatalf("a chain that drifted is rewritten: %q", run.calls)
	}
}

func TestDroppingTheRulesTakesTheChainsAndJumps(t *testing.T) {
	executor, run := stackExecutor(t)
	run.respond = map[string]string{
		"iptables -S KRY-SERVE":   "-N KRY-SERVE\n",
		"iptables -S KRY-REACH":   "-N KRY-REACH\n-A KRY-REACH -j DROP\n",
		"iptables -S DOCKER-USER": "-N DOCKER-USER\n-A DOCKER-USER -d 10.88.0.0/24 -i krc+ -j KRY-REACH\n-A DOCKER-USER -i kry0 -j KRY-SERVE\n-A DOCKER-USER -j RETURN\n",
	}
	executor.dropRules(context.Background())
	for _, call := range []string{
		"iptables -D DOCKER-USER -d 10.88.0.0/24 -i krc+ -j KRY-REACH",
		"iptables -D DOCKER-USER -i kry0 -j KRY-SERVE",
		"iptables -F KRY-SERVE", "iptables -X KRY-SERVE", "iptables -F KRY-REACH", "iptables -X KRY-REACH",
	} {
		if !slices.Contains(run.calls, call) {
			t.Fatalf("missing %q in %q", call, run.calls)
		}
	}
	before(t, run.calls, "iptables -D DOCKER-USER -i kry0 -j KRY-SERVE", "iptables -X KRY-SERVE")
	executor, run = stackExecutor(t)
	executor.dropRules(context.Background())
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, " -D ") || strings.Contains(call, " -X ") }) {
		t.Fatalf("nothing to take away: %q", run.calls)
	}
	executor.syncRules(context.Background())
	if len(run.calls) != 2 {
		t.Fatalf("off the network nothing is read: %q", run.calls)
	}
}

func TestReachChangesTheListWithoutRestartingTheStack(t *testing.T) {
	executor, run := stackExecutor(t)
	inNetwork(t, executor)
	dir, stack := ownKuma(t, executor, "contained", kumaText)
	bridged := map[string]any{"name": "kuma", "networks": map[string]any{"default": map[string]any{"driver_opts": map[string]any{"com.docker.network.bridge.name": bridgeName("kuma", "default")}}}}
	if err := writeJSON(dir, "compose.krynodes.json", bridged, 0o640); err != nil {
		t.Fatal(err)
	}
	withStacks(&executor, stack)
	result := runRequest(t, executor, composeRequest(t, idA, "kuma", "reach", func(command *Command) {
		command.Args = map[string]string{"reaches": "10.88.0.1:6379/tcp"}
	}))
	if !result.OK {
		t.Fatalf("result %#v", result)
	}
	var meta stackMeta
	if err := readJSON(filepath.Join(dir, "krynodes.json"), &meta); err != nil || !slices.Equal(meta.Reaches, []string{"10.88.0.1:6379/tcp"}) || meta.Access != "contained" {
		t.Fatalf("meta %#v err %v", meta, err)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "compose") }) {
		t.Fatalf("the stack keeps running: %q", run.calls)
	}
	if !strings.Contains(restored(t, executor), "--dport 6379 -j RETURN") {
		t.Fatal("the new place is ruled")
	}
	executor, _ = stackExecutor(t)
	inNetwork(t, executor)
	_, full := ownKuma(t, executor, "full", kumaText)
	withStacks(&executor, full)
	if result := runRequest(t, executor, composeRequest(t, idB, "kuma", "reach", func(command *Command) {
		command.Args = map[string]string{"reaches": "10.88.0.1:6379/tcp"}
	})); result.OK {
		t.Fatal("a Full access stack has no list")
	}
}

func TestReadingAStackShowsWhatItServesAndReaches(t *testing.T) {
	executor, run, result := servingKuma(t, true, "", map[string]string{"serves": "3001/tcp=all", "reaches": "10.88.0.1:5432/tcp"})
	if !result.OK {
		t.Fatalf("result %#v", result)
	}
	withStacks(&executor, Stack{Project: "kuma", Directory: kumaDir(executor), Files: []string{filepath.Join(kumaDir(executor), "compose.yaml")}})
	run.failing = map[string]string{}
	read := runRequest(t, executor, composeRequest(t, idB, "kuma", "read", nil))
	var shown composeRead
	if !read.OK || json.Unmarshal([]byte(read.Output), &shown) != nil || len(shown.Serves) != 1 || !slices.Equal(shown.Reaches, []string{"10.88.0.1:5432/tcp"}) {
		t.Fatalf("read %#v", read)
	}
}

func TestEveryMemberIsANameInsideAContainedStackAndHoldsNoAddress(t *testing.T) {
	executor, run, result := servingKuma(t, true, "", nil)
	if !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	dir := kumaDir(executor)
	web := krynodesConfig(t, dir)["services"].(map[string]any)["web"].(map[string]any)
	hosts, _ := web["extra_hosts"].([]any)
	if len(hosts) != 2 || hosts[0] != "io.kry:10.88.0.1" || hosts[1] != "vps-2.kry:10.88.0.2" {
		t.Fatalf("extra_hosts %#v", web["extra_hosts"])
	}
	withStacks(&executor, Stack{Project: "kuma", Directory: dir, Files: []string{filepath.Join(dir, "compose.krynodes.json")}})
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	var inventory Inventory
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.Network == nil || len(inventory.Network.Points) != 0 {
		t.Fatalf("Krynodes' own names point nowhere: %+v", inventory.Network)
	}
}

func TestTheInventoryReportsWhatAStackServesReachesAndBindsPrivately(t *testing.T) {
	executor, _, result := servingKuma(t, true, "", map[string]string{"serves": "3001/tcp=" + peerNode, "reaches": "10.88.0.1:5432/tcp"})
	if !result.OK {
		t.Fatalf("result %#v", result)
	}
	dir := kumaDir(executor)
	withStacks(&executor, Stack{Project: "kuma", Directory: dir, Files: []string{filepath.Join(dir, "compose.krynodes.json")}, Bindings: []reporter.Listener{
		{Address: "10.88.0.2", Port: 3001, Protocol: "tcp"}, {Address: "0.0.0.0", Port: 80, Protocol: "tcp"},
	}})
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	var inventory Inventory
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	entry := inventory.Stacks[0]
	if entry.Network == nil || !slices.Equal(entry.Network.Private, []string{"3001/tcp"}) || !slices.Equal(entry.Public, []string{"80/tcp"}) ||
		len(entry.Network.Serves) != 1 || !slices.Equal(entry.Network.Serves[0].To, []string{peerNode}) || !slices.Equal(entry.Network.Reaches, []string{"10.88.0.1:5432/tcp"}) {
		t.Fatalf("entry %+v network %+v", entry, entry.Network)
	}
	if !slices.Equal(inventory.Network.Points, []reporter.NetworkPoint{{Stack: "kuma", Target: "10.88.0.1:5432/tcp"}}) {
		t.Fatalf("points %+v", inventory.Network.Points)
	}
}
