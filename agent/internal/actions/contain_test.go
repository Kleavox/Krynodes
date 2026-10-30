package actions

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	replies   = " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
	jump      = " -i krc+ -j KRY-CONTAINED"
	oldDrop   = " -i krc+ -j DROP"
	chainDrop = " -j DROP"
)

func containedServer(t *testing.T) (Executor, *fakeRun) {
	t.Helper()
	executor, run := stackExecutor(t)
	panelReady(t, executor, run, panelService(panelDir(executor)), nil)
	if result := runRequest(t, executor, createRequest(t, idA, "panel", panelText)); !result.OK {
		t.Fatalf("result %#v", result)
	}
	run.calls = nil
	return executor, run
}

func missing(run *fakeRun, calls ...string) {
	run.failing = map[string]string{}
	for _, call := range calls {
		run.failing[call] = ""
	}
}

func TestContainedStacksGetRepliesFromTheServerButCannotReachIt(t *testing.T) {
	executor, run := containedServer(t)
	var absent []string
	for _, tool := range []string{"iptables", "ip6tables"} {
		absent = append(absent,
			tool+" -C KRY-CONTAINED"+chainDrop,
			tool+" -C KRY-CONTAINED"+replies,
			tool+" -C INPUT"+jump,
			tool+" -C INPUT"+oldDrop,
		)
	}
	missing(run, absent...)
	executor.Contain(context.Background())
	for _, tool := range []string{"iptables", "ip6tables"} {
		create := slices.Index(run.calls, tool+" -N KRY-CONTAINED")
		drop := slices.Index(run.calls, tool+" -A KRY-CONTAINED"+chainDrop)
		accept := slices.Index(run.calls, tool+" -I KRY-CONTAINED 1"+replies)
		enter := slices.Index(run.calls, tool+" -I INPUT 1"+jump)
		if create < 0 || drop < create || accept < create || enter < drop || enter < accept {
			t.Fatalf("%s: the chain must hold its rules before INPUT jumps to it: %q", tool, run.calls)
		}
		if slices.Contains(run.calls, tool+" -D INPUT"+oldDrop) {
			t.Fatalf("%s: there was no old rule to remove: %q", tool, run.calls)
		}
	}
}

func TestTheOldDropRuleGoesOnlyAfterTheChainIsInPlace(t *testing.T) {
	executor, run := containedServer(t)
	missing(run,
		"iptables -C KRY-CONTAINED"+chainDrop, "iptables -C KRY-CONTAINED"+replies, "iptables -C INPUT"+jump,
		"ip6tables -C KRY-CONTAINED"+chainDrop, "ip6tables -C KRY-CONTAINED"+replies, "ip6tables -C INPUT"+jump,
	)
	executor.Contain(context.Background())
	for _, tool := range []string{"iptables", "ip6tables"} {
		enter := slices.Index(run.calls, tool+" -I INPUT 1"+jump)
		gone := slices.Index(run.calls, tool+" -D INPUT"+oldDrop)
		if enter < 0 || gone < enter {
			t.Fatalf("%s: the old drop is removed after the jump: %q", tool, run.calls)
		}
	}
}

func portRule(tool, verb, bridge, protocol, port string) string {
	return tool + " " + verb + " -i " + bridge + " -p " + protocol + " -m " + protocol + " --dport " + port + " -j ACCEPT"
}

func reachingPanel(t *testing.T, ports string) (Executor, *fakeRun, Result) {
	t.Helper()
	executor, run := stackExecutor(t)
	panelReady(t, executor, run, panelService(panelDir(executor)), nil)
	bridge := bridgeName("panel", "default")
	run.failing = map[string]string{}
	for _, tool := range []string{"iptables", "ip6tables"} {
		run.failing[portRule(tool, "-C KRY-CONTAINED", bridge, "tcp", "3000")] = ""
		run.failing[portRule(tool, "-C KRY-CONTAINED", bridge, "udp", "53")] = ""
	}
	result := runRequest(t, executor, composeRequest(t, idA, "panel", "create", func(command *Command) {
		command.Compose = panelText
		command.Args = map[string]string{"hostPorts": ports}
	}))
	return executor, run, result
}

func TestAContainedStackReachesTheServerOnlyOnTheChosenPorts(t *testing.T) {
	executor, run, result := reachingPanel(t, " 3000/tcp, 53/udp,3000/tcp ")
	if !result.OK {
		t.Fatalf("result %#v", result)
	}
	var meta stackMeta
	if err := readJSON(filepath.Join(panelDir(executor), "krynodes.json"), &meta); err != nil || !slices.Equal(meta.HostPorts, []string{"3000/tcp", "53/udp"}) {
		t.Fatalf("meta %#v err %v", meta, err)
	}
	bridge := bridgeName("panel", "default")
	for _, tool := range []string{"iptables", "ip6tables"} {
		for _, rule := range []string{portRule(tool, "-I KRY-CONTAINED 1", bridge, "tcp", "3000"), portRule(tool, "-I KRY-CONTAINED 1", bridge, "udp", "53")} {
			if !slices.Contains(run.calls, rule) {
				t.Fatalf("missing %q in %q", rule, run.calls)
			}
		}
	}
}

func TestTheReachIsInPlaceBeforeTheStackStarts(t *testing.T) {
	executor, run, result := reachingPanel(t, "3000/tcp")
	if !result.OK {
		t.Fatalf("result %#v", result)
	}
	allow := slices.Index(run.calls, portRule("iptables", "-I KRY-CONTAINED 1", bridgeName("panel", "default"), "tcp", "3000"))
	enter := slices.Index(run.calls, "iptables -I INPUT 1 -i krc+ -j KRY-CONTAINED")
	up := slices.Index(run.calls, composeCall(panelDir(executor), "compose.krynodes.json", "up -d"))
	if allow < 0 || up < 0 || allow > up {
		t.Fatalf("an app that calls the server as it starts must find the port open: %q", run.calls)
	}
	if enter >= 0 && enter > up {
		t.Fatalf("the chain is entered before the stack starts: %q", run.calls)
	}
}

func TestOnlyRealPortsOfAContainedStackMayBeReached(t *testing.T) {
	var many []string
	for port := 1; port <= 17; port++ {
		many = append(many, strconv.Itoa(port)+"/tcp")
	}
	for _, ports := range []string{"70000/tcp", "0/tcp", "3000/sctp", "3000", "tcp/3000", strings.Join(many, ",")} {
		if _, _, result := reachingPanel(t, ports); result.OK {
			t.Fatalf("%q was taken", ports)
		}
	}
	executor, run := stackExecutor(t)
	panelReady(t, executor, run, panelService(panelDir(executor)), nil)
	result := runRequest(t, executor, composeRequest(t, idA, "panel", "create", func(command *Command) {
		command.Compose = panelText
		command.Access = "full"
		command.Args = map[string]string{"hostPorts": "3000/tcp"}
	}))
	if result.OK || !strings.Contains(result.Output, "Contained") {
		t.Fatalf("a Full access stack already reaches the server: %#v", result)
	}
}

func TestReadingAStackShowsTheChosenPorts(t *testing.T) {
	executor, run, result := reachingPanel(t, "3000/tcp")
	if !result.OK {
		t.Fatalf("result %#v", result)
	}
	withStacks(&executor, Stack{Project: "panel", Directory: panelDir(executor), Files: []string{filepath.Join(panelDir(executor), "compose.yaml")}})
	run.failing = map[string]string{}
	read := runRequest(t, executor, composeRequest(t, idB, "panel", "read", nil))
	var shown composeRead
	if !read.OK || json.Unmarshal([]byte(read.Output), &shown) != nil || !slices.Equal(shown.HostPorts, []string{"3000/tcp"}) {
		t.Fatalf("read %#v", read)
	}
}

func TestTheReachKeepsOrClearsOnEdit(t *testing.T) {
	kept, err := hostPortsFrom(Command{}, "contained", []string{"3000/tcp"})
	if err != nil || !slices.Equal(kept, []string{"3000/tcp"}) {
		t.Fatalf("kept %v err %v", kept, err)
	}
	cleared, err := hostPortsFrom(Command{Args: map[string]string{"hostPorts": ""}}, "contained", []string{"3000/tcp"})
	if err != nil || len(cleared) != 0 {
		t.Fatalf("cleared %v err %v", cleared, err)
	}
	if moved, err := hostPortsFrom(Command{Access: "full"}, "full", []string{"3000/tcp"}); err != nil || len(moved) != 0 {
		t.Fatalf("a stack that becomes Full access drops its reach: %v %v", moved, err)
	}
}

func TestAPortTheStackNoLongerNeedsIsClosed(t *testing.T) {
	executor, run, result := reachingPanel(t, "3000/tcp")
	if !result.OK {
		t.Fatalf("result %#v", result)
	}
	bridge := bridgeName("panel", "default")
	run.calls = nil
	run.failing = map[string]string{}
	listed := "-N KRY-CONTAINED\n" +
		"-A KRY-CONTAINED -i " + bridge + " -p tcp -m tcp --dport 8080 -j ACCEPT\n" +
		"-A KRY-CONTAINED -i " + bridge + " -p tcp -m tcp --dport 3000 -j ACCEPT\n" +
		"-A KRY-CONTAINED -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n" +
		"-A KRY-CONTAINED -i krc0123456789ab -p udp -m udp --dport 53 -j ACCEPT\n" +
		"-A KRY-CONTAINED -j DROP\n"
	run.respond["iptables -S KRY-CONTAINED"] = listed
	run.respond["ip6tables -S KRY-CONTAINED"] = listed
	executor.Contain(context.Background())
	for _, tool := range []string{"iptables", "ip6tables"} {
		for _, gone := range []string{portRule(tool, "-D KRY-CONTAINED", bridge, "tcp", "8080"), portRule(tool, "-D KRY-CONTAINED", "krc0123456789ab", "udp", "53")} {
			if !slices.Contains(run.calls, gone) {
				t.Fatalf("missing %q in %q", gone, run.calls)
			}
		}
		for _, kept := range []string{portRule(tool, "-D KRY-CONTAINED", bridge, "tcp", "3000"), tool + " -D KRY-CONTAINED" + replies, tool + " -D KRY-CONTAINED" + chainDrop} {
			if slices.Contains(run.calls, kept) {
				t.Fatalf("%q must stay: %q", kept, run.calls)
			}
		}
	}
}

func TestAContainmentInPlaceIsLeftAlone(t *testing.T) {
	executor, run := containedServer(t)
	missing(run, "iptables -C INPUT"+oldDrop, "ip6tables -C INPUT"+oldDrop)
	executor.Contain(context.Background())
	for _, call := range run.calls {
		for _, verb := range []string{" -A ", " -I ", " -D "} {
			if strings.Contains(call, verb) {
				t.Fatalf("nothing changes when every rule is there: %q", run.calls)
			}
		}
	}
}
