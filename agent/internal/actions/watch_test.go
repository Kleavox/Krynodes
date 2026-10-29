package actions

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/watch"
)

const (
	watchOwnerKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINgR/LmOeWesWGV4gX2RBfBT5TKbBcKMCk+GVyMOWScy budi@laptop"
	watchOtherKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDVFg4Wx2NViu9ZffqPwSTCUsSzH60Im/4s1noczsx+q evil"
	nginxListener = "tcp LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:((\"nginx\",pid=812,fd=6))\n"
)

func sshJournal() string {
	return fmt.Sprintf("journalctl -t sshd -t sshd-session --since=@%d -o short-unix --no-pager -q", executorNow.Add(-network.KnockWindow).Unix())
}

func watchedServer(t *testing.T) (Executor, *fakeRun) {
	t.Helper()
	executor, run := securityExecutor(t)
	rootFile(t, executor, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nbudi:x:1000:1000::/home/budi:/bin/bash\n")
	rootFile(t, executor, "/etc/group", "sudo:x:27:budi\n")
	rootFile(t, executor, "/etc/sudoers", "root ALL=(ALL:ALL) ALL\n")
	rootFile(t, executor, "/root/.ssh/authorized_keys", watchOwnerKey+"\n")
	run.respond["ss -H -tulnp"] = nginxListener + "udp UNCONN 0 0 100.101.7.10:41641 0.0.0.0:* users:((\"tailscaled\",pid=90,fd=3))\n"
	return executor, run
}

func eventKinds(t *testing.T, executor Executor) []string {
	t.Helper()
	var kinds []string
	for _, event := range readEvents(t, executor) {
		kinds = append(kinds, event.Kind)
	}
	return kinds
}

func TestTheFirstRunTakesTheStartingPointAndOnlyNewThingsWarn(t *testing.T) {
	executor, run := watchedServer(t)
	executor.watchServer(context.Background())
	start, err := readState[watch.State](executor.StateDir, watchFile)
	if err != nil || !slices.Equal(start.Ports, []string{"8080/tcp nginx"}) || len(start.Keys) != 1 {
		t.Fatalf("start %+v %v", start, err)
	}
	if events := readEvents(t, executor); len(events) != 0 {
		t.Fatalf("the starting point warned: %+v", events)
	}
	rootFile(t, executor, "/root/.ssh/authorized_keys", watchOwnerKey+"\n"+watchOtherKey+"\n")
	run.respond["ss -H -tulnp"] = nginxListener + "tcp LISTEN 0 5 [::]:4444 [::]:* users:((\"nc\",pid=666,fd=3))\n"
	for range 2 {
		executor.watchServer(context.Background())
	}
	if kinds := eventKinds(t, executor); !slices.Equal(kinds, []string{"ssh-key", "port"}) {
		t.Fatalf("events %v", kinds)
	}
	if event := readEvents(t, executor)[0]; event.Detail["user"] != "root" || !strings.HasPrefix(event.Detail["item"], "root:/root/.ssh/authorized_keys:SHA256:") {
		t.Fatalf("event %+v", event)
	}
}

func TestAnUnknownKeySigningInAsRootWarns(t *testing.T) {
	executor, run := watchedServer(t)
	executor.watchServer(context.Background())
	run.respond[sshJournal()] = fmt.Sprintf("%d.000000 vps-1 sshd[902]: Accepted publickey for root from 203.0.113.9 port 51515 ssh2: ED25519 SHA256:1s+YW4SIoq6rDRmD1o/df0ZH56AiCmAMwmKR+Drp/v4\n", executorNow.Unix()-5)
	executor.watchServer(context.Background())
	events := readEvents(t, executor)
	if len(events) != 1 || events[0].Kind != "ssh-login" || events[0].Detail["from"] != "203.0.113.9" {
		t.Fatalf("events %+v", events)
	}
}

func TestItWasMeAcceptsTheItemAndTheNextNewKeyStillWarns(t *testing.T) {
	executor, _ := watchedServer(t)
	executor.watchServer(context.Background())
	rootFile(t, executor, "/root/.ssh/authorized_keys", watchOwnerKey+"\n"+watchOtherKey+"\n")
	executor.watchServer(context.Background())
	item := readEvents(t, executor)[0].Detail["item"]
	unsigned := hostRequest(t, idA, "server", "accept", map[string]string{"kind": "ssh-key", "item": item})
	unsigned.Signed = nil
	if result := runRequest(t, executor, unsigned); result.OK {
		t.Fatalf("accepted unsigned: %+v", result)
	}
	if result := runRequest(t, executor, hostRequest(t, idB, "server", "accept", map[string]string{"kind": "ssh-key", "item": item})); !result.OK {
		t.Fatalf("accept: %+v", result)
	}
	os.Remove(filepath.Join(executor.StateDir, eventsFile))
	executor.watchServer(context.Background())
	if events := readEvents(t, executor); len(events) != 0 {
		t.Fatalf("still warns: %+v", events)
	}
	rootFile(t, executor, "/home/budi/.ssh/authorized_keys", watchOtherKey+"\n")
	executor.watchServer(context.Background())
	if events := readEvents(t, executor); len(events) != 1 || events[0].Detail["user"] != "budi" {
		t.Fatalf("the next key: %+v", events)
	}
	if result := runRequest(t, executor, hostRequest(t, "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a03", "server", "accept", map[string]string{"kind": "rule", "item": "x"})); result.OK {
		t.Fatalf("accepted a rule: %+v", result)
	}
}

func TestAJoinKeepsTheStartingPoint(t *testing.T) {
	executor, run := networkExecutor(t)
	rootFile(t, executor, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
	rootFile(t, executor, "/etc/group", "sudo:x:27:\n")
	run.respond["ss -H -tulnp"] = nginxListener
	if err := writeJSON(executor.StateDir, watchFile, watch.State{Users: []string{"old"}}, 0o640); err != nil {
		t.Fatal(err)
	}
	keys := prepared(t, executor)
	peer, _ := peerKeys(t)
	if result := hostRun(t, executor, applyDocument(t, idB, twoMembers(t, executor, 1, keys, peer))); !result.OK {
		t.Fatalf("join: %+v", result)
	}
	start, _ := readState[watch.State](executor.StateDir, watchFile)
	if !slices.Equal(start.Users, []string{"old"}) || len(start.Ports) != 0 {
		t.Fatalf("a join took what it found as the starting point: %+v", start)
	}
}

func TestWireGuardOnThePreparedPortIsNotANewPortWhileItJoins(t *testing.T) {
	executor, run := networkExecutor(t)
	rootFile(t, executor, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
	rootFile(t, executor, "/etc/group", "sudo:x:27:\n")
	prepared(t, executor)
	kernel := func(port int) string { return fmt.Sprintf("udp UNCONN 0 0 0.0.0.0:%d 0.0.0.0:*\n", port) }
	run.respond["ss -H -tulnp"] = nginxListener + kernel(51821)
	if now, _ := executor.watchNow(context.Background()); !slices.Equal(now.Ports, []string{"8080/tcp nginx"}) {
		t.Fatalf("WireGuard on the prepared port %q", now.Ports)
	}
	run.respond["ss -H -tulnp"] = nginxListener + kernel(51822)
	if now, _ := executor.watchNow(context.Background()); !slices.Equal(now.Ports, []string{"32768-60999/udp", "8080/tcp nginx"}) {
		t.Fatalf("a kernel socket on another port %q", now.Ports)
	}
}

func TestAKrynodesActionTakesItsPortsIntoTheStartingPointButNotKeys(t *testing.T) {
	executor, run := watchedServer(t)
	executor.watchServer(context.Background())
	rootFile(t, executor, "/root/.ssh/authorized_keys", watchOwnerKey+"\n"+watchOtherKey+"\n")
	run.respond["ss -H -tulnp"] = nginxListener + "udp UNCONN 0 0 0.0.0.0:41641 0.0.0.0:* users:((\"tailscaled\",pid=90,fd=3))\n"
	if result := hostRun(t, executor, hostRequest(t, idA, "reboot-window", "undo", nil)); result.Output == "" {
		t.Fatalf("result %+v", result)
	}
	start, _ := readState[watch.State](executor.StateDir, watchFile)
	if !slices.Equal(start.Ports, []string{"32768-60999/udp tailscaled", "8080/tcp nginx"}) || len(start.Keys) != 1 {
		t.Fatalf("start %+v", start)
	}
	executor.watchServer(context.Background())
	if kinds := eventKinds(t, executor); !slices.Equal(kinds, []string{"ssh-key"}) {
		t.Fatalf("events %v", kinds)
	}
}

func chainsOf(restore string) map[string]string {
	listed := map[string][]string{}
	for _, chain := range []string{network.ServeChain, network.ReachChain, network.DropChain, network.KnockChain} {
		listed[chain] = []string{"-N " + chain}
	}
	for line := range strings.SplitSeq(restore, "\n") {
		if fields := strings.Fields(line); len(fields) > 1 && fields[0] == "-A" {
			listed[fields[1]] = append(listed[fields[1]], line)
		}
	}
	chains := map[string]string{}
	for chain, lines := range listed {
		chains[chain] = strings.Join(lines, "\n")
	}
	return chains
}

func TestARemovedBlockingRuleWarnsAndIsPutBack(t *testing.T) {
	executor, run, _, _, _ := joinedServer(t)
	knockingStack(t, executor)
	if err := executor.syncRules(context.Background()); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(filepath.Join(executor.networkDir(), rulesFile))
	if err != nil {
		t.Fatal(err)
	}
	if events := readEvents(t, executor); len(events) != 0 {
		t.Fatalf("writing warned: %+v", events)
	}
	removed := "-A KRY-REACH -i krc111111111111 -m comment --comment kry-reach:app -j DROP"
	for chain, listing := range chainsOf(string(written)) {
		run.respond["iptables -S "+chain] = strings.Replace(listing, "\n"+removed, "", 1)
	}
	run.calls = nil
	if err := executor.syncRules(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "iptables-restore --noflush") }) {
		t.Fatalf("not put back: %v", run.calls)
	}
	events := readEvents(t, executor)
	if len(events) != 1 || events[0].Kind != "rule" || events[0].Detail["rule"] != removed || events[0].Detail["chain"] != network.ReachChain {
		t.Fatalf("events %+v", events)
	}
}

func TestAMissingChainIsARebootNotARemovedRule(t *testing.T) {
	executor, _, _, _, _ := joinedServer(t)
	knockingStack(t, executor)
	for range 2 {
		if err := executor.syncRules(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if events := readEvents(t, executor); len(events) != 0 {
		t.Fatalf("events %+v", events)
	}
}

func udpListener(port int, process string) string {
	return fmt.Sprintf("udp UNCONN 0 0 0.0.0.0:%d 0.0.0.0:* users:((\"%s\",pid=90,fd=3))\n", port, process)
}

func portEvents(t *testing.T, executor Executor) []string {
	t.Helper()
	var ports []string
	for _, event := range readEvents(t, executor) {
		if event.Kind == "port" {
			ports = append(ports, event.Detail["port"]+" "+event.Detail["process"])
		}
	}
	return ports
}

func TestOnlyTheProbesOwnSocketPassesWhileItsMarkLasts(t *testing.T) {
	executor, run := watchedServer(t)
	executor.watchServer(context.Background())
	probe := "udp UNCONN 0 0 *:51820 *:* users:((\"kry\",pid=4242,fd=7))\n"
	mark := func(until time.Time) {
		if err := writeJSON(executor.StateDir, probeFile, probeMark{Port: 51820, PID: 4242, Until: until}, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ports := func(listeners string) []string {
		run.respond["ss -H -tulnp"] = nginxListener + listeners
		now, _ := executor.watchNow(context.Background())
		return now.Ports
	}
	mark(executorNow.Add(30 * time.Second))
	if seen := ports(probe); !slices.Equal(seen, []string{"8080/tcp nginx"}) {
		t.Fatalf("the probe's socket %q", seen)
	}
	executor.watchServer(context.Background())
	if events := portEvents(t, executor); len(events) != 0 {
		t.Fatalf("the probe's socket warned: %q", events)
	}
	if seen := ports("udp UNCONN 0 0 *:51821 *:* users:((\"kry\",pid=4242,fd=8))\n"); !slices.Equal(seen, []string{"32768-60999/udp kry", "8080/tcp nginx"}) {
		t.Fatalf("another port of the probe %q", seen)
	}
	if seen := ports("udp UNCONN 0 0 *:51820 *:* users:((\"nc\",pid=666,fd=3))\n"); !slices.Equal(seen, []string{"32768-60999/udp nc", "8080/tcp nginx"}) {
		t.Fatalf("another process on the probe's port %q", seen)
	}
	mark(executorNow.Add(-time.Second))
	if seen := ports(probe); !slices.Equal(seen, []string{"32768-60999/udp kry", "8080/tcp nginx"}) {
		t.Fatalf("the probe's socket after its mark %q", seen)
	}
}

func TestTemporaryUDPPortsAreOneItemPerProcess(t *testing.T) {
	executor, run := watchedServer(t)
	executor.watchServer(context.Background())
	run.respond["ss -H -tulnp"] = nginxListener + udpListener(42566, "tailscaled") + udpListener(55406, "tailscaled")
	now, _ := executor.watchNow(context.Background())
	if !slices.Equal(now.Ports, []string{"32768-60999/udp tailscaled", "8080/tcp nginx"}) {
		t.Fatalf("ports %q", now.Ports)
	}
	for range 2 {
		executor.watchServer(context.Background())
	}
	if ports := portEvents(t, executor); !slices.Equal(ports, []string{"32768-60999/udp tailscaled"}) {
		t.Fatalf("events %q", ports)
	}
}

func TestAPortAcceptedUnder070CountsAsTheRange(t *testing.T) {
	executor, run := watchedServer(t)
	executor.watchServer(context.Background())
	start, _ := readState[watch.State](executor.StateDir, watchFile)
	start.Ports = []string{"42566/udp tailscaled", "8080/tcp nginx"}
	writeJSON(executor.StateDir, watchFile, start, 0o640)
	run.respond["ss -H -tulnp"] = nginxListener + udpListener(33453, "tailscaled")
	executor.watchServer(context.Background())
	if events := readEvents(t, executor); len(events) != 0 {
		t.Fatalf("an accepted temporary port warned again: %+v", events)
	}
}

func TestOnlyUDPInTheKernelRangeCollapses(t *testing.T) {
	executor, run := watchedServer(t)
	executor.watchServer(context.Background())
	run.respond["ss -H -tulnp"] = nginxListener + "tcp LISTEN 0 5 0.0.0.0:45000 0.0.0.0:* users:((\"nc\",pid=666,fd=3))\n" + udpListener(45000, "nc") + udpListener(5353, "avahi")
	executor.watchServer(context.Background())
	if ports := portEvents(t, executor); !slices.Equal(ports, []string{"32768-60999/udp nc", "45000/tcp nc", "5353/udp avahi"}) {
		t.Fatalf("events %q", ports)
	}
}

func TestTheRangeComesFromTheKernel(t *testing.T) {
	root := t.TempDir()
	if low, high := ephemeral(root); low != 32768 || high != 60999 {
		t.Fatalf("default %d-%d", low, high)
	}
	path := filepath.Join(root, "proc", "sys", "net", "ipv4", "ip_local_port_range")
	os.MkdirAll(filepath.Dir(path), 0o755)
	os.WriteFile(path, []byte("40000\t50000\n"), 0o644)
	if low, high := ephemeral(root); low != 40000 || high != 50000 {
		t.Fatalf("read %d-%d", low, high)
	}
	if ports := collapse([]string{"45000/udp nc", "39999/udp nc", "45000/tcp nc"}, 40000, 50000); !slices.Equal(ports, []string{"39999/udp nc", "40000-50000/udp nc", "45000/tcp nc"}) {
		t.Fatalf("collapse %q", ports)
	}
}
