package mesh

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

const (
	routes4 = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0100710A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
		"eth0\t0000710A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
	routes6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n" +
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     ens3\n"
)

func TestTheRulesFailWithoutAnAppliedDocument(t *testing.T) {
	m, run := networkMesh(t)
	if err := m.Rules(context.Background()); err == nil || !strings.Contains(err.Error(), "no applied network document") {
		t.Fatalf("rules %v", err)
	}
	prepare(t, m)
	before := len(run.calls)
	if err := m.Rules(context.Background()); err == nil {
		t.Fatal("a prepared server restored rules")
	}
	if len(run.calls) != before {
		t.Fatalf("calls %v", run.calls[before:])
	}
	if err := os.WriteFile(m.statePath(), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Rules(context.Background()); err == nil {
		t.Fatal("an unreadable record restored rules")
	}
}

func TestTheRulesRestoreBothFamiliesAndInsertOnlyMissingJumps(t *testing.T) {
	m, run := networkMesh(t)
	document, _ := joined(t, m)
	current, _ := m.load()
	current.Dropped = []string{"10.88.0.7"}
	m.save(current)
	rootFile(t, m, "/proc/net/route", routes4)
	rootFile(t, m, "/proc/net/ipv6_route", routes6)
	run.failing["iptables -w -N DOCKER-USER"] = "iptables: Chain already exists."
	run.failing["iptables -w -C INPUT -j KRY-EDGE"] = "Bad rule"
	run.failing["ip6tables -w -C DOCKER-USER -i kry0 -j KRY-FWD"] = "Bad rule"
	if err := m.Rules(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := run.restored["iptables-restore"], network.RenderRules(document, selfNode, []string{"10.88.0.7"}, 4, "eth0"); got != want {
		t.Fatalf("v4\n%s\nwant\n%s", got, want)
	}
	if got, want := run.restored["ip6tables-restore"], network.RenderRules(document, selfNode, []string{"10.88.0.7"}, 6, "ens3"); got != want {
		t.Fatalf("v6\n%s\nwant\n%s", got, want)
	}
	if !strings.Contains(run.restored["iptables-restore"], "-A KRY-EDGE -d 10.88.0.0/16 -j DROP") || !strings.Contains(run.restored["ip6tables-restore"], "-A KRY-EDGE -d fd88:88::/64 -j DROP") {
		t.Fatalf("v4 edge %s", run.restored["iptables-restore"])
	}
	inserted := append(run.called("iptables -w -I"), run.called("ip6tables -w -I")...)
	if !slices.Equal(inserted, []string{"iptables -w -I INPUT 1 -j KRY-EDGE", "ip6tables -w -I DOCKER-USER 1 -i kry0 -j KRY-FWD"}) {
		t.Fatalf("inserted %v", inserted)
	}
	for _, tool := range []string{"iptables", "ip6tables"} {
		checked := run.called(tool + " -w -C")
		if len(checked) != len(network.Jumps()) {
			t.Fatalf("%s checked %v", tool, checked)
		}
		made := slices.Index(run.calls, tool+" -w -S DOCKER-USER")
		if tool == "ip6tables" {
			made = slices.Index(run.calls, tool+" -w -N DOCKER-USER")
		}
		if made < 0 || made > slices.Index(run.calls, checked[0]) {
			t.Fatalf("%s: DOCKER-USER is not made before the jumps: %v", tool, run.calls)
		}
	}
	if len(run.files) != 2 || run.files[0] == run.files[1] {
		t.Fatalf("restored from %v", run.files)
	}
	for _, path := range run.files {
		if filepath.Dir(path) != m.State || !strings.HasPrefix(filepath.Base(path), "rules-") {
			t.Fatalf("restored from %s", path)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s stays: %v", path, err)
		}
	}
}

func TestTheExitNodeAlsoGetsTheExitJumps(t *testing.T) {
	m, run := networkMesh(t)
	document, _ := joined(t, m)
	document.Members[1].Exit = true
	document.Members = append(document.Members, network.Member{Node: "33333333-3333-4333-8333-333333333333", Name: "laptop-1", Address: "10.88.0.9", Key: peerKeys(t).Public, Signer: peerKeys(t).Signer, SealKey: otherSealKey, Port: 51820, Kind: "laptop", PSK: map[string]string{}})
	m.save(record{Applied: network.Applied{Version: 1}, Document: &document, Joined: true})
	rootFile(t, m, "/proc/net/route", routes4)
	for _, spec := range network.ExitJumps {
		run.failing["iptables -w -C "+strings.Join(spec, " ")] = "Bad rule"
	}
	if err := m.Rules(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(run.called("iptables -w -I FORWARD 1 -i kry0 ! -o kry0 -j KRY-EXIT")) != 1 || len(run.called("iptables -w -I FORWARD 1 ! -i kry0 -o kry0 -j KRY-EXIT")) != 1 {
		t.Fatalf("calls %v", run.calls)
	}
	if !strings.Contains(run.restored["iptables-restore"], "-A KRY-EXIT -s 10.88.0.9/32 -i kry0 -o eth0 -j ACCEPT") {
		t.Fatalf("v4 %s", run.restored["iptables-restore"])
	}
	if len(run.called("ip6tables -w -C FORWARD -i kry0 ! -o kry0")) != 0 {
		t.Fatalf("no v6 uplink, yet v6 exit jumps: %v", run.calls)
	}
}

func TestWithoutADefaultRouteTheExitStaysEmptyAndThePoolClosed(t *testing.T) {
	m, run := networkMesh(t)
	document, _ := joined(t, m)
	document.Members[1].Exit = true
	m.save(record{Applied: network.Applied{Version: 1}, Document: &document, Joined: true})
	if err := m.Rules(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := run.restored["iptables-restore"], network.RenderRules(document, selfNode, nil, 4, ""); got != want || strings.Contains(got, "-A KRY-EXIT") || !strings.Contains(got, "-A KRY-EDGE -d 10.88.0.0/16 -j DROP") {
		t.Fatalf("v4\n%s", got)
	}
	if !strings.Contains(run.restored["iptables-restore"], "-A KRY-IN -j DROP") {
		t.Fatalf("v4 is not closed: %s", run.restored["iptables-restore"])
	}
}

func TestTheRulesFailClosedWhenARestoreOrAJumpFails(t *testing.T) {
	m, run := networkMesh(t)
	joined(t, m)
	run.failing["ip6tables-restore -w --noflush"] = "ip6tables-restore: unable to initialize table 'filter'"
	if err := m.Rules(context.Background()); err == nil || !strings.Contains(err.Error(), "unable to initialize") {
		t.Fatalf("rules %v", err)
	}
	if len(run.called("ip6tables -w -I")) != 0 || len(run.called("ip6tables -w -C")) != 0 {
		t.Fatalf("jumps after a failed restore: %v", run.calls)
	}

	m, run = networkMesh(t)
	joined(t, m)
	run.failing["iptables -w -N DOCKER-USER"] = ""
	run.failing["iptables -w -S DOCKER-USER"] = "iptables: No chain/target/match by that name."
	if err := m.Rules(context.Background()); err == nil || !strings.Contains(err.Error(), "DOCKER-USER") {
		t.Fatalf("rules %v", err)
	}

	m, run = networkMesh(t)
	joined(t, m)
	run.failing["iptables -w -C INPUT -i kry0 -j KRY-IN"] = "Bad rule"
	run.failing["iptables -w -I INPUT 1 -i kry0 -j KRY-IN"] = "iptables: Resource temporarily unavailable."
	if err := m.Rules(context.Background()); err == nil || !strings.Contains(err.Error(), "KRY-IN") {
		t.Fatalf("rules %v", err)
	}
}

func TestTheUplinkIsTheLowestMetricDefaultRouteThatIsUp(t *testing.T) {
	m, _ := newMesh(t)
	rootFile(t, m, "/proc/net/route", "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"+
		"eth0\t00000000\t0100710A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"+
		"wlan0\t00000000\t0100A8C0\t0002\t0\t0\t10\t00000000\t0\t0\t0\n"+
		"eth2\t00000000\t00000000\t0201\t0\t0\t5\t00000000\t0\t0\t0\n"+
		"eth1\t00000000\t0101710A\t0003\t0\t0\t50\t00000000\t0\t0\t0\n"+
		"eth3\t0000710A\t00000000\t0001\t0\t0\t1\t00FFFFFF\t0\t0\t0\n"+
		"kry0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n")
	rootFile(t, m, "/proc/net/ipv6_route", routes6+
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000100 00000001 00000000 00000003     ens4\n"+
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000001 00000001 00000000 00000002     ens5\n")
	if got := m.uplinks(4); !slices.Equal(got, []string{"eth1", "eth0"}) {
		t.Fatalf("v4 %v", got)
	}
	if got := m.uplinks(6); !slices.Equal(got, []string{"ens4", "ens3"}) {
		t.Fatalf("v6 %v", got)
	}
}

func TestOwnIsThisServersAddressInTheAppliedDocument(t *testing.T) {
	n := newNet(t)
	if own := n.m.Own(); own != "" {
		t.Fatalf("a server that never joined owns %q", own)
	}
	n.apply(t, pair)
	if own := n.m.Own(); own != "10.88.0.2" {
		t.Fatalf("own %q", own)
	}
}

func TestOwnNameIsThisServersNameInTheAppliedDocument(t *testing.T) {
	n := newNet(t)
	if name := n.m.OwnName(); name != "" {
		t.Fatalf("a server that never joined is called %q", name)
	}
	n.apply(t, pair)
	if name := n.m.OwnName(); name != "server-1" {
		t.Fatalf("name %q", name)
	}
}
