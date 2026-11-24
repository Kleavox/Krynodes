package mesh

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

func selfKey(key, signer string) change {
	return func(self *network.Member, members []network.Member) []network.Member {
		self.Key, self.Signer = key, signer
		return members[:1]
	}
}

func rekeyed(self *network.Member, members []network.Member) []network.Member {
	self.Rekey = true
	return members[:1]
}

func TestADocumentNamingAnotherSealKeyChangesNothing(t *testing.T) {
	n := joinedNet(t)
	before := n.applied(t)
	otherSeal := func(self *network.Member, members []network.Member) []network.Member {
		self.SealKey = otherSealKey
		return members[:1]
	}
	if applied := n.offer(t, n.next(t, otherSeal)); applied.OK || applied.Message != "the document names another seal key for server-1" {
		t.Fatalf("another seal key: %+v", applied)
	}
	if after := n.applied(t); after.Version != before.Version || after.Hash != before.Hash {
		t.Fatalf("applied moved from %+v to %+v", before, after)
	}
}

func TestOnlyThisServersOwnKeysAreTaken(t *testing.T) {
	n := joinedNet(t)
	stranger := peerKeys(t)
	if applied := n.offer(t, n.next(t, selfKey(n.keys.Public, stranger.Signer))); applied.OK || !strings.Contains(applied.Message, "another key for server-1") {
		t.Fatalf("another signer: %+v", applied)
	}
	old := n.keys
	if _, err := call(t, n.m, "rekey", nil); err != nil {
		t.Fatal(err)
	}
	if applied := n.offer(t, n.next(t, selfKey(stranger.Public, old.Signer))); applied.OK || !strings.Contains(applied.Message, "another key for server-1") {
		t.Fatalf("a stranger key during a pending announce: %+v", applied)
	}
	if applied := n.offer(t, n.next(t, selfKey(old.Public, old.Signer))); !applied.OK {
		t.Fatalf("the old key during a pending announce: %+v", applied)
	}
	if current, _ := n.m.load(); current.Announce == nil || current.Announce.Key != ownKeys(t, n.m).Public {
		t.Fatalf("the pending announce was lost: %+v", current.Announce)
	}
}

func TestARekeyIsAnnouncedOnlyOnceItsDocumentIsSaved(t *testing.T) {
	n := joinedNet(t)
	n.m.Send = func(message any) error {
		if _, ok := message.(reporter.Announce); ok {
			if current, _ := n.m.load(); current.Applied.Version != 2 || current.Announce == nil || current.Announce.Key != ownKeys(t, n.m).Public {
				t.Errorf("announced before the save: version %d %+v", current.Applied.Version, current.Announce)
			}
		}
		return n.send(message)
	}
	if applied := n.offer(t, n.next(t, rekeyed)); !applied.OK {
		t.Fatalf("%+v", applied)
	}
	if !slices.ContainsFunc(n.messages(), func(message any) bool { _, ok := message.(reporter.Announce); return ok }) {
		t.Fatal("nothing was announced")
	}
}

func TestACrashBeforeTheNewKeyIsKeptLeavesAnAnnounceThatHeals(t *testing.T) {
	n := joinedNet(t)
	fresh, err := network.Next(n.m.keysDir())
	if err != nil {
		t.Fatal(err)
	}
	current, _ := n.m.load()
	current.Announce = &announcement{Key: fresh.Public, Signature: fresh.Announce(selfNode)}
	if err := n.m.save(current); err != nil {
		t.Fatal(err)
	}
	if ownKeys(t, n.m).Public != n.keys.Public {
		t.Fatal("the next key was kept before its announce was")
	}
	if applied := n.offer(t, n.next(t, rekeyed)); !applied.OK {
		t.Fatalf("%+v", applied)
	}
	kept := ownKeys(t, n.m)
	if current, _ := n.m.load(); kept.Public == n.keys.Public || current.Announce == nil || current.Announce.Key != kept.Public {
		t.Fatalf("the announce does not name the key in use: %+v", current.Announce)
	}
}

type boot struct {
	at      string
	version int
	staged  bool
	started bool
}

func (n *testNet) boots(prefixes ...string) *[]boot {
	seen := &[]boot{}
	n.run.effects = map[string]func(){}
	for _, prefix := range prefixes {
		n.run.effects[prefix] = func() {
			current, _ := n.m.load()
			document, _, ok := n.m.boot(current)
			version := 0
			if ok {
				version = document.Version
			}
			*seen = append(*seen, boot{at: prefix, version: version, staged: current.Next != nil, started: exists(n.m, network.RulesDropInPath)})
		}
	}
	return seen
}

func TestACrashAtAnyStepBootsTheNewOrThePreviousRulesNeverNone(t *testing.T) {
	n := newNet(t)
	seen := n.boots("iptables-restore", "ufw allow", "systemctl daemon-reload", "systemctl enable", "iptables -w -t nat -S")
	n.apply(t, pair)
	for _, at := range *seen {
		if (at.started || at.at != "iptables-restore") && (at.version != 1 || !at.staged) {
			t.Fatalf("first join: a crash at %q boots %+v: %+v", at.at, at, *seen)
		}
	}
	if current, _ := n.m.load(); current.Next != nil {
		t.Fatalf("an applied document stays staged: %+v", current.Next)
	}
	seen = n.boots("iptables-restore", "wg syncconf", "iptables -w -t nat -S")
	n.apply(t, asIs)
	if first := (*seen)[0]; first.version != 1 || first.staged {
		t.Fatalf("before the stage: %+v", first)
	}
	for _, at := range (*seen)[1:] {
		if at.version != 2 || !at.staged {
			t.Fatalf("update: a crash at %q boots %+v: %+v", at.at, at, *seen)
		}
	}
	n.run.effects = nil
	crashed, _ := n.m.load()
	crashed.Next = &staged{Document: n.build(3, "", pair)}
	if err := n.m.save(crashed); err != nil {
		t.Fatal(err)
	}
	mtu := 1380
	n.run.failing["systemctl restart wg-quick@kry0.service"] = "Job for wg-quick@kry0.service failed."
	applied := n.offer(t, n.next(t, pair, func(self *network.Member, members []network.Member) []network.Member {
		self.MTU = &mtu
		return members
	}))
	current, _ := n.m.load()
	document, _, ok := n.m.boot(current)
	if applied.OK || current.Next != nil || !ok || document.Version != 2 {
		t.Fatalf("a rolled-back apply boots %d staged %v: %+v", document.Version, current.Next != nil, applied)
	}
}

func TestTheBootStepDuringAnApplyRendersTheStagedDocument(t *testing.T) {
	n := joinedNet(t)
	rendered := ""
	n.run.effects = map[string]func(){"wg syncconf kry0 ": func() {
		n.run.effects = nil
		if err := n.m.Rules(t.Context()); err != nil {
			t.Error(err)
		}
		n.run.mu.Lock()
		rendered = n.run.restored["iptables-restore"]
		n.run.mu.Unlock()
	}}
	if applied := n.offer(t, n.next(t, asIs)); !applied.OK {
		t.Fatalf("%+v", applied)
	}
	if !strings.Contains(rendered, "-A KRY-IN -s 10.88.0.9/32 -j ACCEPT") {
		t.Fatalf("the boot step rendered the previous document:\n%s", rendered)
	}
}

func TestOnFirewalldTheRulesAreBackBeforeKry0Starts(t *testing.T) {
	n := newNet(t)
	rootFile(t, n.m, "/etc/os-release", "ID=rocky\nVERSION_ID=\"9.4\"\n")
	rootFile(t, n.m, "/etc/ufw/ufw.conf", "ENABLED=no\n")
	n.run.respond["firewall-cmd --state"] = "running\n"
	guarded := false
	n.run.effects = map[string]func(){
		"firewall-cmd --reload": func() {
			n.tables.mu.Lock()
			defer n.tables.mu.Unlock()
			for key := range n.tables.rules {
				if strings.Contains(key, " KRY-") {
					delete(n.tables.rules, key)
					continue
				}
				n.tables.rules[key] = slices.DeleteFunc(n.tables.rules[key], func(line string) bool { return strings.Contains(line, "-j KRY-") })
			}
		},
		"systemctl enable --now": func() {
			guarded = len(n.tables.chain("iptables", "filter", network.InChain)) > 0 && slices.Contains(n.tables.chain("ip6tables", "filter", "INPUT"), "-A INPUT -i kry0 -j KRY-IN")
		},
	}
	n.apply(t, pair)
	reload := slices.Index(n.run.calls, "firewall-cmd --reload")
	if reload < 0 || !guarded {
		t.Fatalf("kry0 started unguarded after the reload: %v", n.run.calls)
	}
	before(t, n.run.calls[reload:], "ip6tables-restore -w --noflush", "systemctl enable --now wg-quick@kry0.service")
}

func TestLeaveRemovesTheDockerChainItMade(t *testing.T) {
	n := joinedNet(t)
	if err := n.m.Leave(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"iptables", "ip6tables"} {
		if n.tables.has(tool, "filter", network.DockerUser) {
			t.Fatalf("%s keeps the empty DOCKER-USER Krynodes made:\n%s", tool, n.tables)
		}
	}
}

func TestAnUnreadableRecordClosesEveryKrynodesPort(t *testing.T) {
	n := joinedNet(t)
	rootFile(t, n.m, "/etc/os-release", "ID=rocky\nVERSION_ID=\"9.4\"\n")
	n.run.respond["firewall-cmd --state"] = "running\n"
	n.run.respond["firewall-cmd --permanent --list-ports"] = "22/tcp 51821/udp 51920/udp 8080/udp 51821/tcp 52176/udp\n"
	if err := os.WriteFile(n.m.statePath(), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	n.run.calls = nil
	n.m.Leave(t.Context())
	for _, want := range []string{"firewall-cmd --permanent --remove-port=51821/udp", "firewall-cmd --permanent --remove-port=51920/udp", "firewall-cmd --reload"} {
		if !slices.Contains(n.run.calls, want) {
			t.Fatalf("missing %q in %v", want, n.run.calls)
		}
	}
	if slices.ContainsFunc(n.run.calls, func(call string) bool {
		return strings.Contains(call, "8080") || strings.Contains(call, "51821/tcp") || strings.Contains(call, "52176")
	}) {
		t.Fatalf("closed a port that is not Krynodes': %v", n.run.calls)
	}
}

func TestADropKeepsAHeldExitOff(t *testing.T) {
	n := joinedNet(t)
	n.apply(t, exitOn)
	n.m.Hints(t.Context(), reporter.Hints{Type: "hints", Held: []string{selfNode}})
	noExit(t, n.tables, "iptables")
	if _, err := call(t, n.m, "drop", map[string]string{"node": thirdNode, "key": n.third.Public, "address": "10.88.0.3"}); err != nil {
		t.Fatal(err)
	}
	noExit(t, n.tables, "iptables")
}

func TestAPairPortOpenedBeforeAFailedSaveIsClosed(t *testing.T) {
	n := joinedNet(t)
	n.run.respond["ufw status numbered"] = "[ 1] 51821/udp ALLOW IN Anywhere # krynodes-network\n[ 2] Anywhere on kry0 ALLOW IN Anywhere # krynodes-network\n[ 3] 51920/udp ALLOW IN Anywhere # krynodes-network\n"
	state := n.m.statePath()
	n.run.effects = map[string]func(){"ufw allow 51920/udp": func() {
		n.run.effects = nil
		os.Remove(state)
		os.Mkdir(state, 0o700)
	}}
	applied := n.offer(t, n.next(t, asIs))
	os.Remove(state)
	if applied.OK || !strings.HasPrefix(applied.Message, "save: ") || !slices.Contains(n.run.calls, "ufw --force delete 3") || slices.Contains(n.run.calls, "ufw --force delete 1") {
		t.Fatalf("%+v %v", applied, n.run.calls)
	}
}

func TestOnlyTheLaptopsMasqueradeOfThisRangeIsTouched(t *testing.T) {
	n := joinedNet(t)
	withIPv6(t, n, "eth0")
	own := map[string]string{"iptables": "-A POSTROUTING -s 10.88.5.7/32 -o eth0 -j MASQUERADE", "ip6tables": "-A POSTROUTING -s fd88:88::5:7/128 -o eth0 -j MASQUERADE"}
	for tool, line := range own {
		n.tables.rules[tool+" nat POSTROUTING"] = []string{line}
	}
	n.apply(t, exitOn)
	for tool, line := range own {
		if got := n.tables.chain(tool, "nat", "POSTROUTING"); len(got) != 2 || !slices.Contains(got, line) {
			t.Fatalf("exit on: %s POSTROUTING %q", tool, got)
		}
	}
	n.apply(t, exitOffPrivate)
	for tool, line := range own {
		if got := n.tables.chain(tool, "nat", "POSTROUTING"); !slices.Equal(got, []string{line}) {
			t.Fatalf("exit off: %s POSTROUTING %q", tool, got)
		}
	}
	n.apply(t, exitOn)
	if err := n.m.Leave(t.Context()); err != nil {
		t.Fatal(err)
	}
	for tool, line := range own {
		if got := n.tables.chain(tool, "nat", "POSTROUTING"); !slices.Equal(got, []string{line}) {
			t.Fatalf("leave: %s POSTROUTING %q", tool, got)
		}
	}
}

func TestAnExitThatFailsIsStagedOffBeforeKry0IsReconfigured(t *testing.T) {
	n := joinedNet(t)
	withIPv6(t, n, "eth0")
	accept := n.m.path("/proc/sys/net/ipv6/conf/eth0/accept_ra")
	exitStaged := []bool{}
	look := func() {
		current, _ := n.m.load()
		document, _, _ := n.m.boot(current)
		self, _ := member(document, selfNode)
		exitStaged = append(exitStaged, self.Exit)
	}
	n.run.effects = map[string]func(){
		"ip6tables -w -t nat -S POSTROUTING": func() {
			if info, err := os.Stat(accept); err == nil && !info.IsDir() {
				os.Remove(accept)
				os.Mkdir(accept, 0o755)
			}
		},
		"wg syncconf":       look,
		"systemctl restart": look,
	}
	if applied := n.offer(t, n.next(t, exitOnPrivate)); !applied.OK || !strings.Contains(applied.Message, "the exit for laptops is off") {
		t.Fatalf("%+v", applied)
	}
	if len(exitStaged) < 2 || exitStaged[len(exitStaged)-1] {
		t.Fatalf("kry0 was reconfigured with the exit still staged on: %v", exitStaged)
	}
}

func TestADropAfterACrashedApplyReachesTheStagedDocument(t *testing.T) {
	n := joinedNet(t)
	current, _ := n.m.load()
	current.Next = &staged{Document: n.build(2, "", asIs)}
	if err := n.m.save(current); err != nil {
		t.Fatal(err)
	}
	if _, err := call(t, n.m, "drop", map[string]string{"node": thirdNode, "key": n.third.Public, "address": "10.88.0.3"}); err != nil {
		t.Fatal(err)
	}
	n.m.keep(t.Context(), map[string]string{})
	for _, tool := range []string{"iptables", "ip6tables"} {
		for _, chain := range []string{network.InChain, "KRY-FWD"} {
			for _, line := range n.tables.chain(tool, "filter", chain) {
				if (strings.Contains(line, "10.88.0.3/") || strings.Contains(line, "fd88:88::3/")) && !strings.HasSuffix(line, "-j DROP") {
					t.Fatalf("the dropped member keeps a grant in %s %s: %s", tool, chain, line)
				}
			}
		}
	}
	if !strings.Contains(n.run.restored["iptables-restore"], "10.88.0.9/32") {
		t.Fatalf("the guard did not render the staged document:\n%s", n.run.restored["iptables-restore"])
	}
}

func TestLeaveAfterAFirstJoinThatCrashedTakesItAllDown(t *testing.T) {
	n := newNet(t)
	var snapshot []byte
	n.run.effects = map[string]func(){"systemctl enable --now": func() {
		snapshot, _ = os.ReadFile(n.m.statePath())
	}}
	n.apply(t, pair)
	if err := os.WriteFile(n.m.statePath(), snapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	if current, _ := n.m.load(); current.Joined || current.Next == nil {
		t.Fatalf("not a crashed first join: %+v", current)
	}
	n.run.effects = nil
	n.run.respond["ufw status numbered"] = "[ 1] 22/tcp ALLOW IN Anywhere\n[ 2] 51821/udp ALLOW IN Anywhere # krynodes-network\n[ 3] Anywhere on kry0 ALLOW IN Anywhere # krynodes-network\n"
	n.run.calls = nil
	if err := n.m.Leave(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"systemctl disable --now wg-quick@kry0.service", "ufw --force delete 3", "ufw --force delete 2"} {
		if !slices.Contains(n.run.calls, want) {
			t.Fatalf("missing %q in %v", want, n.run.calls)
		}
	}
	if slices.Contains(n.run.calls, "ufw --force delete 1") || exists(n.m, network.RulesDropInPath) || exists(n.m, network.DropInPath) || n.tables.has("iptables", "filter", network.InChain) {
		t.Fatalf("left behind:\n%s%v", n.tables, n.run.calls)
	}
}
