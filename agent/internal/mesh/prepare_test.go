package mesh

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

func prepare(t *testing.T, m *Mesh) {
	t.Helper()
	if _, err := call(t, m, "prepare", map[string]string{"range": "10.88.0.0/24", "port": "51821"}); err != nil {
		t.Fatalf("prepare: %v", err)
	}
}

func TestPrepareStaysOutOfWhatTheServerAlreadyUses(t *testing.T) {
	m, run := networkMesh(t)
	if _, err := call(t, m, "prepare", map[string]string{"range": "10.88.0.0/24", "port": "51820"}); err == nil || !strings.Contains(err.Error(), "51820/udp is taken") {
		t.Fatalf("port of wg0: %v", err)
	}
	run.respond["docker network ls -q"] = "n1\n"
	run.respond["docker network inspect --format {{range .IPAM.Config}}{{.Subnet}} {{end}} n1"] = "10.88.0.0/24 \n"
	if _, err := call(t, m, "prepare", map[string]string{"range": "10.88.0.0/24", "port": "51821"}); err == nil || !strings.Contains(err.Error(), "10.88.0.0/24 is already used") {
		t.Fatalf("range of a Docker network: %v", err)
	}
	if _, err := os.Stat(m.statePath()); !os.IsNotExist(err) {
		t.Fatalf("a refused prepare wrote the record: %v", err)
	}
}

func TestPrepareAnswersTheKeysTheOwnerSawAndRecordsThePort(t *testing.T) {
	m, run := networkMesh(t)
	keys := ownKeys(t, m)
	message, err := call(t, m, "prepare", map[string]string{"range": "10.88.0.0/24", "port": "51821"})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(message), &fields); err != nil || len(fields) != 4 {
		t.Fatalf("answer %s", message)
	}
	if fields["key"] != keys.Public || fields["signer"] != keys.Signer || fields["port"] != 51821.0 || fields["mtu"] != 1500.0 {
		t.Fatalf("answer %s", message)
	}
	if strings.Contains(message, keys.Private) {
		t.Fatal("the answer carries the private key")
	}
	current, err := m.load()
	if err != nil || current.Prepared == nil || current.Prepared.Port != 51821 || current.Prepared.Range != "10.88.0.0/24" || current.Tools {
		t.Fatalf("record %+v %v", current, err)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "apt-get") }) {
		t.Fatalf("tools were installed on a server that has them: %v", run.calls)
	}
	joined(t, m)
	if _, err := call(t, m, "prepare", map[string]string{"range": "10.88.0.0/24", "port": "51821"}); err == nil || !strings.Contains(err.Error(), "already in the private network") {
		t.Fatalf("a joined server prepared again: %v", err)
	}
}

func TestUnprepareKeepsTheKeysAndTakesOnlyToolsKrynodesAdded(t *testing.T) {
	m, run := networkMesh(t)
	os.Remove(m.Root + "/usr/bin/wg")
	before := ownKeys(t, m)
	prepare(t, m)
	if !slices.Contains(run.calls, "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -q wireguard-tools") {
		t.Fatalf("the tools were not installed: %v", run.calls)
	}
	rootFile(t, m, "/usr/bin/wg", "")
	run.respond["ip -d -j addr show"] = `[{"ifname":"eth0","mtu":1500,"addr_info":[]}]`
	if _, err := call(t, m, "unprepare", nil); err != nil {
		t.Fatalf("unprepare: %v", err)
	}
	if after := ownKeys(t, m); after.Public != before.Public || after.Signer != before.Signer || after.Private != before.Private {
		t.Fatal("unprepare changed the network keys")
	}
	if !slices.Contains(run.calls, "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 purge -y -q wireguard-tools") {
		t.Fatalf("Krynodes' tools stay: %v", run.calls)
	}
	if current, _ := m.load(); current.Prepared != nil || current.Tools {
		t.Fatalf("record %+v", current)
	}

	m, run = networkMesh(t)
	os.Remove(m.Root + "/usr/bin/wg")
	prepare(t, m)
	run.respond["ip -d -j addr show"] = `[{"ifname":"eth0","mtu":1500,"addr_info":[]}]`
	run.failing["env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 purge -y -q wireguard-tools"] = "E: dpkg was interrupted"
	if _, err := call(t, m, "unprepare", nil); err == nil || !strings.Contains(err.Error(), "dpkg was interrupted") {
		t.Fatalf("a failed purge: %v", err)
	}
	if current, _ := m.load(); current.Prepared != nil || !current.Tools {
		t.Fatalf("a failed purge forgot the tools: %+v", current)
	}

	m, run = networkMesh(t)
	prepare(t, m)
	run.respond["ip -d -j addr show"] = `[{"ifname":"eth0","mtu":1500,"addr_info":[]}]`
	call(t, m, "unprepare", nil)
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "purge") }) {
		t.Fatalf("the owner's tools were removed: %v", run.calls)
	}

	m, _ = networkMesh(t)
	joined(t, m)
	if _, err := call(t, m, "unprepare", nil); err == nil || !strings.Contains(err.Error(), "remove it from the network") {
		t.Fatalf("a joined server unprepared: %v", err)
	}
}

func TestAToolInstallThatFailsPartwayIsStillRemembered(t *testing.T) {
	m, run := networkMesh(t)
	os.Remove(m.Root + "/usr/bin/wg")
	run.sequence = map[string][]string{"dpkg-query -W -f ${Status} wireguard-tools": {"", "install ok installed"}}
	run.failing["env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -q wireguard-tools"] = "E: post-install script failed"
	if _, err := call(t, m, "prepare", map[string]string{"range": "10.88.0.0/24", "port": "51821"}); err == nil || !strings.Contains(err.Error(), "wireguard-tools") {
		t.Fatalf("prepare: %v", err)
	}
	if current, _ := m.load(); !current.Tools || current.Prepared != nil {
		t.Fatalf("record %+v", current)
	}
}

const (
	aptInstall = "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -q "
	aptPurge   = "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 purge -y -q "
)

func withoutIptables(t *testing.T, m *Mesh) {
	t.Helper()
	for _, tool := range []string{"iptables", "ip6tables", "iptables-restore", "ip6tables-restore"} {
		if err := os.Remove(filepath.Join(m.Root, "usr", "sbin", tool)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPrepareInstallsIptablesWhenMissing(t *testing.T) {
	m, run := networkMesh(t)
	withoutIptables(t, m)
	hello := m.Hello(context.Background())
	if hello == nil || !hello.Ready || hello.Reason == nil || *hello.Reason != "Iptables will be installed when you approve." {
		t.Fatalf("hello %+v", hello)
	}
	prepare(t, m)
	if !slices.Contains(run.calls, aptInstall+"iptables") {
		t.Fatalf("iptables was not installed: %v", run.calls)
	}
	if current, _ := m.load(); !current.Iptables || current.Tools || current.Prepared == nil {
		t.Fatalf("record %+v", current)
	}
	run.respond["ip -d -j addr show"] = `[{"ifname":"eth0","mtu":1500,"addr_info":[]}]`
	run.respond["apt-get -s purge iptables"] = "Purg iptables [1.8.9-2]\n"
	if _, err := call(t, m, "unprepare", nil); err != nil {
		t.Fatalf("unprepare: %v", err)
	}
	if !slices.Contains(run.calls, aptPurge+"iptables") {
		t.Fatalf("Krynodes' iptables stays: %v", run.calls)
	}
	if current, _ := m.load(); current.Iptables || current.Prepared != nil {
		t.Fatalf("record %+v", current)
	}

	m, run = networkMesh(t)
	prepare(t, m)
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "iptables") && strings.Contains(call, "apt-get") }) {
		t.Fatalf("iptables was installed on a server that has it: %v", run.calls)
	}
	if current, _ := m.load(); current.Iptables {
		t.Fatalf("record %+v", current)
	}
}

func TestPrepareInstallsBothToolsInOneCall(t *testing.T) {
	m, run := networkMesh(t)
	withoutIptables(t, m)
	os.Remove(filepath.Join(m.Root, "usr", "bin", "wg"))
	prepare(t, m)
	if !slices.Contains(run.calls, aptInstall+"wireguard-tools iptables") {
		t.Fatalf("calls %v", run.calls)
	}
	if current, _ := m.load(); !current.Iptables || !current.Tools {
		t.Fatalf("record %+v", current)
	}
}

func TestAFailedIptablesInstallStopsPrepareWithThePackageManagersLine(t *testing.T) {
	m, run := networkMesh(t)
	withoutIptables(t, m)
	run.failing[aptInstall+"iptables"] = "E: Unable to locate package iptables"
	_, err := call(t, m, "prepare", map[string]string{"range": "10.88.0.0/24", "port": "51821"})
	if err == nil || !strings.Contains(err.Error(), "Unable to locate package iptables") {
		t.Fatalf("prepare: %v", err)
	}
	if current, _ := m.load(); current.Iptables || current.Prepared != nil {
		t.Fatalf("record %+v", current)
	}
}

func TestUnprepareKeepsTheIptablesOtherPackagesNeed(t *testing.T) {
	for name, simulated := range map[string]string{
		"another package goes": "Remv kubelet [1.30.0]\nPurg iptables [1.8.9-2]\n",
		"nothing is simulated": "",
	} {
		m, run := networkMesh(t)
		withoutIptables(t, m)
		prepare(t, m)
		run.respond["ip -d -j addr show"] = `[{"ifname":"eth0","mtu":1500,"addr_info":[]}]`
		run.respond["apt-get -s purge iptables"] = simulated
		if _, err := call(t, m, "unprepare", nil); err != nil {
			t.Fatalf("%s: unprepare: %v", name, err)
		}
		if slices.Contains(run.calls, aptPurge+"iptables") {
			t.Fatalf("%s: iptables was purged: %v", name, run.calls)
		}
		if current, _ := m.load(); current.Iptables || current.Prepared != nil {
			t.Fatalf("%s: record %+v", name, current)
		}
	}
}

func TestIptablesComesFromIptablesNftOnRHEL(t *testing.T) {
	m, run := networkMesh(t)
	rootFile(t, m, "/etc/os-release", "ID=rocky\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\n")
	withoutIptables(t, m)
	run.failing["rpm -q iptables-nft"] = "package iptables-nft is not installed"
	prepare(t, m)
	if !slices.Contains(run.calls, "yum install -y -q iptables-nft") {
		t.Fatalf("calls %v", run.calls)
	}
	if current, _ := m.load(); !current.Iptables {
		t.Fatalf("record %+v", current)
	}
	run.respond["ip -d -j addr show"] = `[{"ifname":"eth0","mtu":1500,"addr_info":[]}]`
	simulation := "env LC_ALL=C yum remove --assumeno iptables-nft"
	run.respond[simulation] = "Removing:\n iptables-nft x86_64 1.8.10 @baseos 80 k\nRemoving dependent packages:\n docker-ce x86_64 27.0 @docker 100 M\nOperation aborted.\n"
	if _, err := call(t, m, "unprepare", nil); err != nil {
		t.Fatalf("unprepare: %v", err)
	}
	if slices.Contains(run.calls, "yum remove -y -q iptables-nft") {
		t.Fatalf("iptables-nft was purged under docker: %v", run.calls)
	}

	m, run = networkMesh(t)
	rootFile(t, m, "/etc/os-release", "ID=rocky\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\n")
	withoutIptables(t, m)
	run.failing["rpm -q iptables-nft"] = "package iptables-nft is not installed"
	prepare(t, m)
	run.respond["ip -d -j addr show"] = `[{"ifname":"eth0","mtu":1500,"addr_info":[]}]`
	run.respond[simulation] = "Removing:\n iptables-nft x86_64 1.8.10 @baseos 80 k\nOperation aborted.\n"
	if _, err := call(t, m, "unprepare", nil); err != nil {
		t.Fatalf("unprepare: %v", err)
	}
	if !slices.Contains(run.calls, "yum remove -y -q iptables-nft") {
		t.Fatalf("Krynodes' iptables-nft stays: %v", run.calls)
	}
}

func TestRekeyAnswersANewKeySignedByTheSameSigner(t *testing.T) {
	m, _ := networkMesh(t)
	before := ownKeys(t, m)
	message, err := call(t, m, "rekey", nil)
	if err != nil {
		t.Fatal(err)
	}
	var answer struct {
		Key       string `json:"key"`
		Signature string `json:"signature"`
	}
	var fields map[string]any
	if json.Unmarshal([]byte(message), &answer) != nil || json.Unmarshal([]byte(message), &fields) != nil || len(fields) != 4 || fields["signer"] != before.Signer || fields["fingerprint"] != network.Fingerprint(answer.Key, before.Signer, m.SealKey()) {
		t.Fatalf("answer %s", message)
	}
	after := ownKeys(t, m)
	if after.Public == before.Public || after.Signer != before.Signer || answer.Key != after.Public || !network.Announced(after.Signer, selfNode, answer.Key, answer.Signature) {
		t.Fatalf("answer %s", message)
	}
	if strings.Contains(message, after.Private) {
		t.Fatal("the answer carries the private key")
	}
	if current, _ := m.load(); current.Announce == nil || current.Announce.Key != after.Public {
		t.Fatalf("record %+v", current)
	}
	if _, err := call(t, m, "rekey", map[string]string{"key": "x"}); err == nil {
		t.Fatal("rekey took an argument")
	}
}

func TestADropBlocksTheMemberAndClosesTheRulesFirst(t *testing.T) {
	m, run := networkMesh(t)
	_, peer := joined(t, m)
	args := map[string]string{"node": peerNode, "key": peer.Public, "address": "10.88.0.1"}
	message, err := call(t, m, "drop", args)
	if err != nil || message != "Dropped 10.88.0.1." {
		t.Fatalf("drop %q %v", message, err)
	}
	current, _ := m.load()
	if !slices.Contains(current.Applied.Blocked, peer.Public) || !slices.Equal(current.Dropped, []string{"10.88.0.1"}) || !current.Document.Members[0].Cut {
		t.Fatalf("record %+v", current)
	}
	if !strings.Contains(run.restored["iptables-restore"], "-A KRY-IN -s 10.88.0.1/32 -j DROP") || !strings.Contains(run.restored["ip6tables-restore"], "-A KRY-IN -s fd88:88::1/128 -j DROP") {
		t.Fatalf("restored %v", run.restored)
	}
	restore := slices.IndexFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "iptables-restore") })
	remove := slices.Index(run.calls, "wg set kry0 peer "+peer.Public+" remove")
	if restore < 0 || remove < restore {
		t.Fatalf("calls %v", run.calls)
	}
	if message, err := call(t, m, "drop", args); err != nil || message != "Already dropped." {
		t.Fatalf("again %q %v", message, err)
	}
	if _, err := call(t, m, "drop", map[string]string{"node": selfNode, "key": ownKeys(t, m).Public, "address": "10.88.0.2"}); err == nil {
		t.Fatal("a server dropped itself")
	}
	for _, bad := range []map[string]string{
		{"node": peerNode, "key": peer.Public},
		{"node": peerNode, "key": "short", "address": "10.88.0.1"},
		{"node": peerNode, "key": peer.Public, "address": "fd88:88::1"},
	} {
		if _, err := call(t, m, "drop", bad); err == nil {
			t.Fatalf("%v was taken", bad)
		}
	}

	m, run = networkMesh(t)
	if message, err := call(t, m, "drop", args); err != nil || message != "This server is not in the private network." || len(run.calls) != 0 {
		t.Fatalf("not joined %q %v %v", message, err, run.calls)
	}
}

func TestADropIsKeptWhenTheRulesCannotBeRestored(t *testing.T) {
	m, run := networkMesh(t)
	_, peer := joined(t, m)
	run.failing["iptables-restore -w --noflush"] = "iptables-restore: line 3 failed"
	if _, err := call(t, m, "drop", map[string]string{"node": peerNode, "key": peer.Public, "address": "10.88.0.1"}); err == nil || !strings.Contains(err.Error(), "line 3 failed") {
		t.Fatalf("drop %v", err)
	}
	if current, _ := m.load(); !slices.Equal(current.Dropped, []string{"10.88.0.1"}) || !current.Document.Members[0].Cut {
		t.Fatalf("record %+v", current)
	}
	if len(run.called("wg set")) != 0 || len(run.called("iptables -w -I")) != 0 {
		t.Fatalf("calls %v", run.calls)
	}
}

func TestADropNeverNamesThisServer(t *testing.T) {
	m, run := networkMesh(t)
	_, peer := joined(t, m)
	own := ownKeys(t, m).Public
	for _, args := range []map[string]string{
		{"node": peerNode, "key": own, "address": "10.88.0.1"},
		{"node": peerNode, "key": peer.Public, "address": "10.88.0.2"},
	} {
		if _, err := call(t, m, "drop", args); err == nil || !strings.Contains(err.Error(), "does not drop itself") {
			t.Fatalf("%v: %v", args, err)
		}
	}
	call(t, m, "rekey", nil)
	if _, err := call(t, m, "drop", map[string]string{"node": peerNode, "key": ownKeys(t, m).Public, "address": "10.88.0.1"}); err == nil {
		t.Fatal("a drop named this server's new key")
	}
	if current, _ := m.load(); len(current.Dropped) != 0 || len(run.called("iptables-restore")) != 0 {
		t.Fatalf("record %+v calls %v", current, run.calls)
	}
}
