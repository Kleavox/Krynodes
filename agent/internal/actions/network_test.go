package actions

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/seal"
)

const (
	peerNode     = "11111111-1111-4111-8111-111111111111"
	peerEndpoint = "141.95.0.21:51820"
	wg0Address   = `{"ifname":"wg0","mtu":1420,"linkinfo":{"info_kind":"wireguard"},"addr_info":[{"family":"inet","local":"10.0.0.1","prefixlen":24}]}`
)

var testPSK = []byte("0123456789abcdef0123456789abcdef")

func networkExecutor(t *testing.T) (Executor, *fakeRun) {
	t.Helper()
	executor, run := securityExecutor(t)
	rootFile(t, executor, "/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n")
	rootFile(t, executor, "/sys/module/wireguard/version", "1.0.0\n")
	rootFile(t, executor, "/usr/bin/wg", "")
	rootFile(t, executor, "/etc/hosts", "127.0.0.1 localhost\n")
	rootFile(t, executor, "/etc/ufw/ufw.conf", "ENABLED=yes\n")
	run.respond["ip -d -j addr show"] = `[{"ifname":"eth0","mtu":1500,"addr_info":[{"family":"inet","local":"141.95.0.30","prefixlen":24}]},` + wg0Address + `]`
	run.respond["ip -j route show default"] = `[{"dev":"eth0"}]`
	run.respond["wg show all listen-port"] = "wg0\t51820\n"
	return executor, run
}

func networkRequest(t *testing.T, id, action string, args map[string]string) Request {
	t.Helper()
	return signedRequest(t, Command{ID: id, Kind: "network", Name: "kry0", Action: action, Args: args})
}

func askNetwork(t *testing.T, id, action string, args map[string]string) Request {
	t.Helper()
	asked := request(t, id, "network", "kry0", action, executorNow.Add(10*time.Minute))
	asked.Signed = nil
	if args != nil {
		encoded, err := json.Marshal(args)
		if err != nil {
			t.Fatal(err)
		}
		asked.Attachment = base64.RawURLEncoding.EncodeToString(encoded)
	}
	return asked
}

func applyDocument(t *testing.T, id string, document network.Document) Request {
	t.Helper()
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return Request{ID: id, Kind: "network", Name: "kry0", Action: "apply", ExpiresAt: executorNow.Add(time.Hour).Format(time.RFC3339Nano), Signed: testSigner(t).document(t, body)}
}

func hostRun(t *testing.T, executor Executor, request Request) Result {
	t.Helper()
	hostQueue(t, executor, request)
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	return readResult(t, executor, request.ID)
}

func prepared(t *testing.T, executor Executor) network.Keys {
	t.Helper()
	if result := hostRun(t, executor, networkRequest(t, idA, "prepare", map[string]string{"range": "10.88.0.0/24", "port": "51821"})); !result.OK {
		t.Fatalf("prepare: %+v", result)
	}
	keys, err := network.Load(executor.networkDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func twoMembers(t *testing.T, executor Executor, version int, keys network.Keys, peer network.Keys) network.Document {
	t.Helper()
	sealed, err := seal.Seal(seal.Public(mustKey(t, executor)), testPSK)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := peerEndpoint
	return network.Document{V: 1, Version: version, Range: "10.88.0.0/24", Port: 51820, MTU: 1420, Blocked: []string{}, Members: []network.Member{
		{Node: peerNode, Name: "io", Address: "10.88.0.1", Key: peer.Public, Signer: peer.Signer, Port: 51820, Endpoint: &endpoint, PSK: map[string]string{testNode: "eyJ2IjoxfQ"}},
		{Node: testNode, Name: "vps-2", Address: "10.88.0.2", Key: keys.Public, Signer: keys.Signer, Port: 51821, PSK: map[string]string{peerNode: sealed}},
	}}
}

func peerKeys(t *testing.T) (network.Keys, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "peer")
	keys, err := network.Load(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	return keys, dir
}

func joinedServer(t *testing.T) (Executor, *fakeRun, network.Keys, network.Keys, string) {
	t.Helper()
	executor, run := networkExecutor(t)
	keys := prepared(t, executor)
	peer, peerDir := peerKeys(t)
	if result := hostRun(t, executor, applyDocument(t, idB, twoMembers(t, executor, 1, keys, peer))); !result.OK {
		t.Fatalf("join: %+v", result)
	}
	return executor, run, keys, peer, peerDir
}

func readRoot(t *testing.T, executor Executor, path string) string {
	t.Helper()
	body, err := os.ReadFile(executor.path(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}

func before(t *testing.T, calls []string, first, second string) {
	t.Helper()
	a, b := slices.Index(calls, first), slices.Index(calls, second)
	if a < 0 || b < 0 || a > b {
		t.Fatalf("want %q before %q in %v", first, second, calls)
	}
}

func TestAServerJoinsInTheOrderTheSpecSays(t *testing.T) {
	executor, run := networkExecutor(t)
	os.Remove(executor.path("/usr/bin/wg"))
	result := hostRun(t, executor, networkRequest(t, idA, "prepare", map[string]string{"range": "10.88.0.0/24", "port": "51821"}))
	var answer struct {
		Key, Signer string
		Port        int
		MTU         *int
	}
	if err := json.Unmarshal([]byte(result.Output), &answer); !result.OK || err != nil || answer.Port != 51821 || answer.MTU == nil || *answer.MTU != 1500 || answer.Key == "" || answer.Signer == "" {
		t.Fatalf("prepare %+v (%v)", result, err)
	}
	if !slices.Contains(run.calls, "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -q wireguard-tools") || !executor.readNetwork().Tools {
		t.Fatalf("the tools were not installed as Krynodes': %v", run.calls)
	}
	keys, _ := network.Load(executor.networkDir(), false)
	peer, _ := peerKeys(t)
	run.calls = nil
	if result := hostRun(t, executor, applyDocument(t, idB, twoMembers(t, executor, 1, keys, peer))); !result.OK {
		t.Fatalf("join %+v", result)
	}
	before(t, run.calls, "ufw allow 51821/udp comment krynodes-network", "ufw allow in on kry0 comment krynodes-network")
	before(t, run.calls, "ufw allow in on kry0 comment krynodes-network", "systemctl enable --now wg-quick@kry0.service")
	before(t, run.calls, "systemctl enable --now wg-quick@kry0.service", "systemctl daemon-reload")
	config := readRoot(t, executor, network.ConfigPath)
	if !strings.Contains(config, "ListenPort = 51821\n") || !strings.Contains(config, "AllowedIPs = 10.88.0.1/32\n") || !strings.Contains(config, "PresharedKey = "+base64.StdEncoding.EncodeToString(testPSK)+"\n") || !strings.Contains(config, "Endpoint = "+peerEndpoint+"\n") {
		t.Fatalf("config:\n%s", config)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(executor.path(network.ConfigPath)); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("config mode %v %v", info.Mode(), err)
		}
	}
	if readRoot(t, executor, network.DropInPath) != network.DropInBody {
		t.Fatal("the Docker drop-in is missing")
	}
	if hosts := readRoot(t, executor, network.HostsPath); !strings.Contains(hosts, "10.88.0.1 io.kry\n10.88.0.2 vps-2.kry\n") || !strings.HasPrefix(hosts, "127.0.0.1 localhost\n") {
		t.Fatalf("hosts:\n%s", hosts)
	}
	for _, call := range run.calls {
		if strings.Contains(call, "wg0") {
			t.Fatalf("Krynodes touched wg0: %s", call)
		}
	}
}

func TestPrepareStaysOutOfWhatTheServerAlreadyUses(t *testing.T) {
	executor, run := networkExecutor(t)
	if result := hostRun(t, executor, networkRequest(t, idA, "prepare", map[string]string{"range": "10.88.0.0/24", "port": "51820"})); result.OK || !strings.Contains(result.Output, "51820/udp is taken") {
		t.Fatalf("port of wg0: %+v", result)
	}
	run.respond["docker network ls -q"] = "n1\n"
	run.respond["docker network inspect --format {{range .IPAM.Config}}{{.Subnet}} {{end}} n1"] = "10.88.0.0/24 \n"
	if result := hostRun(t, executor, networkRequest(t, idB, "prepare", map[string]string{"range": "10.88.0.0/24", "port": "51821"})); result.OK || !strings.Contains(result.Output, "10.88.0.0/24 is already used") {
		t.Fatalf("range of a Docker network: %+v", result)
	}
}

func TestUnprepareTakesTheKeyAndOnlyToolsKrynodesAdded(t *testing.T) {
	executor, run := networkExecutor(t)
	os.Remove(executor.path("/usr/bin/wg"))
	prepared(t, executor)
	rootFile(t, executor, "/usr/bin/wg", "")
	run.respond["ip -d -j addr show"] = `[{"ifname":"eth0","mtu":1500,"addr_info":[]}]`
	if result := hostRun(t, executor, networkRequest(t, idB, "unprepare", nil)); !result.OK || result.Output != "removed" {
		t.Fatalf("unprepare %+v", result)
	}
	if _, err := os.Stat(executor.networkDir()); !os.IsNotExist(err) {
		t.Fatalf("the key stays: %v", err)
	}
	if !slices.Contains(run.calls, "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 purge -y -q wireguard-tools") {
		t.Fatalf("Krynodes' tools stay: %v", run.calls)
	}

	executor, run = networkExecutor(t)
	prepared(t, executor)
	hostRun(t, executor, networkRequest(t, idB, "unprepare", nil))
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "purge") }) {
		t.Fatalf("the owner's tools were removed: %v", run.calls)
	}
}

func TestLeavingRemovesExactlyWhatKrynodesMade(t *testing.T) {
	executor, run, _, peer, _ := joinedServer(t)
	run.respond["ufw status numbered"] = "[ 1] 22/tcp ALLOW IN Anywhere\n[ 2] 51821/udp ALLOW IN Anywhere # krynodes-network\n[ 3] Anywhere on kry0 ALLOW IN Anywhere # krynodes-network\n[ 4] 51820/udp ALLOW IN Anywhere # wg0\n"
	run.calls = nil
	endpoint := peerEndpoint
	alone := network.Document{V: 1, Version: 2, Range: "10.88.0.0/24", Port: 51820, MTU: 1420, Members: []network.Member{
		{Node: peerNode, Name: "io", Address: "10.88.0.1", Key: peer.Public, Signer: peer.Signer, Port: 51820, Endpoint: &endpoint, PSK: map[string]string{}},
	}}
	if result := hostRun(t, executor, applyDocument(t, idC, alone)); !result.OK {
		t.Fatalf("leave %+v", result)
	}
	for _, call := range []string{"systemctl disable --now wg-quick@kry0.service", "ufw --force delete 3", "ufw --force delete 2", "systemctl daemon-reload"} {
		if !slices.Contains(run.calls, call) {
			t.Fatalf("missing %q in %v", call, run.calls)
		}
	}
	for _, call := range run.calls {
		if strings.Contains(call, "wg0") || call == "ufw --force delete 4" || call == "ufw --force delete 1" {
			t.Fatalf("removed what is not Krynodes': %s", call)
		}
	}
	for _, path := range []string{network.ConfigPath, network.DropInPath} {
		if _, err := os.Stat(executor.path(path)); !os.IsNotExist(err) {
			t.Fatalf("%s stays", path)
		}
	}
	if hosts := readRoot(t, executor, network.HostsPath); hosts != "127.0.0.1 localhost\n" {
		t.Fatalf("hosts:\n%s", hosts)
	}
	if record := executor.readNetwork(); record.Joined || record.Key != "" || record.Applied.Version != 2 {
		t.Fatalf("record %+v", record)
	}
	if _, err := os.Stat(executor.networkDir()); !os.IsNotExist(err) {
		t.Fatal("the key stays")
	}
}

func TestOnlyTheNewestDocumentIsAppliedAndNothingIsRewritten(t *testing.T) {
	executor, run, keys, peer, _ := joinedServer(t)
	if result := hostRun(t, executor, applyDocument(t, idC, twoMembers(t, executor, 3, keys, peer))); !result.OK {
		t.Fatalf("v3 %+v", result)
	}
	config := readRoot(t, executor, network.ConfigPath)
	run.calls = nil
	for index, version := range []int{2, 3} {
		id := []string{"0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a04", "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a05"}[index]
		document := twoMembers(t, executor, version, keys, peer)
		document.Members[0].Address = "10.88.0.9"
		if result := hostRun(t, executor, applyDocument(t, id, document)); result.OK || !strings.Contains(result.Output, "not newer") {
			t.Fatalf("v%d %+v", version, result)
		}
	}
	if readRoot(t, executor, network.ConfigPath) != config || len(run.calls) != 0 {
		t.Fatalf("an old document changed something: %v", run.calls)
	}
}

func TestADocumentWithAWidePeerRangeWritesNothing(t *testing.T) {
	executor, run := networkExecutor(t)
	keys := prepared(t, executor)
	peer, _ := peerKeys(t)
	for index, address := range []string{"0.0.0.0/0", "::/0", "10.88.0.0/24", "10.89.0.1"} {
		document := twoMembers(t, executor, 1, keys, peer)
		document.Members[0].Address = address
		id := []string{idB, idC, "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a04", "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a05"}[index]
		run.calls = nil
		if result := hostRun(t, executor, applyDocument(t, id, document)); result.OK {
			t.Fatalf("%s was applied", address)
		}
		if _, err := os.Stat(executor.path(network.ConfigPath)); !os.IsNotExist(err) || len(run.calls) != 0 {
			t.Fatalf("%s wrote something: %v", address, run.calls)
		}
	}
	unsigned := applyDocument(t, idA, twoMembers(t, executor, 1, keys, peer))
	unsigned.ID = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a06"
	unsigned.Signed = nil
	if result := hostRun(t, executor, unsigned); result.OK || !strings.Contains(result.Output, "not signed") {
		t.Fatalf("unsigned %+v", result)
	}
}

func TestUse1380RestartsWithTheClampAndALaterDocumentTakesItOff(t *testing.T) {
	executor, run, keys, peer, _ := joinedServer(t)
	smaller := twoMembers(t, executor, 2, keys, peer)
	mtu := 1380
	smaller.Members[1].MTU = &mtu
	run.calls = nil
	if result := hostRun(t, executor, applyDocument(t, idC, smaller)); !result.OK || !slices.Contains(run.calls, "systemctl restart wg-quick@kry0.service") {
		t.Fatalf("1380 %+v %v", result, run.calls)
	}
	if config := readRoot(t, executor, network.ConfigPath); !strings.Contains(config, "MTU = 1380\nPostUp = iptables -w -t mangle -A POSTROUTING -o kry0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340\n") {
		t.Fatalf("config:\n%s", config)
	}
	run.calls = nil
	if result := hostRun(t, executor, applyDocument(t, "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a04", twoMembers(t, executor, 3, keys, peer))); !result.OK || !slices.Contains(run.calls, "systemctl restart wg-quick@kry0.service") {
		t.Fatalf("back %+v %v", result, run.calls)
	}
	if config := readRoot(t, executor, network.ConfigPath); strings.Contains(config, "PostUp") || !strings.Contains(config, "MTU = 1420\n") {
		t.Fatalf("config:\n%s", config)
	}
	run.calls = nil
	hostRun(t, executor, applyDocument(t, "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a05", twoMembers(t, executor, 4, keys, peer)))
	if slices.Contains(run.calls, "systemctl restart wg-quick@kry0.service") || !slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "wg syncconf kry0 ") }) {
		t.Fatalf("an unchanged MTU restarted kry0: %v", run.calls)
	}
}

func TestAnAnnouncedKeyIsTakenOnlyWithTheMembersSignature(t *testing.T) {
	executor, run, _, peer, peerDir := joinedServer(t)
	fresh, err := network.Rekey(peerDir)
	if err != nil {
		t.Fatal(err)
	}
	stranger, _ := peerKeys(t)
	bad := askNetwork(t, idC, "announce", map[string]string{"node": peerNode, "key": fresh.Public, "signature": stranger.Announce(peerNode)})
	if result := hostRun(t, executor, bad); result.OK || !strings.Contains(result.Output, "not signed by io") {
		t.Fatalf("bad %+v", result)
	}
	if config := readRoot(t, executor, network.ConfigPath); !strings.Contains(config, "PublicKey = "+peer.Public) {
		t.Fatal("a bad announcement changed the key")
	}
	run.calls = nil
	good := askNetwork(t, "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a04", "announce", map[string]string{"node": peerNode, "key": fresh.Public, "signature": fresh.Announce(peerNode)})
	if result := hostRun(t, executor, good); !result.OK {
		t.Fatalf("good %+v", result)
	}
	if config := readRoot(t, executor, network.ConfigPath); !strings.Contains(config, "PublicKey = "+fresh.Public) || strings.Contains(config, peer.Public) {
		t.Fatalf("config:\n%s", config)
	}
	if !slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "wg syncconf kry0 ") }) {
		t.Fatalf("the running kry0 was not told: %v", run.calls)
	}
}

func TestAMemberMarkedForNewKeysMakesThemWhenItIsBack(t *testing.T) {
	executor, _, keys, peer, _ := joinedServer(t)
	marked := twoMembers(t, executor, 2, keys, peer)
	marked.Members[1].Rekey = true
	if result := hostRun(t, executor, applyDocument(t, idC, marked)); !result.OK {
		t.Fatalf("%+v", result)
	}
	record := executor.readNetwork()
	if record.Key == keys.Public || record.Announce == nil || record.Announce.Key != record.Key || !network.Announced(keys.Signer, testNode, record.Key, record.Announce.Signature) {
		t.Fatalf("record %+v", record)
	}
	if config := readRoot(t, executor, network.ConfigPath); strings.Contains(config, "PrivateKey = "+keys.Private) {
		t.Fatal("the old private key stays")
	}
}

func TestAProbeIsLimitedAndSaysWhetherItListened(t *testing.T) {
	executor, _ := networkExecutor(t)
	probeListen, probeOn = 50*time.Millisecond, netip.MustParseAddr("127.0.0.1")
	t.Cleanup(func() { probeListen, probeOn = 20*time.Second, netip.IPv6Unspecified() })
	peers := make([]string, 17)
	for index := range peers {
		peers[index] = "203.0.113." + string(rune('1'+index%9)) + ":51820"
	}
	writeRequest(t, executor.RequestDir, idA+".json", askNetwork(t, idA, "probe", map[string]string{"port": "51900", "peers": strings.Join(peers, " ")}))
	writeRequest(t, executor.RequestDir, idB+".json", askNetwork(t, idB, "probe", map[string]string{"port": "51900", "peers": "127.0.0.1:51901"}))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, idA); result.OK || !strings.Contains(result.Output, "1 to 16 peers") {
		t.Fatalf("17 peers %+v", result)
	}
	var answer struct {
		Listened *bool     `json:"listened"`
		Arrived  *[]string `json:"arrived"`
	}
	if result := readResult(t, executor, idB); !result.OK || json.Unmarshal([]byte(result.Output), &answer) != nil || answer.Listened == nil || answer.Arrived == nil {
		t.Fatalf("probe %+v", result)
	}
}

func TestATestCountsBeforeAndAfterAndWalksLargeSizesDown(t *testing.T) {
	executor, run, _, peer, _ := joinedServer(t)
	line := func(handshake, rx, tx string) string {
		return "cHJpdmF0ZQ==\tcHVibGlj\t51821\toff\n" + peer.Public + "\t(none)\t" + peerEndpoint + "\t10.88.0.1/32\t" + handshake + "\t" + rx + "\t" + tx + "\t25\n"
	}
	run.sequence = map[string][]string{"wg show kry0 dump": {line("1790000000", "100", "200"), line("1790000060", "400", "900")}}
	run.respond["systemctl is-active wg-quick@kry0.service"] = "active\n"
	run.respond["ping -n -c 5 -i 0.2 -W 1 -I kry0 10.88.0.1"] = "5 packets transmitted, 4 received, 20% packet loss, time 804ms\nrtt min/avg/max/mdev = 1.1/4.2/8.0/1.0 ms\n"
	run.respond["ping -n -c 2 -W 1 -M do -s 1352 -I kry0 10.88.0.1"] = "2 packets transmitted, 2 received, 0% packet loss\n"
	run.respond["ip -j route get 141.95.0.21"] = `[{"dst":"141.95.0.21","prefsrc":"141.95.0.30"}]`
	writeRequest(t, executor.RequestDir, idC+".json", askNetwork(t, idC, "test", map[string]string{"peer": peerNode, "address": "10.88.0.1", "mtu": "1420"}))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	result := readResult(t, executor, idC)
	var found struct {
		Up, HasKey    bool
		Version       *int
		Clock         int64
		PublicAddress *string
		Handshakes    struct {
			Sent, Received, Answered int
			Third                    *bool
		}
		Small struct {
			Sent, Lost int
			MS         *float64
		}
		Large struct {
			Passed *int
			Tried  []int
		}
	}
	if err := json.Unmarshal([]byte(result.Output), &found); !result.OK || err != nil {
		t.Fatalf("%+v (%v)", result, err)
	}
	if !found.Up || !found.HasKey || found.Version == nil || *found.Version != 1 || found.Clock != executorNow.Unix() || found.PublicAddress == nil || *found.PublicAddress != "141.95.0.30" {
		t.Fatalf("found %+v", found)
	}
	if found.Handshakes.Sent != 700 || found.Handshakes.Received != 300 || found.Handshakes.Answered != 1 || found.Handshakes.Third != nil {
		t.Fatalf("handshakes %+v", found.Handshakes)
	}
	if found.Small.Sent != 5 || found.Small.Lost != 1 || found.Small.MS == nil || *found.Small.MS != 4.2 {
		t.Fatalf("small %+v", found.Small)
	}
	if found.Large.Passed == nil || *found.Large.Passed != 1380 || !slices.Equal(found.Large.Tried, []int{1420, 1400, 1380}) {
		t.Fatalf("large %+v", found.Large)
	}
}

func TestTheLinksRideTheHeartbeat(t *testing.T) {
	executor, run, keys, peer, _ := joinedServer(t)
	recent := executorNow.Add(-20 * time.Second).Unix()
	run.respond["wg show kry0 dump"] = "cHJpdmF0ZQ==\tcHVibGlj\t51821\toff\n" + peer.Public + "\t(none)\t" + peerEndpoint + "\t10.88.0.1/32\t" + strconv.FormatInt(recent, 10) + "\t310\t1200\t25\n"
	run.respond["ping -n -c 1 -W 1 -I kry0 10.88.0.1"] = "64 bytes from 10.88.0.1: icmp_seq=1 ttl=64 time=4.12 ms\n"
	executor.WriteLinks(context.Background())
	relay := &Relay{RequestDir: executor.RequestDir, StateDir: executor.StateDir, Now: executor.Now}
	beat := relay.NetworkBeat()
	if beat == nil || beat.Version != 1 || beat.Key == nil || *beat.Key != keys.Public || len(beat.Links) != 1 || beat.Links[0].MS == nil || *beat.Links[0].MS != 4.12 || *beat.Links[0].Handshake != recent {
		t.Fatalf("beat %+v", beat)
	}
	newer, err := json.Marshal(twoMembers(t, executor, 2, keys, peer))
	if err != nil {
		t.Fatal(err)
	}
	older, _ := json.Marshal(twoMembers(t, executor, 1, keys, peer))
	if err := relay.NetworkReply(&reporter.NetworkReply{Document: testSigner(t).document(t, older)}); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(executor.RequestDir); len(entries) != 0 {
		t.Fatalf("an applied version was queued again: %v", entries)
	}
	if err := relay.NetworkReply(&reporter.NetworkReply{Document: testSigner(t).document(t, newer)}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(executor.RequestDir)
	if len(entries) != 1 {
		t.Fatalf("queued %v", entries)
	}
	var queuedApply Request
	if err := readJSON(filepath.Join(executor.RequestDir, entries[0].Name()), &queuedApply); err != nil || queuedApply.Kind != "network" || queuedApply.Action != "apply" {
		t.Fatalf("queued %+v (%v)", queuedApply, err)
	}
}

func TestEndpointsChangeOnlyThePeersOfTheNetwork(t *testing.T) {
	executor, run, _, peer, _ := joinedServer(t)
	stranger, _ := peerKeys(t)
	writeRequest(t, executor.RequestDir, idC+".json", askNetwork(t, idC, "endpoints", map[string]string{"endpoints": peer.Public + " 141.95.0.99:51820 " + stranger.Public + " 203.0.113.9:51820"}))
	run.calls = nil
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, idC); !result.OK || !slices.Contains(run.calls, "wg set kry0 peer "+peer.Public+" endpoint 141.95.0.99:51820") {
		t.Fatalf("%+v %v", result, run.calls)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, stranger.Public) }) {
		t.Fatalf("a stranger's endpoint was set: %v", run.calls)
	}
}

func TestTheInventoryNamesWhatStacksPointAt(t *testing.T) {
	executor, _, _, _, _ := joinedServer(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    environment:\n      DB: postgres://io.kry:5432/shop\n      OLD: 10.89.0.1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("CACHE=10.88.0.1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	executor.Collect = func(context.Context, []string) (Snapshot, error) {
		return Snapshot{Compose: true, Docker: "ready", Stacks: []Stack{{Project: "shop", Directory: dir, Files: []string{filepath.Join(dir, "compose.yaml")}}}}, nil
	}
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	var inventory Inventory
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.Network == nil || inventory.Network.Prepared != nil || !slices.Equal(inventory.Network.Points, []reporter.NetworkPoint{{Stack: "shop", Target: "10.88.0.1"}, {Stack: "shop", Target: "io.kry"}}) {
		t.Fatalf("network %+v", inventory.Network)
	}
}

func TestAPreparedServerSaysSoInItsInventory(t *testing.T) {
	executor, _ := networkExecutor(t)
	keys := prepared(t, executor)
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	var inventory Inventory
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.Network == nil || inventory.Network.Prepared == nil || inventory.Network.Prepared.Key != keys.Public || inventory.Network.Prepared.Port != 51821 {
		t.Fatalf("network %+v", inventory.Network)
	}
}

func TestUninstallTakesTheServerOutOfTheNetwork(t *testing.T) {
	executor, run, _, _, _ := joinedServer(t)
	run.calls = nil
	removal := executor.Uninstall(context.Background(), false)
	if !slices.Contains(run.calls, "systemctl disable --now wg-quick@kry0.service") || !slices.Contains(removal.TurnedOff, "This server left the private network") {
		t.Fatalf("%v %+v", run.calls, removal)
	}
	if _, err := os.Stat(executor.path(network.ConfigPath)); !os.IsNotExist(err) {
		t.Fatal("kry0.conf stays")
	}
}
