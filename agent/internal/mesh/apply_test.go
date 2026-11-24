package mesh

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

const (
	testOrigin  = "https://kry.example.org"
	testRPID    = "kry.example.org"
	sealedPSK   = "c2VhbGVkLWZvci10aGlzLXNlcnZlcg"
	kryPath     = "/usr/local/bin/kry"
	laptopNode  = "99999999-9999-4999-8999-999999999999"
	thirdNode   = "33333333-3333-4333-8333-333333333333"
	behindNode  = "44444444-4444-4444-8444-444444444444"
	strangeNode = "55555555-5555-4555-8555-555555555555"
	selfPublic  = "203.0.113.30:51821"
	ipForward   = "/proc/sys/net/ipv4/ip_forward"
	ip6Forward  = "/proc/sys/net/ipv6/conf/all/forwarding"
	exitOutOf   = "-A FORWARD -i kry0 ! -o kry0 -j KRY-EXIT"
	exitInto    = "-A FORWARD ! -i kry0 -o kry0 -j KRY-EXIT"
	apartOf     = "-A FORWARD -i kry0 -o kry0 -j DROP"
	hostsBefore = "127.0.0.1 localhost\n"
)

var testPSK = []byte("0123456789abcdef0123456789abcdef")

type signer struct {
	trust   trust.Trust
	passkey *ecdsa.PrivateKey
	session *ecdsa.PrivateKey
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	passkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	session, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&passkey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{
		trust: trust.Trust{V: 1, NodeID: selfNode, Origin: testOrigin, RPID: testRPID, Version: 1, Keys: []trust.TrustKey{{ID: "cred-1", Name: "Laptop", Alg: -7, PublicKey: base64.RawURLEncoding.EncodeToString(der)}},
			Core: []string{"cred-1"}, Access: []string{"cred-1"}, RequireUV: true},
		passkey: passkey,
		session: session,
	}
}

func digestOf(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func (s *signer) sign(t *testing.T, body []byte) string {
	t.Helper()
	b64 := base64.RawURLEncoding
	sessionKey, err := x509.MarshalPKIXPublicKey(&s.session.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	grant, _ := json.Marshal(map[string]any{"v": 1, "rpId": testRPID, "sessionKey": b64.EncodeToString(sessionKey),
		"issuedAt": testNow.Add(-time.Minute).Format(time.RFC3339Nano), "expiresAt": testNow.Add(14 * time.Minute).Format(time.RFC3339Nano), "nonce": "bm9uY2U"})
	client, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": b64.EncodeToString(digestOf(grant)), "origin": testOrigin, "crossOrigin": false})
	authData := append(digestOf([]byte(testRPID)), 0x05, 0, 0, 0, 7)
	assertion, err := ecdsa.SignASN1(rand.Reader, s.passkey, digestOf(append(slices.Clone(authData), digestOf(client)...)))
	if err != nil {
		t.Fatal(err)
	}
	r, sv, err := ecdsa.Sign(rand.Reader, s.session, digestOf(append([]byte("krynodes-document-v1\n"), body...)))
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	sv.FillBytes(signature[32:])
	signed, err := json.Marshal(trust.SignedDocument{
		Grant:     trust.SignedGrant{Grant: b64.EncodeToString(grant), Assertion: trust.Assertion{CredentialID: "cred-1", AuthenticatorData: b64.EncodeToString(authData), ClientDataJSON: b64.EncodeToString(client), Signature: b64.EncodeToString(assertion)}},
		Document:  b64.EncodeToString(body),
		Signature: b64.EncodeToString(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

type fakeTables struct {
	mu     sync.Mutex
	rules  map[string][]string
	policy map[string]string
	next   network.Runner
}

func builtInChain(chain string) bool {
	return slices.Contains([]string{"INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING"}, chain)
}

func tableFail() ([]byte, int, error) {
	return []byte("iptables: No chain/target/match by that name."), 1, errors.New("exit status 1")
}

func (f *fakeTables) run(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	output, code, err := f.next(ctx, name, args...)
	tool, restore := strings.CutSuffix(name, "-restore")
	if err != nil || (tool != "iptables" && tool != "ip6tables") {
		return output, code, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(args) > 0 && args[0] == "-w" {
		args = args[1:]
	}
	if restore {
		body, readErr := os.ReadFile(args[len(args)-1])
		if readErr != nil {
			return tableFail()
		}
		table := "filter"
		for line := range strings.SplitSeq(string(body), "\n") {
			switch {
			case strings.HasPrefix(line, "*"):
				table = line[1:]
			case strings.HasPrefix(line, ":"):
				f.rules[tool+" "+table+" "+strings.Fields(line[1:])[0]] = []string{}
			case strings.HasPrefix(line, "-A "):
				key := tool + " " + table + " " + strings.Fields(line)[1]
				f.rules[key] = append(f.rules[key], line)
			}
		}
		return nil, 0, nil
	}
	table := "filter"
	if len(args) > 2 && args[0] == "-t" {
		table, args = args[1], args[2:]
	}
	if len(args) == 1 && args[0] == "-S" {
		var lines []string
		for _, chain := range []string{"INPUT", "FORWARD", "OUTPUT"} {
			lines = append(lines, "-P "+chain+" "+cmp.Or(f.policy[tool+" "+table+" "+chain], "ACCEPT"))
		}
		var all []string
		for _, key := range slices.Sorted(maps.Keys(f.rules)) {
			if chain, found := strings.CutPrefix(key, tool+" "+table+" "); found {
				if !builtInChain(chain) {
					lines = append(lines, "-N "+chain)
				}
				all = append(all, f.rules[key]...)
			}
		}
		return []byte(strings.Join(append(lines, all...), "\n") + "\n"), 0, nil
	}
	if len(args) < 2 {
		return output, code, err
	}
	verb, chain, rest := args[0], args[1], args[2:]
	key := tool + " " + table + " " + chain
	current, exists := f.rules[key]
	exists = exists || builtInChain(chain)
	if verb == "-I" && len(rest) > 0 {
		if _, numbered := strconv.Atoi(rest[0]); numbered == nil {
			rest = rest[1:]
		}
	}
	line := strings.Join(append([]string{"-A", chain}, rest...), " ")
	target := ""
	if index := slices.Index(rest, "-j"); index >= 0 && index+1 < len(rest) {
		target = rest[index+1]
	}
	switch verb {
	case "-S":
		if !exists {
			return tableFail()
		}
		head := "-N " + chain
		if builtInChain(chain) {
			head = "-P " + chain + " " + cmp.Or(f.policy[key], "ACCEPT")
		}
		return []byte(strings.Join(append([]string{head}, current...), "\n") + "\n"), 0, nil
	case "-P":
		if !builtInChain(chain) || len(rest) != 1 {
			return tableFail()
		}
		f.policy[key] = rest[0]
	case "-N":
		if exists {
			return []byte("iptables: Chain already exists."), 1, errors.New("exit status 1")
		}
		f.rules[key] = []string{}
	case "-F":
		if !exists {
			return tableFail()
		}
		f.rules[key] = []string{}
	case "-X":
		referenced := false
		for other, lines := range f.rules {
			referenced = referenced || (strings.HasPrefix(other, tool+" "+table+" ") && slices.ContainsFunc(lines, func(rule string) bool { return strings.HasSuffix(rule, "-j "+chain) }))
		}
		if !exists || builtInChain(chain) || len(current) > 0 || referenced {
			return tableFail()
		}
		delete(f.rules, key)
	case "-A", "-I":
		if _, known := f.rules[tool+" "+table+" "+target]; !exists || ((strings.HasPrefix(target, "KRY-") || target == network.DockerUser) && !known) {
			return tableFail()
		}
		if verb == "-A" {
			f.rules[key] = append(current, line)
		} else {
			f.rules[key] = append([]string{line}, current...)
		}
	case "-C":
		if !exists || !slices.Contains(current, line) {
			return tableFail()
		}
	case "-D":
		index := slices.Index(current, line)
		if index < 0 {
			return tableFail()
		}
		f.rules[key] = slices.Delete(slices.Clone(current), index, index+1)
	default:
		return output, code, err
	}
	return nil, 0, nil
}

func (f *fakeTables) chain(tool, table, chain string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.rules[tool+" "+table+" "+chain])
}

func (f *fakeTables) has(tool, table, chain string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.rules[tool+" "+table+" "+chain]
	return ok
}

func (f *fakeTables) String() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var text strings.Builder
	for _, key := range slices.Sorted(maps.Keys(f.rules)) {
		if len(f.rules[key]) == 0 && builtInChain(key[strings.LastIndex(key, " ")+1:]) {
			continue
		}
		fmt.Fprintf(&text, "%s: %s\n", key, strings.Join(f.rules[key], " | "))
	}
	return text.String()
}

func v6route(device string) string {
	return "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 " + device + "\n"
}

type testNet struct {
	m                                 *Mesh
	run                               *fakeRun
	tables                            *fakeTables
	signer                            *signer
	keys, peer, third, behind, laptop network.Keys

	mu   sync.Mutex
	sent []any
}

func (n *testNet) send(message any) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, message)
	return nil
}

func (n *testNet) messages() []any {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.sent)
}

func newNet(t *testing.T) *testNet {
	t.Helper()
	m, run := networkMesh(t)
	n := &testNet{m: m, run: run, signer: newSigner(t), keys: ownKeys(t, m), peer: peerKeys(t), third: peerKeys(t), behind: peerKeys(t), laptop: peerKeys(t)}
	n.tables = &fakeTables{rules: map[string][]string{}, policy: map[string]string{}, next: run.run}
	m.Run = n.tables.run
	trusted := n.signer.trust
	m.Trust = func() trust.Trust { return trusted }
	m.Executable = kryPath
	m.Send = n.send
	m.Unseal = func(sealed string) ([]byte, error) {
		if sealed == sealedPSK {
			return testPSK, nil
		}
		return nil, errors.New("the sealed message is not for this server")
	}
	rootFile(t, m, network.HostsPath, hostsBefore)
	rootFile(t, m, "/proc/net/route", routes4)
	rootFile(t, m, ipForward, "0\n")
	rootFile(t, m, ip6Forward, "0\n")
	prepare(t, m)
	return n
}

type change func(self *network.Member, members []network.Member) []network.Member

func asIs(_ *network.Member, members []network.Member) []network.Member {
	return members
}

func pair(_ *network.Member, members []network.Member) []network.Member {
	return members[:1]
}

func withoutLaptop(_ *network.Member, members []network.Member) []network.Member {
	return slices.DeleteFunc(members, network.Member.IsLaptop)
}

func behindNAT(self *network.Member, members []network.Member) []network.Member {
	self.Endpoint, self.NAT = nil, true
	return members
}

func exitOn(self *network.Member, members []network.Member) []network.Member {
	self.Exit = true
	return members
}

func exitOnPrivate(self *network.Member, members []network.Member) []network.Member {
	self.Exit, self.Endpoint = true, nil
	return members
}

func exitOffPrivate(self *network.Member, members []network.Member) []network.Member {
	self.Endpoint = nil
	return members
}

func (n *testNet) applied(t *testing.T) network.Applied {
	t.Helper()
	current, err := n.m.load()
	if err != nil {
		t.Fatal(err)
	}
	return current.Applied
}

func (n *testNet) next(t *testing.T, changes ...change) network.Document {
	t.Helper()
	applied := n.applied(t)
	return n.build(applied.Version+1, applied.Hash, changes...)
}

func (n *testNet) build(version int, parent string, changes ...change) network.Document {
	peerEnd, thirdEnd, ownEnd := peerEndpoint, "203.0.113.23:51820", selfPublic
	self := network.Member{Node: selfNode, Name: "server-1", Address: "10.88.0.2", Key: n.keys.Public, Signer: n.keys.Signer, SealKey: ownSealKey, Port: 51821, Endpoint: &ownEnd}
	members := []network.Member{
		{Node: peerNode, Name: "server-2", Address: "10.88.0.1", Key: n.peer.Public, Signer: n.peer.Signer, SealKey: otherSealKey, Port: 51820, Endpoint: &peerEnd},
		{Node: thirdNode, Name: "server-3", Address: "10.88.0.3", Key: n.third.Public, Signer: n.third.Signer, SealKey: otherSealKey, Port: 51820, Endpoint: &thirdEnd},
		{Node: behindNode, Name: "server-4", Address: "10.88.0.4", Key: n.behind.Public, Signer: n.behind.Signer, SealKey: otherSealKey, Port: 51820, NAT: true},
		{Node: laptopNode, Name: "laptop-1", Address: "10.88.0.9", Key: n.laptop.Public, Signer: n.laptop.Signer, SealKey: otherSealKey, Port: 51820, Kind: "laptop"},
	}
	for _, change := range changes {
		members = change(&self, members)
	}
	members = append(slices.Clone(members), self)
	relayPort := network.FirstRelayPort
	for index := range members {
		members[index].PSK = map[string]string{}
		for _, other := range members {
			if other.Node != members[index].Node && network.Links(members[index], other) {
				members[index].PSK[other.Node] = "eyJ2IjoxfQ"
				if members[index].Node == selfNode {
					members[index].PSK[other.Node] = sealedPSK
				}
			}
		}
		if members[index].IsLaptop() {
			members[index].Relay = network.Relays{}
			for _, other := range members {
				if other.NAT && !other.IsLaptop() && !other.Cut {
					members[index].Relay[other.Node] = relayPort
					relayPort++
				}
			}
		}
	}
	allow := []network.Rule{{From: network.Side{Group: "laptops"}, To: network.Side{Group: "servers"}, Ports: network.Ports{All: true}}}
	if _, ok := member(network.Document{Members: members}, peerNode); ok {
		allow = append(allow, network.Rule{From: network.Side{Node: peerNode}, To: network.Side{Node: selfNode}, Ports: network.Ports{List: []string{"22/tcp"}}})
	}
	return network.Document{V: 1, Version: version, Range: "10.88.0.0/24", Port: 51820, MTU: 1420, Parent: parent, Blocked: []string{}, Members: members, Allow: allow}
}

func body(t *testing.T, document network.Document) []byte {
	t.Helper()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (n *testNet) offer(t *testing.T, document network.Document) reporter.Applied {
	t.Helper()
	return n.m.Document(context.Background(), document.Version, n.signer.sign(t, body(t, document)))
}

func (n *testNet) apply(t *testing.T, changes ...change) network.Document {
	t.Helper()
	document := n.next(t, changes...)
	if applied := n.offer(t, document); !applied.OK {
		t.Fatalf("apply version %d: %+v", document.Version, applied)
	}
	return document
}

func joinedNet(t *testing.T) *testNet {
	t.Helper()
	n := newNet(t)
	n.apply(t, pair)
	n.run.calls = nil
	return n
}

func readRoot(t *testing.T, m *Mesh, path string) string {
	t.Helper()
	raw, err := os.ReadFile(m.path(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

func exists(m *Mesh, path string) bool {
	_, err := os.Stat(m.path(path))
	return err == nil
}

func before(t *testing.T, calls []string, first, second string) {
	t.Helper()
	a := slices.IndexFunc(calls, func(call string) bool { return strings.HasPrefix(call, first) })
	b := slices.IndexFunc(calls, func(call string) bool { return strings.HasPrefix(call, second) })
	if a < 0 || b < 0 || a > b {
		t.Fatalf("want %q before %q in %v", first, second, calls)
	}
}

type world struct {
	config, hosts, tables string
	version               int
}

func (n *testNet) world(t *testing.T) world {
	t.Helper()
	config, _ := os.ReadFile(n.m.path(network.ConfigPath))
	return world{config: string(config), hosts: readRoot(t, n.m, network.HostsPath), tables: n.tables.String(), version: n.applied(t).Version}
}

func TestAServerJoinsInTheOrderTheSpecSays(t *testing.T) {
	m, run := networkMesh(t)
	os.Remove(m.path("/usr/bin/wg"))
	message, err := call(t, m, "prepare", map[string]string{"range": "10.88.0.0/24", "port": "51821"})
	if err != nil || !slices.Contains(run.calls, "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -q wireguard-tools") {
		t.Fatalf("prepare %q %v %v", message, err, run.calls)
	}
	rootFile(t, m, "/usr/bin/wg", "")
	n := &testNet{m: m, run: run, signer: newSigner(t), keys: ownKeys(t, m), peer: peerKeys(t)}
	n.tables = &fakeTables{rules: map[string][]string{}, policy: map[string]string{}, next: run.run}
	trusted := n.signer.trust
	m.Run, m.Trust, m.Executable, m.Send = n.tables.run, func() trust.Trust { return trusted }, kryPath, n.send
	m.Unseal = func(string) ([]byte, error) { return testPSK, nil }
	rootFile(t, m, network.HostsPath, hostsBefore)
	run.calls = nil
	readyAtStart := false
	run.effects = map[string]func(){"systemctl enable --now": func() {
		current, _ := m.load()
		_, _, staged := m.boot(current)
		readyAtStart = staged && exists(m, network.RulesDropInPath) && len(n.tables.chain("iptables", "filter", network.InChain)) > 0
	}}
	applied := n.offer(t, n.next(t, pair))
	if !readyAtStart {
		t.Fatal("kry0 started before its boot step could put the rules in place")
	}
	if !applied.OK || applied.Version != 1 || applied.Type != "applied" || applied.Message != "Applied version 1." {
		t.Fatalf("join %+v", applied)
	}
	before(t, run.calls, "iptables-restore -w --noflush", "ufw allow 51821/udp comment krynodes-network")
	before(t, run.calls, "ip6tables -w -I INPUT 1 -i kry0 -j KRY-IN", "ufw allow 51821/udp comment krynodes-network")
	before(t, run.calls, "ufw allow 51821/udp comment krynodes-network", "ufw allow in on kry0 comment krynodes-network")
	before(t, run.calls, "ufw allow in on kry0 comment krynodes-network", "systemctl daemon-reload")
	before(t, run.calls, "systemctl daemon-reload", "systemctl enable --now wg-quick@kry0.service")
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "wg syncconf") || strings.Contains(call, "wg0") }) {
		t.Fatalf("calls %v", run.calls)
	}
	config := readRoot(t, m, network.ConfigPath)
	if !strings.Contains(config, "ListenPort = 51821\n") || !strings.Contains(config, "AllowedIPs = 10.88.0.1/32\n") || !strings.Contains(config, "PresharedKey = "+base64.StdEncoding.EncodeToString(testPSK)+"\n") || !strings.Contains(config, "Endpoint = "+peerEndpoint+"\n") {
		t.Fatalf("config:\n%s", config)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(m.path(network.ConfigPath)); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("config mode %v %v", info.Mode(), err)
		}
	}
	if readRoot(t, m, network.DropInPath) != network.DropInBody || readRoot(t, m, network.RulesDropInPath) != "[Service]\nExecStartPre=/usr/local/bin/kry network rules\n" {
		t.Fatal("a drop-in is missing")
	}
	if hosts := readRoot(t, m, network.HostsPath); !strings.Contains(hosts, "10.88.0.1 server-2.kry\n10.88.0.2 server-1.kry\n") || !strings.HasPrefix(hosts, hostsBefore) {
		t.Fatalf("hosts:\n%s", hosts)
	}
	current, _ := m.load()
	if !current.Joined || current.Port != 51821 || current.Firewall != "ufw" || current.Prepared != nil || current.Applied.Version != 1 || current.Document == nil || !current.Tools {
		t.Fatalf("record %+v", current)
	}
	if sent := n.messages(); len(sent) != 1 || sent[0] != applied {
		t.Fatalf("sent %+v", sent)
	}
}

func TestRulesAreInPlaceBeforeNewPeers(t *testing.T) {
	n := joinedNet(t)
	grant := "-A KRY-IN -s 10.88.0.3/32 -p tcp -m multiport --dports 80 -j ACCEPT"
	inPlace := false
	n.run.effects = map[string]func(){"wg syncconf kry0 ": func() {
		inPlace = slices.Contains(n.tables.chain("iptables", "filter", network.InChain), grant)
	}}
	document := n.next(t, func(_ *network.Member, members []network.Member) []network.Member { return members[:2] })
	document.Allow = append(document.Allow, network.Rule{From: network.Side{Node: thirdNode}, To: network.Side{Node: selfNode}, Ports: network.Ports{List: []string{"80/tcp"}}})
	if applied := n.offer(t, document); !applied.OK {
		t.Fatalf("%+v", applied)
	}
	if !inPlace || !strings.Contains(readRoot(t, n.m, network.ConfigPath), "PublicKey = "+n.third.Public) {
		t.Fatalf("the new peer came before its rules: %v\n%s", n.run.calls, n.tables)
	}
	before(t, n.run.calls, "iptables-restore", "wg syncconf kry0 ")
	before(t, n.run.calls, "ip6tables-restore", "wg syncconf kry0 ")
}

func TestPeersGoBeforeTheirRules(t *testing.T) {
	n := joinedNet(t)
	grant := "-A KRY-IN -s 10.88.0.1/32 -p tcp -m multiport --dports 22 -j ACCEPT"
	if !slices.Contains(n.tables.chain("iptables", "filter", network.InChain), grant) {
		t.Fatalf("tables:\n%s", n.tables)
	}
	stillThere := false
	n.run.effects = map[string]func(){"wg syncconf kry0 ": func() {
		stillThere = slices.Contains(n.tables.chain("iptables", "filter", network.InChain), grant)
	}}
	if applied := n.offer(t, n.next(t, func(_ *network.Member, _ []network.Member) []network.Member { return nil })); !applied.OK {
		t.Fatalf("%+v", applied)
	}
	if !stillThere {
		t.Fatal("the rules went before the peer")
	}
	if slices.ContainsFunc(n.tables.chain("iptables", "filter", network.InChain), func(line string) bool { return strings.Contains(line, "10.88.0.1/32") }) {
		t.Fatalf("the rules stay after the peer:\n%s", n.tables)
	}
	if strings.Contains(readRoot(t, n.m, network.ConfigPath), n.peer.Public) {
		t.Fatal("the peer stays")
	}
}

func TestAFailedRuleRestoreChangesNothing(t *testing.T) {
	n := joinedNet(t)
	was := n.world(t)
	n.run.failing["ip6tables-restore -w --noflush"] = "ip6tables-restore: line 4 failed"
	applied := n.offer(t, n.next(t, asIs))
	if applied.OK || !strings.HasPrefix(applied.Message, "rules: ") || !strings.Contains(applied.Message, "line 4 failed") {
		t.Fatalf("%+v", applied)
	}
	if now := n.world(t); now != was {
		t.Fatalf("a failed restore changed something:\n%+v\nwas\n%+v", now, was)
	}
	if slices.ContainsFunc(n.run.calls, func(call string) bool {
		return strings.HasPrefix(call, "wg ") || strings.HasPrefix(call, "systemctl") || strings.HasPrefix(call, "ufw")
	}) {
		t.Fatalf("calls %v", n.run.calls)
	}
}

func TestAFailureAfterThePeersPutsEverythingBack(t *testing.T) {
	n := joinedNet(t)
	was := n.world(t)
	restores := 0
	n.run.effects = map[string]func(){"ip6tables-restore": func() {
		n.run.mu.Lock()
		defer n.run.mu.Unlock()
		if restores++; restores == 2 {
			n.run.failing["ip6tables-restore -w --noflush"] = "ip6tables-restore: line 9 failed"
		} else {
			delete(n.run.failing, "ip6tables-restore -w --noflush")
		}
	}}
	applied := n.offer(t, n.next(t, asIs))
	if applied.OK || !strings.HasPrefix(applied.Message, "rules: ") || restores != 3 {
		t.Fatalf("%+v", applied)
	}
	if now := n.world(t); now != was {
		t.Fatalf("a failed exit changed something:\n%+v\nwas\n%+v", now, was)
	}
	if syncs := n.run.called("wg syncconf kry0 "); len(syncs) != 2 {
		t.Fatalf("the previous peers were not put back: %v", n.run.calls)
	}
}

func TestAFailedFirstJoinLeavesNothingBehind(t *testing.T) {
	n := newNet(t)
	n.run.failing["systemctl enable --now wg-quick@kry0.service"] = "Job for wg-quick@kry0.service failed."
	n.run.respond["ufw status numbered"] = "[ 1] 22/tcp ALLOW IN Anywhere\n[ 2] 51821/udp ALLOW IN Anywhere # krynodes-network\n[ 3] Anywhere on kry0 ALLOW IN Anywhere # krynodes-network\n"
	applied := n.offer(t, n.next(t, pair))
	if applied.OK || !strings.HasPrefix(applied.Message, "join: start kry0: ") {
		t.Fatalf("%+v", applied)
	}
	for _, call := range []string{"ufw --force delete 3", "ufw --force delete 2"} {
		if !slices.Contains(n.run.calls, call) {
			t.Fatalf("missing %q in %v", call, n.run.calls)
		}
	}
	if strings.Contains(n.tables.String(), "KRY-") || exists(n.m, network.ConfigPath) || readRoot(t, n.m, network.HostsPath) != hostsBefore {
		t.Fatalf("left behind:\n%s", n.tables)
	}
	if current, _ := n.m.load(); current.Joined || current.Applied.Version != 0 || current.Prepared == nil {
		t.Fatalf("record %+v", current)
	}
}

func TestAFirstJoinTakesOnlyTheDocumentTheServerWasPreparedFor(t *testing.T) {
	n := newNet(t)
	base := network.BodyHash([]byte("the document the owner builds on"))
	stale := network.BodyHash([]byte("an older document of the same network"))
	reprepare := func(networkRange, port string) {
		t.Helper()
		if _, err := call(t, n.m, "prepare", map[string]string{"range": networkRange, "port": port, "parent": base}); err != nil {
			t.Fatalf("prepare: %v", err)
		}
	}
	reprepare("10.88.0.0/24", "51821")
	was := n.world(t)
	for name, parent := range map[string]string{"an older parent": stale, "no parent": ""} {
		if applied := n.offer(t, n.build(4, parent, pair)); applied.OK || !strings.Contains(applied.Message, "not the one this server was prepared for") {
			t.Fatalf("%s: %+v", name, applied)
		}
	}
	reprepare("10.88.1.0/24", "51821")
	if applied := n.offer(t, n.build(4, base, pair)); applied.OK || !strings.Contains(applied.Message, "not the one this server was prepared for") {
		t.Fatalf("another range: %+v", applied)
	}
	reprepare("10.88.0.0/24", "51822")
	if applied := n.offer(t, n.build(4, base, pair)); applied.OK || !strings.Contains(applied.Message, "not the one this server was prepared for") {
		t.Fatalf("another port: %+v", applied)
	}
	if now := n.world(t); now != was {
		t.Fatal("a refused first document changed something")
	}
	reprepare("10.88.0.0/24", "51821")
	if applied := n.offer(t, n.build(4, base, pair)); !applied.OK {
		t.Fatalf("the prepared document: %+v", applied)
	}
}

func TestATamperedDocumentChangesNothing(t *testing.T) {
	n := joinedNet(t)
	was := n.world(t)
	document := n.next(t, asIs)
	signed := n.signer.sign(t, body(t, document))
	var envelope map[string]any
	if err := json.Unmarshal([]byte(signed), &envelope); err != nil {
		t.Fatal(err)
	}
	other := peerKeys(t)
	swapped := document
	swapped.Members = slices.Clone(document.Members)
	swapped.Members[0].Key = other.Public
	opened := document
	opened.Allow = append(slices.Clone(document.Allow), network.Rule{From: network.Side{Group: "servers"}, To: network.Side{Group: "servers"}, Ports: network.Ports{All: true}})
	for name, changed := range map[string]network.Document{"a member key": swapped, "a rule": opened} {
		envelope["document"] = base64.RawURLEncoding.EncodeToString(body(t, changed))
		tampered, _ := json.Marshal(envelope)
		if applied := n.m.Document(context.Background(), document.Version, string(tampered)); applied.OK || !strings.Contains(applied.Message, "signature is invalid") {
			t.Fatalf("%s: %+v", name, applied)
		}
	}
	if applied := n.m.Document(context.Background(), document.Version+1, signed); applied.OK || !strings.Contains(applied.Message, "not 3") {
		t.Fatalf("another version: %+v", applied)
	}
	unsigned := n.signer
	n.signer = newSigner(t)
	if applied := n.offer(t, document); applied.OK || !strings.Contains(applied.Message, "passkey signature is invalid") {
		t.Fatalf("another passkey: %+v", applied)
	}
	n.signer = unsigned
	if now := n.world(t); now != was || len(n.run.calls) != 0 {
		t.Fatalf("a tampered document changed something: %v", n.run.calls)
	}
}

func TestAMemberThatMissedTwoVersionsAppliesBothInOrder(t *testing.T) {
	n := joinedNet(t)
	applied := n.applied(t)
	second := n.build(2, applied.Hash, asIs)
	third := n.build(3, network.BodyHash(body(t, second)), withoutLaptop)
	if result := n.offer(t, third); result.OK || !strings.Contains(result.Message, "is not the next one after 1") || n.applied(t).Version != 1 {
		t.Fatalf("v3 first: %+v", result)
	}
	for _, document := range []network.Document{second, third} {
		if result := n.offer(t, document); !result.OK {
			t.Fatalf("v%d: %+v", document.Version, result)
		}
	}
	if n.applied(t).Version != 3 || strings.Contains(readRoot(t, n.m, network.HostsPath), "laptop-1") || !strings.Contains(readRoot(t, n.m, network.HostsPath), "server-4") {
		t.Fatalf("applied %+v hosts %s", n.applied(t), readRoot(t, n.m, network.HostsPath))
	}
}

func TestADocumentOnAnotherBaseIsRefused(t *testing.T) {
	n := joinedNet(t)
	was := n.world(t)
	doctored := n.next(t, asIs)
	doctored.Parent = network.BodyHash([]byte("a body the Worker made up"))
	if applied := n.offer(t, doctored); applied.OK || !strings.Contains(applied.Message, "does not follow the version this server applied") {
		t.Fatalf("%+v", applied)
	}
	if now := n.world(t); now != was || len(n.run.calls) != 0 {
		t.Fatalf("a document on another base changed something: %v", n.run.calls)
	}
}

func TestOnlyTheNewestDocumentIsAppliedAndNothingIsRewritten(t *testing.T) {
	n := joinedNet(t)
	n.apply(t, pair)
	was := n.world(t)
	n.run.calls = nil
	for _, version := range []int{1, 2} {
		document := n.build(version, "", pair)
		document.Members[0].Address = "10.88.0.9"
		if applied := n.offer(t, document); !applied.OK || applied.Message != "Already applied." || applied.Version != 2 {
			t.Fatalf("v%d %+v", version, applied)
		}
	}
	if now := n.world(t); now != was || len(n.run.calls) != 0 {
		t.Fatalf("an old document changed something: %v", n.run.calls)
	}
}

func TestAJoinedServerRefusesADocumentBuiltOnAnotherBase(t *testing.T) {
	n := joinedNet(t)
	skipped := n.build(3, n.applied(t).Hash, pair)
	if applied := n.offer(t, skipped); applied.OK || !strings.Contains(applied.Message, "is not the next one after 1") {
		t.Fatalf("skipped %+v", applied)
	}
	if applied := n.offer(t, n.next(t, pair)); !applied.OK {
		t.Fatalf("next %+v", applied)
	}
}

func TestADocumentWithAWidePeerRangeWritesNothing(t *testing.T) {
	n := newNet(t)
	n.run.calls = nil
	for _, address := range []string{"0.0.0.0/0", "::/0", "10.88.0.0/24", "10.89.0.1"} {
		document := n.next(t, pair)
		document.Members[0].Address = address
		if applied := n.offer(t, document); applied.OK {
			t.Fatalf("%s was applied", address)
		}
	}
	if exists(n.m, network.ConfigPath) || len(n.run.calls) != 0 {
		t.Fatalf("a wide range wrote something: %v", n.run.calls)
	}
}

func TestUse1380RestartsWithTheClampAndALaterDocumentTakesItOff(t *testing.T) {
	n := joinedNet(t)
	mtu := 1380
	if applied := n.offer(t, n.next(t, pair, func(self *network.Member, members []network.Member) []network.Member {
		self.MTU = &mtu
		return members
	})); !applied.OK || !slices.Contains(n.run.calls, "systemctl restart wg-quick@kry0.service") {
		t.Fatalf("1380 %+v %v", applied, n.run.calls)
	}
	restarted := slices.Index(n.run.calls, "systemctl restart wg-quick@kry0.service")
	if !slices.ContainsFunc(n.run.calls[restarted:], func(call string) bool { return strings.HasPrefix(call, "iptables-restore") }) {
		t.Fatalf("the rules the boot step restored are not renewed after the restart: %v", n.run.calls)
	}
	if config := readRoot(t, n.m, network.ConfigPath); !strings.Contains(config, "MTU = 1380\nPostUp = iptables -w -t mangle -A POSTROUTING -o kry0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340\n") {
		t.Fatalf("config:\n%s", config)
	}
	n.run.calls = nil
	if applied := n.offer(t, n.next(t, pair)); !applied.OK || !slices.Contains(n.run.calls, "systemctl restart wg-quick@kry0.service") {
		t.Fatalf("back %+v %v", applied, n.run.calls)
	}
	n.run.calls = nil
	n.apply(t, pair)
	if slices.Contains(n.run.calls, "systemctl restart wg-quick@kry0.service") || len(n.run.called("wg syncconf kry0 ")) != 1 {
		t.Fatalf("an unchanged MTU restarted kry0: %v", n.run.calls)
	}
}

func TestAMemberMarkedForNewKeysMakesThemWhenItIsBack(t *testing.T) {
	n := joinedNet(t)
	if applied := n.offer(t, n.next(t, pair, func(self *network.Member, members []network.Member) []network.Member {
		self.Rekey = true
		return members
	})); !applied.OK {
		t.Fatalf("%+v", applied)
	}
	fresh := ownKeys(t, n.m)
	current, _ := n.m.load()
	if fresh.Public == n.keys.Public || current.Announce == nil || current.Announce.Key != fresh.Public || !network.Announced(n.keys.Signer, selfNode, fresh.Public, current.Announce.Signature) {
		t.Fatalf("record %+v", current)
	}
	if config := readRoot(t, n.m, network.ConfigPath); strings.Contains(config, "PrivateKey = "+n.keys.Private) || !strings.Contains(config, "PrivateKey = "+fresh.Private) {
		t.Fatal("the old private key stays")
	}
	if !slices.Contains(n.messages(), any(reporter.Announce{Type: "announce", Key: fresh.Public, Signature: current.Announce.Signature})) {
		t.Fatalf("sent %+v", n.messages())
	}
	n.keys = fresh
	if applied := n.offer(t, n.next(t, pair)); !applied.OK {
		t.Fatalf("the new key in the document: %+v", applied)
	}
	if current, _ := n.m.load(); current.Announce != nil {
		t.Fatalf("the announcement stays once the document names the key: %+v", current.Announce)
	}
}

func TestLeavingRemovesExactlyWhatKrynodesMade(t *testing.T) {
	n := joinedNet(t)
	n.run.respond["ufw status numbered"] = "[ 1] 22/tcp ALLOW IN Anywhere\n[ 2] 51821/udp ALLOW IN Anywhere # krynodes-network\n[ 3] Anywhere on kry0 ALLOW IN Anywhere # krynodes-network\n[ 4] 51820/udp ALLOW IN Anywhere # wg0\n"
	old := n.keys
	alone := n.next(t, pair)
	alone.Members = alone.Members[:1]
	alone.Members[0].PSK = map[string]string{}
	alone.Allow = []network.Rule{}
	applied := n.offer(t, alone)
	if !applied.OK || applied.Message != "Left the private network." {
		t.Fatalf("leave %+v", applied)
	}
	for _, call := range []string{"systemctl disable --now wg-quick@kry0.service", "ufw --force delete 3", "ufw --force delete 2", "systemctl daemon-reload"} {
		if !slices.Contains(n.run.calls, call) {
			t.Fatalf("missing %q in %v", call, n.run.calls)
		}
	}
	for _, call := range n.run.calls {
		if strings.Contains(call, "wg0") || call == "ufw --force delete 4" || call == "ufw --force delete 1" {
			t.Fatalf("removed what is not Krynodes': %s", call)
		}
	}
	for _, path := range []string{network.ConfigPath, network.DropInPath, network.RulesDropInPath} {
		if exists(n.m, path) {
			t.Fatalf("%s stays", path)
		}
	}
	if hosts := readRoot(t, n.m, network.HostsPath); hosts != hostsBefore {
		t.Fatalf("hosts:\n%s", hosts)
	}
	if strings.Contains(n.tables.String(), "KRY-") {
		t.Fatalf("tables:\n%s", n.tables)
	}
	if current, _ := n.m.load(); current.Joined || current.Document != nil || current.Applied.Version != 2 {
		t.Fatalf("record %+v", current)
	}
	if fresh := ownKeys(t, n.m); fresh.Public == old.Public || fresh.Signer == old.Signer {
		t.Fatal("a server that left keeps the keys the network blocked")
	}
}

func TestRemoveTakesTheServerOutOfTheNetwork(t *testing.T) {
	n := joinedNet(t)
	n.apply(t, exitOn)
	n.tables.rules["iptables filter DOCKER-USER"] = append(n.tables.rules["iptables filter DOCKER-USER"], "-A DOCKER-USER -j RETURN")
	n.run.respond["ufw status numbered"] = "[ 1] 51821/udp ALLOW IN Anywhere # krynodes-network\n[ 2] Anywhere on kry0 ALLOW IN Anywhere # krynodes-network\n[ 3] 51920/udp ALLOW IN Anywhere # krynodes-network\n"
	if err := n.m.Leave(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, call := range []string{"systemctl disable --now wg-quick@kry0.service", "ufw --force delete 3", "ufw --force delete 2", "ufw --force delete 1"} {
		if !slices.Contains(n.run.calls, call) {
			t.Fatalf("missing %q in %v", call, n.run.calls)
		}
	}
	if text := n.tables.String(); strings.Contains(text, "KRY-") || strings.Contains(text, "MASQUERADE") || !slices.Equal(n.tables.chain("iptables", "filter", network.DockerUser), []string{"-A DOCKER-USER -j RETURN"}) {
		t.Fatalf("tables:\n%s", text)
	}
	for _, path := range []string{network.ConfigPath, network.DropInPath, network.RulesDropInPath, "/etc/sysctl.d/99-krynodes-laptop-exit.conf"} {
		if exists(n.m, path) {
			t.Fatalf("%s stays", path)
		}
	}
	if hosts := readRoot(t, n.m, network.HostsPath); hosts != hostsBefore {
		t.Fatalf("hosts:\n%s", hosts)
	}
	if _, err := os.Stat(n.m.keysDir()); !os.IsNotExist(err) {
		t.Fatalf("the keys stay: %v", err)
	}
	if _, err := os.Stat(n.m.statePath()); !os.IsNotExist(err) {
		t.Fatalf("network.json stays: %v", err)
	}
	if err := n.m.Leave(context.Background()); err != nil {
		t.Fatalf("leaving twice: %v", err)
	}
}

func TestALeaveRemovesOnlyToolsKrynodesInstalled(t *testing.T) {
	n := joinedNet(t)
	current, _ := n.m.load()
	current.Tools = true
	n.m.save(current)
	n.run.respond["ip -d -j addr show"] = `[{"ifname":"eth0","mtu":1500,"addr_info":[]}]`
	if err := n.m.Leave(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(n.run.calls, "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 purge -y -q wireguard-tools") {
		t.Fatalf("Krynodes' tools stay: %v", n.run.calls)
	}
	n = joinedNet(t)
	if err := n.m.Leave(context.Background()); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(n.run.calls, func(call string) bool { return strings.Contains(call, "purge") }) {
		t.Fatalf("the owner's tools were removed: %v", n.run.calls)
	}
}

func TestADockerPortOnAllAddressesIsClosedToOtherServers(t *testing.T) {
	n := joinedNet(t)
	n.apply(t, withoutLaptop)
	for _, tool := range []string{"iptables", "ip6tables"} {
		if !slices.Contains(n.tables.chain(tool, "filter", network.DockerUser), "-A DOCKER-USER -i kry0 -j KRY-FWD") || !slices.Contains(n.tables.chain(tool, "filter", "FORWARD"), "-A FORWARD -i kry0 -j KRY-FWD") {
			t.Fatalf("%s:\n%s", tool, n.tables)
		}
	}
	forward := n.tables.chain("iptables", "filter", network.ForwardChain)
	var grants []string
	for _, line := range forward {
		if strings.HasSuffix(line, "-j RETURN") && strings.Contains(line, "-s ") {
			grants = append(grants, line)
		}
	}
	if !slices.Equal(grants, []string{"-A KRY-FWD -s 10.88.0.1/32 -p tcp -m conntrack --ctstate DNAT --ctorigdstport 22 -j RETURN"}) || forward[len(forward)-1] != "-A KRY-FWD -j DROP" {
		t.Fatalf("KRY-FWD %q", forward)
	}
	if in := n.tables.chain("iptables", "filter", network.InChain); slices.ContainsFunc(in, func(line string) bool {
		return strings.Contains(line, "10.88.0.3/32") || strings.Contains(line, "10.88.0.4/32")
	}) || in[len(in)-1] != "-A KRY-IN -j DROP" {
		t.Fatalf("KRY-IN %q", in)
	}
}

func TestAPresharedKeyThisServerCannotOpenChangesNothing(t *testing.T) {
	n := joinedNet(t)
	was := n.world(t)
	document := n.next(t, pair)
	document.Members[1].PSK[peerNode] = "c29tZW9uZS1lbHNl"
	if applied := n.offer(t, document); applied.OK || !strings.Contains(applied.Message, "server-2") || strings.Contains(applied.Message, base64.StdEncoding.EncodeToString(testPSK)) {
		t.Fatalf("%+v", applied)
	}
	if now := n.world(t); now != was || len(n.run.calls) != 0 {
		t.Fatalf("calls %v", n.run.calls)
	}
}

func TestNothingPrivateIsInAnAnswer(t *testing.T) {
	n := joinedNet(t)
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	n.run.failing["systemctl restart wg-quick@kry0.service"] = "Job for wg-quick@kry0.service failed."
	mtu := 1380
	applied := n.offer(t, n.next(t, pair, func(self *network.Member, members []network.Member) []network.Member {
		self.MTU = &mtu
		return members
	}))
	if applied.OK || !strings.HasPrefix(applied.Message, "peers: restart kry0: ") || !strings.Contains(applied.Message, "putting the previous network back") {
		t.Fatalf("%+v", applied)
	}
	for _, secret := range []string{n.keys.Private, base64.StdEncoding.EncodeToString(testPSK)} {
		if strings.Contains(applied.Message, secret) || strings.Contains(logged.String(), secret) {
			t.Fatalf("a secret in %+v / %s", applied, logged.String())
		}
	}
	for _, path := range n.run.files {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s stays", path)
		}
	}
	entries, _ := os.ReadDir(n.m.keysDir())
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "sync-") {
			t.Fatalf("%s stays", filepath.Join(n.m.keysDir(), entry.Name()))
		}
	}
}

func TestADropAndARekeyRewriteKry0Conf(t *testing.T) {
	n := joinedNet(t)
	if _, err := call(t, n.m, "drop", map[string]string{"node": peerNode, "key": n.peer.Public, "address": "10.88.0.1"}); err != nil {
		t.Fatal(err)
	}
	if config := readRoot(t, n.m, network.ConfigPath); strings.Contains(config, n.peer.Public) || strings.Contains(config, "10.88.0.1/32") {
		t.Fatalf("a restart would bring the dropped peer back:\n%s", config)
	}
	n = joinedNet(t)
	if _, err := call(t, n.m, "rekey", nil); err != nil {
		t.Fatal(err)
	}
	fresh := ownKeys(t, n.m)
	if config := readRoot(t, n.m, network.ConfigPath); !strings.Contains(config, "PrivateKey = "+fresh.Private+"\n") || strings.Contains(config, n.keys.Private) {
		t.Fatal("kry0.conf keeps the old private key")
	}
	if len(n.run.called("wg syncconf kry0 ")) != 1 {
		t.Fatalf("the running kry0 keeps the old key: %v", n.run.calls)
	}
}

func TestALeaveSaysHelloAgainRightAfterItsAnswer(t *testing.T) {
	n := joinedNet(t)
	n.m.Left = func() { n.send("hello") }
	kept := n.apply(t)
	if sent := n.messages(); slices.Contains(sent, any("hello")) {
		t.Fatalf("a member that stayed said hello: %+v", sent)
	}
	alone := n.next(t, pair)
	alone.Members = alone.Members[:1]
	alone.Members[0].PSK = map[string]string{}
	alone.Allow = []network.Rule{}
	n.sent = nil
	applied := n.offer(t, alone)
	if sent := n.messages(); !applied.OK || len(sent) != 2 || sent[0] != any(applied) || sent[1] != "hello" {
		t.Fatalf("sent %+v after %d", sent, kept.Version)
	}
	later := alone
	later.Version++
	n.sent = nil
	n.offer(t, later)
	if slices.Contains(n.messages(), any("hello")) {
		t.Fatalf("a server outside the network said hello again: %+v", n.messages())
	}
}

func TestALeaveThatCannotSaveItsRecordSaysNoHello(t *testing.T) {
	n := joinedNet(t)
	n.m.Left = func() { n.send("hello") }
	n.run.effects = map[string]func(){"systemctl disable --now wg-quick@kry0.service": func() {
		os.Remove(n.m.statePath())
		if err := os.Mkdir(n.m.statePath(), 0o700); err != nil {
			t.Error(err)
		}
	}}
	alone := n.next(t, pair)
	alone.Members = alone.Members[:1]
	alone.Members[0].PSK = map[string]string{}
	alone.Allow = []network.Rule{}
	n.sent = nil
	applied := n.offer(t, alone)
	if sent := n.messages(); applied.OK || len(sent) != 1 || sent[0] != any(applied) {
		t.Fatalf("a leave that kept no record sent %+v", sent)
	}
}
