package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/daemon"
	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

const (
	selfNode     = "22222222-2222-4222-8222-222222222222"
	peerNode     = "11111111-1111-4111-8111-111111111111"
	peerEndpoint = "203.0.113.21:51820"
	wg0Address   = `{"ifname":"wg0","mtu":1420,"linkinfo":{"info_kind":"wireguard"},"addr_info":[{"family":"inet","local":"10.0.0.1","prefixlen":24}]}`
)

var testNow = time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)

type fakeRun struct {
	mu       sync.Mutex
	calls    []string
	respond  map[string]string
	failing  map[string]string
	sequence map[string][]string
	restored map[string]string
	files    []string
	block    map[string]chan struct{}
	effects  map[string]func()
}

func (f *fakeRun) run(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := name + " " + strings.Join(args, " ")
	if strings.HasSuffix(name, "-restore") && len(args) > 0 {
		body, _ := os.ReadFile(args[len(args)-1])
		f.restored[name] = string(body)
		f.files = append(f.files, args[len(args)-1])
		call = name + " " + strings.Join(args[:len(args)-1], " ")
	}
	f.calls = append(f.calls, call)
	for prefix, effect := range f.effects {
		if strings.HasPrefix(call, prefix) {
			f.mu.Unlock()
			effect()
			f.mu.Lock()
		}
	}
	if started, ok := f.block[call]; ok {
		f.mu.Unlock()
		close(started)
		<-ctx.Done()
		f.mu.Lock()
		delete(f.block, call)
		return nil, -1, ctx.Err()
	}
	if answer, ok := f.failing[call]; ok {
		return []byte(answer), 1, errors.New("exit status 1")
	}
	if answer, ok := f.respond[call]; ok {
		return []byte(answer), 0, nil
	}
	if answers, ok := f.sequence[call]; ok && len(answers) > 0 {
		answer := answers[0]
		if len(answers) > 1 {
			f.sequence[call] = answers[1:]
		}
		return []byte(answer), 0, nil
	}
	return nil, 0, nil
}

func (f *fakeRun) called(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var found []string
	for _, call := range f.calls {
		if strings.HasPrefix(call, prefix) {
			found = append(found, call)
		}
	}
	return found
}

const (
	ownSealKey   = "BKjpRA_slHw4x3NdGJcyQ75R9_DQQtbaWv1M8JLZI1Y0jhyDrnX9kl3a9IjqweVG1-weFpLFHMr0nXfvK_uB2Iw"
	otherSealKey = "BAoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dzj6vH4_wYNFBsiKTA3PkVMU1phaG92fYSLkpmgp661vMM"
)

func newMesh(t *testing.T) (*Mesh, *fakeRun) {
	t.Helper()
	run := &fakeRun{respond: map[string]string{}, failing: map[string]string{}, restored: map[string]string{}}
	return &Mesh{
		State:   t.TempDir(),
		Root:    t.TempDir(),
		Run:     run.run,
		Now:     func() time.Time { return testNow },
		Trust:   func() trust.Trust { return trust.Trust{NodeID: selfNode} },
		SealKey: func() string { return ownSealKey },
		Send:    func(any) error { return nil },
	}, run
}

func rootFile(t *testing.T, m *Mesh, path, body string) {
	t.Helper()
	full := filepath.Join(m.Root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func networkMesh(t *testing.T) (*Mesh, *fakeRun) {
	t.Helper()
	m, run := newMesh(t)
	rootFile(t, m, "/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n")
	rootFile(t, m, "/sys/module/wireguard/version", "1.0.0\n")
	rootFile(t, m, "/usr/bin/wg", "")
	rootFile(t, m, "/usr/sbin/iptables", "")
	rootFile(t, m, "/usr/sbin/ip6tables", "")
	rootFile(t, m, "/etc/ufw/ufw.conf", "ENABLED=yes\n")
	run.respond["ip -d -j addr show"] = `[{"ifname":"eth0","mtu":1500,"addr_info":[{"family":"inet","local":"203.0.113.30","prefixlen":24}]},` + wg0Address + `]`
	run.respond["ip -j route show default"] = `[{"dev":"eth0"}]`
	run.respond["wg show all listen-port"] = "wg0\t51820\n"
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	return m, run
}

func call(t *testing.T, m *Mesh, action string, args map[string]string) (string, error) {
	t.Helper()
	handler := m.Handlers()["network/"+action]
	if handler == nil {
		t.Fatalf("no handler for %s", action)
	}
	message, err := handler(context.Background(), trust.Command{V: 1, Kind: "network", Name: "kry0", Action: action, Args: args}, func(string) {})
	if len(message) > maxMessage {
		t.Fatalf("%s answered %d bytes", action, len(message))
	}
	return message, err
}

func ownKeys(t *testing.T, m *Mesh) network.Keys {
	t.Helper()
	keys, err := network.Load(m.keysDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func peerKeys(t *testing.T) network.Keys {
	t.Helper()
	keys, err := network.Load(filepath.Join(t.TempDir(), "peer"), true)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func twoMembers(keys, peer network.Keys) network.Document {
	endpoint := peerEndpoint
	return network.Document{V: 1, Version: 1, Range: "10.88.0.0/24", Port: 51820, MTU: 1420, Blocked: []string{}, Members: []network.Member{
		{Node: peerNode, Name: "server-2", Address: "10.88.0.1", Key: peer.Public, Signer: peer.Signer, SealKey: otherSealKey, Port: 51820, Endpoint: &endpoint, PSK: map[string]string{}},
		{Node: selfNode, Name: "server-1", Address: "10.88.0.2", Key: keys.Public, Signer: keys.Signer, SealKey: ownSealKey, Port: 51821, PSK: map[string]string{}},
	}, Allow: []network.Rule{{From: network.Side{Node: peerNode}, To: network.Side{Node: selfNode}, Ports: network.Ports{List: []string{"22/tcp"}}}}}
}

func joined(t *testing.T, m *Mesh) (network.Document, network.Keys) {
	t.Helper()
	peer := peerKeys(t)
	document := twoMembers(ownKeys(t, m), peer)
	if err := m.save(record{Applied: network.Applied{Version: 1, Hash: "hash-1"}, Document: &document, Joined: true, Port: 51821}); err != nil {
		t.Fatal(err)
	}
	return document, peer
}

func TestEnsureMakesTheKeysOnceAndRunsNothing(t *testing.T) {
	m, run := newMesh(t)
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := ownKeys(t, m)
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if again := ownKeys(t, m); again.Public != first.Public || again.Signer != first.Signer {
		t.Fatal("Ensure made new keys over the old ones")
	}
	if len(run.calls) != 0 {
		t.Fatalf("Ensure ran %v", run.calls)
	}
	if _, err := os.Stat(filepath.Join(m.State, "network.json")); !os.IsNotExist(err) {
		t.Fatalf("Ensure wrote a record: %v", err)
	}
	if runtime.GOOS != "windows" {
		for _, name := range []string{"key", "signer"} {
			if info, err := os.Stat(filepath.Join(m.keysDir(), name)); err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("%s: %v %v", name, info.Mode(), err)
			}
		}
		if info, _ := os.Stat(m.keysDir()); info.Mode().Perm() != 0o700 {
			t.Fatalf("the key directory is %v", info.Mode())
		}
	}
}

func TestHelloSaysWhyAServerIsNotReady(t *testing.T) {
	m, _ := networkMesh(t)
	keys := ownKeys(t, m)
	hello := m.Hello(context.Background())
	if hello == nil || !hello.Ready || hello.Reason != nil || hello.Key != keys.Public || hello.Signer != keys.Signer || hello.Version != 0 {
		t.Fatalf("a ready server: %+v", hello)
	}
	encoded, _ := json.Marshal(hello)
	if strings.Contains(string(encoded), keys.Private) {
		t.Fatal("hello carries the private key")
	}
	joined(t, m)
	if hello := m.Hello(context.Background()); hello.Version != 1 {
		t.Fatalf("a joined server says version %d", hello.Version)
	}

	reasons := map[string]func(*Mesh, *fakeRun){
		"kernel has no WireGuard": func(m *Mesh, run *fakeRun) {
			os.RemoveAll(filepath.Join(m.Root, "sys"))
			run.failing["modprobe -n -q wireguard"] = ""
			run.respond["systemd-detect-virt --container"] = "none\n"
		},
		"container that cannot load WireGuard": func(m *Mesh, run *fakeRun) {
			os.RemoveAll(filepath.Join(m.Root, "sys"))
			run.failing["modprobe -n -q wireguard"] = ""
			run.respond["systemd-detect-virt --container"] = "lxc\n"
		},
		"no iptables": func(m *Mesh, run *fakeRun) {
			os.Remove(filepath.Join(m.Root, "usr", "sbin", "ip6tables"))
		},
		"ip6tables does not work: ip6tables v1.8.9 (nf_tables): Could not fetch rule set generation id": func(m *Mesh, run *fakeRun) {
			run.failing["ip6tables -w -S"] = "ip6tables v1.8.9 (nf_tables): Could not fetch rule set generation id: Permission denied (you must be root)\nmore"
		},
		"No UDP port": func(m *Mesh, run *fakeRun) {
			var lines []string
			for port := network.FirstPort; port <= network.LastPort; port++ {
				lines = append(lines, "UNCONN 0 0 0.0.0.0:"+strconv.Itoa(port)+" 0.0.0.0:*")
			}
			run.respond["ss -lunH"] = strings.Join(lines, "\n")
		},
	}
	for want, breakIt := range reasons {
		m, run := networkMesh(t)
		breakIt(m, run)
		hello := m.Hello(context.Background())
		if hello == nil || hello.Ready || hello.Reason == nil || !strings.Contains(*hello.Reason, want) || len(*hello.Reason) > 300 {
			t.Fatalf("%s: %+v", want, hello)
		}
		if _, err := call(t, m, "prepare", map[string]string{"range": "10.88.0.0/24", "port": "51821"}); err == nil || err.Error() != *hello.Reason {
			t.Fatalf("%s: prepare said %v", want, err)
		}
		if _, err := call(t, m, "inspect", nil); err != nil {
			t.Fatalf("%s: inspect refused: %v", want, err)
		}
	}

	m, _ = newMesh(t)
	if hello := m.Hello(context.Background()); hello != nil {
		t.Fatalf("a server without keys says %+v", hello)
	}
}

func TestTheFingerprintNeedsTheKeys(t *testing.T) {
	m, _ := newMesh(t)
	if _, err := m.Fingerprint(); err == nil {
		t.Fatal("a fingerprint without keys")
	}
	m.Ensure(context.Background())
	keys := ownKeys(t, m)
	if got, err := m.Fingerprint(); err != nil || got != network.Fingerprint(keys.Public, keys.Signer, m.SealKey()) {
		t.Fatalf("fingerprint %q %v", got, err)
	}
	m.SealKey = func() string { return "" }
	if _, err := m.Fingerprint(); err == nil {
		t.Fatal("a fingerprint without a seal key")
	}
}

type sentResults struct {
	mu   sync.Mutex
	sent []reporter.Result
}

func (s *sentResults) send(message any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if result, ok := message.(reporter.Result); ok {
		s.sent = append(s.sent, result)
	}
	return nil
}

func TestAnUnsignedNetworkCommandIsRefused(t *testing.T) {
	m, run := networkMesh(t)
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "protocol", "src", "fixtures", "browser-signed.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Origin  string           `json:"origin"`
		NodeID  string           `json:"nodeId"`
		Now     string           `json:"now"`
		Tokens  []string         `json:"tokens"`
		Change  reporter.Command `json:"change"`
		Command reporter.Command `json:"command"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	first, err := trust.FirstTrust(fixture.NodeID, fixture.Origin, fixture.Tokens)
	if err != nil {
		t.Fatal(err)
	}
	now, _ := time.Parse(time.RFC3339Nano, fixture.Now)
	if first, err = trust.ApplyTrustChange(first, []byte(fixture.Change.Signed), now); err != nil {
		t.Fatal(err)
	}
	results := &sentResults{}
	d := &daemon.Daemon{State: t.TempDir(), Trust: func() trust.Trust { return first }, Send: results.send, Now: func() time.Time { return now }, Handlers: m.Handlers()}
	before := len(run.calls)
	for index, action := range []string{"inspect", "probe", "test", "prepare", "unprepare", "rekey", "drop"} {
		unsigned := reporter.Command{Type: "command", ID: "6c1f5a52-30de-4c1e-9d1b-0d7c3f6f2a1" + strconv.Itoa(index), Kind: "network", Name: "kry0", Action: action}
		d.Handle(context.Background(), unsigned)
		forged := unsigned
		forged.ID = fixture.Command.ID
		forged.Signed = fixture.Command.Signed
		d.Handle(context.Background(), forged)
	}
	if len(run.calls) != before {
		t.Fatalf("a handler ran: %v", run.calls[before:])
	}
	if len(results.sent) != 14 {
		t.Fatalf("results %+v", results.sent)
	}
	for index, result := range results.sent {
		want := "the command is not signed"
		if index%2 == 1 {
			want = "the command does not match the request"
		}
		if result.OK || result.Message != want {
			t.Fatalf("result %d %+v", index, result)
		}
	}
	if _, err := os.Stat(filepath.Join(m.State, "network.json")); !os.IsNotExist(err) {
		t.Fatalf("a refused command changed the record: %v", err)
	}
}

func TestANetworkCommandNamesKry0(t *testing.T) {
	m, run := networkMesh(t)
	if _, err := m.Handlers()["network/inspect"](context.Background(), trust.Command{Kind: "network", Name: "wg0", Action: "inspect"}, func(string) {}); err == nil || len(run.calls) != 0 {
		t.Fatalf("err %v calls %v", err, run.calls)
	}
}

func TestAServerThatHangsStillSaysHelloAndHoldsNoOneUp(t *testing.T) {
	readLimit = 300 * time.Millisecond
	t.Cleanup(func() { readLimit = 20 * time.Second })
	m, run := networkMesh(t)
	run.block = map[string]chan struct{}{"docker network ls -q": make(chan struct{})}
	started := time.Now()
	hello := m.Hello(context.Background())
	if time.Since(started) > 5*time.Second || hello == nil || hello.Ready || hello.Reason == nil || !strings.Contains(*hello.Reason, "in time") {
		t.Fatalf("hello after %s: %+v", time.Since(started), hello)
	}

	blocked := make(chan struct{})
	run.mu.Lock()
	run.block["docker network ls -q"] = blocked
	run.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := call(t, m, "prepare", map[string]string{"range": "10.88.0.0/24", "port": "51821"})
		done <- err
	}()
	<-blocked
	message, err := call(t, m, "drop", map[string]string{"node": peerNode, "key": peerKeys(t).Public, "address": "10.88.0.1"})
	select {
	case <-done:
		t.Fatal("prepare finished before the drop could run")
	default:
	}
	if err != nil || message != "This server is not in the private network." {
		t.Fatalf("drop %q %v", message, err)
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "did not finish checking itself") {
		t.Fatalf("prepare %v", err)
	}
	if current, _ := m.load(); current.Prepared != nil {
		t.Fatalf("a timed-out prepare recorded %+v", current.Prepared)
	}
	run.mu.Lock()
	run.block["docker network ls -q"] = make(chan struct{})
	run.mu.Unlock()
	if _, err := call(t, m, "inspect", nil); err == nil {
		t.Fatal("inspect answered without finishing")
	}
}

func TestAnUnreadableRecordMakesTheServerNotReady(t *testing.T) {
	m, _ := networkMesh(t)
	if err := os.WriteFile(m.statePath(), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	hello := m.Hello(context.Background())
	if hello == nil || hello.Ready || hello.Reason == nil || !strings.Contains(*hello.Reason, "cannot read its network record") || len(*hello.Reason) > 300 {
		t.Fatalf("hello %+v", hello)
	}
}
