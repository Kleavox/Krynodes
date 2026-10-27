package actions

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

func throughBoth(t *testing.T, executor Executor, request Request) Result {
	t.Helper()
	writeRequest(t, executor.RequestDir, request.ID+".json", request)
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	return readResult(t, executor, request.ID)
}

func fresh(n int) string {
	return fmt.Sprintf("0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1b%02d", n)
}

func attached(t *testing.T, request Request, args map[string]string) Request {
	t.Helper()
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	request.Signed, request.Attachment = nil, base64.RawURLEncoding.EncodeToString(encoded)
	return request
}

func TestAnUnsignedLockdownRunsAndAnUnsignedUnlockIsRefused(t *testing.T) {
	executor, run := securityExecutor(t)
	healthyServer(t, executor, run)
	lockdown := hostRequest(t, idA, "server", "lockdown", nil)
	lockdown.Signed = nil
	if result := throughBoth(t, executor, lockdown); !result.OK || !executor.lockedDown() {
		t.Fatalf("lockdown %+v", result)
	}
	unlock := hostRequest(t, idB, "server", "unlock", nil)
	unlock.Signed = nil
	if result := throughBoth(t, executor, unlock); result.OK || !executor.lockedDown() {
		t.Fatalf("unlock %+v", result)
	}
}

func TestADropTakesThePeerOutOnceAndBlocksItsKey(t *testing.T) {
	executor, _, _, peer, _ := joinedServer(t)
	if !strings.Contains(readRoot(t, executor, network.ConfigPath), peer.Public) {
		t.Fatal("the peer is not in kry0.conf before the drop")
	}
	args := map[string]string{"node": peerNode, "key": peer.Public, "address": "10.88.0.1"}
	for _, id := range []string{fresh(1), fresh(2)} {
		if result := throughBoth(t, executor, askNetwork(t, id, "drop", args)); !result.OK {
			t.Fatalf("drop %+v", result)
		}
	}
	record := executor.readNetwork()
	if !slices.Contains(record.Applied.Blocked, peer.Public) || !slices.Equal(record.Dropped, []string{"10.88.0.1"}) {
		t.Fatalf("record %+v", record)
	}
	if strings.Contains(readRoot(t, executor, network.ConfigPath), peer.Public) {
		t.Fatal("the dropped peer is still in kry0.conf")
	}
	rules, _ := os.ReadFile(filepath.Join(executor.networkDir(), rulesFile))
	if strings.Count(string(rules), "-A KRY-DROP -s 10.88.0.1/32 -j DROP") != 1 {
		t.Fatalf("rules %s", rules)
	}
	if result := throughBoth(t, executor, askNetwork(t, "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a03", "drop", map[string]string{"node": testNode, "key": peer.Public, "address": "10.88.0.2"})); result.OK {
		t.Fatalf("dropped itself %+v", result)
	}
}

func TestADroppedMemberComesBackOnlyWithNewKeysInASignedDocument(t *testing.T) {
	executor, _, keys, peer, _ := joinedServer(t)
	throughBoth(t, executor, askNetwork(t, fresh(1), "drop", map[string]string{"node": peerNode, "key": peer.Public, "address": "10.88.0.1"}))
	same := twoMembers(t, executor, 2, keys, peer)
	if result := hostRun(t, executor, applyDocument(t, "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a03", same)); result.OK {
		t.Fatalf("the old key came back %+v", result)
	}
	cut := twoMembers(t, executor, 2, keys, peer)
	cut.Members[0].Cut = true
	if result := hostRun(t, executor, applyDocument(t, "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a04", cut)); !result.OK || !slices.Equal(executor.readNetwork().Dropped, []string{"10.88.0.1"}) {
		t.Fatalf("kept cut %+v %v", result, executor.readNetwork().Dropped)
	}
	released, _ := peerKeys(t)
	back := twoMembers(t, executor, 3, keys, released)
	if result := hostRun(t, executor, applyDocument(t, "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a05", back)); !result.OK {
		t.Fatalf("released %+v", result)
	}
	record := executor.readNetwork()
	if len(record.Dropped) != 0 || !slices.Contains(record.Applied.Blocked, peer.Public) {
		t.Fatalf("record %+v", record)
	}
}

func TestTightenTakesTheStricterValueUntilASignedDocument(t *testing.T) {
	executor, _, keys, peer, _ := joinedServer(t)
	if result := throughBoth(t, executor, askNetwork(t, fresh(1), "tighten", map[string]string{"scan": "5", "stop": "true"})); !result.OK {
		t.Fatalf("tighten %+v", result)
	}
	record := executor.readNetwork()
	if knocks := network.Effective(*record.Document, record.Tightened); knocks.Scan != 5 || !knocks.Stop {
		t.Fatalf("knocks %+v", knocks)
	}
	if result := throughBoth(t, executor, askNetwork(t, fresh(2), "tighten", map[string]string{"scan": "7", "stop": "true"})); result.OK {
		t.Fatalf("tightened to 7 %+v", result)
	}
	next := twoMembers(t, executor, 2, keys, peer)
	next.Knocks = &network.Knocks{Scan: 20, Stop: true}
	if result := hostRun(t, executor, applyDocument(t, "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a03", next)); !result.OK {
		t.Fatalf("apply %+v", result)
	}
	record = executor.readNetwork()
	if knocks := network.Effective(*record.Document, record.Tightened); record.Tightened != nil || knocks.Scan != 20 {
		t.Fatalf("after a signed document %+v %+v", record.Tightened, knocks)
	}
}

func TestATailnetBlockWritesBothFamiliesAndOnlyASignedUnblockLiftsIt(t *testing.T) {
	executor, run := securityExecutor(t)
	for _, tool := range []string{"iptables", "ip6tables"} {
		for _, parent := range []string{"INPUT", "FORWARD"} {
			run.failing[tool+" -C "+parent+" -i tailscale0 -j KRY-TAILNET"] = "Bad rule"
		}
	}
	block := attached(t, hostRequest(t, idA, "tailscale", "block", nil), map[string]string{"addresses": "100.101.7.10 fd7a:115c:a1e0::7"})
	if result := runRequest(t, executor, block); !result.OK {
		t.Fatalf("block %+v", result)
	}
	for _, call := range []string{
		"iptables -A KRY-TAILNET -s 100.101.7.10/32 -j DROP",
		"ip6tables -A KRY-TAILNET -s fd7a:115c:a1e0::7/128 -j DROP",
		"iptables -I INPUT 1 -i tailscale0 -j KRY-TAILNET",
		"iptables -I FORWARD 1 -i tailscale0 -j KRY-TAILNET",
		"ip6tables -I INPUT 1 -i tailscale0 -j KRY-TAILNET",
		"ip6tables -I FORWARD 1 -i tailscale0 -j KRY-TAILNET",
	} {
		if !slices.Contains(run.calls, call) {
			t.Fatalf("missing %q in %q", call, run.calls)
		}
	}
	unsigned := hostRequest(t, idB, "tailscale", "unblock", map[string]string{"addresses": "100.101.7.10"})
	unsigned.Signed = nil
	if result := runRequest(t, executor, unsigned); result.OK {
		t.Fatalf("unblocked unsigned %+v", result)
	}
	if result := runRequest(t, executor, hostRequest(t, "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a03", "tailscale", "unblock", map[string]string{"addresses": "100.101.7.10"})); !result.OK {
		t.Fatalf("unblock %+v", result)
	}
	state, _ := readState[tailnetBlock](executor.StateDir, tailnetFile)
	if !slices.Equal(state.Addresses, []string{"fd7a:115c:a1e0::7"}) {
		t.Fatalf("kept %v", state.Addresses)
	}
	run.calls = nil
	if result := runRequest(t, executor, hostRequest(t, "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a04", "tailscale", "unblock", map[string]string{"addresses": "fd7a:115c:a1e0::7"})); !result.OK {
		t.Fatalf("unblock the last %+v", result)
	}
	for _, call := range []string{"iptables -D INPUT -i tailscale0 -j KRY-TAILNET", "ip6tables -X KRY-TAILNET"} {
		if !slices.Contains(run.calls, call) {
			t.Fatalf("missing %q in %q", call, run.calls)
		}
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, tailnetFile)); !os.IsNotExist(err) {
		t.Fatalf("the block file is kept: %v", err)
	}
}
