package actions

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/config"
	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/seal"
)

func TestTheReleaseCodeMatchesTheProtocol(t *testing.T) {
	code := releaseCode(reporter.Release{Key: "KEY", Signer: "SIGNER", Seal: "SEAL", Token: strings.Repeat("a", 64), Expires: "2026-10-27T21:20:00.000Z"})
	if code != "274DW-SMBYH" {
		t.Fatalf("code %s", code)
	}
}

type releasing struct {
	executor Executor
	run      *fakeRun
	mark     string
	keys     network.Keys
	peer     network.Keys
}

func quarantinedServer(t *testing.T) releasing {
	t.Helper()
	executor, run, keys, peer, _ := joinedServer(t)
	executor.ConfigPath = filepath.Join(t.TempDir(), "config.json")
	if err := config.Save(executor.ConfigPath, config.Config{Endpoint: "https://kry.example.com", NodeID: testNode, Token: "old-token"}); err != nil {
		t.Fatal(err)
	}
	return releasing{executor: executor, run: run, mark: filepath.Join(t.TempDir(), quarantinedFile), keys: keys, peer: peer}
}

func (r releasing) code(t *testing.T) (reporter.Release, string) {
	t.Helper()
	code, err := r.executor.ReleaseCode(r.mark)
	if err != nil {
		t.Fatal(err)
	}
	var pending reporter.Release
	if err := readJSON(filepath.Join(r.executor.StateDir, releaseFile), &pending); err != nil {
		t.Fatal(err)
	}
	return pending, code
}

func releaseRequest(t *testing.T, id string, pending reporter.Release, code string) Request {
	t.Helper()
	return hostRequest(t, id, "server", "release", map[string]string{"key": pending.Key, "signer": pending.Signer, "seal": pending.Seal, "token": pending.Token, "code": code})
}

func TestTheReleaseCodeIsMadeOnlyOnAServerThatIsCutOff(t *testing.T) {
	r := quarantinedServer(t)
	if _, err := r.executor.ReleaseCode(r.mark); err == nil {
		t.Fatal("made a code on a trusted server")
	}
	if err := os.WriteFile(r.mark, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	pending, code := r.code(t)
	if code != releaseCode(pending) || len(code) != 11 || code[5] != '-' {
		t.Fatalf("code %s for %+v", code, pending)
	}
	ends, err := time.Parse(time.RFC3339, pending.Expires)
	if err != nil || !ends.Equal(executorNow.Add(10*time.Minute)) || len(pending.Token) != 64 || pending.Key == r.keys.Public {
		t.Fatalf("pending %+v", pending)
	}
	var fields map[string]string
	if err := readJSON(filepath.Join(r.executor.StateDir, releaseFile), &fields); err != nil || len(fields) != 5 || fields["key"] != pending.Key {
		t.Fatalf("release.json holds more than it reports: %v %v", fields, err)
	}
}

func TestAReleaseWithAWrongCodeAnEndedCodeOrOtherKeysChangesNothing(t *testing.T) {
	r := quarantinedServer(t)
	os.WriteFile(r.mark, nil, 0o640)
	pending, _ := r.code(t)
	sealBefore, _ := os.ReadFile(filepath.Join(r.executor.StateDir, "keys", "seal.key"))
	other := pending
	other.Key = r.peer.Public
	for index, request := range []Request{
		releaseRequest(t, fresh(1), pending, "AAAAA-AAAAA"),
		releaseRequest(t, fresh(2), other, releaseCode(other)),
	} {
		if result := throughBoth(t, r.executor, request); result.OK {
			t.Fatalf("case %d released: %+v", index, result)
		}
	}
	ended := pending
	ended.Expires = executorNow.Add(-time.Second).Format(releaseTime)
	if err := writeJSON(r.executor.StateDir, releaseFile, ended, 0o640); err != nil {
		t.Fatal(err)
	}
	if result := throughBoth(t, r.executor, releaseRequest(t, fresh(3), ended, releaseCode(ended))); result.OK || !strings.Contains(result.Output, "ended") {
		t.Fatalf("an ended code released: %+v", result)
	}
	keys, _ := network.Load(r.executor.networkDir(), false)
	sealAfter, _ := os.ReadFile(filepath.Join(r.executor.StateDir, "keys", "seal.key"))
	cfg, _ := config.Load(r.executor.ConfigPath)
	if keys.Public != r.keys.Public || string(sealAfter) != string(sealBefore) || cfg.Token != "old-token" {
		t.Fatalf("something changed: key %v seal %v token %s", keys.Public != r.keys.Public, string(sealAfter) != string(sealBefore), cfg.Token)
	}
}

func TestAGoodReleaseSwapsTheKeysAndTheSignInToKrynodes(t *testing.T) {
	r := quarantinedServer(t)
	os.WriteFile(r.mark, nil, 0o640)
	sealBefore, _ := os.ReadFile(filepath.Join(r.executor.StateDir, "keys", "seal.key"))
	pending, code := r.code(t)
	if result := throughBoth(t, r.executor, releaseRequest(t, fresh(1), pending, code)); !result.OK {
		t.Fatalf("release %+v", result)
	}
	keys, err := network.Load(r.executor.networkDir(), false)
	if err != nil || keys.Public != pending.Key || keys.Signer != pending.Signer {
		t.Fatalf("network keys %+v %v", keys, err)
	}
	record := r.executor.readNetwork()
	if record.Key != pending.Key || record.Signer != pending.Signer {
		t.Fatalf("record %+v", record)
	}
	key := mustKey(t, r.executor)
	sealAfter, _ := os.ReadFile(filepath.Join(r.executor.StateDir, "keys", "seal.key"))
	if seal.Public(key) != pending.Seal || string(sealAfter) == string(sealBefore) {
		t.Fatal("the seal key was not swapped")
	}
	sealed, _ := seal.Seal(pending.Seal, testPSK)
	if plain, err := seal.Open(key, sealed); err != nil || string(plain) != string(testPSK) {
		t.Fatalf("a secret sealed to the new key does not open: %v", err)
	}
	cfg, _ := config.Load(r.executor.ConfigPath)
	sum := sha256.Sum256([]byte(cfg.Token))
	if hex.EncodeToString(sum[:]) != pending.Token || cfg.Token == "old-token" {
		t.Fatalf("token %s", cfg.Token)
	}
	for _, gone := range []string{releaseFile, "release"} {
		if _, err := os.Stat(filepath.Join(r.executor.StateDir, gone)); !os.IsNotExist(err) {
			t.Fatalf("%s kept: %v", gone, err)
		}
	}
	if !slices.Contains(r.run.calls, "systemctl restart --no-block "+agentUnit) {
		t.Fatalf("the agent was not restarted: %q", r.run.calls)
	}
}
