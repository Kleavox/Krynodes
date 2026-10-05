package actions

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/cloudflare"
	"github.com/Kleavox/krynodes/agent/internal/cloudflare/cftest"
	"github.com/Kleavox/krynodes/agent/internal/seal"
	"github.com/Kleavox/krynodes/agent/internal/shamir"
)

const splitSet = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a20"

func pieces(t *testing.T, token string, holders int) [][]byte {
	t.Helper()
	split, err := shamir.Split([]byte(token), holders)
	if err != nil {
		t.Fatal(err)
	}
	return split
}

func sealedPiece(t *testing.T, executor Executor, set string, piece []byte) string {
	t.Helper()
	return sealFor(t, executor, vaultPiece{Set: set, Piece: piece})
}

func vaultRequest(t *testing.T, id, action string, change func(*Command)) Request {
	t.Helper()
	command := Command{ID: id, Kind: "vault", Name: "cloudflare", Action: action}
	if change != nil {
		change(&command)
	}
	return signedRequest(t, command)
}

func storePiece(t *testing.T, executor Executor, piece []byte, holders string) {
	t.Helper()
	request := vaultRequest(t, idA, "store", func(c *Command) {
		c.Piece = sealedPiece(t, executor, splitSet, piece)
		c.Args = map[string]string{"set": splitSet, "holders": holders}
	})
	if result := runRequest(t, executor, request); !result.OK {
		t.Fatalf("store %#v", result)
	}
	os.Remove(filepath.Join(executor.StateDir, "results", idA+".json"))
	ledger, _ := readState[map[string]any](executor.StateDir, "executed.json")
	delete(ledger, idA)
	writeJSON(executor.StateDir, "executed.json", ledger, 0o640)
}

func TestAPieceIsStoredReleasedAndForgotten(t *testing.T) {
	executor, _ := newTrustedExecutor(t)
	split := pieces(t, "cf-token", 3)
	storePiece(t, executor, split[0], "3")
	var stored vaultFile
	if err := readJSON(filepath.Join(executor.StateDir, "vault.json"), &stored); err != nil || stored.Set != splitSet || stored.Holders != 3 {
		t.Fatalf("stored %#v %v", stored, err)
	}
	target, _ := ecdh.P256().GenerateKey(rand.Reader)
	release := vaultRequest(t, idB, "release", func(c *Command) {
		c.Args = map[string]string{"key": seal.Public(target), "set": splitSet}
	})
	result := runRequest(t, executor, release)
	if !result.OK {
		t.Fatalf("release %#v", result)
	}
	opened, err := seal.Open(target, result.Output)
	if err != nil {
		t.Fatal(err)
	}
	var released vaultPiece
	if json.Unmarshal(opened, &released) != nil || released.Set != splitSet || string(released.Piece) != string(split[0]) {
		t.Fatalf("released %#v", released)
	}
	var inventory Inventory
	readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory)
	if inventory.Vault == nil || inventory.Vault.Set != splitSet || inventory.Vault.Holders != 3 {
		t.Fatalf("vault %#v", inventory.Vault)
	}
	forget := vaultRequest(t, "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a03", "forget", nil)
	if result := runRequest(t, executor, forget); !result.OK {
		t.Fatalf("forget %#v", result)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "vault.json")); !os.IsNotExist(err) {
		t.Fatal("the piece must be gone")
	}
}

func TestAPieceOfAnotherSplitIsRefused(t *testing.T) {
	executor, _ := newTrustedExecutor(t)
	request := vaultRequest(t, idA, "store", func(c *Command) {
		c.Piece = sealedPiece(t, executor, "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a99", []byte{1, 2, 3})
		c.Args = map[string]string{"set": splitSet, "holders": "2"}
	})
	if result := runRequest(t, executor, request); result.OK {
		t.Fatal("a piece of another split must be refused")
	}
}

func cloudflareExecutor(t *testing.T, stacks ...Stack) (Executor, *fakeRun, *cftest.API) {
	t.Helper()
	executor, run := stackExecutor(t, stacks...)
	fake := cftest.New()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	executor.CloudflareBase = server.URL + "/client/v4"
	executor.CloudflareHTTP = server.Client()
	return executor, run, fake
}

func listmonkStack() Stack {
	return Stack{Project: "listmonk", Directory: "/opt/listmonk", Files: []string{"/opt/listmonk/docker-compose.yml"}, Running: 2, Total: 2}
}

func exposeRequest(t *testing.T, executor Executor, piece []byte, action string, args map[string]string) Request {
	t.Helper()
	request := composeRequest(t, idA, "listmonk", action, func(c *Command) { c.Args = args })
	if piece != nil {
		request.Attachment = sealedPiece(t, executor, splitSet, piece)
	}
	return request
}

func TestAServiceGetsAWebAddressWithTheDashboardLogin(t *testing.T) {
	executor, run, fake := cloudflareExecutor(t, listmonkStack())
	split := pieces(t, "cf-token", 2)
	storePiece(t, executor, split[0], "2")
	run.respond = map[string]string{
		"docker ps --filter label=com.docker.compose.project=listmonk --filter label=com.docker.compose.service=app --format {{.Names}}": "listmonk-app-1\n",
		"docker inspect --format {{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}} listmonk-app-1":                       "listmonk_default \n",
	}
	run.failing = map[string]string{"docker inspect --format {{.State.Running}} " + TunnelContainer: "No such object"}
	args := map[string]string{"service": "app", "port": "9000", "hostname": "listmonk-pivox.kleavox.xyz", "mode": "path", "path": "/admin", "zone": "kleavox.xyz", "aud": "aud-1"}
	result := runRequest(t, executor, exposeRequest(t, executor, split[1], "expose", args))
	if !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	var tunnel string
	for id := range fake.Tunnels {
		tunnel = id
	}
	rules := fake.Ingress[tunnel]
	if len(rules) != 2 || rules[0].Hostname != "listmonk-pivox.kleavox.xyz" || rules[0].Service != "http://listmonk-app-1:9000" {
		t.Fatalf("rules %#v", rules)
	}
	if len(fake.Records) != 1 || len(fake.Apps) != 2 {
		t.Fatalf("records %v apps %v", fake.Records, fake.Apps)
	}
	if !slices.ContainsFunc(run.calls, func(call string) bool {
		return strings.HasPrefix(call, "docker run -d --name krynodes-tunnel --restart unless-stopped --env-file ") && strings.HasSuffix(call, cloudflaredImage+" tunnel --no-autoupdate run")
	}) || !slices.Contains(run.calls, "docker network connect listmonk_default krynodes-tunnel") {
		t.Fatalf("calls %q", run.calls)
	}
	if env, _ := os.ReadFile(filepath.Join(executor.StateDir, "tunnel.env")); string(env) != "TUNNEL_TOKEN=tunnel-token-"+tunnel+"\n" {
		t.Fatalf("env %q", env)
	}
	if strings.Contains(strings.Join(run.calls, " "), "tunnel-token-") {
		t.Fatal("the tunnel token never appears in a command line")
	}
	var output struct {
		Hostname string `json:"hostname"`
		Expires  string `json:"expires"`
	}
	if json.Unmarshal([]byte(result.Output), &output) != nil || output.Expires != "2027-10-05T00:00:00Z" {
		t.Fatalf("output %q", result.Output)
	}
}

func TestAWebAddressNeedsTwoPiecesAndAGoodName(t *testing.T) {
	executor, run, fake := cloudflareExecutor(t, listmonkStack())
	split := pieces(t, "cf-token", 2)
	storePiece(t, executor, split[0], "2")
	good := map[string]string{"service": "app", "port": "9000", "hostname": "listmonk-pivox.kleavox.xyz", "mode": "allow", "zone": "kleavox.xyz", "aud": "aud-1"}
	cases := map[string]Request{
		"one piece":  exposeRequest(t, executor, nil, "expose", good),
		"other zone": exposeRequest(t, executor, split[1], "expose", merge(good, map[string]string{"hostname": "listmonk.evil.example"})),
		"bad port":   exposeRequest(t, executor, split[1], "expose", merge(good, map[string]string{"port": "99999"})),
		"bad mode":   exposeRequest(t, executor, split[1], "expose", merge(good, map[string]string{"mode": "open"})),
		"bad path":   exposeRequest(t, executor, split[1], "expose", merge(good, map[string]string{"mode": "path", "path": "admin"})),
	}
	for label, request := range cases {
		if result := runRequest(t, executor, request); result.OK {
			t.Fatalf("%s must be refused", label)
		}
		os.Remove(filepath.Join(executor.StateDir, "results", idA+".json"))
		ledger, _ := readState[map[string]any](executor.StateDir, "executed.json")
		delete(ledger, idA)
		writeJSON(executor.StateDir, "executed.json", ledger, 0o640)
	}
	if len(fake.Tunnels) != 0 || slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "docker run") }) {
		t.Fatalf("nothing may change: %v %q", fake.Tunnels, run.calls)
	}
}

func merge(base, change map[string]string) map[string]string {
	merged := map[string]string{}
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range change {
		merged[key] = value
	}
	return merged
}

func TestRemovingTheLastAddressStopsTheTunnel(t *testing.T) {
	executor, run, fake := cloudflareExecutor(t, listmonkStack())
	split := pieces(t, "cf-token", 2)
	storePiece(t, executor, split[0], "2")
	run.respond = map[string]string{
		"docker ps --filter label=com.docker.compose.project=listmonk --filter label=com.docker.compose.service=app --format {{.Names}}": "listmonk-app-1\n",
		"docker inspect --format {{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}} listmonk-app-1":                       "listmonk_default \n",
	}
	args := map[string]string{"service": "app", "port": "9000", "hostname": "listmonk-pivox.kleavox.xyz", "mode": "allow", "zone": "kleavox.xyz", "aud": "aud-1"}
	if result := runRequest(t, executor, exposeRequest(t, executor, split[1], "expose", args)); !result.OK {
		t.Fatalf("expose %#v", result)
	}
	off := composeRequest(t, idB, "listmonk", "unexpose", func(c *Command) {
		c.Args = map[string]string{"hostname": "listmonk-pivox.kleavox.xyz", "zone": "kleavox.xyz"}
	})
	off.Attachment = sealedPiece(t, executor, splitSet, split[1])
	if result := runRequest(t, executor, off); !result.OK {
		t.Fatalf("unexpose %#v", result)
	}
	for _, rules := range fake.Ingress {
		if len(rules) != 1 {
			t.Fatalf("rules %#v", rules)
		}
	}
	if len(fake.Records) != 0 || len(fake.Apps) != 1 || !slices.Contains(run.calls, "docker rm -f krynodes-tunnel") {
		t.Fatalf("records %v apps %v calls %q", fake.Records, fake.Apps, run.calls)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "tunnel.env")); !os.IsNotExist(err) {
		t.Fatal("the tunnel token file goes with the last address")
	}
}

func TestReshareMakesFreshPiecesAndCleansARemovedServer(t *testing.T) {
	executor, _, fake := cloudflareExecutor(t)
	split := pieces(t, "cf-token", 3)
	storePiece(t, executor, split[0], "3")
	cf := &cloudflare.Client{Token: "cf-token", Base: executor.CloudflareBase, HTTP: executor.CloudflareHTTP}
	ctx := context.Background()
	gone, _ := cf.Tunnel(ctx, "acc-1", "krynodes-node-gone")
	cf.Point(ctx, "zone-1", "kuma-gone.kleavox.xyz", gone)
	cf.Guard(ctx, "acc-1", "kuma-gone.kleavox.xyz", "aud-1")
	first, _ := ecdh.P256().GenerateKey(rand.Reader)
	second, _ := ecdh.P256().GenerateKey(rand.Reader)
	next := "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a21"
	request := vaultRequest(t, idB, "reshare", func(c *Command) {
		c.Args = map[string]string{"holders": "node-1:" + seal.Public(first) + ",node-2:" + seal.Public(second), "set": next, "cleanup": "node-gone", "zone": "kleavox.xyz"}
	})
	request.Attachment = sealedPiece(t, executor, splitSet, split[2])
	result := runRequest(t, executor, request)
	if !result.OK {
		t.Fatalf("reshare %#v", result)
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(result.Output), &out); err != nil || len(out) != 2 {
		t.Fatalf("output %q", result.Output)
	}
	var rebuilt [][]byte
	for node, key := range map[string]*ecdh.PrivateKey{"node-1": first, "node-2": second} {
		opened, err := seal.Open(key, out[node])
		if err != nil {
			t.Fatal(err)
		}
		var piece vaultPiece
		json.Unmarshal(opened, &piece)
		if piece.Set != next {
			t.Fatalf("piece %#v", piece)
		}
		rebuilt = append(rebuilt, piece.Piece)
	}
	if token, err := shamir.Combine(rebuilt); err != nil || string(token) != "cf-token" {
		t.Fatalf("token %q %v", token, err)
	}
	if len(fake.Tunnels) != 0 || len(fake.Records) != 0 || len(fake.Apps) != 1 {
		t.Fatalf("tunnels %v records %v apps %v", fake.Tunnels, fake.Records, fake.Apps)
	}
}

func TestTheAgentReadsAPieceWrittenByTheBrowser(t *testing.T) {
	var piece vaultPiece
	if err := json.Unmarshal([]byte(`{"set":"`+splitSet+`","piece":"AQID+g=="}`), &piece); err != nil {
		t.Fatal(err)
	}
	if piece.Set != splitSet || string(piece.Piece) != string([]byte{1, 2, 3, 250}) {
		t.Fatalf("piece %#v", piece)
	}
}
