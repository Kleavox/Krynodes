package actions

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/seal"
	"github.com/Kleavox/krynodes/agent/internal/tailscale"
)

const pivoxTailnet = `{"BackendState":"Running","MagicDNSSuffix":"tail4d2a.ts.net","Self":{"ID":"nSelf1CNTRL","DNSName":"pivox.tail4d2a.ts.net.","TailscaleIPs":["100.101.7.20","fd7a:115c:a1e0::20"],"Tags":["tag:kry"]},"Peer":{"k1":{"DNSName":"io.tail4d2a.ts.net.","TailscaleIPs":["100.101.7.11"]}}}`

func tailnetServer(t *testing.T) (Executor, *fakeRun) {
	t.Helper()
	executor, run := securityExecutor(t)
	rootFile(t, executor, "/usr/bin/tailscale", "")
	run.respond["tailscale status --json"] = pivoxTailnet
	return executor, run
}

func TestTheServerReportsWhoMayReachItThroughTheLocalAPI(t *testing.T) {
	executor, _ := tailnetServer(t)
	if report := executor.tailnet(context.Background()); report == nil || report.Reach != nil || *report.ID != "nSelf1CNTRL" {
		t.Fatalf("without the local API: %+v", report)
	}
	executor.TailscaleLocal = func(context.Context, string) ([]byte, error) {
		return []byte(`[{"SrcIPs":["100.101.7.11"],"DstPorts":[{"IP":"100.101.7.20","Ports":{"First":53,"Last":53}}],"IPProto":[17]}]`), nil
	}
	report := executor.tailnet(context.Background())
	if report == nil || report.Reach == nil || !reflect.DeepEqual(*report.Reach, []reporter.TailscaleReach{{From: []string{"100.101.7.11"}, Ports: []string{"53/udp"}}}) || report.Names["100.101.7.11"] != "io" {
		t.Fatalf("got %+v", report)
	}
}

func TestTheInventoryChangesWhenWhoMayReachTheServerChanges(t *testing.T) {
	hash := func(ports string) string {
		reach := []reporter.TailscaleReach{{From: []string{"*"}, Ports: []string{ports}}}
		inventory, err := NewInventory(Parts{Tailscale: &reporter.TailscaleReport{State: "running", Addresses: []string{}, Tags: []string{}, Names: map[string]string{}, Reach: &reach}}, executorNow)
		if err != nil {
			t.Fatal(err)
		}
		return inventory.Hash
	}
	if hash("*") == hash("22/tcp") || hash("*") != hash("*") {
		t.Fatal("the hash does not follow the reach report")
	}
}

func TestInspectReadsInUseNowWithoutASignature(t *testing.T) {
	executor, run := tailnetServer(t)
	run.respond["ss -H -tuln"] = "udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\ntcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n"
	run.respond["ss -H -tn state established"] = "0 0 100.101.7.20:22 100.101.7.33:51515\n"
	rootFile(t, executor, "/proc/net/nf_conntrack", "ipv4     2 udp      17 25 src=100.101.7.11 dst=100.101.7.20 sport=40000 dport=53 src=100.101.7.20 dst=100.101.7.11 sport=53 dport=40000 [ASSURED] mark=0 use=2\n")
	request := hostRequest(t, idA, "tailscale", "inspect", nil)
	request.Signed = nil
	result := runRequest(t, executor, request)
	if !result.OK {
		t.Fatalf("inspect %+v", result)
	}
	var output struct {
		At    string                  `json:"at"`
		InUse []reporter.TailscaleUse `json:"inUse"`
	}
	if err := json.Unmarshal([]byte(result.Output), &output); err != nil {
		t.Fatal(err)
	}
	want := []reporter.TailscaleUse{{From: "100.101.7.33", Port: "22/tcp"}, {From: "100.101.7.11", Port: "53/udp"}}
	if output.At == "" || !reflect.DeepEqual(output.InUse, want) {
		t.Fatalf("got %+v", output)
	}
}

func tailscaleRequest(t *testing.T, id, action string, change func(*Command)) Request {
	t.Helper()
	command := Command{ID: id, Kind: "vault", Name: "tailscale", Action: action}
	if change != nil {
		change(&command)
	}
	return signedRequest(t, command)
}

func TestTheTailscaleCredentialKeepsItsOwnPieces(t *testing.T) {
	executor, _ := newTrustedExecutor(t)
	storePiece(t, executor, pieces(t, "cf-token", 2)[0], "2")
	store := tailscaleRequest(t, idB, "store", func(c *Command) {
		c.Piece = sealedPiece(t, executor, nextSet, pieces(t, "tskey-client-secret", 2)[0])
		c.Args = map[string]string{"set": nextSet, "holders": "2"}
	})
	if result := runRequest(t, executor, store); !result.OK {
		t.Fatalf("store %#v", result)
	}
	var cloudflare, tailnet vaultFile
	readJSON(filepath.Join(executor.StateDir, "vault.json"), &cloudflare)
	readJSON(filepath.Join(executor.StateDir, "vault-tailscale.json"), &tailnet)
	if cloudflare.Set != splitSet || tailnet.Set != nextSet || tailnet.Holders != 2 {
		t.Fatalf("cloudflare %#v tailscale %#v", cloudflare, tailnet)
	}
	var inventory Inventory
	readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory)
	if inventory.Vault == nil || inventory.Vault.Set != splitSet || inventory.TailscaleVault == nil || inventory.TailscaleVault.Set != nextSet {
		t.Fatalf("inventory %#v %#v", inventory.Vault, inventory.TailscaleVault)
	}
	if result := runRequest(t, executor, tailscaleRequest(t, idC, "forget", nil)); !result.OK {
		t.Fatalf("forget %#v", result)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "vault-tailscale.json")); !os.IsNotExist(err) {
		t.Fatal("the Tailscale piece must be gone")
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "vault.json")); err != nil {
		t.Fatal("the Cloudflare piece must stay")
	}
}

func TestTheSecretTakesNoPieceOfTheOtherVault(t *testing.T) {
	executor, _ := newTrustedExecutor(t)
	token := pieces(t, "cf-token", 2)
	secret := pieces(t, "tskey-client-secret", 2)
	storeInto(t, executor, idA, splitSet, "", token[0], "2")
	store := tailscaleRequest(t, idB, "store", func(c *Command) {
		c.Piece = sealedPiece(t, executor, nextSet, secret[0])
		c.Args = map[string]string{"set": nextSet, "holders": "2"}
	})
	if result := runRequest(t, executor, store); !result.OK {
		t.Fatalf("store %#v", result)
	}
	if _, err := executor.secret(Request{Attachment: sealedPiece(t, executor, splitSet, token[1])}, Command{}, "tailscale"); err == nil {
		t.Fatal("a Cloudflare piece must not rebuild the Tailscale secret")
	}
	rebuilt, err := executor.secret(Request{Attachment: sealedPiece(t, executor, nextSet, secret[1])}, Command{}, "tailscale")
	if err != nil || string(rebuilt) != "tskey-client-secret" {
		t.Fatalf("got %q %v", rebuilt, err)
	}
	if token, err := executor.secret(Request{Attachment: sealedPiece(t, executor, splitSet, token[1])}, Command{}, "cloudflare"); err != nil || string(token) != "cf-token" {
		t.Fatalf("cloudflare %q %v", token, err)
	}
}

const (
	tsClient = "kQ1clientCNTRL"
	tsSecret = "tskey-" + "client-kQ1clientCNTRL-0123456789abcdef"
	tsKey    = "tskey-" + "auth-k1CNTRL-0123456789abcdef"
	pivoxID  = "6f1c2c8e-4a51-4d0c-9a59-1d2a6c7b8e90"
	idD      = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a04"
)

const tailnetPolicy = `{
	"tagOwners": {"tag:kry": ["autogroup:admin"], "tag:nas": ["autogroup:admin"]},
	// mine
	"acls": [
		{"action": "accept", "src": ["*"], "dst": ["*:*"]},
	],
}
`

const tailnetDevices = `{"devices":[
	{"nodeId":"nA","name":"pivox.tail4d2a.ts.net","addresses":["100.101.7.20"]},
	{"nodeId":"nL","name":"laptop.tail4d2a.ts.net","addresses":["100.101.7.33"],"advertisedRoutes":["192.168.1.0/24","0.0.0.0/0"]},
	{"nodeId":"nN","name":"nas.tail4d2a.ts.net","addresses":["100.101.7.40"],"tags":["tag:nas"]}]}`

type fakeTailnet struct {
	policy  string
	etag    string
	devices string
	moved   bool
	tokens  int
	calls   []string
	bodies  map[string]string
}

func (f *fakeTailnet) called(key string) bool {
	return slices.Contains(f.calls, key)
}

func tailnetVault(t *testing.T) (Executor, *fakeRun, *fakeTailnet, func(id, action string, args map[string]string) Request) {
	t.Helper()
	executor, run := tailnetServer(t)
	secret := pieces(t, tsSecret, 2)
	store := tailscaleRequest(t, idA, "store", func(c *Command) {
		c.Piece = sealedPiece(t, executor, nextSet, secret[0])
		c.Args = map[string]string{"set": nextSet, "holders": "2"}
	})
	if result := runRequest(t, executor, store); !result.OK {
		t.Fatalf("store %#v", result)
	}
	fake := &fakeTailnet{policy: tailnetPolicy, etag: `"e1"`, devices: tailnetDevices, bodies: map[string]string{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		key := r.Method + " " + r.URL.Path
		fake.calls = append(fake.calls, key)
		fake.bodies[key] = string(body)
		switch {
		case key == "POST /api/v2/oauth/token":
			fake.tokens++
			form, _ := url.ParseQuery(string(body))
			if form.Get("client_id") != tsClient || form.Get("client_secret") != tsSecret {
				w.WriteHeader(http.StatusUnauthorized)
				io.WriteString(w, `{"message":"invalid client credentials"}`)
				return
			}
			io.WriteString(w, `{"access_token":"tok-1"}`)
		case r.Header.Get("Authorization") != "Bearer tok-1":
			w.WriteHeader(http.StatusUnauthorized)
		case key == "GET /api/v2/tailnet/-/acl":
			w.Header().Set("ETag", fake.etag)
			io.WriteString(w, fake.policy)
		case key == "POST /api/v2/tailnet/-/acl":
			if fake.moved || r.Header.Get("If-Match") != fake.etag {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			fake.policy = string(body)
			io.WriteString(w, fake.policy)
		case key == "GET /api/v2/tailnet/-/devices":
			io.WriteString(w, fake.devices)
		case key == "POST /api/v2/tailnet/-/keys":
			io.WriteString(w, `{"id":"k1","key":"`+tsKey+`"}`)
		default:
			io.WriteString(w, `{}`)
		}
	}))
	t.Cleanup(server.Close)
	executor.TailscaleBase, executor.TailscaleHTTP = server.URL, server.Client()
	job := func(id, action string, args map[string]string) Request {
		if args == nil {
			args = map[string]string{}
		}
		if _, set := args["client"]; !set {
			args["client"] = tsClient
		}
		request := tailscaleRequest(t, id, action, func(c *Command) { c.Args = args })
		request.Attachment = sealedPiece(t, executor, nextSet, secret[1])
		return request
	}
	return executor, run, fake, job
}

func saveArgs(expected, tag string) map[string]string {
	rules, _ := json.Marshal([]tailscale.Rule{{From: "devices", To: "rest"}, {From: "devices", To: "servers", Ports: []string{"22/tcp"}}})
	servers, _ := json.Marshal(map[string][]string{pivoxID: {"100.101.7.20"}})
	return map[string]string{"rules": string(rules), "servers": string(servers), "expected": expected, "tag": tag, "label": ""}
}

const (
	tailnetRest = `{"src":["autogroup:member"],"dst":["autogroup:member","autogroup:internet","192.168.1.0/24","tag:nas"],"ip":["*"]}`
	tailnetSSH  = `{"src":["autogroup:member"],"dst":["100.101.7.20"],"ip":["tcp:22"]}`
)

func TestASaveRewritesOnlyKrynodesRulesAfterTailscaleChecksThem(t *testing.T) {
	executor, _, fake, job := tailnetVault(t)
	result := runRequest(t, executor, job(idB, "save", saveArgs("", "nA")))
	if !result.OK || strings.Contains(result.Output, tsSecret) {
		t.Fatalf("save %#v", result)
	}
	var output struct {
		Saved   bool     `json:"saved"`
		At      string   `json:"at"`
		Etag    string   `json:"etag"`
		Block   string   `json:"block"`
		Lines   []string `json:"lines"`
		Members []string `json:"members"`
		Devices []string `json:"devices"`
	}
	if err := json.Unmarshal([]byte(result.Output), &output); err != nil {
		t.Fatal(err)
	}
	lines := []string{tailnetRest, tailnetSSH}
	if !output.Saved || output.At == "" || output.Etag != `"e1"` || output.Block != tailscale.BlockHash(lines) || !reflect.DeepEqual(output.Lines, lines) || !reflect.DeepEqual(output.Members, []string{"100.101.7.33"}) || !reflect.DeepEqual(output.Devices, []string{"nA", "nL", "nN"}) {
		t.Fatalf("output %+v", output)
	}
	want := "{\n\t\"tagOwners\": {\"tag:kry\": [\"autogroup:admin\"], \"tag:nas\": [\"autogroup:admin\"]},\n\t// mine\n\t\"acls\": [\n\t],\n\t\"grants\": [\n\t\t// krynodes: begin · kept by Krynodes, change it there\n\t\t" + tailnetRest + ",\n\t\t" + tailnetSSH + ",\n\t\t// krynodes: end\n\t]\n}\n"
	if fake.policy != want {
		t.Fatalf("written:\n%s", fake.policy)
	}
	order := []string{"POST /api/v2/device/nA/tags", "POST /api/v2/device/nA/key", "POST /api/v2/tailnet/-/acl/validate", "POST /api/v2/tailnet/-/acl"}
	at := -1
	for _, call := range order {
		next := slices.Index(fake.calls, call)
		if next <= at {
			t.Fatalf("calls %v", fake.calls)
		}
		at = next
	}
	if fake.bodies["POST /api/v2/device/nA/tags"] != `{"tags":["tag:kry"]}` || fake.bodies["POST /api/v2/tailnet/-/acl/validate"] != want || fake.tokens != 1 {
		t.Fatalf("bodies %v tokens %d", fake.bodies, fake.tokens)
	}
}

func TestARuleChangedInTheAdminConsoleIsNeverOverwritten(t *testing.T) {
	executor, _, fake, job := tailnetVault(t)
	fake.policy = "{\n\t\"grants\": [\n\t\t// krynodes: begin · kept by Krynodes, change it there\n\t\t" + tailnetSSH + ",\n\t\t{\"src\":[\"autogroup:member\"],\"dst\":[\"100.101.7.20\"],\"ip\":[\"tcp:3000\"]},\n\t\t// krynodes: end\n\t],\n}\n"
	result := runRequest(t, executor, job(idB, "save", saveArgs(tailscale.BlockHash([]string{tailnetSSH}), "nA")))
	var output struct {
		Saved   bool   `json:"saved"`
		Block   string `json:"block"`
		Changed struct {
			Now []string `json:"now"`
		} `json:"changed"`
	}
	if err := json.Unmarshal([]byte(result.Output), &output); err != nil || !result.OK {
		t.Fatalf("result %#v %v", result, err)
	}
	now := []string{tailnetSSH, `{"src":["autogroup:member"],"dst":["100.101.7.20"],"ip":["tcp:3000"]}`}
	if output.Saved || !reflect.DeepEqual(output.Changed.Now, now) || output.Block != tailscale.BlockHash(now) {
		t.Fatalf("output %+v", output)
	}
	if fake.called("POST /api/v2/tailnet/-/acl") || fake.called("POST /api/v2/device/nA/tags") {
		t.Fatalf("something was written: %v", fake.calls)
	}
}

func TestAPolicyThatMovedWhileSavingIsRefusedAndTaggedOnce(t *testing.T) {
	executor, _, fake, job := tailnetVault(t)
	fake.moved = true
	fake.devices = strings.Replace(tailnetDevices, `"addresses":["100.101.7.20"]`, `"addresses":["100.101.7.20"],"tags":["tag:kry"]`, 1)
	result := runRequest(t, executor, job(idB, "save", saveArgs("", "nA")))
	if result.OK || result.Output != "refused: Your policy file changed while saving. Try again." {
		t.Fatalf("result %#v", result)
	}
	if fake.called("POST /api/v2/device/nA/tags") || !fake.called("POST /api/v2/device/nA/key") {
		t.Fatalf("calls %v", fake.calls)
	}
}

func TestThePolicyJobReadsWhatTheFileHolds(t *testing.T) {
	executor, _, _, job := tailnetVault(t)
	result := runRequest(t, executor, job(idB, "policy", nil))
	var output struct {
		At      string             `json:"at"`
		Etag    string             `json:"etag"`
		Kry     bool               `json:"kry"`
		Open    *string            `json:"open"`
		Block   []string           `json:"block"`
		Hash    *string            `json:"hash"`
		Tags    []string           `json:"tags"`
		Devices []tailscale.Device `json:"devices"`
	}
	if err := json.Unmarshal([]byte(result.Output), &output); err != nil || !result.OK {
		t.Fatalf("result %#v %v", result, err)
	}
	if output.At == "" || output.Etag != `"e1"` || !output.Kry || output.Open == nil || *output.Open != "acls" || output.Block != nil || output.Hash == nil || *output.Hash != "" || !reflect.DeepEqual(output.Tags, []string{"tag:kry", "tag:nas"}) || len(output.Devices) != 3 || !output.Devices[1].User {
		t.Fatalf("output %+v", output)
	}
}

func TestTheOneTimeKeyIsSealedToTheJoiningServer(t *testing.T) {
	executor, _, fake, job := tailnetVault(t)
	joining, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	result := runRequest(t, executor, job(idB, "key", map[string]string{"to": pivoxID, "key": seal.Public(joining)}))
	if !result.OK || strings.Contains(result.Output, tsKey) {
		t.Fatalf("key %#v", result)
	}
	opened, err := seal.Open(joining, result.Output)
	if err != nil || string(opened) != `{"authKey":"`+tsKey+`"}` {
		t.Fatalf("opened %s %v", opened, err)
	}
	if _, err := seal.Open(mustKey(t, executor), result.Output); err == nil {
		t.Fatal("the server that made the key can open it")
	}
	var asked struct {
		Capabilities struct {
			Devices struct {
				Create struct {
					Reusable      bool     `json:"reusable"`
					Preauthorized bool     `json:"preauthorized"`
					Tags          []string `json:"tags"`
				} `json:"create"`
			} `json:"devices"`
		} `json:"capabilities"`
		ExpirySeconds int `json:"expirySeconds"`
	}
	json.Unmarshal([]byte(fake.bodies["POST /api/v2/tailnet/-/keys"]), &asked)
	if create := asked.Capabilities.Devices.Create; create.Reusable || !create.Preauthorized || !reflect.DeepEqual(create.Tags, []string{"tag:kry"}) || asked.ExpirySeconds != 600 {
		t.Fatalf("asked %+v", asked)
	}
}

func TestRemoveDeletesTheDevice(t *testing.T) {
	executor, _, fake, job := tailnetVault(t)
	result := runRequest(t, executor, job(idB, "remove", map[string]string{"device": "nA", "node": pivoxID}))
	if !result.OK || result.Output != `{"removed":"nA"}` || !fake.called("DELETE /api/v2/device/nA") {
		t.Fatalf("result %#v calls %v", result, fake.calls)
	}
}

func TestATailnetJobWantsTheClientTheSecondPieceAndASignature(t *testing.T) {
	executor, _, fake, job := tailnetVault(t)
	if result := runRequest(t, executor, job(idB, "policy", map[string]string{"client": ""})); result.OK || !strings.Contains(result.Output, "client") {
		t.Fatalf("no client %#v", result)
	}
	alone := job(idC, "policy", nil)
	alone.Attachment = ""
	if result := runRequest(t, executor, alone); result.OK || !strings.Contains(result.Output, "second piece") {
		t.Fatalf("one piece %#v", result)
	}
	unsigned := job(idD, "save", saveArgs("", ""))
	unsigned.Signed = nil
	if result := runRequest(t, executor, unsigned); result.OK {
		t.Fatalf("unsigned %#v", result)
	}
	if fake.tokens != 0 {
		t.Fatalf("Tailscale was called %v", fake.calls)
	}
	cloudflare := job("0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a05", "policy", nil)
	cloudflare.Name = "cloudflare"
	if result := runRequest(t, executor, cloudflare); result.OK {
		t.Fatalf("cloudflare policy %#v", result)
	}
}

func joinRequest(t *testing.T, executor Executor, key string) Request {
	t.Helper()
	request := hostRequest(t, idB, "tailscale", "join", nil)
	request.Attachment = sealFor(t, executor, map[string]string{"authKey": key})
	return request
}

func TestJoinSignsInWithTheOneTimeKeyFromAFile(t *testing.T) {
	executor, run := tailnetServer(t)
	var seen []string
	held := ""
	executor.Stream = func(ctx context.Context, each func(string), name string, args ...string) error {
		seen = args
		for _, arg := range args {
			if file, found := strings.CutPrefix(arg, "--auth-key=file:"); found {
				raw, _ := os.ReadFile(file)
				held = string(raw)
				if info, err := os.Stat(file); err != nil || info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
					t.Fatalf("the key file %v %v", info, err)
				}
			}
		}
		return nil
	}
	writeRequest(t, executor.RequestDir, idB+".json", joinRequest(t, executor, tsKey))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	delete(run.respond, "tailscale status --json")
	run.sequence = map[string][]string{"tailscale status --json": {`{"BackendState":"NeedsLogin"}`, pivoxTailnet}}
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	result := readResult(t, executor, idB)
	if !result.OK || result.Output != `{"id":"nSelf1CNTRL","addresses":["100.101.7.20","fd7a:115c:a1e0::20"],"name":"pivox.tail4d2a.ts.net"}` {
		t.Fatalf("join %#v", result)
	}
	if held != tsKey || !slices.Contains(seen, "--accept-dns=false") || !slices.Contains(seen, "--ssh=false") || slices.Contains(seen, tsKey) {
		t.Fatalf("args %v held %q", seen, held)
	}
	leftovers, _ := filepath.Glob(filepath.Join(executor.StateDir, "*tailscale-key*"))
	if len(leftovers) != 0 {
		t.Fatalf("the key file stayed: %v", leftovers)
	}
}

func TestJoinRefusesARunningTailscaleAndCleansUpAFailure(t *testing.T) {
	executor, run := tailnetServer(t)
	hostQueue(t, executor, joinRequest(t, executor, tsKey))
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, idB); result.OK || !strings.Contains(result.Output, "already on a tailnet") {
		t.Fatalf("running %#v", result)
	}
	delete(run.respond, "tailscale status --json")
	run.respond["tailscale status --json"] = `{"BackendState":"NeedsLogin"}`
	executor.Stream = func(ctx context.Context, each func(string), name string, args ...string) error {
		each("backend error: invalid key: " + tsKey + " not valid")
		return context.DeadlineExceeded
	}
	os.Remove(filepath.Join(executor.StateDir, "results", idB+".json"))
	hostQueue(t, executor, joinRequest(t, executor, tsKey))
	if err := executor.HostApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	result := readResult(t, executor, idB)
	if result.OK || strings.Contains(result.Output, tsKey) || !strings.Contains(result.Output, "invalid key") {
		t.Fatalf("failed %#v", result)
	}
	leftovers, _ := filepath.Glob(filepath.Join(executor.StateDir, "*tailscale-key*"))
	if len(leftovers) != 0 {
		t.Fatalf("the key file stayed: %v", leftovers)
	}
	unsigned := joinRequest(t, executor, tsKey)
	unsigned.ID = idC
	unsigned.Signed = nil
	if result := runRequest(t, executor, unsigned); result.OK {
		t.Fatalf("unsigned %#v", result)
	}
}
