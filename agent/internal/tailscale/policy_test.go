package tailscale

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const ownersPolicy = `// The owner's policy file.
{
	// Who may hand out tags.
	"tagOwners": {
		"tag:kry": ["autogroup:admin"],
		"tag:nas": ["autogroup:admin"], // the NAS
	},
	"acls": [
		// Allow all connections.
		{"action": "accept", "src": ["*"], "dst": ["*:*"]},
	],
	"grants": [
		{"src": ["owner@example.com"], "dst": ["tag:nas"], "ip": ["tcp:445"]}, // "// not a comment"
		// krynodes: begin · kept by Krynodes, change it there
		{"src":["autogroup:member"],"dst":["100.101.7.20"],"ip":["tcp:22"]},
		// krynodes: end
		{"src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["*"]},
	],
	"ssh": [
		{"action": "check", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["autogroup:nonroot", "root"]},
	],
}
`

const (
	restLine = `{"src":["autogroup:member"],"dst":["autogroup:member","autogroup:internet","tag:nas"],"ip":["*"]}`
	sshLine  = `{"src":["autogroup:member"],"dst":["100.101.7.20"],"ip":["tcp:22"]}`
)

func TestBlankingKeepsEveryOffsetAndEveryString(t *testing.T) {
	blank := Blank([]byte(ownersPolicy))
	if len(blank) != len(ownersPolicy) || !json.Valid(blank) {
		t.Fatalf("blanked %q", blank)
	}
	if strings.Count(string(blank), "\n") != strings.Count(ownersPolicy, "\n") || strings.Contains(string(blank), "not a comment") || !strings.Contains(string(blank), `"owner@example.com"`) {
		t.Fatalf("lines or strings moved: %q", blank)
	}
	if got := string(Blank([]byte(`{"note": "a // b /* c */", "x": [1,],}`))); got != `{"note": "a // b /* c */", "x": [1 ] }` {
		t.Fatalf("got %q", got)
	}
}

func TestReadFindsTheTagsTheAllowAllRuleAndTheBlock(t *testing.T) {
	policy, err := Read([]byte(ownersPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(policy.Tags, []string{"tag:kry", "tag:nas"}) || !policy.Kry || policy.Open != "acls" {
		t.Fatalf("policy %+v", policy)
	}
	if open := ownersPolicy[policy.OpenSpan[0]:policy.OpenSpan[1]]; open != `{"action": "accept", "src": ["*"], "dst": ["*:*"]}` {
		t.Fatalf("open %q", open)
	}
	if !reflect.DeepEqual(policy.Block, []string{sshLine}) || policy.GrantsAt < 0 {
		t.Fatalf("block %q at %d", policy.Block, policy.GrantsAt)
	}
	if mine, _ := Read([]byte(`{"grants": [{"src": ["// krynodes: begin"], "dst": ["*"], "ip": ["*"]}]}`)); mine.Block != nil || mine.Open != "" {
		t.Fatalf("a marker inside a string %+v", mine)
	}
	if _, err := Read([]byte(`{"grants": [`)); err == nil {
		t.Fatal("a broken policy file must be refused")
	}
	for _, unclosed := range []string{"{\"grants\": [\n// krynodes: begin\n]}", "{\"grants\": [\n// krynodes: begin\n// krynodes: end\n// krynodes: begin\n// krynodes: end\n]}"} {
		if _, err := Read([]byte(unclosed)); err == nil || !strings.Contains(err.Error(), "admin console") {
			t.Fatalf("%q gave %v", unclosed, err)
		}
	}
}

func TestASaveChangesOnlyTheBlockAndTheAllowAllRule(t *testing.T) {
	policy, _ := Read([]byte(ownersPolicy))
	saved := string(Splice([]byte(ownersPolicy), policy, []string{restLine, sshLine}, true))
	want := strings.Replace(ownersPolicy, "\n\t\t{\"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"*:*\"]},", "", 1)
	want = strings.Replace(want, "\t\t"+sshLine+",\n", "\t\t"+restLine+",\n\t\t"+sshLine+",\n", 1)
	if saved != want {
		t.Fatalf("saved:\n%s\nwant:\n%s", saved, want)
	}
	again, _ := Read([]byte(saved))
	if again.Open != "" || !reflect.DeepEqual(again.Block, []string{restLine, sshLine}) || BlockHash(again.Block) != BlockHash([]string{restLine, sshLine}) {
		t.Fatalf("read back %+v", again)
	}
	if twice := string(Splice([]byte(saved), again, []string{restLine, sshLine}, true)); twice != saved {
		t.Fatalf("a second save changed it:\n%s", twice)
	}
}

func TestAPolicyWithoutGrantsGetsOneBeforeItsClosingBrace(t *testing.T) {
	for _, src := range []string{
		"{\n  \"acls\": [\n    {\"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"*:*\"]}\n  ]\n}\n",
		"{\n  \"acls\": [\n    {\"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"*:*\"]}\n  ], // mine\n}\n",
	} {
		policy, err := Read([]byte(src))
		if err != nil || policy.GrantsAt != -1 {
			t.Fatalf("policy %+v %v", policy, err)
		}
		saved := Splice([]byte(src), policy, []string{sshLine}, false)
		if !json.Valid(Blank(saved)) || !strings.Contains(string(saved), "  \"grants\": [\n    // krynodes: begin · kept by Krynodes, change it there\n    "+sshLine+",\n    // krynodes: end\n  ]") || !strings.HasPrefix(string(saved), src[:strings.Index(src, "  ]")+3]) {
			t.Fatalf("saved:\n%s", saved)
		}
		back, _ := Read(saved)
		if !reflect.DeepEqual(back.Block, []string{sshLine}) || back.Open != "acls" {
			t.Fatalf("read back %+v", back)
		}
	}
}

func TestAnEmptyGrantsListTakesTheBlock(t *testing.T) {
	src := `{"grants": [], "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`
	policy, _ := Read([]byte(src))
	saved := Splice([]byte(src), policy, []string{restLine}, true)
	back, err := Read(saved)
	if err != nil || !reflect.DeepEqual(back.Block, []string{restLine}) || back.Open != "" || !json.Valid(Blank(saved)) {
		t.Fatalf("saved %s %+v %v", saved, back, err)
	}
}

func TestTheBlockHashReadsTheLinesTrimmed(t *testing.T) {
	if BlockHash(nil) != "" || BlockHash([]string{}) == "" {
		t.Fatal("no block hashes to nothing, an empty block does not")
	}
	if BlockHash([]string{sshLine}) != BlockHash([]string{"   " + sshLine + ",  "}) || BlockHash([]string{sshLine}) == BlockHash([]string{restLine}) {
		t.Fatal("the hash must follow the trimmed lines")
	}
}

var twoServers = map[string][]string{
	"6f1c2c8e-4a51-4d0c-9a59-1d2a6c7b8e90": {"100.101.7.20", "fd7a:115c:a1e0::20"},
	"0b2e6d1a-7c3f-4e5b-8a9d-2c1b0a9f8e7d": {"100.101.7.11", "fd7a:115c:a1e0::11"},
}

func TestRulesBecomeGrantsByAddress(t *testing.T) {
	lines, err := Grants([]Rule{
		{From: "devices", To: "servers", Ports: []string{"22/tcp"}},
		{From: "0b2e6d1a-7c3f-4e5b-8a9d-2c1b0a9f8e7d", To: "6f1c2c8e-4a51-4d0c-9a59-1d2a6c7b8e90", Ports: []string{"53", "8000-8100/tcp", "*"}},
		{From: "devices", To: "rest"},
		{Raw: `{"src":["tag:nas"],"dst":["100.101.7.20"],"ip":["tcp:80"]}`},
	}, twoServers, []string{"autogroup:member", "autogroup:internet", "192.168.1.0/24", "tag:nas"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`{"src":["autogroup:member"],"dst":["100.101.7.11","fd7a:115c:a1e0::11","100.101.7.20","fd7a:115c:a1e0::20"],"ip":["tcp:22"]}`,
		`{"src":["100.101.7.11","fd7a:115c:a1e0::11"],"dst":["100.101.7.20","fd7a:115c:a1e0::20"],"ip":["tcp:53","udp:53","tcp:8000-8100","*"]}`,
		`{"src":["autogroup:member"],"dst":["autogroup:member","autogroup:internet","192.168.1.0/24","tag:nas"],"ip":["*"]}`,
		`{"src":["tag:nas"],"dst":["100.101.7.20"],"ip":["tcp:80"]}`,
	}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("lines\n%s", strings.Join(lines, "\n"))
	}
	for _, line := range lines[:3] {
		if strings.Contains(line, "tag:kry") {
			t.Fatalf("a grant names the servers' tag: %s", line)
		}
	}
	for _, broken := range [][]Rule{
		{{From: "devices", To: "9a9a9a9a-0000-4000-8000-000000000000", Ports: []string{"22/tcp"}}},
		{{From: "servers", To: "rest"}},
		{{From: "devices", To: "servers"}},
		{{Raw: "{\"src\":[\"*\"]}\n// krynodes: end"}},
		{{Raw: "not json"}},
	} {
		if _, err := Grants(broken, twoServers, nil); err == nil {
			t.Fatalf("%+v must be refused", broken)
		}
	}
}

func TestEverythingExceptYourServers(t *testing.T) {
	devices := []Device{
		{ID: "nA", Tags: []string{"tag:kry"}, Routes: []string{"0.0.0.0/0", "::/0", "192.168.1.0/24"}},
		{ID: "nB", Routes: []string{"192.168.1.0/24", "10.0.0.0/8"}},
	}
	if rest := Rest(devices, []string{"tag:kry", "tag:nas"}); !reflect.DeepEqual(rest, []string{"autogroup:member", "autogroup:internet", "10.0.0.0/8", "192.168.1.0/24", "tag:nas"}) {
		t.Fatalf("rest %v", rest)
	}
}

func Blank(src []byte) []byte {
	return scan(src).blank
}
