package network

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	nodeA = "11111111-1111-4111-8111-111111111111"
	nodeB = "22222222-2222-4222-8222-222222222222"
	nodeC = "33333333-3333-4333-8333-333333333333"
)

func fixtureBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "protocol", "src", "fixtures", "network-document.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return raw
}

func fixture(t *testing.T) Document {
	t.Helper()
	document, err := Parse(fixtureBytes(t))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return document
}

func edited(t *testing.T, change func(map[string]any)) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(fixtureBytes(t), &document); err != nil {
		t.Fatal(err)
	}
	change(document)
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func member(document map[string]any, index int) map[string]any {
	return document["members"].([]any)[index].(map[string]any)
}

func TestTheSharedFixtureParses(t *testing.T) {
	document := fixture(t)
	if document.Version != 3 || len(document.Members) != 2 || document.Members[1].Name != "server-1" || !document.Members[1].NAT {
		t.Fatalf("document %+v", document)
	}
	if document.Members[1].MTU == nil || *document.Members[1].MTU != 1380 || document.Members[0].MTU != nil {
		t.Fatalf("mtu %v %v", document.Members[0].MTU, document.Members[1].MTU)
	}
}

func TestAPeerThatIsNotOneAddressInsideTheRangeIsRefused(t *testing.T) {
	for _, address := range []string{"10.88.0.0/24", "10.88.0.2/32", "0.0.0.0/0", "::/0", "10.89.0.2", "10.88.0.0", "10.88.0.255", "fd00::2", ""} {
		raw := edited(t, func(document map[string]any) { member(document, 1)["address"] = address })
		if _, err := Parse(raw); err == nil {
			t.Errorf("address %q was accepted", address)
		}
	}
}

func TestADocumentThatBreaksItsOwnRulesIsRefused(t *testing.T) {
	cases := map[string]func(map[string]any){
		"two members share an address": func(document map[string]any) { member(document, 1)["address"] = "10.88.0.1" },
		"two members share a key":      func(document map[string]any) { member(document, 1)["key"] = member(document, 0)["key"] },
		"a preshared key for a stranger": func(document map[string]any) {
			member(document, 0)["psk"] = map[string]any{nodeC: "eyJ2IjoxfQ"}
		},
		"a missing preshared key": func(document map[string]any) { member(document, 0)["psk"] = map[string]any{} },
		"a member key blocked":    func(document map[string]any) { document["blocked"] = []any{member(document, 0)["key"]} },
		"a range outside the pool": func(document map[string]any) {
			document["range"] = "10.0.0.0/24"
		},
		"a range wider than /24": func(document map[string]any) { document["range"] = "10.88.0.0/16" },
		"a key that is not 32 bytes": func(document map[string]any) {
			member(document, 1)["key"] = "c2hvcnQ="
		},
		"a port outside the network's": func(document map[string]any) { member(document, 1)["port"] = 53 },
		"an unknown field":             func(document map[string]any) { document["allowedIPs"] = "0.0.0.0/0" },
		"a member field unknown":       func(document map[string]any) { member(document, 1)["allowedIPs"] = "0.0.0.0/0" },
		"an endpoint that is a name":   func(document map[string]any) { member(document, 0)["endpoint"] = "vps-1.example.com:51820" },
		"a parent that is not a hash":  func(document map[string]any) { document["parent"] = "abc" },
		"a scan outside the choices":   func(document map[string]any) { document["knocks"] = map[string]any{"scan": 7, "stop": true} },
	}
	for name, change := range cases {
		if _, err := Parse(edited(t, change)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestOnlyANewerVersionIsApplied(t *testing.T) {
	document := fixture(t)
	for _, applied := range []int{3, 4, 9} {
		if _, err := Accept(document, Applied{Version: applied}, nodeA, false); err == nil || !strings.Contains(err.Error(), "not newer") {
			t.Errorf("applied %d: %v", applied, err)
		}
	}
	own, err := Accept(document, Applied{Version: 1}, nodeA, false)
	if err != nil || own.Name != "vps-1" {
		t.Fatalf("own %+v err %v", own, err)
	}
}

func TestABlockedKeyNeverComesBack(t *testing.T) {
	document := fixture(t)
	_, err := Accept(document, Applied{Version: 1, Blocked: []string{document.Members[1].Key}}, nodeA, false)
	if err == nil || !strings.Contains(err.Error(), "cannot come back") {
		t.Fatalf("err %v", err)
	}
}

func TestADocumentWithoutThisServerSaysLeave(t *testing.T) {
	document := fixture(t)
	if _, err := Accept(document, Applied{}, nodeC, false); !errors.Is(err, ErrLeave) {
		t.Fatalf("not a member: %v", err)
	}
	document.Deleted = true
	if _, err := Accept(document, Applied{}, nodeA, false); !errors.Is(err, ErrLeave) {
		t.Fatalf("deleted: %v", err)
	}
}

func TestAppliedKeepsEveryBlockedKey(t *testing.T) {
	document := fixture(t)
	next := Applied{Version: 1, Blocked: []string{"old"}}.After(document, "")
	if next.Version != 3 || strings.Join(next.Blocked, ",") != "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=,old" {
		t.Fatalf("next %+v", next)
	}
}

func TestAJoinedServerAppliesOnlyTheNextVersionOnTopOfWhatItApplied(t *testing.T) {
	document := fixture(t)
	applied := Applied{Version: 2, Hash: BodyHash([]byte("two"))}
	document.Parent = BodyHash([]byte("doctored"))
	if _, err := Accept(document, applied, nodeA, true); err == nil || err.Error() != "version 3 does not follow the version this server applied" {
		t.Fatalf("wrong parent: %v", err)
	}
	document.Parent = applied.Hash
	if own, err := Accept(document, applied, nodeA, true); err != nil || own.Name != "vps-1" {
		t.Fatalf("next: %+v %v", own, err)
	}
	if _, err := Accept(document, Applied{Version: 1, Hash: applied.Hash}, nodeA, true); err == nil || err.Error() != "version 3 is not the next one after 1" {
		t.Fatalf("jump: %v", err)
	}
}

func TestAServerThatIsNotJoinedTakesAnyNewerVersion(t *testing.T) {
	if _, err := Accept(fixture(t), Applied{Version: 1, Hash: BodyHash([]byte("one"))}, nodeA, false); err != nil {
		t.Fatal(err)
	}
}

func TestTheBodyHashIsSHA256InBase64URL(t *testing.T) {
	if got := BodyHash([]byte("abc")); got != "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0" {
		t.Fatal(got)
	}
}

func TestACutMemberRendersNoPeerAndItsKeyCountsAsBlocked(t *testing.T) {
	document := fixture(t)
	cut := document.Members[1].Key
	document.Members[1].Cut = true
	if config := Render(document, document.Members[0], "private", map[string]string{}); strings.Contains(config, cut) {
		t.Fatalf("config %s", config)
	}
	applied := Applied{}.After(document, "h")
	if !slices.Contains(applied.Blocked, cut) || applied.Hash != "h" || applied.Version != 3 {
		t.Fatalf("applied %+v", applied)
	}
	document.Version, document.Parent = 4, "h"
	if _, err := Accept(document, applied, nodeA, true); err != nil {
		t.Fatalf("still cut: %v", err)
	}
	document.Members[1].Cut = false
	if _, err := Accept(document, applied, nodeA, true); err == nil || !strings.Contains(err.Error(), "cannot come back") {
		t.Fatalf("back uncut: %v", err)
	}
}

func TestTheStricterKnockSettingWins(t *testing.T) {
	document := fixture(t)
	if got := Effective(document, nil); got != (Knocks{Scan: 10, Stop: true}) {
		t.Fatalf("default %+v", got)
	}
	document.Knocks = &Knocks{Scan: 20, Stop: false}
	if got := Effective(document, nil); got != (Knocks{Scan: 20, Stop: false}) {
		t.Fatalf("document %+v", got)
	}
	if got := Effective(document, &Knocks{Scan: 5, Stop: true}); got != (Knocks{Scan: 5, Stop: true}) {
		t.Fatalf("tightened %+v", got)
	}
}
