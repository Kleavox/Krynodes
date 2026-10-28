package actions

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func requireUvCase(core []TrustKey, access []string) *changeCase {
	c := newChange(2, core, map[string][]string{testNode: access})
	c.body["requireUv"] = true
	return c
}

func TestWithTwoDevicesOneFingerprintTurnsFingerprintsOn(t *testing.T) {
	found := devices(t, "a", "b")
	current := storeOf(found, []string{"a", "b"}, []string{"a", "b"})
	next, err := apply(t, current, requireUvCase(nil, []string{"a", "b"}).by(found, "b"))
	if err != nil || !next.RequireUV || len(next.Core) != 2 {
		t.Fatalf("next %+v err %v", next, err)
	}
}

func TestTheFingerprintRuleCannotBeTurnedOff(t *testing.T) {
	found := devices(t, "a", "b")
	current := storeOf(found, []string{"a", "b"}, []string{"a", "b"})
	current.RequireUV = true
	c := newChange(2, nil, map[string][]string{testNode: {"a", "b"}}).by(found, "a", "b")
	c.body["requireUv"] = false
	_, err := apply(t, current, c)
	refused(t, err, "malformed")

	next, err := apply(t, current, newChange(2, nil, map[string][]string{testNode: {"a", "b"}}).by(found, "a"))
	if err != nil || !next.RequireUV {
		t.Fatalf("an ordinary change keeps the rule: %+v %v", next, err)
	}
}

func TestAFirstTrustCarriesTheFingerprintRule(t *testing.T) {
	found := devices(t, "a")
	c := requireUvCase(keysOf(found, "a"), []string{"a"})
	c.body["version"] = 1
	next, err := apply(t, Trust{}, c)
	if err != nil || !next.RequireUV {
		t.Fatalf("next %+v err %v", next, err)
	}
}

func TestOnceFingerprintsAreRequiredATouchOnlyGrantIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	c.trust.RequireUV = true
	if err := c.verify(t, testNow); err != nil {
		t.Fatal(err)
	}
	c.assertion.flags = flagPresent
	refused(t, c.verify(t, testNow), "was opened without a fingerprint, face or PIN")
}

func TestTheFingerprintRuleRoundTripsThroughTheStateDirectory(t *testing.T) {
	dir := t.TempDir()
	found := devices(t, "a")
	current := storeOf(found, []string{"a"}, []string{"a"})
	current.RequireUV = true
	if err := SaveTrust(dir, current); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTrust(dir)
	if err != nil || !loaded.RequireUV {
		t.Fatalf("loaded %+v err %v", loaded, err)
	}
}

type browserUVFixture struct {
	NodeID string  `json:"nodeId"`
	Now    string  `json:"now"`
	First  Request `json:"first"`
	Admit  Request `json:"admit"`
	Enable Request `json:"enable"`
	Deploy Request `json:"deploy"`
}

func loadBrowserUVFixture(t *testing.T) browserUVFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "protocol", "src", "fixtures", "browser-uv.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture browserUVFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestTheBrowsersTouchApprovalIsRefusedAndItsFingerprintDeployVerifies(t *testing.T) {
	fixture := loadBrowserUVFixture(t)
	trust, err := ApplyTrustChange(Trust{}, fixture.First, issuedAt(t, fixture.First))
	if err != nil {
		t.Fatal(err)
	}
	_, err = ApplyTrustChange(trust, fixture.Admit, issuedAt(t, fixture.Admit))
	refused(t, err, "was opened without a fingerprint, face or PIN")

	var signed signedTrust
	if err := json.Unmarshal(fixture.Enable.Signed, &signed); err != nil {
		t.Fatal(err)
	}
	raw, err := b64.DecodeString(signed.Change)
	if err != nil {
		t.Fatal(err)
	}
	var change trustChange
	if err := json.Unmarshal(raw, &change); err != nil {
		t.Fatal(err)
	}
	ruled := Trust{V: 2, NodeID: fixture.NodeID, Origin: change.Origin, RPID: change.RPID, Version: change.Version, Core: change.Core, Access: change.Access[fixture.NodeID], RequireUV: true}
	now, err := time.Parse(time.RFC3339Nano, fixture.Now)
	if err != nil {
		t.Fatal(err)
	}
	command, err := VerifyCommand(ruled, fixture.Deploy, now)
	if err != nil || command.Name != "listmonk" {
		t.Fatalf("command %+v err %v", command, err)
	}
}
