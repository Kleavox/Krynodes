package trust

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

type browserFixture struct {
	Origin     string                 `json:"origin"`
	RPID       string                 `json:"rpId"`
	NodeID     string                 `json:"nodeId"`
	Now        string                 `json:"now"`
	First      reporter.ActionRequest `json:"first"`
	Admit      reporter.ActionRequest `json:"admit"`
	Passphrase reporter.ActionRequest `json:"passphrase"`
}

func loadBrowserFixture(t *testing.T) browserFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "protocol", "src", "fixtures", "browser-signed.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture browserFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return fixture
}

func issuedAt(t *testing.T, request reporter.ActionRequest) time.Time {
	t.Helper()
	var signed signedTrust
	if err := json.Unmarshal(request.Signed, &signed); err != nil {
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
	at, err := time.Parse(time.RFC3339Nano, change.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	return at.Add(time.Second)
}

func TestTheBrowsersFirstTrustApplies(t *testing.T) {
	fixture := loadBrowserFixture(t)
	trust, err := ApplyTrustChange(Trust{}, fixture.First, issuedAt(t, fixture.First))
	if err != nil {
		t.Fatal(err)
	}
	if trust.NodeID != fixture.NodeID || trust.Origin != fixture.Origin || trust.RPID != fixture.RPID || len(trust.Core) != 1 || len(trust.Access) != 1 {
		t.Fatalf("trust %+v", trust)
	}
}

func TestTheBrowsersPassphraseChangeIsRefused(t *testing.T) {
	fixture := loadBrowserFixture(t)
	trust, err := ApplyTrustChange(Trust{}, fixture.First, issuedAt(t, fixture.First))
	if err != nil {
		t.Fatal(err)
	}
	_, err = ApplyTrustChange(trust, fixture.Passphrase, issuedAt(t, fixture.Passphrase))
	refused(t, err, "no longer use a passphrase")
}
