package trust

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

type browserFixture struct {
	Origin  string           `json:"origin"`
	RPID    string           `json:"rpId"`
	NodeID  string           `json:"nodeId"`
	Now     string           `json:"now"`
	Tokens  []string         `json:"tokens"`
	Change  reporter.Command `json:"change"`
	Command reporter.Command `json:"command"`
}

func loadBrowserFixture(t *testing.T, name string) (browserFixture, time.Time) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "protocol", "src", "fixtures", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture browserFixture
	if err := strict(raw, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	now, err := time.Parse(time.RFC3339Nano, fixture.Now)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, now
}

func TestTheBrowsersFirstTrustApplies(t *testing.T) {
	fixture, now := loadBrowserFixture(t, "browser-signed.json")
	first, err := FirstTrust(fixture.NodeID, fixture.Origin, fixture.Tokens)
	if err != nil {
		t.Fatal(err)
	}
	if first.NodeID != fixture.NodeID || first.Origin != fixture.Origin || first.RPID != fixture.RPID || first.Version != 1 || len(first.Core) != 1 || len(first.Access) != 1 {
		t.Fatalf("first %+v", first)
	}

	next, err := ApplyTrustChange(first, []byte(fixture.Change.Signed), now)
	if err != nil {
		t.Fatal(err)
	}
	if next.Version != 2 || len(next.Keys) != 2 || len(next.Core) != 2 || len(next.Access) != 2 || !slices.Equal(next.Core, next.Access) {
		t.Fatalf("next %+v", next)
	}

	command, err := VerifyCommand(next, fixture.Command, now)
	if err != nil || command.ID != fixture.Command.ID || command.Action != fixture.Command.Action {
		t.Fatalf("command %+v err %v", command, err)
	}
}

func TestTheBrowsersCommandNeedsTheTrustItWasSignedFor(t *testing.T) {
	fixture, now := loadBrowserFixture(t, "browser-signed.json")
	first, err := FirstTrust(fixture.NodeID, fixture.Origin, fixture.Tokens)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyCommand(first, fixture.Command, now)
	refused(t, err, "passkey is not trusted")
}

func TestTheBrowsersTouchOnlyAnswersAreRefused(t *testing.T) {
	fixture, now := loadBrowserFixture(t, "browser-uv.json")
	first, err := FirstTrust(fixture.NodeID, fixture.Origin, fixture.Tokens)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ApplyTrustChange(first, []byte(fixture.Change.Signed), now)
	refused(t, err, "was opened without a fingerprint, face or PIN")
	_, err = VerifyCommand(first, fixture.Command, now)
	refused(t, err, "was opened without a fingerprint, face or PIN")
}
