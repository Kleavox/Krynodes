package actions

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type quorumFixture struct {
	Cases []struct {
		Name string `json:"name"`
		quorumInput
		OK bool `json:"ok"`
	} `json:"cases"`
}

func TestQuorumMatchesTheSharedFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "protocol", "src", "fixtures", "quorum.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture quorumFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) < 20 {
		t.Fatalf("only %d cases", len(fixture.Cases))
	}
	for _, item := range fixture.Cases {
		t.Run(item.Name, func(t *testing.T) {
			err := evaluateQuorum(item.quorumInput)
			if (err == nil) != item.OK {
				t.Fatalf("want ok %v, got %v", item.OK, err)
			}
		})
	}
}

func TestQuorumSaysWhatIsMissing(t *testing.T) {
	input := quorumInput{Approvals: []string{"a"}}
	input.Current.Core = []string{"a", "b", "c"}
	input.Current.Access = []string{"a", "b", "c"}
	input.Change.Core = []string{"a", "b", "c", "d"}
	input.Change.Access = []string{"a", "b", "c"}
	refused(t, evaluateQuorum(input), "needs 1 more approval")
	input.Approvals = nil
	refused(t, evaluateQuorum(input), "needs an approval")
}

func TestQuorumSaysWhichApprovalTwoAccountsStillNeed(t *testing.T) {
	input := quorumInput{Approvals: []string{"a"}}
	owners := map[string]string{"a": "user1@example.com", "b": "user1@example.com", "c": "user2@example.com"}
	input.Current.Core = []string{"a", "b", "c"}
	input.Current.Access = []string{"a", "b", "c"}
	input.Current.Accounts = owners
	input.Change.Core = []string{"a", "b", "c", "d"}
	input.Change.Access = []string{"a", "b", "c"}
	input.Change.Accounts = map[string]string{"a": "user1@example.com", "b": "user1@example.com", "c": "user2@example.com", "d": "user1@example.com"}
	exactly(t, evaluateQuorum(input), "needs 1 more approval, from another account or a passkey that is not synced")
	input.Unsynced = []string{"a"}
	exactly(t, evaluateQuorum(input), "needs 1 more approval")
	input.Unsynced = nil
	input.Approvals = []string{"a", "b"}
	exactly(t, evaluateQuorum(input), "needs approval from another account's passkey, or from one that is not synced")
	input.Change.Accounts = nil
	input.Approvals = []string{"a", "c"}
	exactly(t, evaluateQuorum(input), "every passkey needs its account")
	input.Change.Core = []string{"a", "b", "c"}
	input.Change.Accounts = map[string]string{"a": "user1@example.com", "b": "user1@example.com", "c": "user1@example.com"}
	input.Approvals = []string{"a", "b"}
	input.Unsynced = []string{"a"}
	exactly(t, evaluateQuorum(input), "needs approval from a passkey of the account it leaves")
}

func exactly(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || err.Error() != want {
		t.Fatalf("want %q, got %v", want, err)
	}
}
