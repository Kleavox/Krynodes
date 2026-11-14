package actions

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	userOne = "user1@example.com"
	userTwo = "user2@example.com"
)

func owned(found map[string]device, owners map[string]string, ids ...string) []TrustKey {
	keys := keysOf(found, ids...)
	for index := range keys {
		keys[index].Account = owners[keys[index].ID]
	}
	return keys
}

func ownedStore(found map[string]device, owners map[string]string, ids ...string) Trust {
	return Trust{V: 2, NodeID: testNode, Origin: testOrigin, RPID: testRPID, Version: 1, Core: owned(found, owners, ids...), Access: ids}
}

func (c *changeCase) bySynced(found map[string]device, ids ...string) *changeCase {
	for _, id := range ids {
		c.approvals = append(c.approvals, changeApproval{device: found[id], flags: flagPresent | flagVerified | flagBackupEligible})
	}
	return c
}

var twoAccounts = map[string]string{"a": userOne, "b": userOne, "c": userTwo, "d": userOne}

func fourthPasskey(found map[string]device) *changeCase {
	return newChange(2, owned(found, twoAccounts, "a", "b", "c", "d"), map[string][]string{testNode: {"a", "b", "c"}})
}

func TestTwoSyncedPasskeysOfOneAccountCannotAdmitWhenTwoAccountsAreTrusted(t *testing.T) {
	found := devices(t, "a", "b", "c", "d")
	_, err := apply(t, ownedStore(found, twoAccounts, "a", "b", "c"), fourthPasskey(found).bySynced(found, "a", "b"))
	refused(t, err, "needs approval from another account's passkey, or from one that is not synced")
}

func TestAnApprovalFromEachAccountAdmitsAndKeepsTheOwner(t *testing.T) {
	found := devices(t, "a", "b", "c", "d")
	next, err := apply(t, ownedStore(found, twoAccounts, "a", "b", "c"), fourthPasskey(found).bySynced(found, "a", "c"))
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Core) != 4 || next.Core[3].Account != userOne || next.Core[2].Account != userTwo {
		t.Fatalf("core %+v", next.Core)
	}
}

func TestAPasskeyThatIsNotSyncedStandsInForTheOtherAccount(t *testing.T) {
	found := devices(t, "a", "b", "c", "d")
	c := fourthPasskey(found).bySynced(found, "a").by(found, "b")
	if _, err := apply(t, ownedStore(found, twoAccounts, "a", "b", "c"), c); err != nil {
		t.Fatal(err)
	}
}

func TestOneAccountKeepsTheOldRule(t *testing.T) {
	found := devices(t, "a", "b", "c", "d")
	alone := map[string]string{"a": userOne, "b": userOne, "c": userOne, "d": userOne}
	c := newChange(2, owned(found, alone, "a", "b", "c", "d"), map[string][]string{testNode: {"a", "b", "c"}}).bySynced(found, "a", "b")
	if _, err := apply(t, ownedStore(found, alone, "a", "b", "c"), c); err != nil {
		t.Fatal(err)
	}
}

func TestAChangeWithoutAccountsIsRefusedOnceTheyAreStored(t *testing.T) {
	found := devices(t, "a", "b", "c", "d")
	c := newChange(2, keysOf(found, "a", "b", "c", "d"), map[string][]string{testNode: {"a", "b", "c"}}).bySynced(found, "a", "c")
	_, err := apply(t, ownedStore(found, twoAccounts, "a", "b", "c"), c)
	refused(t, err, "every passkey needs its account")
}

func TestRecordingTheOwnersStoresAndReportsThem(t *testing.T) {
	found := devices(t, "a", "b")
	owners := map[string]string{"a": userOne, "b": userTwo}
	current := storeOf(found, []string{"a", "b"}, []string{"a", "b"})
	if report := current.Report(); report.Accounts != nil {
		t.Fatalf("a store without owners reports none: %+v", report)
	}
	next, err := apply(t, current, newChange(2, owned(found, owners, "a", "b"), map[string][]string{testNode: {"a", "b"}}).bySynced(found, "a"))
	if err != nil {
		t.Fatal(err)
	}
	report := next.Report()
	if len(report.Accounts) != 2 || report.Accounts[0] != userOne || report.Accounts[1] != userTwo || report.Core[1] != Fingerprint(found["b"].key) {
		t.Fatalf("report %+v", report)
	}
	dir := t.TempDir()
	if err := SaveTrust(dir, next); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTrust(dir)
	if err != nil || loaded.Core[1].Account != userTwo {
		t.Fatalf("loaded %+v err %v", loaded.Core, err)
	}
	encoded, err := json.Marshal(current.Core[0])
	if err != nil || strings.Contains(string(encoded), "account") {
		t.Fatalf("a key without an owner writes no account: %s %v", encoded, err)
	}
}

func TestRecordingTheOwnersOfThreePasskeysNeedsTwoApprovals(t *testing.T) {
	found := devices(t, "a", "b", "c")
	c := newChange(2, owned(found, twoAccounts, "a", "b", "c"), map[string][]string{testNode: {"a", "b", "c"}}).bySynced(found, "a")
	_, err := apply(t, storeOf(found, []string{"a", "b", "c"}, []string{"a", "b", "c"}), c)
	refused(t, err, "needs 1 more approval")
}

func TestAMoveNeedsThePasskeyOfTheAccountItLeaves(t *testing.T) {
	found := devices(t, "a", "b", "c")
	moved := map[string]string{"a": userOne, "b": userOne, "c": userOne}
	change := func() *changeCase {
		return newChange(2, owned(found, moved, "a", "b", "c"), map[string][]string{testNode: {"a", "b", "c"}})
	}
	current := ownedStore(found, twoAccounts, "a", "b", "c")
	_, err := apply(t, current, change().bySynced(found, "a").by(found, "b"))
	refused(t, err, "needs approval from a passkey of the account it leaves")
	next, err := apply(t, current, change().bySynced(found, "c", "a"))
	if err != nil {
		t.Fatal(err)
	}
	if next.Core[2].Account != userOne {
		t.Fatalf("core %+v", next.Core)
	}
}

func TestAccountsAreNamedOnEveryKeyOrNoneAndAreAddresses(t *testing.T) {
	found := devices(t, "a", "b")
	some := newChange(1, owned(found, map[string]string{"a": userOne}, "a", "b"), map[string][]string{testNode: {"a"}})
	_, err := apply(t, Trust{}, some)
	refused(t, err, "every passkey needs its account")
	for _, bad := range []string{"user1 @example.com", "user1@example.com\n", strings.Repeat("a", 255), "\x7f"} {
		c := newChange(1, owned(found, map[string]string{"a": bad, "b": userOne}, "a", "b"), map[string][]string{testNode: {"a"}})
		if _, err := apply(t, Trust{}, c); err == nil || !strings.Contains(err.Error(), "an account is not an address") {
			t.Errorf("%q: %v", bad, err)
		}
	}
	first, err := apply(t, Trust{}, newChange(1, owned(found, map[string]string{"a": "usér1@example.com", "b": userTwo}, "a", "b"), map[string][]string{testNode: {"a"}}))
	if err != nil || first.Core[1].Account != userTwo {
		t.Fatalf("first %+v err %v", first.Core, err)
	}
}

func TestParseTrustArgsReadsTheOwnerOfEachKey(t *testing.T) {
	one, _ := newPasskey(t, "cred-1", algES256)
	two, _ := newPasskey(t, "cred-2", algES256)
	owner := func(account string) string { return "." + b64.EncodeToString([]byte(account)) }
	keys := []string{"cred-1.-7." + one.PublicKey + owner(userOne), "cred-2.-7." + two.PublicKey + owner(userTwo)}
	trust, err := ParseTrustArgs(testOrigin, keys, false, "cred-2")
	if err != nil {
		t.Fatal(err)
	}
	if trust.Core[0].Account != userOne || trust.Core[1].Account != userTwo {
		t.Fatalf("core %+v", trust.Core)
	}
	for _, bad := range [][]string{
		{keys[0], "cred-2.-7." + two.PublicKey},
		{"cred-1.-7." + one.PublicKey + ".***"},
		{"cred-1.-7." + one.PublicKey + owner("user1 @example.com")},
		{"cred-1.-7." + one.PublicKey + owner(userOne) + ".more"},
		{"cred-1.-7." + one.PublicKey + "."},
	} {
		if _, err := ParseTrustArgs(testOrigin, bad, false, ""); err == nil {
			t.Errorf("%v should be refused", bad)
		}
	}
}
