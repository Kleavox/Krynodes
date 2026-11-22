package trust

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"
)

const otherNode = "44444444-4444-4444-8444-444444444444"

type device struct {
	key    TrustKey
	signer crypto.Signer
}

type changeApproval struct {
	device    device
	flags     byte
	challenge []byte
}

type changeCase struct {
	body      map[string]any
	approvals []changeApproval
	extra     bool
}

func devices(t *testing.T, ids ...string) map[string]device {
	t.Helper()
	found := map[string]device{}
	for _, id := range ids {
		key, signer := newPasskey(t, id, algES256)
		found[id] = device{key: key, signer: signer}
	}
	return found
}

func keysOf(found map[string]device, ids ...string) []TrustKey {
	keys := make([]TrustKey, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, found[id].key)
	}
	return keys
}

func storeOf(found map[string]device, core []string, access []string) Trust {
	return Trust{V: 1, NodeID: testNode, Origin: testOrigin, RPID: testRPID, Version: 1, Keys: keysOf(found, core...), Core: core, Access: access, RequireUV: true}
}

func newChange(version int, core []TrustKey, access map[string][]string) *changeCase {
	body := map[string]any{
		"v": 1, "origin": testOrigin, "rpId": testRPID, "version": version,
		"issuedAt": testNow.Format(time.RFC3339Nano), "expiresAt": testNow.Add(time.Hour).Format(time.RFC3339Nano),
		"access": access,
	}
	if core != nil {
		body["core"] = core
	}
	return &changeCase{body: body}
}

func (c *changeCase) by(found map[string]device, ids ...string) *changeCase {
	for _, id := range ids {
		c.approvals = append(c.approvals, changeApproval{device: found[id], flags: flagPresent | flagVerified})
	}
	return c
}

func (c *changeCase) signed(t *testing.T) []byte {
	t.Helper()
	changeBytes, err := json.Marshal(c.body)
	if err != nil {
		t.Fatal(err)
	}
	approvals := []map[string]any{}
	for _, approval := range c.approvals {
		challenge := approval.challenge
		if challenge == nil {
			challenge = digest(changeBytes)
		}
		assertion := sign(t, approval.device.signer, approval.device.key.ID, assertionOptions{origin: testOrigin, rpID: testRPID, clientType: "webauthn.get", flags: approval.flags, challenge: challenge})
		approvals = append(approvals, map[string]any{
			"credentialId": assertion.CredentialID, "authenticatorData": assertion.AuthenticatorData,
			"clientDataJSON": assertion.ClientDataJSON, "signature": assertion.Signature,
		})
	}
	envelope := map[string]any{"change": b64.EncodeToString(changeBytes), "approvals": approvals}
	if c.extra {
		envelope["extra"] = true
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func apply(t *testing.T, current Trust, c *changeCase) (Trust, error) {
	t.Helper()
	return ApplyTrustChange(current, c.signed(t), testNow)
}

func TestOneCorePasskeyApprovesAChange(t *testing.T) {
	found := devices(t, "a", "b", "c")
	c := newChange(2, keysOf(found, "a", "b", "c"), map[string][]string{testNode: {"a", "b"}}).by(found, "a")
	next, err := apply(t, storeOf(found, []string{"a", "b"}, []string{"a", "b"}), c)
	if err != nil {
		t.Fatal(err)
	}
	if next.V != 1 || next.Version != 2 || next.NodeID != testNode || next.Origin != testOrigin || next.RPID != testRPID || !next.RequireUV {
		t.Fatalf("next %+v", next)
	}
	if !slices.Equal(next.Core, []string{"a", "b", "c"}) || !slices.Equal(next.Access, []string{"a", "b"}) || len(next.Keys) != 3 {
		t.Fatalf("next %+v", next)
	}
}

func TestACoreOmittedFromAChangeStaysAsItWas(t *testing.T) {
	found := devices(t, "a", "b")
	c := newChange(2, nil, map[string][]string{testNode: {"b"}}).by(found, "a")
	next, err := apply(t, storeOf(found, []string{"a", "b"}, []string{"a", "b"}), c)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(next.Core, []string{"a", "b"}) || len(next.Keys) != 2 || !slices.Equal(next.Access, []string{"b"}) {
		t.Fatalf("next %+v", next)
	}
}

func TestAnAccessOnlyPasskeyCannotChangeTrust(t *testing.T) {
	found := devices(t, "a", "b")
	current := Trust{V: 1, NodeID: testNode, Origin: testOrigin, RPID: testRPID, Version: 1, Keys: keysOf(found, "a", "b"), Core: []string{"a"}, Access: []string{"a", "b"}, RequireUV: true}
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "b")
	_, err := apply(t, current, c)
	refused(t, err, "cannot approve a change")
}

func TestACorePasskeyWithoutAccessCanApproveAChange(t *testing.T) {
	found := devices(t, "a", "b")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "b")
	if _, err := apply(t, storeOf(found, []string{"a", "b"}, []string{"a"}), c); err != nil {
		t.Fatal(err)
	}
}

func TestTheLastCorePasskeyCannotBeRemoved(t *testing.T) {
	found := devices(t, "a", "b")
	c := newChange(2, []TrustKey{}, map[string][]string{testNode: {}}).by(found, "a")
	_, err := apply(t, storeOf(found, []string{"a", "b"}, []string{"a"}), c)
	refused(t, err, "at least one passkey must stay trusted")
}

func TestAServerCannotBeLeftWithoutAccess(t *testing.T) {
	found := devices(t, "a", "b")
	for _, access := range [][]string{{}, nil} {
		c := newChange(2, nil, map[string][]string{testNode: access}).by(found, "a")
		_, err := apply(t, storeOf(found, []string{"a", "b"}, []string{"a"}), c)
		refused(t, err, "at least one passkey with access")
	}
}

func TestAPasskeyCanReplaceTheOneThatApprovesIt(t *testing.T) {
	found := devices(t, "a", "b")
	c := newChange(2, keysOf(found, "b"), map[string][]string{testNode: {"b"}}).by(found, "a")
	next, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	if err != nil || !slices.Equal(next.Core, []string{"b"}) || !slices.Equal(next.Access, []string{"b"}) {
		t.Fatalf("next %+v err %v", next, err)
	}
}

func TestAnOlderVersionIsRefused(t *testing.T) {
	found := devices(t, "a")
	store := storeOf(found, []string{"a"}, []string{"a"})
	store.Version = 5
	for _, version := range []int{1, 5} {
		c := newChange(version, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
		_, err := apply(t, store, c)
		refused(t, err, "not newer")
	}
}

func TestAVersionFarAheadIsRefusedAndASmallStepPasses(t *testing.T) {
	found := devices(t, "a")
	store := storeOf(found, []string{"a"}, []string{"a"})
	far := newChange(store.Version+1001, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	_, err := apply(t, store, far)
	refused(t, err, "too far ahead")
	near := newChange(store.Version+1000, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	if _, err := apply(t, store, near); err != nil {
		t.Fatal(err)
	}
}

func TestAChangeLongerThanADayIsRefused(t *testing.T) {
	found := devices(t, "a")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.body["expiresAt"] = testNow.Add(25 * time.Hour).Format(time.RFC3339Nano)
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "24 hours")
}

func TestAChangeOfExactlyADayPasses(t *testing.T) {
	found := devices(t, "a")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.body["expiresAt"] = testNow.Add(24 * time.Hour).Format(time.RFC3339Nano)
	if _, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c); err != nil {
		t.Fatal(err)
	}
}

func TestAnExpiredChangeIsRefused(t *testing.T) {
	found := devices(t, "a")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.body["expiresAt"] = testNow.Add(-2 * time.Minute).Format(time.RFC3339Nano)
	c.body["issuedAt"] = testNow.Add(-time.Hour).Format(time.RFC3339Nano)
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "the change expired at 29 Sep 09:58:00 UTC; this server's clock says 29 Sep 10:00:00 UTC")
}

func TestAChangeThatEndsBeforeItBeginsIsRefused(t *testing.T) {
	found := devices(t, "a")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.body["expiresAt"] = testNow.Add(-time.Minute).Format(time.RFC3339Nano)
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "ends before it begins")
}

func TestAnUnapprovedChangeIsRefused(t *testing.T) {
	found := devices(t, "a")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}})
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "approved by a trusted passkey")
}

func TestAChangeNeedsAStoredTrust(t *testing.T) {
	found := devices(t, "a")
	c := newChange(1, keysOf(found, "a"), map[string][]string{testNode: {"a"}})
	_, err := apply(t, Trust{}, c)
	refused(t, err, "no passkey is trusted yet")
	_, err = apply(t, Trust{}, c.by(found, "a"))
	refused(t, err, "no passkey is trusted yet")
}

func TestATouchOnlyApprovalIsRefused(t *testing.T) {
	found := devices(t, "a", "b")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.approvals[0].flags = flagPresent
	_, err := apply(t, storeOf(found, []string{"a", "b"}, []string{"a", "b"}), c)
	refused(t, err, "was opened without a fingerprint, face or PIN")
}

func TestAnApprovalOverOtherBytesIsRefused(t *testing.T) {
	found := devices(t, "a")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.approvals[0].challenge = digest([]byte("something else"))
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "challenge does not match")
}

func TestAnApprovalFromOutsideTheKeysIsRefused(t *testing.T) {
	found := devices(t, "a", "x")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "x")
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "passkey is not trusted")
}

func TestOneBadApprovalRefusesTheChange(t *testing.T) {
	found := devices(t, "a", "b")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a", "b")
	c.approvals[1].flags = flagPresent
	_, err := apply(t, storeOf(found, []string{"a", "b"}, []string{"a"}), c)
	refused(t, err, "was opened without a fingerprint, face or PIN")

	other := devices(t, "b")
	c = newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.approvals = append(c.approvals, changeApproval{device: device{key: found["b"].key, signer: other["b"].signer}, flags: flagPresent | flagVerified})
	_, err = apply(t, storeOf(found, []string{"a", "b"}, []string{"a"}), c)
	refused(t, err, "passkey signature is invalid")
}

func TestAChangeForOtherServersIsRefused(t *testing.T) {
	found := devices(t, "a")
	c := newChange(2, nil, map[string][]string{otherNode: {"a"}}).by(found, "a")
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "not for this server")
}

func TestAnotherOriginIsRefused(t *testing.T) {
	found := devices(t, "a")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.body["origin"] = "https://evil.example"
	c.body["rpId"] = "evil.example"
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "another origin")
}

func TestARPIDThatIsNotTheOriginHostIsRefused(t *testing.T) {
	found := devices(t, "a")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.body["rpId"] = "example.com"
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "host of the origin")
}

func TestAWeakRSAKeyIsRefused(t *testing.T) {
	found := devices(t, "a")
	private, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weak := TrustKey{ID: "weak", Name: "Old", Alg: algRS256, PublicKey: spki(t, &private.PublicKey)}
	c := newChange(2, append(keysOf(found, "a"), weak), map[string][]string{testNode: {"a"}}).by(found, "a")
	_, err = apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "at least 2048 bits")
}

func TestOneApprovalCannotGiveATrustedPasskeyAnotherKey(t *testing.T) {
	found := devices(t, "a", "b", "c")
	other := devices(t, "x")
	keys := keysOf(found, "a", "b", "c")
	keys[1].PublicKey, keys[1].Alg = other["x"].key.PublicKey, other["x"].key.Alg
	c := newChange(2, keys, map[string][]string{testNode: {"a", "b", "c"}}).by(found, "a")
	_, err := apply(t, storeOf(found, []string{"a", "b", "c"}, []string{"a", "b", "c"}), c)
	refused(t, err, "another key")
}

func TestTheSameKeyUnderTwoPasskeysIsRefused(t *testing.T) {
	found := devices(t, "a", "b", "c")
	keys := keysOf(found, "a", "b", "c")
	keys[2].PublicKey, keys[2].Alg = keys[0].PublicKey, keys[0].Alg
	c := newChange(2, keys, map[string][]string{testNode: {"a", "b"}}).by(found, "a")
	_, err := apply(t, storeOf(found, []string{"a", "b"}, []string{"a", "b"}), c)
	refused(t, err, "same key")
}

func TestAPasskeyListedTwiceIsRefused(t *testing.T) {
	found := devices(t, "a")
	c := newChange(2, append(keysOf(found, "a"), found["a"].key), map[string][]string{testNode: {"a"}}).by(found, "a")
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "listed twice")
}

func TestMoreThanTwentyPasskeysAreRefused(t *testing.T) {
	found := devices(t, "a")
	keys := keysOf(found, "a")
	for index := range 20 {
		extra, _ := newPasskey(t, "k"+strconv.Itoa(index), algES256)
		keys = append(keys, extra)
	}
	c := newChange(2, keys, map[string][]string{testNode: {"a"}}).by(found, "a")
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "too many passkeys")
}

func TestAPasskeyIdThatIsNotBase64urlIsRefused(t *testing.T) {
	found := devices(t, "a")
	odd, _ := newPasskey(t, "a b", algES256)
	c := newChange(2, append(keysOf(found, "a"), odd), map[string][]string{testNode: {"a"}}).by(found, "a")
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "not base64url")
}

func TestAccessMustNameTrustedPasskeys(t *testing.T) {
	found := devices(t, "a", "x")
	c := newChange(2, nil, map[string][]string{testNode: {"a", "x"}}).by(found, "a")
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "access names a passkey the servers do not trust")

	c = newChange(2, nil, map[string][]string{testNode: {"a", "a"}}).by(found, "a")
	_, err = apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "access lists a passkey twice")
}

func TestAccessCannotNameAPasskeyTheChangeRemoves(t *testing.T) {
	found := devices(t, "a", "b")
	c := newChange(2, keysOf(found, "a"), map[string][]string{testNode: {"a", "b"}}).by(found, "a")
	_, err := apply(t, storeOf(found, []string{"a", "b"}, []string{"a"}), c)
	refused(t, err, "access names a passkey the servers do not trust")
}

func TestAChangeCannotTurnTheFingerprintRuleOff(t *testing.T) {
	found := devices(t, "a")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.body["requireUv"] = false
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "malformed")

	c = newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.body["requireUv"] = true
	next, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	if err != nil || !next.RequireUV {
		t.Fatalf("next %+v err %v", next, err)
	}
}

func TestAChangeWithUnknownFieldsIsRefused(t *testing.T) {
	found := devices(t, "a")
	store := storeOf(found, []string{"a"}, []string{"a"})

	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.body["passphrase"] = nil
	_, err := apply(t, store, c)
	refused(t, err, "malformed")

	c = newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.extra = true
	_, err = apply(t, store, c)
	refused(t, err, "malformed")
}

func TestAChangeOfAnotherVersionIsRefused(t *testing.T) {
	found := devices(t, "a")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.body["v"] = 2
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "malformed")
}

func TestFirstTrustReadsTheInstallTokens(t *testing.T) {
	one, _ := newPasskey(t, "cred-1", algES256)
	two, _ := newPasskey(t, "cred-2", algES256)
	trust, err := FirstTrust(testNode, testOrigin, []string{"cred-1.-7." + one.PublicKey, "cred-2.-7." + two.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if trust.V != 1 || trust.NodeID != testNode || trust.Origin != testOrigin || trust.RPID != testRPID || trust.Version != 1 || !trust.RequireUV {
		t.Fatalf("trust %+v", trust)
	}
	if len(trust.Keys) != 2 || trust.Keys[0].ID != "cred-1" || trust.Keys[0].Alg != algES256 || trust.Keys[0].PublicKey != one.PublicKey {
		t.Fatalf("keys %+v", trust.Keys)
	}
	if !slices.Equal(trust.Core, []string{"cred-1", "cred-2"}) || !slices.Equal(trust.Access, []string{"cred-1", "cred-2"}) {
		t.Fatalf("trust %+v", trust)
	}
}

func TestFirstTrustRefusesWhatIsNotAnInstallToken(t *testing.T) {
	key, _ := newPasskey(t, "cred-1", algES256)
	rsaKey, _ := newPasskey(t, "cred-1", algRS256)
	for _, bad := range [][]string{
		{"cred-1"},
		{"cred-1.x." + key.PublicKey},
		{"cred-1.5." + key.PublicKey},
		{"cred-1.-7.bm90YWtleQ"},
		{"cred-1.-7." + key.PublicKey + ".dXNlckBleGFtcGxlLmNvbQ"},
		{"cred-1.-257." + key.PublicKey},
		{"cred-1.-7." + key.PublicKey, "cred-1.-7." + key.PublicKey},
		{"cred-1.-7." + key.PublicKey, "cred-2.-7." + key.PublicKey},
		{"cred 1.-7." + key.PublicKey},
		{},
		nil,
	} {
		if _, err := FirstTrust(testNode, testOrigin, bad); err == nil {
			t.Errorf("%v should be refused", bad)
		}
	}
	if _, err := FirstTrust(testNode, testOrigin, []string{"cred-1.-257." + rsaKey.PublicKey}); err != nil {
		t.Errorf("an RS256 token should be accepted: %v", err)
	}
	if _, err := FirstTrust(testNode, "kry.example.org", []string{"cred-1.-7." + key.PublicKey}); err == nil {
		t.Error("an origin without a scheme should be refused")
	}
	if _, err := FirstTrust("", testOrigin, []string{"cred-1.-7." + key.PublicKey}); err == nil {
		t.Error("a missing server id should be refused")
	}
}

func TestFirstTrustRefusesMoreThanTwentyPasskeys(t *testing.T) {
	var tokens []string
	for index := range 21 {
		key, _ := newPasskey(t, "k"+strconv.Itoa(index), algES256)
		tokens = append(tokens, key.ID+".-7."+key.PublicKey)
	}
	if _, err := FirstTrust(testNode, testOrigin, tokens); err == nil {
		t.Fatal("21 passkeys should be refused")
	}
	if _, err := FirstTrust(testNode, testOrigin, tokens[:20]); err != nil {
		t.Fatal(err)
	}
}

func TestTrustRoundTripsThroughTheStateDirectory(t *testing.T) {
	dir := t.TempDir()
	empty, err := Load(dir)
	if err != nil || len(empty.Core) != 0 {
		t.Fatalf("empty %+v err %v", empty, err)
	}
	found := devices(t, "a")
	current := storeOf(found, []string{"a"}, []string{"a"})
	if err := Save(dir, current); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil || loaded.NodeID != testNode || loaded.V != 1 || len(loaded.Keys) != 1 || !slices.Equal(loaded.Core, []string{"a"}) || !slices.Equal(loaded.Access, []string{"a"}) || !loaded.RequireUV {
		t.Fatalf("loaded %+v err %v", loaded, err)
	}
	info, err := os.Stat(filepath.Join(dir, "trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
}

func TestAnUnreadableStoreIsRefused(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":        "{",
		"unknown field":   `{"v":1,"passphrase":null}`,
		"another version": `{"v":2,"nodeId":"n","keys":[],"core":[],"access":[]}`,
		"no version":      `{"nodeId":"n"}`,
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "trust.json"), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir); err == nil {
			t.Errorf("%s: should be refused", name)
		}
	}
}

func TestTheTrustReportCarriesCoreAndAccessIds(t *testing.T) {
	found := devices(t, "a", "b")
	report := storeOf(found, []string{"a", "b"}, []string{"b"}).Report()
	if report.Version != 1 || !slices.Equal(report.Core, []string{"a", "b"}) || !slices.Equal(report.Access, []string{"b"}) {
		t.Fatalf("report %+v", report)
	}
	empty, err := json.Marshal(Trust{}.Report())
	if err != nil || string(empty) != `{"version":0,"core":[],"access":[]}` {
		t.Fatalf("empty %s err %v", empty, err)
	}
}
