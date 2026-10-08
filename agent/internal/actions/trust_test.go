package actions

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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
	return Trust{V: 2, NodeID: testNode, Origin: testOrigin, RPID: testRPID, Version: 1, Core: keysOf(found, core...), Access: access}
}

func passphraseKey(t *testing.T) (PassphraseKey, ed25519.PrivateKey) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(digest([]byte("correct horse battery staple")))
	return PassphraseKey{
		Salt:       b64.EncodeToString(make([]byte, 16)),
		Iterations: 600000,
		PublicKey:  b64.EncodeToString(private.Public().(ed25519.PublicKey)),
	}, private
}

func newChange(version int, core []TrustKey, access map[string][]string) *changeCase {
	body := map[string]any{
		"v": 2, "origin": testOrigin, "rpId": testRPID, "version": version,
		"issuedAt": testNow.Format(time.RFC3339Nano), "expiresAt": testNow.Add(time.Hour).Format(time.RFC3339Nano),
		"core": nil, "passphrase": nil, "access": access,
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

func (c *changeCase) request(t *testing.T) Request {
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
		entry := map[string]any{
			"credentialId": assertion.CredentialID, "authenticatorData": assertion.AuthenticatorData,
			"clientDataJSON": assertion.ClientDataJSON, "signature": assertion.Signature,
		}
		approvals = append(approvals, entry)
	}
	raw, err := json.Marshal(map[string]any{"change": b64.EncodeToString(changeBytes), "approvals": approvals})
	if err != nil {
		t.Fatal(err)
	}
	return Request{ID: testID, Kind: "trust", Name: "devices", Action: "trust", ExpiresAt: testNow.Add(10 * time.Minute).Format(time.RFC3339Nano), Signed: raw}
}

func apply(t *testing.T, current Trust, c *changeCase) (Trust, error) {
	t.Helper()
	return ApplyTrustChange(current, c.request(t), testNow)
}

func TestTheFirstTrustIsAcceptedUnsignedOnAnEmptyStore(t *testing.T) {
	found := devices(t, "a")
	c := newChange(1, keysOf(found, "a"), map[string][]string{testNode: {"a"}})
	next, err := apply(t, Trust{}, c)
	if err != nil {
		t.Fatal(err)
	}
	if next.V != 2 || next.NodeID != testNode || len(next.Core) != 1 || len(next.Access) != 1 || next.Passphrase != nil || !next.RequireUV {
		t.Fatalf("next %+v", next)
	}
}

func TestAFirstTrustForSeveralServersIsRefused(t *testing.T) {
	found := devices(t, "a")
	c := newChange(1, keysOf(found, "a"), map[string][]string{testNode: {}, otherNode: {}})
	_, err := apply(t, Trust{}, c)
	refused(t, err, "exactly one server")
}

func TestAnApprovedFirstTrustIsRefused(t *testing.T) {
	found := devices(t, "a")
	c := newChange(1, keysOf(found, "a"), map[string][]string{testNode: {}}).by(found, "a")
	_, err := apply(t, Trust{}, c)
	refused(t, err, "no device is trusted yet")
}

func TestAnUnapprovedChangeIsRefusedOnceTrusted(t *testing.T) {
	found := devices(t, "a")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}})
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "approved by trusted devices")
}

func TestTwoApprovalsAdmitACoreDevice(t *testing.T) {
	found := devices(t, "a", "b", "c")
	c := newChange(2, keysOf(found, "a", "b", "c"), map[string][]string{testNode: {"a", "b"}}).by(found, "a", "b")
	next, err := apply(t, storeOf(found, []string{"a", "b"}, []string{"a", "b"}), c)
	if err != nil {
		t.Fatal(err)
	}
	if next.Version != 2 || len(next.Core) != 3 || len(next.Access) != 2 || next.NodeID != testNode {
		t.Fatalf("next %+v", next)
	}
}

func TestWithTwoDevicesOneApprovalAdmitsAThird(t *testing.T) {
	found := devices(t, "a", "b", "c")
	c := newChange(2, keysOf(found, "a", "b", "c"), map[string][]string{testNode: {"a", "b"}}).by(found, "a")
	if _, err := apply(t, storeOf(found, []string{"a", "b"}, []string{"a", "b"}), c); err != nil {
		t.Fatal(err)
	}
}

func TestWithThreeDevicesOneApprovalCannotAdmitAFourth(t *testing.T) {
	found := devices(t, "a", "b", "c", "d")
	c := newChange(2, keysOf(found, "a", "b", "c", "d"), map[string][]string{testNode: {"a", "b", "c"}}).by(found, "a")
	_, err := apply(t, storeOf(found, []string{"a", "b", "c"}, []string{"a", "b", "c"}), c)
	refused(t, err, "needs 1 more approval")
}

func TestADeviceCannotGrantItselfAccess(t *testing.T) {
	found := devices(t, "a", "b", "c")
	c := newChange(2, nil, map[string][]string{testNode: {"a", "b", "c"}}).by(found, "c")
	_, err := apply(t, storeOf(found, []string{"a", "b", "c"}, []string{"a", "b"}), c)
	refused(t, err, "another device that reaches this server")
}

func TestAnApprovalOverOtherBytesIsRefused(t *testing.T) {
	found := devices(t, "a")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.approvals[0].challenge = digest([]byte("something else"))
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "challenge does not match")
}

func TestAnApprovalFromOutsideTheCoreIsRefused(t *testing.T) {
	found := devices(t, "a", "x")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "x")
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "passkey is not trusted")
}

func TestAStaleVersionIsRefused(t *testing.T) {
	found := devices(t, "a")
	c := newChange(1, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "version")
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
	c := newChange(1, keysOf(found, "a"), map[string][]string{testNode: {}})
	c.body["rpId"] = "example.com"
	_, err := apply(t, Trust{}, c)
	refused(t, err, "host of the origin")
}

func TestAnEmptyCoreIsRefused(t *testing.T) {
	found := devices(t, "a", "b")
	c := newChange(2, []TrustKey{}, map[string][]string{testNode: {}}).by(found, "a", "b")
	_, err := apply(t, storeOf(found, []string{"a", "b"}, []string{"a"}), c)
	refused(t, err, "at least one")
}

func TestAWeakRSAKeyIsRefused(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weak := TrustKey{ID: "weak", Name: "Old", Alg: algRS256, PublicKey: spki(t, &private.PublicKey)}
	c := newChange(1, []TrustKey{weak}, map[string][]string{testNode: {}})
	_, err = apply(t, Trust{}, c)
	refused(t, err, "at least 2048 bits")
}

func TestAnExpiredChangeIsRefused(t *testing.T) {
	found := devices(t, "a")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.body["expiresAt"] = testNow.Add(-2 * time.Minute).Format(time.RFC3339Nano)
	c.body["issuedAt"] = testNow.Add(-time.Hour).Format(time.RFC3339Nano)
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "the change expired at 29 Sep 09:58:00 UTC; this server's clock says 29 Sep 10:00:00 UTC")
}

func TestAChangeLongerThanADayIsRefused(t *testing.T) {
	found := devices(t, "a")
	c := newChange(2, nil, map[string][]string{testNode: {"a"}}).by(found, "a")
	c.body["expiresAt"] = testNow.Add(25 * time.Hour).Format(time.RFC3339Nano)
	_, err := apply(t, storeOf(found, []string{"a"}, []string{"a"}), c)
	refused(t, err, "24 hours")
}

func TestAVersionOneStoreBecomesCoreWithAccess(t *testing.T) {
	dir := t.TempDir()
	found := devices(t, "a")
	v1 := map[string]any{"nodeId": testNode, "origin": testOrigin, "rpId": testRPID, "version": 3, "keys": keysOf(found, "a")}
	if err := writeJSON(dir, "trust.json", v1, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.V != 2 || loaded.Version != 3 || len(loaded.Core) != 1 || len(loaded.Access) != 1 || loaded.Access[0] != "a" || loaded.Passphrase != nil {
		t.Fatalf("loaded %+v", loaded)
	}
}

func TestTrustRoundTripsThroughTheStateDirectory(t *testing.T) {
	dir := t.TempDir()
	empty, err := LoadTrust(dir)
	if err != nil || len(empty.Core) != 0 {
		t.Fatalf("empty %+v err %v", empty, err)
	}
	found := devices(t, "a")
	current := storeOf(found, []string{"a"}, []string{"a"})
	if err := SaveTrust(dir, current); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTrust(dir)
	if err != nil || loaded.NodeID != testNode || len(loaded.Core) != 1 || !loaded.RequireUV {
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

func TestTheTrustReportCarriesCoreAndAccess(t *testing.T) {
	found := devices(t, "a", "b")
	current := storeOf(found, []string{"a", "b"}, []string{"b"})
	report := current.Report()
	if report.Version != 1 || len(report.Core) != 2 || len(report.Access) != 1 || report.Access[0] != Fingerprint(found["b"].key) || report.Passphrase {
		t.Fatalf("report %+v", report)
	}
}

func TestParseTrustArgsReadsKeysAndGrant(t *testing.T) {
	key, _ := newPasskey(t, "cred-1", algES256)
	trust, err := ParseTrustArgs(testOrigin, []string{"cred-1.-7." + key.PublicKey}, true)
	if err != nil {
		t.Fatal(err)
	}
	if trust.V != 2 || trust.Origin != testOrigin || trust.RPID != testRPID || trust.Version != 1 || len(trust.Core) != 1 || trust.Core[0].ID != "cred-1" || len(trust.Access) != 1 || !trust.RequireUV {
		t.Fatalf("trust %+v", trust)
	}
	plain, err := ParseTrustArgs(testOrigin, []string{"cred-1.-7." + key.PublicKey}, false)
	if err != nil || len(plain.Access) != 0 {
		t.Fatalf("plain %+v err %v", plain, err)
	}
	for _, bad := range [][]string{{"cred-1"}, {"cred-1.x." + key.PublicKey}, {"cred-1.5." + key.PublicKey}, {"cred-1.-7.bm90YWtleQ"}, {}} {
		if _, err := ParseTrustArgs(testOrigin, bad, false); err == nil {
			t.Errorf("%v should be refused", bad)
		}
	}
	if _, err := ParseTrustArgs("kry.kleavox.xyz", []string{"cred-1.-7." + key.PublicKey}, false); err == nil {
		t.Error("an origin without a scheme should be refused")
	}
}

func TestTheExecutorAppliesATrustRequestAndReportsIt(t *testing.T) {
	executor, run := newExecutor(t)
	executor.Now = func() time.Time { return testNow }
	found := devices(t, "a")
	request := newChange(1, keysOf(found, "a"), map[string][]string{testNode: {"a"}}).request(t)
	writeRequest(t, executor.RequestDir, testID+".json", request)
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, testID); !result.OK {
		t.Fatalf("result %+v", result)
	}
	stored, err := LoadTrust(executor.StateDir)
	if err != nil || stored.NodeID != testNode {
		t.Fatalf("stored %+v err %v", stored, err)
	}
	var inventory Inventory
	if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.Trust.Version != 1 || len(inventory.Trust.Core) != 1 || len(inventory.Trust.Access) != 1 {
		t.Fatalf("inventory trust %+v", inventory.Trust)
	}
	if len(run.calls) != 0 {
		t.Fatalf("calls %#v", run.calls)
	}
}
