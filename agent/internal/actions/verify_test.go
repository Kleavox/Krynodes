package actions

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const (
	testOrigin = "https://kry.kleavox.xyz"
	testRPID   = "kry.kleavox.xyz"
	testNode   = "22222222-2222-4222-8222-222222222222"
	testID     = "33333333-3333-4333-8333-333333333333"
)

var testNow = time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)

func spki(t *testing.T, public any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return b64.EncodeToString(der)
}

func newPasskey(t *testing.T, id string, alg int) (TrustKey, crypto.Signer) {
	t.Helper()
	if alg == algRS256 {
		private, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return TrustKey{ID: id, Name: "Laptop", Alg: algRS256, PublicKey: spki(t, &private.PublicKey)}, private
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return TrustKey{ID: id, Name: "Laptop", Alg: algES256, PublicKey: spki(t, &private.PublicKey)}, private
}

type assertionOptions struct {
	origin     string
	rpID       string
	clientType string
	flags      byte
	challenge  []byte
}

func sign(t *testing.T, signer crypto.Signer, credentialID string, options assertionOptions) Assertion {
	t.Helper()
	authData := append(digest([]byte(options.rpID)), options.flags, 0, 0, 0, 7)
	clientData, err := json.Marshal(map[string]any{
		"type": options.clientType, "challenge": b64.EncodeToString(options.challenge),
		"origin": options.origin, "crossOrigin": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(rand.Reader, digest(append(append([]byte{}, authData...), digest(clientData)...)), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return Assertion{
		CredentialID: credentialID, AuthenticatorData: b64.EncodeToString(authData),
		ClientDataJSON: b64.EncodeToString(clientData), Signature: b64.EncodeToString(signature),
	}
}

func p1363(t *testing.T, key *ecdsa.PrivateKey, data []byte) string {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, key, digest(data))
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return b64.EncodeToString(out)
}

type deployCase struct {
	trust        Trust
	passkey      crypto.Signer
	assertion    assertionOptions
	credentialID string
	grant        map[string]any
	session      *ecdsa.PrivateKey
	signer       *ecdsa.PrivateKey
	command      Command
	extra        bool
}

func newDeployCase(t *testing.T, alg int) *deployCase {
	t.Helper()
	key, passkey := newPasskey(t, "cred-1", alg)
	session, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &deployCase{
		trust:        Trust{V: 2, NodeID: testNode, Origin: testOrigin, RPID: testRPID, Version: 1, Core: []TrustKey{key}, Access: []string{"cred-1"}},
		passkey:      passkey,
		assertion:    assertionOptions{origin: testOrigin, rpID: testRPID, clientType: "webauthn.get", flags: flagPresent | flagVerified},
		credentialID: "cred-1",
		grant: map[string]any{
			"v": 1, "rpId": testRPID, "sessionKey": spki(t, &session.PublicKey),
			"issuedAt": testNow.Add(-time.Minute).Format(time.RFC3339Nano), "expiresAt": testNow.Add(14 * time.Minute).Format(time.RFC3339Nano),
			"nonce": "bm9uY2U",
		},
		session: session,
		signer:  session,
		command: Command{
			V: 1, ID: testID, NodeID: testNode, Kind: "compose", Name: "listmonk", Action: "deploy",
			IssuedAt: testNow.Format(time.RFC3339Nano), ExpiresAt: testNow.Add(10 * time.Minute).Format(time.RFC3339Nano),
		},
	}
}

func (c *deployCase) request(t *testing.T) Request {
	t.Helper()
	grantBytes, err := json.Marshal(c.grant)
	if err != nil {
		t.Fatal(err)
	}
	options := c.assertion
	if options.challenge == nil {
		options.challenge = digest(grantBytes)
	}
	commandBytes, err := json.Marshal(c.command)
	if err != nil {
		t.Fatal(err)
	}
	signed := map[string]any{
		"grant":     map[string]any{"grant": b64.EncodeToString(grantBytes)},
		"command":   b64.EncodeToString(commandBytes),
		"signature": p1363(t, c.signer, commandBytes),
	}
	assertion := sign(t, c.passkey, c.credentialID, options)
	grant := signed["grant"].(map[string]any)
	grant["credentialId"] = assertion.CredentialID
	grant["authenticatorData"] = assertion.AuthenticatorData
	grant["clientDataJSON"] = assertion.ClientDataJSON
	grant["signature"] = assertion.Signature
	if c.extra {
		signed["extra"] = true
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return Request{ID: testID, Kind: "compose", Name: "listmonk", Action: "deploy", ExpiresAt: testNow.Add(10 * time.Minute).Format(time.RFC3339Nano), Signed: raw}
}

func (c *deployCase) verify(t *testing.T, now time.Time) error {
	t.Helper()
	_, err := VerifyCommand(c.trust, c.request(t), now)
	return err
}

func refused(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), reason) {
		t.Fatalf("want refusal %q, got %v", reason, err)
	}
}

func TestAValidDeployCommandVerifies(t *testing.T) {
	c := newDeployCase(t, algES256)
	command, err := VerifyCommand(c.trust, c.request(t), testNow)
	if err != nil || command.Name != "listmonk" || command.Action != "deploy" {
		t.Fatalf("command %+v err %v", command, err)
	}
}

func TestAnRS256PasskeyVerifies(t *testing.T) {
	if err := newDeployCase(t, algRS256).verify(t, testNow); err != nil {
		t.Fatal(err)
	}
}

func TestAWrongOriginIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	c.assertion.origin = "https://evil.example"
	refused(t, c.verify(t, testNow), "origin does not match")
}

func TestAWrongRPIDHashIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	c.assertion.rpID = "evil.example"
	refused(t, c.verify(t, testNow), "rp id does not match")
}

func TestAMissingUserPresenceIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	c.assertion.flags = flagVerified
	refused(t, c.verify(t, testNow), "was not touched")
}

func TestARegistrationInsteadOfAnAssertionIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	c.assertion.clientType = "webauthn.create"
	refused(t, c.verify(t, testNow), "not an assertion")
}

func TestAWrongChallengeIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	c.assertion.challenge = digest([]byte("another grant"))
	refused(t, c.verify(t, testNow), "challenge does not match")
}

func TestAnUntrustedPasskeyIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	_, stranger := newPasskey(t, "cred-2", algES256)
	c.passkey = stranger
	c.credentialID = "cred-2"
	refused(t, c.verify(t, testNow), "passkey is not trusted")
}

func TestAForgedPasskeySignatureIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	_, stranger := newPasskey(t, "cred-1", algES256)
	c.passkey = stranger
	refused(t, c.verify(t, testNow), "passkey signature is invalid")
}

func TestAGrantLongerThanFifteenMinutesIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	c.grant["expiresAt"] = testNow.Add(15 * time.Minute).Format(time.RFC3339Nano)
	refused(t, c.verify(t, testNow), "longer than 15 minutes")
}

func TestAGrantFromTheFutureIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	c.grant["issuedAt"] = testNow.Add(5 * time.Minute).Format(time.RFC3339Nano)
	c.grant["expiresAt"] = testNow.Add(10 * time.Minute).Format(time.RFC3339Nano)
	refused(t, c.verify(t, testNow), "from the future: signed 29 Sep 10:05:00 UTC; this server's clock says 29 Sep 10:00:00 UTC")
}

func TestAGrantForAnotherRPIDIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	c.grant["rpId"] = "evil.example"
	refused(t, c.verify(t, testNow), "another rp id")
}

func TestACommandSignedByAnotherKeyIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c.signer = other
	refused(t, c.verify(t, testNow), "command signature is invalid")
}

func TestACommandForAnotherNodeIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	c.command.NodeID = "44444444-4444-4444-8444-444444444444"
	refused(t, c.verify(t, testNow), "another server")
}

func TestACommandForAnotherActionIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	c.command.Action = "rollback"
	refused(t, c.verify(t, testNow), "does not match the request")
}

func TestACommandIssuedAfterTheSessionIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	c.command.IssuedAt = testNow.Add(20 * time.Minute).Format(time.RFC3339Nano)
	c.command.ExpiresAt = testNow.Add(30 * time.Minute).Format(time.RFC3339Nano)
	refused(t, c.verify(t, testNow.Add(21*time.Minute)), "after the session ended")
}

func TestAnExpiredCommandIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	refused(t, c.verify(t, testNow.Add(12*time.Minute)), "command expired at 29 Sep 10:10:00 UTC; this server's clock says 29 Sep 10:12:00 UTC")
}

func TestACommandLivingBeyondTheGraceIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	c.command.ExpiresAt = testNow.Add(75 * time.Minute).Format(time.RFC3339Nano)
	refused(t, c.verify(t, testNow), "more than an hour")
}

func TestACommandSignedInTheSessionRunsAfterTheSessionEnds(t *testing.T) {
	c := newDeployCase(t, algES256)
	c.command.ExpiresAt = testNow.Add(74 * time.Minute).Format(time.RFC3339Nano)
	if err := c.verify(t, testNow.Add(54*time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownSignatureFieldsAreRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	c.extra = true
	refused(t, c.verify(t, testNow), "malformed")
}

func TestAnUnsignedRequestIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	request := c.request(t)
	request.Signed = nil
	_, err := VerifyCommand(c.trust, request, testNow)
	refused(t, err, "not signed")
}

func TestAPasskeyWithoutAccessToThisServerIsRefused(t *testing.T) {
	c := newDeployCase(t, algES256)
	c.trust.Access = nil
	refused(t, c.verify(t, testNow), "no access to this server")
}
