package actions

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/trust"
)

const (
	testOrigin = "https://kry.example.org"
	testRPID   = "kry.example.org"
	testNode   = "22222222-2222-4222-8222-222222222222"
	testID     = "33333333-3333-4333-8333-333333333333"
	algES256   = -7
)

func encode(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func sum(data []byte) []byte {
	hashed := sha256.Sum256(data)
	return hashed[:]
}

func spki(t *testing.T, public any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return encode(der)
}

func p1363(t *testing.T, key *ecdsa.PrivateKey, data []byte) string {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, key, sum(data))
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return encode(out)
}

type deployCase struct {
	trust   trust.Trust
	passkey crypto.Signer
	grant   map[string]any
	signer  *ecdsa.PrivateKey
	command Command
}

func newDeployCase(t *testing.T) *deployCase {
	t.Helper()
	passkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	session, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := trust.TrustKey{ID: "cred-1", Name: "Laptop", Alg: algES256, PublicKey: spki(t, &passkey.PublicKey)}
	return &deployCase{
		trust:   trust.Trust{V: 2, NodeID: testNode, Origin: testOrigin, RPID: testRPID, Version: 1, Core: []trust.TrustKey{key}, Access: []string{"cred-1"}},
		passkey: passkey,
		grant: map[string]any{
			"v": 1, "rpId": testRPID, "sessionKey": spki(t, &session.PublicKey),
			"issuedAt": executorNow.Add(-time.Minute).Format(time.RFC3339Nano), "expiresAt": executorNow.Add(14 * time.Minute).Format(time.RFC3339Nano),
			"nonce": "bm9uY2U",
		},
		signer: session,
		command: Command{
			V: 1, ID: testID, NodeID: testNode, Kind: "compose", Name: "listmonk", Action: "deploy",
			IssuedAt: executorNow.Format(time.RFC3339Nano), ExpiresAt: executorNow.Add(10 * time.Minute).Format(time.RFC3339Nano),
		},
	}
}

func (c *deployCase) approval(t *testing.T) map[string]any {
	t.Helper()
	grantBytes, err := json.Marshal(c.grant)
	if err != nil {
		t.Fatal(err)
	}
	authData := append(sum([]byte(testRPID)), 0x01|0x04, 0, 0, 0, 7)
	clientData, err := json.Marshal(map[string]any{
		"type": "webauthn.get", "challenge": encode(sum(grantBytes)),
		"origin": testOrigin, "crossOrigin": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := c.passkey.Sign(rand.Reader, sum(append(append([]byte{}, authData...), sum(clientData)...)), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"grant":             encode(grantBytes),
		"credentialId":      "cred-1",
		"authenticatorData": encode(authData),
		"clientDataJSON":    encode(clientData),
		"signature":         encode(signature),
	}
}

func (c *deployCase) document(t *testing.T, body []byte) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"grant": c.approval(t), "document": encode(body), "signature": p1363(t, c.signer, body)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (c *deployCase) request(t *testing.T) Request {
	t.Helper()
	commandBytes, err := json.Marshal(c.command)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{
		"grant":     c.approval(t),
		"command":   encode(commandBytes),
		"signature": p1363(t, c.signer, commandBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	return Request{ID: testID, Kind: "compose", Name: "listmonk", Action: "deploy", ExpiresAt: executorNow.Add(10 * time.Minute).Format(time.RFC3339Nano), Signed: raw}
}

func firstTrust(t *testing.T) Request {
	t.Helper()
	held := testSigner(t).trust
	change, err := json.Marshal(map[string]any{
		"v": 2, "origin": testOrigin, "rpId": testRPID, "version": 1,
		"issuedAt": executorNow.Format(time.RFC3339Nano), "expiresAt": executorNow.Add(time.Hour).Format(time.RFC3339Nano),
		"core": held.Core, "passphrase": nil, "access": map[string][]string{testNode: held.Access},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"change": encode(change), "approvals": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	return Request{ID: testID, Kind: "trust", Name: "devices", Action: "trust", ExpiresAt: executorNow.Add(10 * time.Minute).Format(time.RFC3339Nano), Signed: raw}
}

func TestTheExecutorAppliesATrustRequestAndReportsIt(t *testing.T) {
	executor, run := newExecutor(t)
	writeRequest(t, executor.RequestDir, testID+".json", firstTrust(t))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := readResult(t, executor, testID); !result.OK {
		t.Fatalf("result %+v", result)
	}
	stored, err := trust.Load(executor.StateDir)
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
