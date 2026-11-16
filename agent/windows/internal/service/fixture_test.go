package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/seal"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

const (
	testOrigin = "https://kry.example.com"
	testRPID   = "kry.example.com"
	laptop1    = "11111111-1111-4111-8111-111111111111"
	server1    = "22222222-2222-4222-8222-222222222222"
	server2    = "33333333-3333-4333-8333-333333333333"
	server3    = "44444444-4444-4444-8444-444444444444"
	laptop2    = "55555555-5555-4555-8555-555555555555"
	server4    = "66666666-6666-4666-8666-666666666666"
)

var (
	testNow = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	b64     = base64.RawURLEncoding
)

type memory map[string][]byte

func (m memory) Get(name string) ([]byte, error) {
	value, ok := m[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(value), nil
}

func (m memory) Put(name string, value []byte) error {
	m[name] = bytes.Clone(value)
	return nil
}

func (m memory) Lock(name string) error {
	m["locked "+name] = nil
	return nil
}

type fakeServer struct {
	response reporter.HeartbeatResponse
	beats    []reporter.Heartbeat
	reports  []reporter.ActionsReport
}

func (f *fakeServer) SendHeartbeat(_ context.Context, beat reporter.Heartbeat) (reporter.HeartbeatResponse, error) {
	f.beats = append(f.beats, beat)
	return f.response, nil
}

func (f *fakeServer) PostActions(_ context.Context, report reporter.ActionsReport) (reporter.ActionsResponse, error) {
	f.reports = append(f.reports, report)
	return reporter.ActionsResponse{OK: true}, nil
}

type fixture struct {
	t       *testing.T
	service *Service
	secrets memory
	keys    network.Keys
	server  network.Keys
	seal    string
	passkey *ecdsa.PrivateKey
	device  trust.TrustKey
	applied []Wanted
}

func spki(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return b64.EncodeToString(der)
}

func digest(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, secrets: memory{}}
	keys, sealing, err := newKeys(f.secrets)
	if err != nil {
		t.Fatal(err)
	}
	f.keys, f.seal = keys, seal.Public(sealing)
	f.server = serverKeys(t, 1)
	if f.passkey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	f.device = trust.TrustKey{ID: "cred-1", Name: "Phone", Alg: -7, PublicKey: spki(t, f.passkey)}
	dir := t.TempDir()
	if err := trust.Save(dir, trust.Trust{V: 2, NodeID: laptop1, Origin: testOrigin, RPID: testRPID, Version: 1, Core: []trust.TrustKey{f.device}, Access: []string{"cred-1"}, RequireUV: true}); err != nil {
		t.Fatal(err)
	}
	f.service = &Service{Dir: dir, Secrets: f.secrets, Now: func() time.Time { return testNow }, Apply: func(wanted Wanted) { f.applied = append(f.applied, wanted) }}
	if err := f.service.save(state{Endpoint: testOrigin, NodeID: laptop1, Interval: 60}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) assert(id string, passkey *ecdsa.PrivateKey, challenge []byte) map[string]any {
	f.t.Helper()
	authData := append(digest([]byte(testRPID)), 0x05, 0, 0, 0, 7)
	clientData, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": b64.EncodeToString(challenge), "origin": testOrigin, "crossOrigin": false})
	if err != nil {
		f.t.Fatal(err)
	}
	signature, err := ecdsa.SignASN1(rand.Reader, passkey, digest(append(append([]byte{}, authData...), digest(clientData)...)))
	if err != nil {
		f.t.Fatal(err)
	}
	return map[string]any{
		"credentialId": id, "authenticatorData": b64.EncodeToString(authData),
		"clientDataJSON": b64.EncodeToString(clientData), "signature": b64.EncodeToString(signature),
	}
}

func (f *fixture) signWith(id string, passkey *ecdsa.PrivateKey, body []byte) json.RawMessage {
	f.t.Helper()
	session, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	grant, err := json.Marshal(map[string]any{
		"v": 1, "rpId": testRPID, "sessionKey": spki(f.t, session),
		"issuedAt": testNow.Add(-time.Minute).Format(time.RFC3339Nano), "expiresAt": testNow.Add(14 * time.Minute).Format(time.RFC3339Nano),
		"nonce": "bm9uY2U",
	})
	if err != nil {
		f.t.Fatal(err)
	}
	approval := f.assert(id, passkey, digest(grant))
	approval["grant"] = b64.EncodeToString(grant)
	r, s, err := ecdsa.Sign(rand.Reader, session, digest(body))
	if err != nil {
		f.t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	raw, err := json.Marshal(map[string]any{"grant": approval, "document": b64.EncodeToString(body), "signature": b64.EncodeToString(signature)})
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *fixture) sign(body []byte) json.RawMessage {
	return f.signWith("cred-1", f.passkey, body)
}

func serverKeys(t *testing.T, private byte) network.Keys {
	t.Helper()
	keys, err := network.KeysOf(bytes.Repeat([]byte{private}, 32), bytes.Repeat([]byte{21}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func wgKey(seed byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32))
}

func endpoint(text string) *string {
	return &text
}

func (f *fixture) psk() string {
	f.t.Helper()
	sealed, err := seal.Seal(f.seal, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		f.t.Fatal(err)
	}
	return sealed
}

func (f *fixture) laptop() network.Member {
	return network.Member{Node: laptop1, Name: "laptop-1", Address: "10.88.0.10", Key: f.keys.Public, Signer: f.keys.Signer, Port: network.FirstPort, Kind: "laptop", PSK: map[string]string{server1: f.psk()}}
}

func (f *fixture) document(version int, parent string, withLaptop bool) []byte {
	f.t.Helper()
	members := []network.Member{
		{Node: server1, Name: "server-1", Address: "10.88.0.1", Key: f.server.Public, Signer: f.server.Signer, Port: network.FirstPort, Endpoint: endpoint("203.0.113.1:51820"), Exit: true, PSK: map[string]string{server2: "c2VhbGVk"}},
		{Node: server2, Name: "server-2", Address: "10.88.0.2", Key: wgKey(2), Signer: wgKey(12), Port: network.FirstPort, NAT: true, PSK: map[string]string{server1: "c2VhbGVk"}},
	}
	blocked := []string{}
	if withLaptop {
		members[0].PSK[laptop1] = "c2VhbGVk"
		members = append(members, f.laptop())
	} else {
		blocked = append(blocked, f.keys.Public)
	}
	body, err := json.Marshal(network.Document{V: 1, Version: version, Range: "10.88.0.0/24", Port: network.FirstPort, MTU: 1420, Parent: parent, DNS: []string{"10.88.0.1"}, Members: members, Blocked: blocked})
	if err != nil {
		f.t.Fatal(err)
	}
	return body
}

func (f *fixture) change(id string, version int, core []trust.TrustKey) reporter.ActionRequest {
	f.t.Helper()
	body, err := json.Marshal(map[string]any{
		"v": 2, "origin": testOrigin, "rpId": testRPID, "version": version,
		"issuedAt": testNow.Format(time.RFC3339Nano), "expiresAt": testNow.Add(time.Hour).Format(time.RFC3339Nano),
		"core": core, "passphrase": nil, "access": map[string][]string{laptop1: {"cred-1"}},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	signed, err := json.Marshal(map[string]any{"change": b64.EncodeToString(body), "approvals": []map[string]any{f.assert("cred-1", f.passkey, digest(body))}})
	if err != nil {
		f.t.Fatal(err)
	}
	return reporter.ActionRequest{ID: id, Kind: "trust", Name: "devices", Action: "trust", ExpiresAt: testNow.Add(10 * time.Minute).Format(time.RFC3339Nano), Signed: signed}
}

func (f *fixture) record() state {
	f.t.Helper()
	record, err := f.service.read()
	if err != nil {
		f.t.Fatal(err)
	}
	return record
}

func (f *fixture) last() Wanted {
	f.t.Helper()
	if len(f.applied) == 0 {
		f.t.Fatal("nothing reached the tunnel")
	}
	return f.applied[len(f.applied)-1]
}
