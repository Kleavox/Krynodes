package seal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestTheServerKeyIsMadeOnceAndKeptPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	first, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if Public(first) != Public(second) || len(Public(first)) != 87 {
		t.Fatalf("the key must stay: %s %s", Public(first), Public(second))
	}
	info, err := os.Stat(filepath.Join(dir, "seal.key"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
}

func TestADamagedServerKeyIsSetAsideAndMadeAgain(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "seal.key"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := Load(dir)
	if err != nil || key == nil {
		t.Fatalf("key %v err %v", key, err)
	}
	again, err := Load(dir)
	if err != nil || Public(again) != Public(key) {
		t.Fatalf("the new key is kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "seal.key.damaged")); err != nil {
		t.Fatalf("the damaged key is set aside: %v", err)
	}
}

func browserSealed(t *testing.T) (*ecdh.PrivateKey, string, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "protocol", "src", "fixtures", "seal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Private   string `json:"private"`
		Public    string `json:"public"`
		Plaintext string `json:"plaintext"`
		Envelope  string `json:"envelope"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	scalar, err := base64.RawURLEncoding.DecodeString(fixture.Private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	if Public(key) != fixture.Public {
		t.Fatalf("public %s, fixture %s", Public(key), fixture.Public)
	}
	return key, fixture.Plaintext, fixture.Envelope
}

func TestTheAgentOpensWhatABrowserSealed(t *testing.T) {
	key, plaintext, sealed := browserSealed(t)
	opened, err := Open(key, sealed)
	if err != nil || string(opened) != plaintext {
		t.Fatalf("opened %q: %v", opened, err)
	}
	other, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(other, sealed); err == nil {
		t.Fatal("another key opened it")
	}
}

func TestATamperedEnvelopeIsRefused(t *testing.T) {
	key, _, sealed := browserSealed(t)
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	ct := []byte(body["ct"].(string))
	ct[0] ^= 1
	body["ct"] = string(ct)
	changed, _ := json.Marshal(body)
	body["ct"], body["extra"] = string(ct[1:]), 1
	extra, _ := json.Marshal(body)
	for _, bad := range []string{base64.RawURLEncoding.EncodeToString(changed), base64.RawURLEncoding.EncodeToString(extra), "", "not base64!", sealed + "AA"} {
		if _, err := Open(key, bad); err == nil {
			t.Fatalf("%q was opened", bad)
		}
	}
}

const (
	vectorPath = "../../../packages/protocol/src/fixtures/sealed-output.json"
	vectorX    = "NR7Ywu9QDBF9DpaHKhmq2KQKQCj4N7yHpeEyo28-4ro"
	vectorY    = "7RgByrxru8NaYiQQoEG-KoLZSIqpzeJfp2dcBEIGRG0"
	vectorD    = "Ha3OL1dti1njLKg9Q2D-JOeR8AmA8v43NMPUY-DFvbY"
	vectorText = "2026-11-25T10:00:00Z app-1 ready\n2026-11-25T10:00:01Z app-1 listening on 203.0.113.7: 8080 ünïcode ✓\n"
)

type sealedVector struct {
	JWK       map[string]string `json:"jwk"`
	To        string            `json:"to"`
	Node      string            `json:"node"`
	Plaintext string            `json:"plaintext"`
	Sealed    string            `json:"sealed"`
}

func testNodeKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.P256().NewPrivateKey(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func plainSeal(t *testing.T, to string, text string) string {
	t.Helper()
	public, raw, err := recipientKey(to)
	if err != nil {
		t.Fatal(err)
	}
	ephemeral := newKey(t)
	shared, err := ephemeral.ECDH(public)
	if err != nil {
		t.Fatal(err)
	}
	epk := ephemeral.PublicKey().Bytes()
	aead, err := derive(shared, slices.Concat(epk, raw), info)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, aead.NonceSize())
	body, err := json.Marshal(envelope{
		V:   1,
		EPK: encoding.EncodeToString(epk),
		IV:  encoding.EncodeToString(iv),
		CT:  encoding.EncodeToString(aead.Seal(nil, iv, []byte(text), nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoding.EncodeToString(body)
}

func vectorKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	scalar, err := base64.RawURLEncoding.DecodeString(vectorD)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func openFrom(key *ecdh.PrivateKey, node, sealed string) ([]byte, error) {
	invalid := errors.New("the sealed message is not valid")
	public, _, err := recipientKey(node)
	if err != nil {
		return nil, err
	}
	body, err := encoding.DecodeString(sealed)
	if err != nil {
		return nil, invalid
	}
	var message envelope
	if err := json.Unmarshal(body, &message); err != nil || message.V != 2 {
		return nil, invalid
	}
	epk, err := encoding.DecodeString(message.EPK)
	if err != nil {
		return nil, invalid
	}
	ephemeral, err := ecdh.P256().NewPublicKey(epk)
	if err != nil {
		return nil, invalid
	}
	fromEphemeral, err := key.ECDH(ephemeral)
	if err != nil {
		return nil, err
	}
	fromNode, err := key.ECDH(public)
	if err != nil {
		return nil, err
	}
	aead, err := derive(slices.Concat(fromEphemeral, fromNode), slices.Concat(epk, public.Bytes(), key.PublicKey().Bytes()), fromNodeInfo)
	if err != nil {
		return nil, err
	}
	iv, ivErr := encoding.DecodeString(message.IV)
	ct, ctErr := encoding.DecodeString(message.CT)
	if ivErr != nil || ctErr != nil || len(iv) != aead.NonceSize() {
		return nil, invalid
	}
	return aead.Open(nil, iv, ct, nil)
}

func TestSealFromOpensOnlyWithTheNodesKey(t *testing.T) {
	node, other, key, stranger := newKey(t), newKey(t), newKey(t), newKey(t)
	for _, plaintext := range []string{"", "line 1\nline 2\n", "SMTP_PASSWORD=pa$$ wörd"} {
		sealed, err := SealFrom(node, Public(key), []byte(plaintext))
		if err != nil {
			t.Fatal(err)
		}
		opened, err := openFrom(key, Public(node), sealed)
		if err != nil || string(opened) != plaintext {
			t.Fatalf("opened %q: %v", opened, err)
		}
		if _, err := openFrom(key, Public(other), sealed); err == nil {
			t.Fatal("a different node key opened it")
		}
		if _, err := openFrom(stranger, Public(node), sealed); err == nil {
			t.Fatal("another recipient opened it")
		}
		if _, err := Open(key, sealed); err == nil {
			t.Fatal("the plain scheme opened a sealed-from-node message")
		}
		forged, err := SealFrom(other, Public(key), []byte(plaintext))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := openFrom(key, Public(node), forged); err == nil {
			t.Fatal("a message from another node was taken for this node's")
		}
		if _, err := openFrom(key, Public(node), plainSeal(t, Public(key), plaintext)); err == nil {
			t.Fatal("a plain seal to the same key opened as the node's")
		}
		again, err := SealFrom(node, Public(key), []byte(plaintext))
		if err != nil || again == sealed {
			t.Fatalf("two seals of one text must differ: %v", err)
		}
	}
}

func TestATamperedSealFromNodeIsRefused(t *testing.T) {
	node, key := newKey(t), newKey(t)
	sealed, err := SealFrom(node, Public(key), []byte("TOKEN=secret"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body["v"] != float64(2) {
		t.Fatalf("version %v", body["v"])
	}
	ct := []byte(body["ct"].(string))
	ct[0] ^= 1
	body["ct"] = string(ct)
	changed, _ := json.Marshal(body)
	body["ct"], body["v"] = string(ct[1:]), 1
	older, _ := json.Marshal(body)
	for _, bad := range []string{base64.RawURLEncoding.EncodeToString(changed), base64.RawURLEncoding.EncodeToString(older), "", "not base64!", sealed + "AA"} {
		if _, err := openFrom(key, Public(node), bad); err == nil {
			t.Fatalf("%q was opened", bad)
		}
	}
	if _, err := openFrom(key, "not a key", sealed); err == nil {
		t.Fatal("a node key that is not a point was taken")
	}
}

func TestSealFromRefusesARecipientThatIsNotAPoint(t *testing.T) {
	node, key := newKey(t), newKey(t)
	good := Public(key)
	for _, bad := range []string{"", "x", good[:86], good + "A", "!" + good[1:], base64.RawURLEncoding.EncodeToString(make([]byte, 65)), base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), good[:86] + "B"} {
		if _, err := SealFrom(node, bad, []byte("text")); err == nil || ValidRecipient(bad) {
			t.Fatalf("%q was taken", bad)
		}
	}
	if !ValidRecipient(good) {
		t.Fatal("a real key was refused")
	}
}

func TestTheSealedVectorOpensToItsPlaintext(t *testing.T) {
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var vector sealedVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	key := vectorKey(t)
	point := key.PublicKey().Bytes()
	if vector.To != Public(key) || vector.JWK["x"] != base64.RawURLEncoding.EncodeToString(point[1:33]) || vector.JWK["y"] != base64.RawURLEncoding.EncodeToString(point[33:]) ||
		vector.JWK["d"] != vectorD || vector.JWK["kty"] != "EC" || vector.JWK["crv"] != "P-256" || len(vector.JWK) != 5 {
		t.Fatalf("the vector's key is not the test key: %+v", vector)
	}
	if vector.Node != Public(testNodeKey(t)) {
		t.Fatalf("the vector's node key is not the test node key: %s", vector.Node)
	}
	opened, err := openFrom(key, vector.Node, vector.Sealed)
	if err != nil || string(opened) != vector.Plaintext || vector.Plaintext != vectorText {
		t.Fatalf("opened %q: %v", opened, err)
	}
	if _, err := openFrom(key, Public(key), vector.Sealed); err == nil {
		t.Fatal("the vector opened under a key that is not the node's")
	}
}

func TestWriteTheSealedVector(t *testing.T) {
	if os.Getenv("KRY_WRITE_SEALED_VECTOR") != "1" {
		t.Skip("set KRY_WRITE_SEALED_VECTOR=1 to write the vector the browser test opens")
	}
	key, node := vectorKey(t), testNodeKey(t)
	sealed, err := SealFrom(node, Public(key), []byte(vectorText))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.MarshalIndent(sealedVector{
		JWK:       map[string]string{"kty": "EC", "crv": "P-256", "x": vectorX, "y": vectorY, "d": vectorD},
		To:        Public(key),
		Node:      Public(node),
		Plaintext: vectorText,
		Sealed:    sealed,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorPath, append(body, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
