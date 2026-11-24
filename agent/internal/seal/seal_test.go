package seal

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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
