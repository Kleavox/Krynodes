package seal

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestASealedMessageOpensOnlyWithItsKey(t *testing.T) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(Public(key), []byte("SMTP_PASSWORD=hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(key, sealed)
	if err != nil || string(opened) != "SMTP_PASSWORD=hunter2" {
		t.Fatalf("opened %q: %v", opened, err)
	}
	if _, err := Open(other, sealed); err == nil {
		t.Fatal("another key must not open it")
	}
	again, err := Seal(Public(key), []byte("SMTP_PASSWORD=hunter2"))
	if err != nil || again == sealed {
		t.Fatal("every seal must differ")
	}
}

func TestATamperedEnvelopeIsRefused(t *testing.T) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(Public(key), []byte("piece"))
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
	ct := []byte(body["ct"].(string))
	ct[0] ^= 1
	body["ct"] = string(ct)
	changed, _ := json.Marshal(body)
	for _, bad := range []string{base64.RawURLEncoding.EncodeToString(changed), "", "not base64!", sealed + "AA"} {
		if _, err := Open(key, bad); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
	if _, err := Seal("short", []byte("x")); err == nil {
		t.Fatal("a bad public key must be refused")
	}
}

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

func TestTheAgentOpensWhatABrowserSealed(t *testing.T) {
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
	opened, err := Open(key, fixture.Envelope)
	if err != nil || string(opened) != fixture.Plaintext || !strings.Contains(fixture.Plaintext, "=") {
		t.Fatalf("opened %q: %v", opened, err)
	}
}
