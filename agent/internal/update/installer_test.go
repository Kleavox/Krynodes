package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func TestTheInstallerChecksSignaturesWithTheReleaseKey(t *testing.T) {
	script, err := os.ReadFile("../../../app/public/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(script, []byte("-----BEGIN PUBLIC KEY-----"))
	if start < 0 {
		t.Fatal("the installer carries no release key")
	}
	block, _ := pem.Decode(script[start:])
	if block == nil {
		t.Fatal("the installer's release key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	want, err := PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if key, ok := parsed.(ed25519.PublicKey); !ok || !key.Equal(want) {
		t.Fatal("the installer's key must be agent/internal/update/release.pub")
	}
	if !bytes.Contains(script, []byte("openssl pkeyutl -verify")) || !bytes.Contains(script, []byte(".sig")) {
		t.Fatal("the installer must verify the release signature")
	}
}
