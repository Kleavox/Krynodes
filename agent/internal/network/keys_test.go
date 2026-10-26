package network

import (
	"crypto/ecdh"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestKeysAreMadeOnceAndKeptPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "network")
	if _, err := Load(dir, false); !os.IsNotExist(err) {
		t.Fatalf("nothing to load yet: %v", err)
	}
	keys, err := Load(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Load(dir, false)
	if err != nil || again.Public != keys.Public || again.Signer != keys.Signer {
		t.Fatalf("again %+v err %v", again, err)
	}
	raw, _ := base64.StdEncoding.DecodeString(keys.Private)
	private, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil || base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()) != keys.Public {
		t.Fatalf("the public key is not the private key's: %v", err)
	}
	if runtime.GOOS != "windows" {
		for _, name := range []string{"key", "signer"} {
			info, err := os.Stat(filepath.Join(dir, name))
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("%s: %v %v", name, info.Mode(), err)
			}
		}
	}
}

func TestANewKeyIsAnnouncedWithTheSigner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "network")
	before, _ := Load(dir, true)
	after, err := Rekey(dir)
	if err != nil || after.Public == before.Public || after.Signer != before.Signer {
		t.Fatalf("after %+v err %v", after, err)
	}
	signature := after.Announce(nodeA)
	if !Announced(after.Signer, nodeA, after.Public, signature) {
		t.Fatal("a true announcement is refused")
	}
	if Announced(after.Signer, nodeA, before.Public, signature) || Announced(after.Signer, nodeB, after.Public, signature) || Announced(before.Public, nodeA, after.Public, signature) || Announced(after.Signer, nodeA, after.Public, "bm8") {
		t.Fatal("a false announcement is accepted")
	}
	if err := Forget(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the keys stay: %v", err)
	}
}
