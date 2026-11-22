package seal

import (
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
