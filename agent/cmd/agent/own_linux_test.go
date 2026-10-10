package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClaimDirectoryReplacesASymlinkInsteadOfFollowingIt(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "actions")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := claimDirectory(link, os.Getuid(), os.Getgid(), 0o750); err != nil {
		t.Fatalf("claim: %v", err)
	}
	info, err := os.Lstat(link)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o750 {
		t.Fatalf("expected a real 0750 directory, got %v %v", info.Mode(), err)
	}
	kept, err := os.Stat(target)
	if err != nil || kept.Mode().Perm() != 0o700 {
		t.Fatalf("the symlink target must be untouched, got %v %v", kept.Mode(), err)
	}
}

func TestClaimDirectoryKeepsSetgidSoNewFilesTakeItsGroup(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "results")
	if err := claimDirectory(directory, os.Getuid(), os.Getgid(), 0o750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(directory)
	if err != nil || info.Mode()&os.ModeSetgid == 0 || info.Mode().Perm() != 0o750 {
		t.Fatalf("mode %v err %v", info.Mode(), err)
	}
}

func TestClaimFileRefusesASymlink(t *testing.T) {
	base := t.TempDir()
	secret := filepath.Join(base, "shadow")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(base, "config.json")
	if err := os.Symlink(secret, config); err != nil {
		t.Fatal(err)
	}
	if err := claimFile(config, os.Getuid(), os.Getgid(), 0o640); err == nil {
		t.Fatal("a symlinked config must be refused")
	}
	info, err := os.Stat(secret)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the symlink target must be untouched, got %v %v", info.Mode(), err)
	}
}

func TestClaimFileSetsTheModeOfARegularFile(t *testing.T) {
	config := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(config, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := claimFile(config, os.Getuid(), os.Getgid(), 0o600); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if info, _ := os.Stat(config); info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600, got %v", info.Mode())
	}
}
