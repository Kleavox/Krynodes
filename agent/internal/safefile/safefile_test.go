package safefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteReplacesALinkInsteadOfWritingThroughIt(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "status")
	if err := os.Symlink(victim, target); err != nil {
		t.Skip("links are not available here: ", err)
	}
	if err := Write(target, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if body, _ := os.ReadFile(victim); string(body) != "keep" {
		t.Fatalf("the file behind the link was changed: %q", body)
	}
	if info, err := os.Lstat(target); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("status is not a regular file: %v %v", info, err)
	}
}

func TestReadRefusesALinkAndStopsAtTheLimit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "request"), []byte("0.7.20\nmore"), 0o644); err != nil {
		t.Fatal(err)
	}
	if body, err := Read(filepath.Join(dir, "request"), 6); err != nil || string(body) != "0.7.20" {
		t.Fatalf("got %q %v", body, err)
	}
	if err := os.Symlink(filepath.Join(dir, "request"), filepath.Join(dir, "link")); err != nil {
		t.Skip("links are not available here: ", err)
	}
	if _, err := Read(filepath.Join(dir, "link"), 6); err == nil {
		t.Fatal("a link was read")
	}
}
