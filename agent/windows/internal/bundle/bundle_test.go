package bundle

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func TestUnpackWritesTheDLLAndLicencesBesideTheProgram(t *testing.T) {
	dir := t.TempDir()
	from := fstest.MapFS{
		"files/.gitkeep":               {},
		"files/wintun.dll":             {Data: []byte("dll")},
		"files/licenses/wintun.txt":    {Data: []byte("prebuilt")},
		"files/licenses/systray.txt":   {Data: []byte("apache")},
		"files/licenses/wireguard.txt": {Data: []byte("mit")},
	}
	if err := unpack(from, dir); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"wintun.dll": "dll", "licenses/wintun.txt": "prebuilt", "licenses/systray.txt": "apache", "licenses/wireguard.txt": "mit"} {
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil || string(got) != want {
			t.Errorf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ".gitkeep")); !os.IsNotExist(err) {
		t.Errorf(".gitkeep was written: %v", err)
	}
	if err := unpack(from, dir); err != nil {
		t.Errorf("a second unpack over the same files: %v", err)
	}
}

func TestABuildWithoutWintunIsRefused(t *testing.T) {
	dir := t.TempDir()
	from := fstest.MapFS{"files/.gitkeep": {}}
	if err := missing(from); !errors.Is(err, ErrNoWintun) {
		t.Errorf("missing = %v, want ErrNoWintun", err)
	}
	if err := unpack(from, dir); !errors.Is(err, ErrNoWintun) {
		t.Errorf("unpack = %v, want ErrNoWintun", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("unpack wrote %d entries without wintun.dll", len(entries))
	}
}
