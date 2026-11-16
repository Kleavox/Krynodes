package bundle

import (
	"bytes"
	"embed"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/Kleavox/krynodes/agent/internal/safefile"
)

const (
	root   = "files"
	Wintun = "wintun.dll"
)

//go:embed all:files
var files embed.FS

var ErrNoWintun = errors.New("this build carries no wintun.dll; download krynodes-windows-amd64.exe from the release")

func Missing() error {
	return missing(files)
}

func Unpack(dir string) error {
	return unpack(files, dir)
}

func missing(from fs.FS) error {
	if _, err := fs.Stat(from, path.Join(root, Wintun)); err != nil {
		return ErrNoWintun
	}
	return nil
}

func unpack(from fs.FS, dir string) error {
	if err := missing(from); err != nil {
		return err
	}
	return fs.WalkDir(from, root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || entry.Name() == ".gitkeep" {
			return err
		}
		data, err := fs.ReadFile(from, name)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, filepath.FromSlash(name))
		if err != nil {
			return err
		}
		target := filepath.Join(dir, relative)
		if current, err := os.ReadFile(target); err == nil && bytes.Equal(current, data) {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return safefile.Write(target, data, 0o644)
	})
}
