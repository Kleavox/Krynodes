package bundle

import (
	"bytes"
	"embed"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
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

func missing(from fs.FS) error {
	if _, err := fs.Stat(from, path.Join(root, Wintun)); err != nil {
		return ErrNoWintun
	}
	return nil
}

func unpack(from fs.FS, dir string, folder func(dir string) error, write func(path string, data []byte) error) error {
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
		if err := folder(filepath.Dir(target)); err != nil {
			return err
		}
		return write(target, data)
	})
}
