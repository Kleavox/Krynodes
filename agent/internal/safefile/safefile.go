package safefile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

func Write(path string, data []byte, mode os.FileMode) error {
	directory, name := filepath.Split(path)
	root, err := os.OpenRoot(filepath.Clean(directory))
	if err != nil {
		return err
	}
	defer root.Close()
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temporary := "." + name + "." + hex.EncodeToString(random) + ".tmp"
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Chmod(mode)
	}
	if closed := file.Close(); err == nil {
		err = closed
	}
	if err == nil {
		err = root.Rename(temporary, name)
	}
	if err != nil {
		root.Remove(temporary)
	}
	return err
}

func Read(path string, most int64) ([]byte, error) {
	directory, name := filepath.Split(path)
	root, err := os.OpenRoot(filepath.Clean(directory))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New(name + " is not a regular file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, most))
}
