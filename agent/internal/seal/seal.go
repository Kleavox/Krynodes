package seal

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
)

func Load(dir string) (*ecdh.PrivateKey, error) {
	path := filepath.Join(dir, "seal.key")
	raw, err := os.ReadFile(path)
	if err == nil {
		key, parseErr := ecdh.P256().NewPrivateKey(raw)
		if parseErr == nil {
			return key, nil
		}
		if err := os.Rename(path, path+".damaged"); err != nil {
			return nil, parseErr
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	temporary, err := os.CreateTemp(dir, ".seal-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(temporary.Name())
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return nil, err
	}
	if _, err := temporary.Write(key.Bytes()); err != nil {
		temporary.Close()
		return nil, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return nil, err
	}
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(temporary.Name(), path); err != nil {
		return nil, err
	}
	return key, nil
}

func Public(key *ecdh.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
}
