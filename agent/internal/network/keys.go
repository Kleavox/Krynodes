package network

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Keys struct {
	Private string
	Public  string
	Signer  string
	seed    ed25519.PrivateKey
}

func Load(dir string, create bool) (Keys, error) {
	private, err := readKey(dir, "key")
	if errors.Is(err, os.ErrNotExist) && create {
		return newKeys(dir, true)
	}
	if err != nil {
		return Keys{}, err
	}
	seed, err := readKey(dir, "signer")
	if err != nil {
		return Keys{}, err
	}
	return keysOf(private, seed)
}

func Rekey(dir string) (Keys, error) {
	return newKeys(dir, false)
}

func Forget(dir string) error {
	return os.RemoveAll(dir)
}

func (k Keys) Announce(node string) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.seed, announcement(node, k.Public)))
}

func Announced(signer, node, key, signature string) bool {
	public, err := base64.StdEncoding.DecodeString(signer)
	if err != nil || len(public) != ed25519.PublicKeySize || !validKey(key) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(signature)
	return err == nil && ed25519.Verify(public, announcement(node, key), raw)
}

func announcement(node, key string) []byte {
	return fmt.Appendf(nil, "krynodes-network-key\n%s\n%s", node, key)
}

func newKeys(dir string, signer bool) (Keys, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Keys{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Keys{}, err
	}
	if signer {
		_, seed, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return Keys{}, err
		}
		if err := writeKey(dir, "signer", seed.Seed()); err != nil {
			return Keys{}, err
		}
	}
	if err := writeKey(dir, "key", private.Bytes()); err != nil {
		return Keys{}, err
	}
	return Load(dir, false)
}

func keysOf(private, seed []byte) (Keys, error) {
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil || len(seed) != ed25519.SeedSize {
		return Keys{}, errors.New("the network keys are unreadable")
	}
	signer := ed25519.NewKeyFromSeed(seed)
	return Keys{
		Private: base64.StdEncoding.EncodeToString(private),
		Public:  base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()),
		Signer:  base64.StdEncoding.EncodeToString(signer.Public().(ed25519.PublicKey)),
		seed:    signer,
	}, nil
}

func readKey(dir, name string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
}

func writeKey(dir, name string, raw []byte) error {
	file, err := os.CreateTemp(dir, "."+name+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.WriteString(base64.StdEncoding.EncodeToString(raw) + "\n"); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(dir, name))
}
