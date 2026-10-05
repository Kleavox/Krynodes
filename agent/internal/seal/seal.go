package seal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
)

const info = "krynodes-seal-v1"

var encoding = base64.RawURLEncoding

type envelope struct {
	V   int    `json:"v"`
	EPK string `json:"epk"`
	IV  string `json:"iv"`
	CT  string `json:"ct"`
}

func Load(dir string) (*ecdh.PrivateKey, error) {
	path := filepath.Join(dir, "seal.key")
	raw, err := os.ReadFile(path)
	if err == nil {
		return ecdh.P256().NewPrivateKey(raw)
	}
	if !errors.Is(err, os.ErrNotExist) {
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
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(temporary.Name(), path); err != nil {
		return nil, err
	}
	return key, nil
}

func Public(key *ecdh.PrivateKey) string {
	return encoding.EncodeToString(key.PublicKey().Bytes())
}

func Seal(public string, plaintext []byte) (string, error) {
	raw, err := encoding.DecodeString(public)
	if err != nil {
		return "", fmt.Errorf("seal key: %w", err)
	}
	recipient, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return "", fmt.Errorf("seal key: %w", err)
	}
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return "", err
	}
	epk := ephemeral.PublicKey().Bytes()
	aead, err := cipherFor(shared, epk, raw)
	if err != nil {
		return "", err
	}
	iv := make([]byte, aead.NonceSize())
	rand.Read(iv)
	body, err := json.Marshal(envelope{V: 1, EPK: encoding.EncodeToString(epk), IV: encoding.EncodeToString(iv), CT: encoding.EncodeToString(aead.Seal(nil, iv, plaintext, nil))})
	if err != nil {
		return "", err
	}
	return encoding.EncodeToString(body), nil
}

func Open(key *ecdh.PrivateKey, sealed string) ([]byte, error) {
	body, err := encoding.DecodeString(sealed)
	if err != nil {
		return nil, errors.New("the sealed message is not valid")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var message envelope
	if err := decoder.Decode(&message); err != nil || message.V != 1 {
		return nil, errors.New("the sealed message is not valid")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("the sealed message is not valid")
	}
	epk, err := encoding.DecodeString(message.EPK)
	if err != nil {
		return nil, errors.New("the sealed message is not valid")
	}
	ephemeral, err := ecdh.P256().NewPublicKey(epk)
	if err != nil {
		return nil, errors.New("the sealed message is not valid")
	}
	shared, err := key.ECDH(ephemeral)
	if err != nil {
		return nil, err
	}
	aead, err := cipherFor(shared, epk, key.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	iv, ivErr := encoding.DecodeString(message.IV)
	ct, ctErr := encoding.DecodeString(message.CT)
	if ivErr != nil || ctErr != nil || len(iv) != aead.NonceSize() {
		return nil, errors.New("the sealed message is not valid")
	}
	plaintext, err := aead.Open(nil, iv, ct, nil)
	if err != nil {
		return nil, errors.New("the sealed message is not for this server")
	}
	return plaintext, nil
}

func cipherFor(shared, epk, recipient []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, shared, append(slices.Clone(epk), recipient...), info, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
