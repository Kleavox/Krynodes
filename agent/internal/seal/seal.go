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
	"io"
	"os"
	"path/filepath"
	"slices"
)

const (
	info         = "krynodes-seal-v1"
	fromNodeInfo = "krynodes-seal-from-node-v1"
)

var (
	encoding            = base64.RawURLEncoding
	errInvalidRecipient = errors.New("the recipient key is not valid")
)

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

func Read(dir string) (*ecdh.PrivateKey, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "seal.key"))
	if err != nil {
		return nil, err
	}
	return ecdh.P256().NewPrivateKey(raw)
}

func Public(key *ecdh.PrivateKey) string {
	return encoding.EncodeToString(key.PublicKey().Bytes())
}

func recipientKey(recipient string) (*ecdh.PublicKey, []byte, error) {
	raw, err := encoding.DecodeString(recipient)
	if err != nil {
		return nil, nil, errInvalidRecipient
	}
	public, err := ecdh.P256().NewPublicKey(raw)
	if err != nil || encoding.EncodeToString(raw) != recipient {
		return nil, nil, errInvalidRecipient
	}
	return public, raw, nil
}

func ValidRecipient(recipient string) bool {
	_, _, err := recipientKey(recipient)
	return err == nil
}

func derive(ikm, salt []byte, label string) (cipher.AEAD, error) {
	secret, err := hkdf.Key(sha256.New, ikm, salt, label, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func SealFrom(node *ecdh.PrivateKey, recipient string, plaintext []byte) (string, error) {
	public, raw, err := recipientKey(recipient)
	if err != nil {
		return "", err
	}
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	toEphemeral, err := ephemeral.ECDH(public)
	if err != nil {
		return "", err
	}
	toNode, err := node.ECDH(public)
	if err != nil {
		return "", err
	}
	epk := ephemeral.PublicKey().Bytes()
	aead, err := derive(slices.Concat(toEphemeral, toNode), slices.Concat(epk, node.PublicKey().Bytes(), raw), fromNodeInfo)
	if err != nil {
		return "", err
	}
	iv := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	body, err := json.Marshal(envelope{
		V:   2,
		EPK: encoding.EncodeToString(epk),
		IV:  encoding.EncodeToString(iv),
		CT:  encoding.EncodeToString(aead.Seal(nil, iv, plaintext, nil)),
	})
	if err != nil {
		return "", err
	}
	return encoding.EncodeToString(body), nil
}

func Open(key *ecdh.PrivateKey, sealed string) ([]byte, error) {
	invalid := errors.New("the sealed message is not valid")
	body, err := encoding.DecodeString(sealed)
	if err != nil {
		return nil, invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var message envelope
	if err := decoder.Decode(&message); err != nil || message.V != 1 {
		return nil, invalid
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, invalid
	}
	epk, err := encoding.DecodeString(message.EPK)
	if err != nil {
		return nil, invalid
	}
	ephemeral, err := ecdh.P256().NewPublicKey(epk)
	if err != nil {
		return nil, invalid
	}
	shared, err := key.ECDH(ephemeral)
	if err != nil {
		return nil, err
	}
	aead, err := derive(shared, slices.Concat(epk, key.PublicKey().Bytes()), info)
	if err != nil {
		return nil, err
	}
	iv, ivErr := encoding.DecodeString(message.IV)
	ct, ctErr := encoding.DecodeString(message.CT)
	if ivErr != nil || ctErr != nil || len(iv) != aead.NonceSize() {
		return nil, invalid
	}
	plaintext, err := aead.Open(nil, iv, ct, nil)
	if err != nil {
		return nil, errors.New("the sealed message is not for this server")
	}
	return plaintext, nil
}
