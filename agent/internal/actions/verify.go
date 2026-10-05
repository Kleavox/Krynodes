package actions

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"
)

const (
	sessionLimit = 15 * time.Minute
	commandGrace = 60 * time.Minute
	clockSkew    = time.Minute
	flagPresent  = 0x01
	flagVerified = 0x04
	algES256     = -7
	algRS256     = -257
)

var b64 = base64.RawURLEncoding

type TrustKey struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Alg       int    `json:"alg"`
	PublicKey string `json:"publicKey"`
}

type PassphraseKey struct {
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
	PublicKey  string `json:"publicKey"`
}

type Trust struct {
	V          int            `json:"v"`
	NodeID     string         `json:"nodeId"`
	Origin     string         `json:"origin"`
	RPID       string         `json:"rpId"`
	Version    int            `json:"version"`
	Core       []TrustKey     `json:"core"`
	Access     []string       `json:"access"`
	Passphrase *PassphraseKey `json:"passphrase"`
	RequireUV  bool           `json:"requireUv,omitempty"`
}

func (t Trust) coreIDs() []string {
	ids := make([]string, 0, len(t.Core))
	for _, key := range t.Core {
		ids = append(ids, key.ID)
	}
	return ids
}

func verified(uv bool) error {
	if uv {
		return nil
	}
	return errors.New("the passkey did not verify a fingerprint; every server requires one")
}

func settled(t Trust) Trust {
	t.Passphrase = nil
	if len(t.Core) > 0 {
		t.RequireUV = true
	}
	return t
}

type Assertion struct {
	CredentialID      string `json:"credentialId"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
}

type SignedGrant struct {
	Grant string `json:"grant"`
	Assertion
	Proof string `json:"proof,omitempty"`
}

type SignedCommand struct {
	Grant     SignedGrant `json:"grant"`
	Command   string      `json:"command"`
	Signature string      `json:"signature"`
}

type grant struct {
	V          int    `json:"v"`
	RPID       string `json:"rpId"`
	SessionKey string `json:"sessionKey"`
	IssuedAt   string `json:"issuedAt"`
	ExpiresAt  string `json:"expiresAt"`
	Nonce      string `json:"nonce"`
}

type Command struct {
	V         int               `json:"v"`
	ID        string            `json:"id"`
	NodeID    string            `json:"nodeId"`
	Kind      string            `json:"kind"`
	Name      string            `json:"name"`
	Action    string            `json:"action"`
	IssuedAt  string            `json:"issuedAt"`
	ExpiresAt string            `json:"expiresAt"`
	Compose   string            `json:"compose,omitempty"`
	Access    string            `json:"access,omitempty"`
	Secrets   string            `json:"secrets,omitempty"`
	Piece     string            `json:"piece,omitempty"`
	Args      map[string]string `json:"args,omitempty"`
}

func strict(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing data")
	}
	return nil
}

func decode(name, value string) ([]byte, error) {
	raw, err := b64.DecodeString(value)
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("%s is not base64url", name)
	}
	return raw, nil
}

func stamp(name, value string) (time.Time, error) {
	at, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s is not a time", name)
	}
	return at, nil
}

func digest(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func parseKey(key TrustKey) (crypto.PublicKey, error) {
	der, err := decode("public key", key.PublicKey)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("public key is not SPKI")
	}
	switch key.Alg {
	case algES256:
		public, ok := parsed.(*ecdsa.PublicKey)
		if !ok || public.Curve != elliptic.P256() {
			return nil, errors.New("an ES256 key must be P-256")
		}
		return public, nil
	case algRS256:
		public, ok := parsed.(*rsa.PublicKey)
		if !ok || public.N.BitLen() < 2048 {
			return nil, errors.New("an RS256 key must be RSA of at least 2048 bits")
		}
		return public, nil
	}
	return nil, fmt.Errorf("algorithm %d is not allowed", key.Alg)
}

func Fingerprint(key TrustKey) string {
	der, err := b64.DecodeString(key.PublicKey)
	if err != nil {
		der = []byte(key.PublicKey)
	}
	return hex.EncodeToString(digest(der))[:16]
}

func verifyAssertion(trust Trust, allowed []string, assertion Assertion, challenge []byte) (bool, error) {
	index := slices.IndexFunc(trust.Core, func(key TrustKey) bool { return key.ID == assertion.CredentialID })
	if index < 0 {
		return false, errors.New("passkey is not trusted")
	}
	if !slices.Contains(allowed, assertion.CredentialID) {
		return false, errors.New("the passkey has no access to this server")
	}
	public, err := parseKey(trust.Core[index])
	if err != nil {
		return false, err
	}
	authData, err := decode("authenticator data", assertion.AuthenticatorData)
	if err != nil {
		return false, err
	}
	clientData, err := decode("client data", assertion.ClientDataJSON)
	if err != nil {
		return false, err
	}
	signature, err := decode("passkey signature", assertion.Signature)
	if err != nil {
		return false, err
	}
	var client struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	if err := json.Unmarshal(clientData, &client); err != nil {
		return false, errors.New("client data is not JSON")
	}
	if client.Type != "webauthn.get" {
		return false, errors.New("client data is not an assertion")
	}
	if client.Challenge != b64.EncodeToString(challenge) {
		return false, errors.New("challenge does not match")
	}
	if client.Origin != trust.Origin {
		return false, errors.New("origin does not match")
	}
	if client.CrossOrigin {
		return false, errors.New("cross-origin assertion")
	}
	if len(authData) < 37 {
		return false, errors.New("authenticator data is too short")
	}
	if !bytes.Equal(authData[:32], digest([]byte(trust.RPID))) {
		return false, errors.New("rp id does not match")
	}
	if authData[32]&flagPresent == 0 {
		return false, errors.New("the passkey was not touched")
	}
	signed := digest(append(append([]byte{}, authData...), digest(clientData)...))
	switch public := public.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(public, signed, signature) {
			return false, errors.New("passkey signature is invalid")
		}
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(public, crypto.SHA256, signed, signature) != nil {
			return false, errors.New("passkey signature is invalid")
		}
	}
	return authData[32]&flagVerified != 0, nil
}

func VerifyCommand(trust Trust, request Request, now time.Time) (Command, error) {
	if len(request.Signed) == 0 {
		return Command{}, errors.New("the request is not signed")
	}
	var signed SignedCommand
	if err := strict(request.Signed, &signed); err != nil {
		return Command{}, fmt.Errorf("the signature is malformed: %w", err)
	}
	grantBytes, err := decode("grant", signed.Grant.Grant)
	if err != nil {
		return Command{}, err
	}
	uv, err := verifyAssertion(trust, trust.Access, signed.Grant.Assertion, digest(grantBytes))
	if err != nil {
		return Command{}, err
	}
	if err := verified(uv); err != nil {
		return Command{}, err
	}
	var session grant
	if err := strict(grantBytes, &session); err != nil || session.V != 1 {
		return Command{}, errors.New("the grant is malformed")
	}
	if session.RPID != trust.RPID {
		return Command{}, errors.New("the grant is for another rp id")
	}
	issued, err := stamp("grant issuedAt", session.IssuedAt)
	if err != nil {
		return Command{}, err
	}
	expires, err := stamp("grant expiresAt", session.ExpiresAt)
	if err != nil {
		return Command{}, err
	}
	if !expires.After(issued) || expires.Sub(issued) > sessionLimit {
		return Command{}, errors.New("the session is longer than 15 minutes")
	}
	if issued.After(now.Add(clockSkew)) {
		return Command{}, errors.New("the grant is from the future")
	}
	keyBytes, err := decode("session key", session.SessionKey)
	if err != nil {
		return Command{}, err
	}
	parsed, err := x509.ParsePKIXPublicKey(keyBytes)
	sessionKey, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || sessionKey.Curve != elliptic.P256() {
		return Command{}, errors.New("the session key is not P-256")
	}
	commandBytes, err := decode("command", signed.Command)
	if err != nil {
		return Command{}, err
	}
	signature, err := decode("command signature", signed.Signature)
	if err != nil {
		return Command{}, err
	}
	if len(signature) != 64 {
		return Command{}, errors.New("the command signature is not P1363")
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(sessionKey, digest(commandBytes), r, s) {
		return Command{}, errors.New("the command signature is invalid")
	}
	var command Command
	if err := strict(commandBytes, &command); err != nil || command.V != 1 {
		return Command{}, errors.New("the command is malformed")
	}
	if command.ID != request.ID || command.Kind != request.Kind || command.Name != request.Name || command.Action != request.Action {
		return Command{}, errors.New("the command does not match the request")
	}
	if command.NodeID != trust.NodeID {
		return Command{}, errors.New("the command is for another server")
	}
	commandIssued, err := stamp("command issuedAt", command.IssuedAt)
	if err != nil {
		return Command{}, err
	}
	commandExpires, err := stamp("command expiresAt", command.ExpiresAt)
	if err != nil {
		return Command{}, err
	}
	if commandIssued.After(expires) {
		return Command{}, errors.New("the command was signed after the session ended")
	}
	if commandExpires.After(expires.Add(commandGrace)) {
		return Command{}, errors.New("the command outlives its session by more than an hour")
	}
	if now.After(commandExpires.Add(clockSkew)) {
		return Command{}, errors.New("the command expired")
	}
	return command, nil
}
