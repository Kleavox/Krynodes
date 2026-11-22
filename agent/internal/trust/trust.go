package trust

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const (
	trustChangeLimit = 24 * time.Hour
	maxTrustedKeys   = 20
	trustVersionStep = 1000
)

var credentialID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type trustChange struct {
	V         int                 `json:"v"`
	Origin    string              `json:"origin"`
	RPID      string              `json:"rpId"`
	Version   int                 `json:"version"`
	IssuedAt  string              `json:"issuedAt"`
	ExpiresAt string              `json:"expiresAt"`
	Core      []TrustKey          `json:"core"`
	RequireUV *bool               `json:"requireUv,omitempty"`
	Access    map[string][]string `json:"access"`
}

type signedTrust struct {
	Change    string      `json:"change"`
	Approvals []Assertion `json:"approvals"`
}

func Load(stateDir string) (Trust, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, "trust.json"))
	if errors.Is(err, os.ErrNotExist) {
		return Trust{}, nil
	}
	if err != nil {
		return Trust{}, err
	}
	var trust Trust
	if err := strict(raw, &trust); err != nil || trust.V != 1 {
		return Trust{}, errors.New("the trust store is unreadable; reset it with kry trust --reset")
	}
	return trust, nil
}

func Save(stateDir string, trust Trust) error {
	encoded, err := json.Marshal(trust)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return err
	}
	temporary := filepath.Join(stateDir, ".trust.json.tmp")
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(encoded); err != nil {
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
	if err := os.Rename(temporary, filepath.Join(stateDir, "trust.json")); err != nil {
		return err
	}
	return syncDirectory(stateDir)
}

func syncDirectory(path string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (t Trust) Report() reporter.TrustReport {
	return reporter.TrustReport{Version: t.Version, Core: append([]string{}, t.Core...), Access: append([]string{}, t.Access...)}
}

func idsOf(keys []TrustKey) []string {
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		ids = append(ids, key.ID)
	}
	return ids
}

func originHost(origin string) (string, error) {
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.User != nil {
		return "", fmt.Errorf("%q is not an origin", origin)
	}
	return parsed.Hostname(), nil
}

func checkKeys(keys []TrustKey) error {
	if len(keys) == 0 {
		return errors.New("at least one passkey must stay trusted")
	}
	if len(keys) > maxTrustedKeys {
		return errors.New("too many passkeys")
	}
	var seen, held []string
	for _, key := range keys {
		if len(key.ID) > 1400 || !credentialID.MatchString(key.ID) {
			return errors.New("a passkey id is not base64url")
		}
		if slices.Contains(seen, key.ID) {
			return errors.New("a passkey is listed twice")
		}
		if slices.Contains(held, key.PublicKey) {
			return errors.New("two passkeys carry the same key")
		}
		seen, held = append(seen, key.ID), append(held, key.PublicKey)
		if _, err := parseKey(key); err != nil {
			return err
		}
	}
	return nil
}

func checkAccess(access, core []string) error {
	var seen []string
	for _, id := range access {
		if !slices.Contains(core, id) {
			return errors.New("access names a passkey the servers do not trust")
		}
		if slices.Contains(seen, id) {
			return errors.New("access lists a passkey twice")
		}
		seen = append(seen, id)
	}
	if len(seen) == 0 {
		return errors.New("this server needs at least one passkey with access")
	}
	return nil
}

func ApplyTrustChange(current Trust, signed []byte, now time.Time) (Trust, error) {
	var envelope signedTrust
	if err := strict(signed, &envelope); err != nil {
		return Trust{}, fmt.Errorf("the change is malformed: %w", err)
	}
	changeBytes, err := decode("change", envelope.Change)
	if err != nil {
		return Trust{}, err
	}
	var change trustChange
	if err := strict(changeBytes, &change); err != nil || change.V != 1 || change.Version < 1 || (change.RequireUV != nil && !*change.RequireUV) {
		return Trust{}, errors.New("the change is malformed")
	}
	issued, err := stamp("change issuedAt", change.IssuedAt)
	if err != nil {
		return Trust{}, err
	}
	expires, err := stamp("change expiresAt", change.ExpiresAt)
	if err != nil {
		return Trust{}, err
	}
	if !expires.After(issued) {
		return Trust{}, errors.New("the change ends before it begins")
	}
	if expires.Sub(issued) > trustChangeLimit {
		return Trust{}, errors.New("the change lasts longer than 24 hours")
	}
	if now.After(expires.Add(clockSkew)) {
		return Trust{}, fmt.Errorf("the change expired at %s", ClockSays(expires, now))
	}
	host, err := originHost(change.Origin)
	if err != nil {
		return Trust{}, err
	}
	if change.RPID != host {
		return Trust{}, errors.New("the rp id is not the host of the origin")
	}
	if len(current.Core) == 0 {
		return Trust{}, errors.New("no passkey is trusted yet; install the server with its passkeys first")
	}
	if len(envelope.Approvals) == 0 {
		return Trust{}, errors.New("the change must be approved by a trusted passkey")
	}
	if change.Version <= current.Version {
		return Trust{}, errors.New("the version is not newer than the stored one")
	}
	if change.Version-current.Version > trustVersionStep {
		return Trust{}, errors.New("the version is too far ahead of the stored one")
	}
	if change.Origin != current.Origin || change.RPID != current.RPID {
		return Trust{}, errors.New("the change is for another origin")
	}
	access, ok := change.Access[current.NodeID]
	if !ok {
		return Trust{}, errors.New("the change is not for this server")
	}
	next := Trust{V: 1, NodeID: current.NodeID, Origin: current.Origin, RPID: current.RPID, Version: change.Version, Keys: current.Keys, Core: current.Core, Access: access, RequireUV: true}
	if change.Core != nil {
		if err := checkKeys(change.Core); err != nil {
			return Trust{}, err
		}
		for _, key := range change.Core {
			if at := slices.IndexFunc(current.Keys, func(known TrustKey) bool { return known.ID == key.ID }); at >= 0 && (current.Keys[at].Alg != key.Alg || current.Keys[at].PublicKey != key.PublicKey) {
				return Trust{}, errors.New("a change cannot give a trusted passkey another key; remove it and add it again")
			}
		}
		next.Keys, next.Core = change.Core, idsOf(change.Core)
	}
	if err := checkAccess(access, next.Core); err != nil {
		return Trust{}, err
	}
	challenge := digest(changeBytes)
	for _, approval := range envelope.Approvals {
		uv, err := verifyAssertion(current, current.Core, "the passkey cannot approve a change", approval, challenge)
		if err != nil {
			return Trust{}, err
		}
		if err := verified(uv); err != nil {
			return Trust{}, err
		}
	}
	return next, nil
}

func FirstTrust(nodeID, origin string, tokens []string) (Trust, error) {
	host, err := originHost(origin)
	if err != nil {
		return Trust{}, err
	}
	if nodeID == "" {
		return Trust{}, errors.New("a server id is needed")
	}
	keys := make([]TrustKey, 0, len(tokens))
	for _, token := range tokens {
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			return Trust{}, fmt.Errorf("%q is not <id>.<alg>.<key>", token)
		}
		alg, err := strconv.Atoi(parts[1])
		if err != nil {
			return Trust{}, fmt.Errorf("%q has no algorithm number", token)
		}
		keys = append(keys, TrustKey{ID: parts[0], Alg: alg, PublicKey: parts[2]})
	}
	if err := checkKeys(keys); err != nil {
		return Trust{}, err
	}
	return Trust{V: 1, NodeID: nodeID, Origin: origin, RPID: host, Version: 1, Keys: keys, Core: idsOf(keys), Access: idsOf(keys), RequireUV: true}, nil
}
