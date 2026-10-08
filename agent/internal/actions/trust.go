package actions

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const (
	trustChangeLimit = 24 * time.Hour
	maxTrustedKeys   = 20
)

var credentialID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type trustChange struct {
	V          int                 `json:"v"`
	Origin     string              `json:"origin"`
	RPID       string              `json:"rpId"`
	Version    int                 `json:"version"`
	IssuedAt   string              `json:"issuedAt"`
	ExpiresAt  string              `json:"expiresAt"`
	Core       []TrustKey          `json:"core"`
	Passphrase *PassphraseKey      `json:"passphrase"`
	RequireUV  *bool               `json:"requireUv,omitempty"`
	Access     map[string][]string `json:"access"`
}

type approval struct {
	Assertion
	Proof string `json:"proof,omitempty"`
}

type signedTrust struct {
	Change    string     `json:"change"`
	Approvals []approval `json:"approvals"`
}

type trustV1 struct {
	NodeID  string     `json:"nodeId"`
	Origin  string     `json:"origin"`
	RPID    string     `json:"rpId"`
	Version int        `json:"version"`
	Keys    []TrustKey `json:"keys"`
}

func LoadTrust(stateDir string) (Trust, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, "trust.json"))
	if errors.Is(err, os.ErrNotExist) {
		return Trust{}, nil
	}
	if err != nil {
		return Trust{}, err
	}
	var trust Trust
	if err := strict(raw, &trust); err == nil && (trust.V == 2 || len(trust.Core) == 0) {
		return settled(trust), nil
	}
	var old trustV1
	if err := strict(raw, &old); err != nil {
		return Trust{}, errors.New("the trust store is unreadable; reset it with kry trust --reset")
	}
	if len(old.Keys) == 0 {
		return Trust{}, nil
	}
	upgraded := Trust{V: 2, NodeID: old.NodeID, Origin: old.Origin, RPID: old.RPID, Version: old.Version, Core: old.Keys}
	upgraded.Access = upgraded.coreIDs()
	return settled(upgraded), nil
}

func SaveTrust(stateDir string, trust Trust) error {
	return writeJSON(stateDir, "trust.json", trust, 0o600)
}

func (t Trust) Report() reporter.TrustReport {
	core := make([]string, 0, len(t.Core))
	access := make([]string, 0, len(t.Access))
	for _, key := range t.Core {
		core = append(core, Fingerprint(key))
		if slices.Contains(t.Access, key.ID) {
			access = append(access, Fingerprint(key))
		}
	}
	return reporter.TrustReport{Version: t.Version, Core: core, Access: access, Passphrase: t.Passphrase != nil, RequireUV: t.RequireUV}
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
		return errors.New("a change needs at least one device")
	}
	if len(keys) > maxTrustedKeys {
		return errors.New("too many devices")
	}
	var seen []string
	for _, key := range keys {
		if len(key.ID) > 1400 || !credentialID.MatchString(key.ID) {
			return errors.New("a device id is not base64url")
		}
		if slices.Contains(seen, key.ID) {
			return errors.New("a device is listed twice")
		}
		seen = append(seen, key.ID)
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
			return errors.New("access names a device the servers do not trust")
		}
		if slices.Contains(seen, id) {
			return errors.New("access lists a device twice")
		}
		seen = append(seen, id)
	}
	return nil
}

func ApplyTrustChange(current Trust, request Request, now time.Time) (Trust, error) {
	var signed signedTrust
	if err := strict(request.Signed, &signed); err != nil {
		return Trust{}, fmt.Errorf("the change is malformed: %w", err)
	}
	changeBytes, err := decode("change", signed.Change)
	if err != nil {
		return Trust{}, err
	}
	var change trustChange
	if err := strict(changeBytes, &change); err != nil || change.V != 2 || change.Version < 1 || (change.RequireUV != nil && !*change.RequireUV) {
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
	if !expires.After(issued) || expires.Sub(issued) > trustChangeLimit {
		return Trust{}, errors.New("the change lasts longer than 24 hours")
	}
	if now.After(expires.Add(clockSkew)) {
		return Trust{}, fmt.Errorf("the change expired at %s", clockSays(expires, now))
	}
	host, err := originHost(change.Origin)
	if err != nil {
		return Trust{}, err
	}
	if change.RPID != host {
		return Trust{}, errors.New("the rp id is not the host of the origin")
	}
	if change.Passphrase != nil {
		return Trust{}, errors.New("servers no longer use a passphrase")
	}
	current = settled(current)
	if len(current.Core) == 0 {
		return firstTrust(change, signed)
	}
	if len(signed.Approvals) == 0 {
		return Trust{}, errors.New("the change must be approved by trusted devices")
	}
	if change.Version <= current.Version {
		return Trust{}, errors.New("the version is not newer than the stored one")
	}
	if change.Origin != current.Origin || change.RPID != current.RPID {
		return Trust{}, errors.New("the change is for another origin")
	}
	access, ok := change.Access[current.NodeID]
	if !ok {
		return Trust{}, errors.New("the change is not for this server")
	}
	core := change.Core
	if core == nil {
		core = current.Core
	}
	if err := checkKeys(core); err != nil {
		return Trust{}, err
	}
	next := Trust{V: 2, NodeID: current.NodeID, Origin: current.Origin, RPID: current.RPID, Version: change.Version, Core: core, Access: access, Passphrase: current.Passphrase, RequireUV: current.RequireUV || change.RequireUV != nil}
	if err := checkAccess(access, next.coreIDs()); err != nil {
		return Trust{}, err
	}
	input := quorumInput{}
	input.Current.Core = current.coreIDs()
	input.Current.Access = current.Access
	if change.Core != nil {
		input.Change.Core = next.coreIDs()
	}
	input.Change.Access = access
	challenge := digest(changeBytes)
	for _, item := range signed.Approvals {
		uv, err := verifyAssertion(current, input.Current.Core, item.Assertion, challenge)
		if err != nil {
			return Trust{}, err
		}
		if err := verified(uv); err != nil {
			return Trust{}, err
		}
		input.Approvals = append(input.Approvals, item.CredentialID)
	}
	if err := evaluateQuorum(input); err != nil {
		return Trust{}, err
	}
	return next, nil
}

func firstTrust(change trustChange, signed signedTrust) (Trust, error) {
	if len(signed.Approvals) != 0 {
		return Trust{}, errors.New("no device is trusted yet")
	}
	if len(change.Access) != 1 {
		return Trust{}, errors.New("a first trust must name exactly one server")
	}
	if err := checkKeys(change.Core); err != nil {
		return Trust{}, err
	}
	var nodeID string
	var access []string
	for id, list := range change.Access {
		nodeID, access = id, list
	}
	next := Trust{V: 2, NodeID: nodeID, Origin: change.Origin, RPID: change.RPID, Version: change.Version, Core: change.Core, Access: access, RequireUV: true}
	if err := checkAccess(access, next.coreIDs()); err != nil {
		return Trust{}, err
	}
	return next, nil
}

func ParseTrustArgs(origin string, tokens []string, grant bool) (Trust, error) {
	host, err := originHost(origin)
	if err != nil {
		return Trust{}, err
	}
	keys := make([]TrustKey, 0, len(tokens))
	for _, token := range tokens {
		parts := strings.SplitN(token, ".", 3)
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
	trust := Trust{V: 2, Origin: origin, RPID: host, Version: 1, Core: keys, Access: []string{}, RequireUV: true}
	if grant {
		trust.Access = trust.coreIDs()
	}
	return trust, nil
}
