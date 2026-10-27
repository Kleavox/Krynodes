package network

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
)

const (
	Interface     = "kry0"
	FirstPort     = 51820
	LastPort      = 51919
	Keepalive     = 25
	AnswerSeconds = 180
	maxMembers    = 32
)

var (
	pool     = netip.MustParsePrefix("10.88.0.0/16")
	nodeID   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	blob     = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	ErrLeave = errors.New("this server is no longer in the private network")
)

type Member struct {
	Node     string            `json:"node"`
	Name     string            `json:"name"`
	Address  string            `json:"address"`
	Key      string            `json:"key"`
	Signer   string            `json:"signer"`
	Port     int               `json:"port"`
	MTU      *int              `json:"mtu"`
	Endpoint *string           `json:"endpoint"`
	NAT      bool              `json:"nat"`
	PSK      map[string]string `json:"psk"`
	Rekey    bool              `json:"rekey,omitempty"`
	Cut      bool              `json:"cut,omitempty"`
}

type Knocks struct {
	Scan int  `json:"scan"`
	Stop bool `json:"stop"`
}

type Document struct {
	V       int      `json:"v"`
	Version int      `json:"version"`
	Range   string   `json:"range"`
	Port    int      `json:"port"`
	MTU     int      `json:"mtu"`
	Deleted bool     `json:"deleted,omitempty"`
	Parent  string   `json:"parent,omitempty"`
	Knocks  *Knocks  `json:"knocks,omitempty"`
	Members []Member `json:"members"`
	Blocked []string `json:"blocked"`
}

type Applied struct {
	Version int      `json:"version"`
	Blocked []string `json:"blocked"`
	Hash    string   `json:"hash,omitempty"`
}

var (
	defaultKnocks = Knocks{Scan: 10, Stop: true}
	scans         = []int{5, 10, 20}
	hash          = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func Effective(document Document, tightened *Knocks) Knocks {
	knocks := defaultKnocks
	if document.Knocks != nil {
		knocks = *document.Knocks
	}
	if tightened != nil {
		knocks.Scan = min(knocks.Scan, tightened.Scan)
		knocks.Stop = knocks.Stop || tightened.Stop
	}
	return knocks
}

func validKey(value string) bool {
	raw, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(raw) == 32 && base64.StdEncoding.EncodeToString(raw) == value
}

func validPort(port int) bool {
	return port >= FirstPort && port <= LastPort
}

func validMTU(mtu int) bool {
	return mtu >= 1280 && mtu <= 1500
}

func Parse(raw []byte) (Document, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document Document
	if err := decoder.Decode(&document); err != nil || decoder.More() || document.V != 1 || document.Version < 1 {
		return Document{}, errors.New("the network document is malformed")
	}
	if !ValidRange(document.Range) {
		return Document{}, fmt.Errorf("the range %q is not a /24 of %s", document.Range, pool)
	}
	network := netip.MustParsePrefix(document.Range)
	if !validPort(document.Port) || !validMTU(document.MTU) || len(document.Members) > maxMembers || len(document.Blocked) > 1000 {
		return Document{}, errors.New("the network document is out of bounds")
	}
	if (document.Parent != "" && !hash.MatchString(document.Parent)) || (document.Knocks != nil && !slices.Contains(scans, document.Knocks.Scan)) {
		return Document{}, errors.New("the network document is malformed")
	}
	for _, key := range document.Blocked {
		if !validKey(key) {
			return Document{}, errors.New("a blocked key is not a WireGuard key")
		}
	}
	nodes := map[string]bool{}
	seen := map[string]bool{}
	for _, member := range document.Members {
		if !nodeID.MatchString(member.Node) || nodes[member.Node] || member.Name == "" || len(member.Name) > 100 {
			return Document{}, errors.New("a member is not named once")
		}
		nodes[member.Node] = true
		address, err := netip.ParseAddr(member.Address)
		if err != nil || !address.Is4() || address.String() != member.Address || !network.Contains(address) || address.As4()[3] == 0 || address.As4()[3] == 255 {
			return Document{}, fmt.Errorf("%s's address %q is not one address inside %s", member.Name, member.Address, document.Range)
		}
		if !validKey(member.Key) || !validKey(member.Signer) {
			return Document{}, fmt.Errorf("%s's keys are not 32 bytes", member.Name)
		}
		if !validPort(member.Port) || (member.MTU != nil && !validMTU(*member.MTU)) {
			return Document{}, fmt.Errorf("%s's port or MTU is out of bounds", member.Name)
		}
		if member.Endpoint != nil {
			if _, err := netip.ParseAddrPort(*member.Endpoint); err != nil {
				return Document{}, fmt.Errorf("%s's endpoint is not an address and port", member.Name)
			}
		}
		if seen[member.Address] || seen[member.Key] {
			return Document{}, fmt.Errorf("%s shares an address or key with another member", member.Name)
		}
		seen[member.Address], seen[member.Key] = true, true
		if slices.Contains(document.Blocked, member.Key) {
			return Document{}, fmt.Errorf("%s's key is blocked", member.Name)
		}
	}
	for _, member := range document.Members {
		if len(member.PSK) != len(document.Members)-1 {
			return Document{}, fmt.Errorf("%s needs one preshared key for each other member", member.Name)
		}
		for peer, sealed := range member.PSK {
			if peer == member.Node || !nodes[peer] || len(sealed) > 4096 || !blob.MatchString(sealed) {
				return Document{}, fmt.Errorf("%s has a preshared key for someone who is not a member", member.Name)
			}
		}
	}
	return document, nil
}

func Accept(document Document, applied Applied, self string, joined bool) (Member, error) {
	if document.Version <= applied.Version {
		return Member{}, fmt.Errorf("version %d is not newer than the applied %d", document.Version, applied.Version)
	}
	if joined && document.Version != applied.Version+1 {
		return Member{}, fmt.Errorf("version %d is not the next one after %d", document.Version, applied.Version)
	}
	if joined && document.Parent != applied.Hash {
		return Member{}, fmt.Errorf("version %d does not follow the version this server applied", document.Version)
	}
	for _, member := range document.Members {
		if !member.Cut && slices.Contains(applied.Blocked, member.Key) {
			return Member{}, fmt.Errorf("%s's key was taken out of the network and cannot come back", member.Name)
		}
	}
	if document.Deleted {
		return Member{}, ErrLeave
	}
	for _, member := range document.Members {
		if member.Node == self {
			return member, nil
		}
	}
	return Member{}, ErrLeave
}

func (a Applied) After(document Document, hash string) Applied {
	blocked := slices.Clone(a.Blocked)
	keys := slices.Clone(document.Blocked)
	for _, member := range document.Members {
		if member.Cut {
			keys = append(keys, member.Key)
		}
	}
	for _, key := range keys {
		if !slices.Contains(blocked, key) {
			blocked = append(blocked, key)
		}
	}
	slices.Sort(blocked)
	return Applied{Version: document.Version, Blocked: blocked, Hash: hash}
}
