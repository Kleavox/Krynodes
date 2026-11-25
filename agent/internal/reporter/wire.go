package reporter

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

type TrustReport struct {
	Version int      `json:"version"`
	Core    []string `json:"core"`
	Access  []string `json:"access"`
}

type NetworkHello struct {
	Version int     `json:"version"`
	Key     string  `json:"key"`
	Signer  string  `json:"signer"`
	Ready   bool    `json:"ready"`
	Reason  *string `json:"reason"`
}

type Hello struct {
	Type     string        `json:"type"`
	V        int           `json:"v"`
	Version  string        `json:"version"`
	Hostname string        `json:"hostname"`
	OS       string        `json:"os"`
	Arch     string        `json:"arch"`
	Kernel   string        `json:"kernel"`
	Kind     string        `json:"kind"`
	SealKey  string        `json:"sealKey"`
	Trust    *TrustReport  `json:"trust"`
	Network  *NetworkHello `json:"network"`
}

type Progress struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Line string `json:"line"`
}

type Result struct {
	Type    string       `json:"type"`
	ID      string       `json:"id"`
	OK      bool         `json:"ok"`
	Message string       `json:"message"`
	Output  string       `json:"output,omitempty"`
	Trust   *TrustReport `json:"trust,omitempty"`
}

type Applied struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type NetworkLink struct {
	Key       string   `json:"key"`
	Handshake *int64   `json:"handshake"`
	RX        int64    `json:"rx"`
	TX        int64    `json:"tx"`
	Endpoint  *string  `json:"endpoint"`
	MS        *float64 `json:"ms"`
}

type Links struct {
	Type  string        `json:"type"`
	Links []NetworkLink `json:"links"`
}

type Announce struct {
	Type      string `json:"type"`
	Key       string `json:"key"`
	Signature string `json:"signature"`
}

type Meet struct {
	Type string `json:"type"`
	Via  string `json:"via"`
}

type StackService struct {
	Service   string `json:"service"`
	Container string `json:"container"`
}

type StackEntry struct {
	Project   string         `json:"project"`
	Title     *string        `json:"title"`
	Directory string         `json:"directory"`
	Own       bool           `json:"own"`
	Access    *string        `json:"access"`
	Running   int            `json:"running"`
	Total     int            `json:"total"`
	Rollback  bool           `json:"rollback"`
	Network   []int          `json:"network"`
	Services  []StackService `json:"services"`
}

type ContainerEntry struct {
	Name    string   `json:"name"`
	Project *string  `json:"project"`
	Service *string  `json:"service"`
	Image   string   `json:"image"`
	State   string   `json:"state"`
	Health  *string  `json:"health"`
	Ports   []string `json:"ports"`
}

type UnitEntry struct {
	Name      string `json:"name"`
	State     string `json:"state"`
	Protected bool   `json:"protected"`
}

type RemovedEntry struct {
	Project   string `json:"project"`
	RemovedAt string `json:"removedAt"`
}

type Inventory struct {
	Type       string           `json:"type"`
	Hash       string           `json:"hash"`
	Docker     string           `json:"docker"`
	Compose    *string          `json:"compose"`
	Stacks     []StackEntry     `json:"stacks"`
	Containers []ContainerEntry `json:"containers"`
	Units      []UnitEntry      `json:"units"`
	Removed    []RemovedEntry   `json:"removed"`
}

type Check struct {
	Type   string  `json:"type"`
	Name   string  `json:"name"`
	State  string  `json:"state"`
	Cause  *string `json:"cause"`
	At     string  `json:"at"`
	Detail string  `json:"detail"`
}

type Checks struct {
	Type  string   `json:"type"`
	Names []string `json:"names"`
}

type Command struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Action string `json:"action"`
	Signed string `json:"signed"`
}

type Ack struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type Document struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
	Signed  string `json:"signed"`
}

type HintEndpoint struct {
	Key      string `json:"key"`
	Endpoint string `json:"endpoint"`
}

type HintAnnounced struct {
	Node      string `json:"node"`
	Key       string `json:"key"`
	Signature string `json:"signature"`
}

type HintMeeting struct {
	Laptop string `json:"laptop"`
	Via    string `json:"via"`
}

type Hints struct {
	Type      string          `json:"type"`
	Endpoints []HintEndpoint  `json:"endpoints"`
	Announced []HintAnnounced `json:"announced"`
	Meetings  []HintMeeting   `json:"meetings"`
	Held      []string        `json:"held"`
	Connected []string        `json:"connected"`
}

type Refresh struct {
	Type string `json:"type"`
}

const (
	maxHints  = 32
	maxSigned = 524288
	maxChecks = 64
)

var containerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{1,127}$`)

var hubFields = map[string][]string{
	"command":  {"type", "id", "kind", "name", "action", "signed"},
	"ack":      {"type", "id"},
	"document": {"type", "version", "signed"},
	"hints":    {"type", "endpoints", "announced", "meetings", "held", "connected"},
	"refresh":  {"type"},
	"checks":   {"type", "names"},
}

func exact(fields map[string]json.RawMessage, names []string) error {
	if len(fields) != len(names) {
		return errors.New("it carries other fields")
	}
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("it needs %s", name)
		}
	}
	return nil
}

func named(values ...string) bool {
	for _, value := range values {
		if value == "" {
			return false
		}
	}
	return true
}

func entries[T any](raw json.RawMessage, valid func(T) bool, names ...string) ([]T, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil || items == nil || len(items) > maxHints {
		return nil, errors.New("a list of 0 to 32 entries")
	}
	decoded := make([]T, len(items))
	for i, item := range items {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(item, &fields); err != nil {
			return nil, err
		}
		if err := exact(fields, names); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(item, &decoded[i]); err != nil {
			return nil, err
		}
		if !valid(decoded[i]) {
			return nil, errors.New("an entry has an empty value")
		}
	}
	return decoded, nil
}

func ids(raw json.RawMessage) ([]string, error) {
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil || list == nil || len(list) > maxHints || !named(list...) {
		return nil, errors.New("a list of 0 to 32 ids")
	}
	return list, nil
}

func decodeChecks(raw json.RawMessage) (Checks, error) {
	var names []string
	if err := json.Unmarshal(raw, &names); err != nil || names == nil || len(names) > maxChecks {
		return Checks{}, errors.New("a list of 0 to 64 container names")
	}
	for _, name := range names {
		if !containerName.MatchString(name) {
			return Checks{}, fmt.Errorf("%q is not a container name", name)
		}
	}
	return Checks{Type: "checks", Names: names}, nil
}

func decodeHints(fields map[string]json.RawMessage) (Hints, error) {
	hints := Hints{Type: "hints"}
	var err error
	if hints.Endpoints, err = entries(fields["endpoints"], func(one HintEndpoint) bool { return named(one.Key, one.Endpoint) }, "key", "endpoint"); err != nil {
		return hints, fmt.Errorf("endpoints: %w", err)
	}
	if hints.Announced, err = entries(fields["announced"], func(one HintAnnounced) bool { return named(one.Node, one.Key, one.Signature) }, "node", "key", "signature"); err != nil {
		return hints, fmt.Errorf("announced: %w", err)
	}
	if hints.Meetings, err = entries(fields["meetings"], func(one HintMeeting) bool { return named(one.Laptop, one.Via) }, "laptop", "via"); err != nil {
		return hints, fmt.Errorf("meetings: %w", err)
	}
	if hints.Held, err = ids(fields["held"]); err != nil {
		return hints, fmt.Errorf("held: %w", err)
	}
	if hints.Connected, err = ids(fields["connected"]); err != nil {
		return hints, fmt.Errorf("connected: %w", err)
	}
	return hints, nil
}

func DecodeHub(raw []byte) (any, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	var kind string
	if err := json.Unmarshal(fields["type"], &kind); err != nil {
		return nil, errors.New("a hub message needs a type")
	}
	names, known := hubFields[kind]
	if !known {
		return nil, fmt.Errorf("unknown hub message %q", kind)
	}
	if err := exact(fields, names); err != nil {
		return nil, fmt.Errorf("a %s: %w", kind, err)
	}
	switch kind {
	case "refresh":
		return Refresh{Type: kind}, nil
	case "checks":
		checks, err := decodeChecks(fields["names"])
		if err != nil {
			return nil, err
		}
		return checks, nil
	case "hints":
		hints, err := decodeHints(fields)
		if err != nil {
			return nil, err
		}
		return hints, nil
	case "document":
		var document Document
		if err := json.Unmarshal(raw, &document); err != nil {
			return nil, err
		}
		if document.Version < 1 || document.Signed == "" || len(document.Signed) > maxSigned {
			return nil, errors.New("a document needs a version from 1 and signed text of up to 524288 characters")
		}
		return document, nil
	}
	var id string
	if err := json.Unmarshal(fields["id"], &id); err != nil || id == "" || len(id) > 64 {
		return nil, fmt.Errorf("a %s needs an id of 1 to 64 characters", kind)
	}
	if kind == "ack" {
		return Ack{Type: kind, ID: id}, nil
	}
	var command Command
	if err := json.Unmarshal(raw, &command); err != nil {
		return nil, err
	}
	return command, nil
}
