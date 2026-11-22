package reporter

import (
	"encoding/json"
	"errors"
	"fmt"
)

type TrustReport struct {
	Version int      `json:"version"`
	Core    []string `json:"core"`
	Access  []string `json:"access"`
}

type Hello struct {
	Type     string       `json:"type"`
	V        int          `json:"v"`
	Version  string       `json:"version"`
	Hostname string       `json:"hostname"`
	OS       string       `json:"os"`
	Arch     string       `json:"arch"`
	Kernel   string       `json:"kernel"`
	SealKey  string       `json:"sealKey"`
	Trust    *TrustReport `json:"trust"`
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
	Trust   *TrustReport `json:"trust,omitempty"`
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

var hubFields = map[string][]string{
	"command": {"type", "id", "kind", "name", "action", "signed"},
	"ack":     {"type", "id"},
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
	if len(fields) != len(names) {
		return nil, fmt.Errorf("a %s carries other fields", kind)
	}
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			return nil, fmt.Errorf("a %s needs %s", kind, name)
		}
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
