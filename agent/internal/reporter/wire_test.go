package reporter

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

type entry struct {
	Why        string          `json:"why"`
	Structural bool            `json:"structural"`
	Message    json.RawMessage `json:"message"`
}

type side struct {
	Valid   []json.RawMessage `json:"valid"`
	Invalid []entry           `json:"invalid"`
}

type fixture struct {
	Agent side `json:"agent"`
	Hub   side `json:"hub"`
}

var errUnknownType = errors.New("unknown type")

func decode(raw json.RawMessage, types map[string]func() any) (any, error) {
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, err
	}
	build, ok := types[head.Type]
	if !ok {
		return nil, errUnknownType
	}
	value := build()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return nil, err
	}
	return value, nil
}

func generic(t *testing.T, raw []byte) any {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func check(t *testing.T, name string, s side, types map[string]func() any) {
	t.Helper()
	for i, raw := range s.Valid {
		value, err := decode(raw, types)
		if err != nil {
			t.Fatalf("%s valid %d: %v", name, i, err)
		}
		again, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(generic(t, raw), generic(t, again)) {
			t.Fatalf("%s valid %d re-encodes to %s, want %s", name, i, again, raw)
		}
	}
	for _, e := range s.Invalid {
		if !e.Structural {
			continue
		}
		if _, err := decode(e.Message, types); err == nil {
			t.Fatalf("%s: %s was accepted", name, e.Why)
		}
	}
}

func TestWireMatchesTheSharedFixture(t *testing.T) {
	raw, err := os.ReadFile("../../../packages/protocol/src/fixtures/wire.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Agent.Valid) == 0 || len(f.Hub.Valid) == 0 {
		t.Fatal("the fixture holds no valid messages")
	}
	check(t, "agent", f.Agent, map[string]func() any{
		"hello":    func() any { return new(Hello) },
		"progress": func() any { return new(Progress) },
		"result":   func() any { return new(Result) },
	})
	check(t, "hub", f.Hub, map[string]func() any{
		"command": func() any { return new(Command) },
		"ack":     func() any { return new(Ack) },
	})
}

func TestDecodeHubTakesOnlyExactHubMessages(t *testing.T) {
	raw, err := os.ReadFile("../../../packages/protocol/src/fixtures/wire.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	for i, message := range f.Hub.Valid {
		value, err := DecodeHub(message)
		if err != nil {
			t.Fatalf("valid %d: %v", i, err)
		}
		again, _ := json.Marshal(value)
		if !reflect.DeepEqual(generic(t, message), generic(t, again)) {
			t.Fatalf("valid %d decodes to %s", i, again)
		}
	}
	for _, e := range f.Hub.Invalid {
		if _, err := DecodeHub(e.Message); e.Structural && err == nil {
			t.Fatalf("%s was accepted", e.Why)
		}
	}
	for _, message := range []string{
		`{"TYPE":"ack","id":"a"}`,
		`{"type":"Ack","id":"a"}`,
		`{"type":"ack","ID":"a"}`,
		`{"type":"ack","id":"a","Id":"b"}`,
		`{"type":"ack","id":""}`,
		`{"type":"ack","id":"` + strings.Repeat("a", 65) + `"}`,
		`{"type":"ack","id":7}`,
		`{"type":"command","id":"a","kind":"host","name":"server-1","action":"restart"}`,
		`{"type":"ack","id":"a"} {"type":"ack","id":"b"}`,
		`[]`,
		`null`,
	} {
		if value, err := DecodeHub([]byte(message)); err == nil {
			t.Fatalf("%s was accepted as %#v", message, value)
		}
	}
	value, err := DecodeHub([]byte(`{"type":"ack","id":"a"}`))
	if ack, ok := value.(Ack); err != nil || !ok || ack.ID != "a" {
		t.Fatalf("ack %#v %v", value, err)
	}
}
