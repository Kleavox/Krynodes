package reporter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
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

func load(t *testing.T) fixture {
	t.Helper()
	raw, err := os.ReadFile("../../../packages/protocol/src/fixtures/wire.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestWireMatchesTheSharedFixture(t *testing.T) {
	f := load(t)
	if len(f.Agent.Valid) == 0 || len(f.Hub.Valid) == 0 {
		t.Fatal("the fixture holds no valid messages")
	}
	check(t, "agent", f.Agent, map[string]func() any{
		"hello":     func() any { return new(Hello) },
		"progress":  func() any { return new(Progress) },
		"result":    func() any { return new(Result) },
		"applied":   func() any { return new(Applied) },
		"links":     func() any { return new(Links) },
		"announce":  func() any { return new(Announce) },
		"meet":      func() any { return new(Meet) },
		"inventory": func() any { return new(Inventory) },
		"check":     func() any { return new(Check) },
	})
	check(t, "hub", f.Hub, map[string]func() any{
		"command":  func() any { return new(Command) },
		"ack":      func() any { return new(Ack) },
		"document": func() any { return new(Document) },
		"hints":    func() any { return new(Hints) },
		"refresh":  func() any { return new(Refresh) },
		"checks":   func() any { return new(Checks) },
	})
}

func TestTheFixtureHoldsEveryKindOfMessage(t *testing.T) {
	f := load(t)
	for name, want := range map[string]struct {
		side  side
		kinds []string
	}{
		"agent": {f.Agent, []string{"hello", "progress", "result", "applied", "links", "announce", "meet", "inventory", "check"}},
		"hub":   {f.Hub, []string{"command", "ack", "document", "hints", "refresh", "checks"}},
	} {
		seen := map[string]bool{}
		for _, raw := range want.side.Valid {
			var head struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(raw, &head); err != nil {
				t.Fatal(err)
			}
			seen[head.Type] = true
		}
		for _, kind := range want.kinds {
			if !seen[kind] {
				t.Fatalf("%s: the fixture has no valid %s", name, kind)
			}
		}
	}
}

func TestHelloSaysWhatKindOfMachineAndWhatItsNetworkIs(t *testing.T) {
	reason := "WireGuard is not available in this kernel"
	encoded, err := json.Marshal(Hello{Type: "hello", V: 1, Kind: "server", Network: &NetworkHello{Version: 2, Key: "k", Signer: "s", Reason: &reason}})
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{`"kind":"server"`, `"network":{"version":2,"key":"k","signer":"s","ready":false,"reason":"WireGuard is not available in this kernel"}`} {
		if !strings.Contains(string(encoded), part) {
			t.Fatalf("hello %s has no %s", encoded, part)
		}
	}
	encoded, _ = json.Marshal(Hello{Type: "hello", Kind: "laptop"})
	if !strings.Contains(string(encoded), `"network":null`) {
		t.Fatalf("hello %s", encoded)
	}
}

func TestDecodeHubTakesOnlyExactHubMessages(t *testing.T) {
	f := load(t)
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

func hintsWith(over map[string]string) string {
	parts := map[string]string{"endpoints": "[]", "announced": "[]", "meetings": "[]", "held": "[]", "connected": "[]"}
	maps.Copy(parts, over)
	return `{"type":"hints","endpoints":` + parts["endpoints"] + `,"announced":` + parts["announced"] + `,"meetings":` + parts["meetings"] + `,"held":` + parts["held"] + `,"connected":` + parts["connected"] + "}"
}

func repeated(entry string, count int) string {
	return "[" + strings.TrimSuffix(strings.Repeat(entry+",", count), ",") + "]"
}

func TestDecodeHubReadsTheNetworkMessages(t *testing.T) {
	value, err := DecodeHub([]byte(`{"type":"document","version":4,"signed":"eyJ2IjoxfQ"}`))
	if got, ok := value.(Document); err != nil || !ok || got.Type != "document" || got.Version != 4 || got.Signed != "eyJ2IjoxfQ" {
		t.Fatalf("document %#v %v", value, err)
	}
	value, err = DecodeHub([]byte(hintsWith(map[string]string{
		"endpoints": `[{"key":"k","endpoint":"203.0.113.1:51820"}]`,
		"announced": `[{"node":"n","key":"k","signature":"c2ln"}]`,
		"meetings":  `[{"laptop":"l","via":"v"}]`,
		"held":      `["l"]`,
		"connected": `["a","b"]`,
	})))
	want := Hints{
		Type:      "hints",
		Endpoints: []HintEndpoint{{Key: "k", Endpoint: "203.0.113.1:51820"}},
		Announced: []HintAnnounced{{Node: "n", Key: "k", Signature: "c2ln"}},
		Meetings:  []HintMeeting{{Laptop: "l", Via: "v"}},
		Held:      []string{"l"},
		Connected: []string{"a", "b"},
	}
	if got, ok := value.(Hints); err != nil || !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("hints %#v %v", value, err)
	}
	value, err = DecodeHub([]byte(hintsWith(nil)))
	if got, ok := value.(Hints); err != nil || !ok || got.Endpoints == nil || len(got.Connected) != 0 {
		t.Fatalf("empty hints %#v %v", value, err)
	}
	value, err = DecodeHub([]byte(`{"type":"refresh"}`))
	if got, ok := value.(Refresh); err != nil || !ok || got.Type != "refresh" {
		t.Fatalf("refresh %#v %v", value, err)
	}
	for _, edge := range []string{
		`{"type":"document","version":1,"signed":"a"}`,
		`{"type":"document","version":1,"signed":"` + strings.Repeat("a", 524288) + `"}`,
		hintsWith(map[string]string{
			"endpoints": repeated(`{"key":"k","endpoint":"e"}`, 32),
			"announced": repeated(`{"node":"n","key":"k","signature":"s"}`, 32),
			"meetings":  repeated(`{"laptop":"l","via":"v"}`, 32),
			"held":      repeated(`"h"`, 32),
			"connected": repeated(`"c"`, 32),
		}),
	} {
		if _, err := DecodeHub([]byte(edge)); err != nil {
			t.Fatalf("%.80s was refused: %v", edge, err)
		}
	}
}

func TestDecodeHubRefusesMalformedNetworkMessages(t *testing.T) {
	for _, message := range []string{
		`{"type":"document","version":0,"signed":"a"}`,
		`{"type":"document","version":-1,"signed":"a"}`,
		`{"type":"document","version":"4","signed":"a"}`,
		`{"type":"document","version":4.5,"signed":"a"}`,
		`{"type":"document","version":null,"signed":"a"}`,
		`{"type":"document","version":4,"signed":""}`,
		`{"type":"document","version":4,"signed":7}`,
		`{"type":"document","version":4,"signed":"` + strings.Repeat("a", 524289) + `"}`,
		`{"type":"document","version":4}`,
		`{"type":"document","version":4,"signed":"a","extra":1}`,
		`{"type":"document","Version":4,"signed":"a"}`,
		`{"type":"document","version":4,"signed":"a","id":"a"}`,
		`{"type":"refresh","extra":1}`,
		`{"type":"refresh","id":"a"}`,
		`{"type":"Refresh"}`,
		`{"type":"hints","endpoints":[],"announced":[],"meetings":[],"held":[]}`,
		`{"type":"hints","endpoints":[],"announced":[],"meetings":[],"held":[],"connected":[],"extra":1}`,
		hintsWith(map[string]string{"endpoints": "null"}),
		hintsWith(map[string]string{"held": "null"}),
		hintsWith(map[string]string{"connected": "{}"}),
		hintsWith(map[string]string{"endpoints": repeated(`{"key":"k","endpoint":"e"}`, 33)}),
		hintsWith(map[string]string{"announced": repeated(`{"node":"n","key":"k","signature":"s"}`, 33)}),
		hintsWith(map[string]string{"meetings": repeated(`{"laptop":"l","via":"v"}`, 33)}),
		hintsWith(map[string]string{"held": repeated(`"h"`, 33)}),
		hintsWith(map[string]string{"connected": repeated(`"c"`, 33)}),
		hintsWith(map[string]string{"endpoints": `[{"key":"k","endpoint":"e","rtt":3}]`}),
		hintsWith(map[string]string{"endpoints": `[{"key":"k"}]`}),
		hintsWith(map[string]string{"endpoints": `[{"Key":"k","endpoint":"e"}]`}),
		hintsWith(map[string]string{"endpoints": `[null]`}),
		hintsWith(map[string]string{"endpoints": `[{"key":"k","endpoint":7}]`}),
		hintsWith(map[string]string{"endpoints": `[{"key":null,"endpoint":"e"}]`}),
		hintsWith(map[string]string{"announced": `[{"node":"n","key":"k"}]`}),
		hintsWith(map[string]string{"meetings": `[{"laptop":"l","via":"v","extra":1}]`}),
		hintsWith(map[string]string{"meetings": `[{"laptop":"","via":"v"}]`}),
		hintsWith(map[string]string{"held": `[null]`}),
		hintsWith(map[string]string{"held": `[7]`}),
		hintsWith(map[string]string{"connected": `[""]`}),
		`{"type":"applied","version":4,"ok":true,"message":"x"}`,
		`{"type":"links","links":[]}`,
	} {
		value, err := DecodeHub([]byte(message))
		if err == nil {
			t.Fatalf("%.120s was accepted as %#v", message, value)
		}
		if value != nil {
			t.Fatalf("%.120s was refused with %#v in hand", message, value)
		}
	}
}

func TestDecodeHubReadsTheChecksTheOwnerChose(t *testing.T) {
	value, err := DecodeHub([]byte(`{"type":"checks","names":["web-app-1","db.1"]}`))
	want := Checks{Type: "checks", Names: []string{"web-app-1", "db.1"}}
	if got, ok := value.(Checks); err != nil || !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("checks %#v %v", value, err)
	}
	value, err = DecodeHub([]byte(`{"type":"checks","names":[]}`))
	if got, ok := value.(Checks); err != nil || !ok || got.Names == nil || len(got.Names) != 0 {
		t.Fatalf("empty checks %#v %v", value, err)
	}
	full := make([]string, 64)
	for i := range full {
		full[i] = fmt.Sprintf("web-%d", i)
	}
	encoded, _ := json.Marshal(Checks{Type: "checks", Names: full})
	if value, err = DecodeHub(encoded); err != nil || len(value.(Checks).Names) != 64 {
		t.Fatalf("64 checks %v", err)
	}
}

func TestDecodeHubRefusesMalformedChecks(t *testing.T) {
	over := make([]string, 65)
	for i := range over {
		over[i] = fmt.Sprintf("web-%d", i)
	}
	tooMany, _ := json.Marshal(Checks{Type: "checks", Names: over})
	for _, message := range []string{
		string(tooMany),
		`{"type":"checks"}`,
		`{"type":"checks","names":null}`,
		`{"type":"checks","names":{}}`,
		`{"type":"checks","names":"web-app-1"}`,
		`{"type":"checks","names":[7]}`,
		`{"type":"checks","names":[null]}`,
		`{"type":"checks","names":[""]}`,
		`{"type":"checks","names":["a"]}`,
		`{"type":"checks","names":["-web"]}`,
		`{"type":"checks","names":["web app"]}`,
		`{"type":"checks","names":["web/app"]}`,
		`{"type":"checks","names":["web-app
"]}`,
		`{"type":"checks","names":["` + strings.Repeat("a", 129) + `"]}`,
		`{"type":"checks","names":[],"extra":1}`,
		`{"type":"checks","Names":[]}`,
		`{"type":"Checks","names":[]}`,
		`{"type":"checks","id":"a","names":[]}`,
	} {
		value, err := DecodeHub([]byte(message))
		if err == nil {
			t.Fatalf("%.120s was accepted as %#v", message, value)
		}
		if value != nil {
			t.Fatalf("%.120s was refused with %#v in hand", message, value)
		}
	}
	if _, err := DecodeHub([]byte(`{"type":"checks","names":["` + strings.Repeat("a", 128) + `"]}`)); err != nil {
		t.Fatalf("a name of 128 characters was refused: %v", err)
	}
}

func TestTheStackArgumentsFixtureHasTheShapeTheNodeReads(t *testing.T) {
	raw, err := os.ReadFile("../../../packages/protocol/src/fixtures/stack-args.json")
	if err != nil {
		t.Fatal(err)
	}
	type entry struct {
		Kind   string          `json:"kind"`
		Action string          `json:"action"`
		Args   json.RawMessage `json:"args"`
		Why    string          `json:"why"`
	}
	var args struct {
		Valid   []entry `json:"valid"`
		Invalid []entry `json:"invalid"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&args); err != nil {
		t.Fatal(err)
	}
	if len(args.Valid) == 0 || len(args.Invalid) == 0 {
		t.Fatal("the fixture holds no arguments of one kind")
	}
	kinds := map[string]bool{}
	for _, one := range args.Valid {
		if one.Why != "" {
			t.Fatalf("a valid %s/%s carries a why", one.Kind, one.Action)
		}
		var values map[string]string
		if err := json.Unmarshal(one.Args, &values); err != nil || values == nil {
			t.Fatalf("the valid %s/%s has args that are not an object of strings: %s", one.Kind, one.Action, one.Args)
		}
		kinds[one.Kind] = true
	}
	for _, kind := range []string{"stack", "container", "unit", "docker"} {
		if !kinds[kind] {
			t.Fatalf("the fixture has no valid %s entry", kind)
		}
	}
	for _, one := range args.Invalid {
		if one.Why == "" {
			t.Fatalf("an invalid %s/%s says no why", one.Kind, one.Action)
		}
		if len(one.Args) == 0 {
			t.Fatalf("an invalid %s/%s has no args member", one.Kind, one.Action)
		}
	}
}
