package address

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
)

type call struct {
	method string
	path   string
	header http.Header
	body   struct {
		Interfaces []Interface `json:"interfaces"`
	}
}

func recorder(answer func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, func() []call) {
	var mu sync.Mutex
	var seen []call
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := call{method: r.Method, path: r.URL.Path, header: r.Header}
		if r.Body != nil {
			json.NewDecoder(r.Body).Decode(&got.body)
		}
		mu.Lock()
		seen = append(seen, got)
		mu.Unlock()
		answer(w, r)
	}))
	return server, func() []call {
		mu.Lock()
		defer mu.Unlock()
		return append([]call(nil), seen...)
	}
}

var oneLink = func() []link {
	return []link{{name: "eth0", up: true, addrs: []netip.Addr{netip.MustParseAddr("51.79.0.10")}}}
}

func answerFour(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"address":"103.28.54.214","family":4}`))
}

func TestTheProbeAsksOverEachFamilyAndKeepsWhatAnswered(t *testing.T) {
	server, seen := recorder(answerFour)
	defer server.Close()
	prober := Prober{Endpoint: server.URL + "/", Token: "agent-token", Version: "0.6.13", links: oneLink}
	found := prober.Probe(context.Background())
	if len(found) != 1 || found["tcp4"] != "103.28.54.214" {
		t.Fatalf("found %v", found)
	}
	calls := seen()
	if len(calls) != 1 {
		t.Fatalf("requests %d", len(calls))
	}
	request := calls[0]
	if request.path != "/api/agent/address" || request.header.Get("Authorization") != "Bearer agent-token" || request.header.Get("User-Agent") != "kry-agent/0.6.13" {
		t.Fatalf("request %s %v", request.path, request.header)
	}
}

func TestTheProbeSendsTheInterfacesWithEachCall(t *testing.T) {
	server, seen := recorder(answerFour)
	defer server.Close()
	(Prober{Endpoint: server.URL, Token: "x", Version: "dev", links: oneLink}).Probe(context.Background())
	calls := seen()
	if len(calls) == 0 {
		t.Fatal("no request")
	}
	for _, got := range calls {
		if got.method != http.MethodPost || len(got.body.Interfaces) != 1 || got.body.Interfaces[0] != (Interface{Name: "eth0", Address: "51.79.0.10"}) {
			t.Fatalf("call %s %v", got.method, got.body.Interfaces)
		}
	}
}

func TestTheProbeAsksWithGETWhenKrynodesDoesNotKnowPOST(t *testing.T) {
	server, seen := recorder(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			http.Error(w, "", http.StatusMethodNotAllowed)
			return
		}
		answerFour(w, r)
	})
	defer server.Close()
	found := (Prober{Endpoint: server.URL, Token: "x", Version: "dev", links: oneLink}).Probe(context.Background())
	if found["tcp4"] != "103.28.54.214" {
		t.Fatalf("found %v", found)
	}
	calls := seen()
	if len(calls) != 2 || calls[0].method != http.MethodPost || calls[1].method != http.MethodGet {
		t.Fatalf("calls %v", calls)
	}
}

func TestTheProbeGoesOnWhenKrynodesRefuses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
	}))
	defer server.Close()
	if found := (Prober{Endpoint: server.URL, Token: "x", Version: "dev", links: oneLink}).Probe(context.Background()); len(found) != 0 {
		t.Fatalf("found %v", found)
	}
}
