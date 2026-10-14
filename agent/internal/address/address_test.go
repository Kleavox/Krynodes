package address

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestTheProbeAsksOverEachFamilyAndKeepsWhatAnswered(t *testing.T) {
	var mu sync.Mutex
	var seen []*http.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"address":"103.28.54.214","family":4}`))
	}))
	defer server.Close()
	prober := Prober{Endpoint: server.URL + "/", Token: "agent-token", Version: "0.6.10"}
	found := prober.Probe(context.Background())
	if len(found) != 1 || found["tcp4"] != "103.28.54.214" {
		t.Fatalf("found %v", found)
	}
	if len(seen) != 1 {
		t.Fatalf("requests %d", len(seen))
	}
	request := seen[0]
	if request.URL.Path != "/api/agent/address" || request.Header.Get("Authorization") != "Bearer agent-token" || request.Header.Get("User-Agent") != "kry-agent/0.6.10" {
		t.Fatalf("request %s %v", request.URL.Path, request.Header)
	}
}

func TestTheProbeGoesOnWhenKrynodesRefuses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
	}))
	defer server.Close()
	if found := (Prober{Endpoint: server.URL, Token: "x", Version: "dev"}).Probe(context.Background()); len(found) != 0 {
		t.Fatalf("found %v", found)
	}
}
