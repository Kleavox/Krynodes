package cftest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/Kleavox/krynodes/agent/internal/cloudflare"
)

type API struct {
	mu       sync.Mutex
	Token    string
	Tunnels  map[string]string
	Ingress  map[string][]cloudflare.Rule
	Records  map[string]cloudflare.Record
	Apps     map[string]cloudflare.App
	Policies map[string][]cloudflare.Policy
	next     int
	Calls    []string
	Fail     map[string]bool
}

func New() *API {
	return &API{
		Token:    "cf-token",
		Tunnels:  map[string]string{},
		Ingress:  map[string][]cloudflare.Rule{},
		Records:  map[string]cloudflare.Record{},
		Apps:     map[string]cloudflare.App{"dash": {ID: "dash", Name: "Krynodes", Domain: "kry.kleavox.xyz", AUD: "aud-1"}},
		Policies: map[string][]cloudflare.Policy{"dash": {{ID: "pol-1", Name: "Owner", Decision: "allow", Reusable: true}}},
	}
}

func (f *API) id(prefix string) string {
	f.next++
	return fmt.Sprintf("%s-%d", prefix, f.next)
}

func (f *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, r.Method+" "+r.URL.Path)
	reply := func(result any) {
		json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": result})
	}
	if r.Header.Get("Authorization") != "Bearer "+f.Token {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"code": 10000, "message": "Authentication error"}}})
		return
	}
	if f.Fail[r.Method+" "+strings.TrimPrefix(r.URL.Path, "/client/v4")] {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"code": 10001, "message": "Internal error"}}})
		return
	}
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	path := strings.TrimPrefix(r.URL.Path, "/client/v4")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case path == "/zones":
		if r.URL.Query().Get("name") == "kleavox.xyz" {
			reply([]any{map[string]any{"id": "zone-1", "name": "kleavox.xyz", "account": map[string]any{"id": "acc-1"}}})
		} else {
			reply([]any{})
		}
	case path == "/accounts/acc-1/tokens/verify":
		reply(map[string]any{"status": "active", "expires_on": "2027-10-05T00:00:00Z"})
	case path == "/accounts/acc-1/cfd_tunnel" && r.Method == http.MethodGet:
		found := []any{}
		for id, name := range f.Tunnels {
			if name == r.URL.Query().Get("name") {
				found = append(found, map[string]any{"id": id, "name": name})
			}
		}
		reply(found)
	case path == "/accounts/acc-1/cfd_tunnel" && r.Method == http.MethodPost:
		id := f.id("tunnel")
		f.Tunnels[id] = body["name"].(string)
		reply(map[string]any{"id": id, "name": body["name"]})
	case len(parts) == 5 && parts[2] == "cfd_tunnel" && parts[4] == "token":
		reply("tunnel-token-" + parts[3])
	case len(parts) == 5 && parts[2] == "cfd_tunnel" && parts[4] == "configurations" && r.Method == http.MethodGet:
		reply(map[string]any{"config": map[string]any{"ingress": f.Ingress[parts[3]]}})
	case len(parts) == 5 && parts[2] == "cfd_tunnel" && parts[4] == "configurations" && r.Method == http.MethodPut:
		var rules []cloudflare.Rule
		raw, _ := json.Marshal(body["config"].(map[string]any)["ingress"])
		json.Unmarshal(raw, &rules)
		f.Ingress[parts[3]] = rules
		reply(map[string]any{})
	case len(parts) == 4 && parts[2] == "cfd_tunnel" && r.Method == http.MethodDelete:
		delete(f.Tunnels, parts[3])
		reply(map[string]any{})
	case path == "/zones/zone-1/dns_records" && r.Method == http.MethodGet:
		found := []any{}
		for _, record := range f.Records {
			if record.Name == r.URL.Query().Get("name") || (r.URL.Query().Get("comment.exact") != "" && record.Comment == r.URL.Query().Get("comment.exact")) {
				found = append(found, record)
			}
		}
		reply(found)
	case path == "/zones/zone-1/dns_records" && r.Method == http.MethodPost:
		raw, _ := json.Marshal(body)
		var record cloudflare.Record
		json.Unmarshal(raw, &record)
		record.ID = f.id("record")
		f.Records[record.ID] = record
		reply(record)
	case len(parts) == 4 && parts[2] == "dns_records" && r.Method == http.MethodDelete:
		delete(f.Records, parts[3])
		reply(map[string]any{"id": parts[3]})
	case path == "/accounts/acc-1/access/apps" && r.Method == http.MethodGet:
		found := []any{}
		for _, app := range f.Apps {
			found = append(found, app)
		}
		reply(found)
	case path == "/accounts/acc-1/access/apps" && r.Method == http.MethodPost:
		raw, _ := json.Marshal(body)
		var app cloudflare.App
		json.Unmarshal(raw, &app)
		app.ID = f.id("app")
		f.Apps[app.ID] = app
		reply(app)
	case len(parts) == 6 && parts[3] == "apps" && parts[5] == "policies":
		reply(f.Policies[parts[4]])
	case len(parts) == 5 && parts[3] == "apps" && r.Method == http.MethodPut:
		raw, _ := json.Marshal(body)
		var app cloudflare.App
		json.Unmarshal(raw, &app)
		app.ID = parts[4]
		f.Apps[app.ID] = app
		reply(app)
	case len(parts) == 5 && parts[3] == "apps" && r.Method == http.MethodDelete:
		delete(f.Apps, parts[4])
		reply(map[string]any{"id": parts[4]})
	default:
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"code": 7000, "message": "No route for that URI"}}})
	}
}
