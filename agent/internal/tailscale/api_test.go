package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

const (
	clientID     = "kQ1clientCNTRL"
	clientSecret = "tskey-client-kQ1clientCNTRL-0123456789abcdef"
)

type fakeAPI struct {
	tokens int
	etag   string
	calls  []string
	bodies map[string]string
	query  map[string]string
	reply  map[string]string
	status map[string]int
}

func newFakeAPI(t *testing.T) (*fakeAPI, *API) {
	t.Helper()
	fake := &fakeAPI{etag: `"e1"`, bodies: map[string]string{}, query: map[string]string{}, reply: map[string]string{}, status: map[string]int{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		key := r.Method + " " + r.URL.Path
		fake.calls = append(fake.calls, key)
		fake.bodies[key] = string(body)
		fake.query[key] = r.URL.RawQuery
		if r.URL.Path == "/api/v2/oauth/token" {
			fake.tokens++
			form, _ := url.ParseQuery(string(body))
			if form.Get("client_id") != clientID || form.Get("client_secret") != clientSecret || form.Get("grant_type") != "client_credentials" {
				w.WriteHeader(http.StatusUnauthorized)
				io.WriteString(w, `{"message":"invalid client credentials"}`)
				return
			}
			io.WriteString(w, `{"access_token":"tok-1","token_type":"Bearer","expires_in":3600}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if key == "GET /api/v2/tailnet/-/acl" {
			if r.Header.Get("Accept") != "application/hujson" {
				w.WriteHeader(http.StatusNotAcceptable)
				return
			}
			w.Header().Set("ETag", fake.etag)
		}
		if key == "POST /api/v2/tailnet/-/acl" && r.Header.Get("If-Match") != fake.etag {
			w.WriteHeader(http.StatusPreconditionFailed)
			io.WriteString(w, `{"message":"precondition failed, invalid old hash"}`)
			return
		}
		if code := fake.status[key]; code != 0 {
			w.WriteHeader(code)
		}
		io.WriteString(w, fake.reply[key])
	}))
	t.Cleanup(server.Close)
	return fake, &API{Base: server.URL, HTTP: server.Client(), ID: clientID, Secret: clientSecret}
}

func TestTheCredentialIsExchangedOnceForAToken(t *testing.T) {
	fake, api := newFakeAPI(t)
	fake.reply["GET /api/v2/tailnet/-/devices"] = `{"devices":[
		{"id":"1","nodeId":"nA","name":"pivox.tail4d2a.ts.net","addresses":["100.101.7.20"],"tags":["tag:kry"],"advertisedRoutes":["192.168.1.0/24"]},
		{"id":"2","nodeId":"nB","name":"laptop.tail4d2a.ts.net","addresses":["100.101.7.33"],"user":"owner@example.com"}]}`
	fake.reply["GET /api/v2/tailnet/-/acl"] = "{\n  // mine\n}\n"
	devices, err := api.Devices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []Device{
		{ID: "nA", Name: "pivox", Addresses: []string{"100.101.7.20"}, Tags: []string{"tag:kry"}, User: false, Routes: []string{"192.168.1.0/24"}},
		{ID: "nB", Name: "laptop", Addresses: []string{"100.101.7.33"}, Tags: []string{}, User: true, Routes: []string{}},
	}
	if !reflect.DeepEqual(devices, want) {
		t.Fatalf("devices %+v", devices)
	}
	body, etag, err := api.Policy(context.Background())
	if err != nil || string(body) != "{\n  // mine\n}\n" || etag != `"e1"` {
		t.Fatalf("policy %q %q %v", body, etag, err)
	}
	if fake.tokens != 1 || fake.query["GET /api/v2/tailnet/-/devices"] != "fields=all" {
		t.Fatalf("tokens %d calls %v", fake.tokens, fake.calls)
	}
}

func TestAPolicyChangedSinceItWasReadIsRefused(t *testing.T) {
	fake, api := newFakeAPI(t)
	if err := api.SetPolicy(context.Background(), []byte("{}"), `"e0"`); !errors.Is(err, ErrChanged) {
		t.Fatalf("got %v", err)
	}
	if err := api.SetPolicy(context.Background(), []byte("{}"), `"e1"`); err != nil {
		t.Fatal(err)
	}
	if fake.bodies["POST /api/v2/tailnet/-/acl"] != "{}" {
		t.Fatalf("bodies %v", fake.bodies)
	}
}

func TestTailscalesRefusalComesBackWithItsMessage(t *testing.T) {
	fake, api := newFakeAPI(t)
	fake.reply["POST /api/v2/tailnet/-/acl/validate"] = `{"message":"test(s) failed","data":[{"user":"owner@example.com","errors":["tag:kry is not in tagOwners"]}]}`
	err := api.Validate(context.Background(), []byte("{}"))
	if err == nil || !strings.Contains(err.Error(), "test(s) failed") || !strings.Contains(err.Error(), "tag:kry is not in tagOwners") {
		t.Fatalf("got %v", err)
	}
	fake.reply["POST /api/v2/tailnet/-/acl/validate"] = `{}`
	if err := api.Validate(context.Background(), []byte("{}")); err != nil {
		t.Fatal(err)
	}
}

func TestDevicesAreTaggedKeptAndDeleted(t *testing.T) {
	fake, api := newFakeAPI(t)
	ctx := context.Background()
	if err := api.Tag(ctx, "nA", []string{"tag:kry"}); err != nil {
		t.Fatal(err)
	}
	if err := api.NoExpiry(ctx, "nA"); err != nil {
		t.Fatal(err)
	}
	if err := api.Delete(ctx, "nA"); err != nil {
		t.Fatal(err)
	}
	if fake.bodies["POST /api/v2/device/nA/tags"] != `{"tags":["tag:kry"]}` || fake.bodies["POST /api/v2/device/nA/key"] != `{"keyExpiryDisabled":true}` || !strings.Contains(strings.Join(fake.calls, " "), "DELETE /api/v2/device/nA") {
		t.Fatalf("calls %v bodies %v", fake.calls, fake.bodies)
	}
	fake.status["POST /api/v2/device/nB/tags"] = http.StatusBadRequest
	fake.reply["POST /api/v2/device/nB/tags"] = `{"message":"requested tags [tag:kry] are invalid or not permitted"}`
	if err := api.Tag(ctx, "nB", []string{"tag:kry"}); err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("got %v", err)
	}
}

func TestTheAuthKeyIsOneTimeTaggedAndPreApproved(t *testing.T) {
	fake, api := newFakeAPI(t)
	fake.reply["POST /api/v2/tailnet/-/keys"] = `{"id":"k1","key":"tskey-auth-k1-secret"}`
	key, err := api.AuthKey(context.Background(), []string{"tag:kry"}, 600)
	if err != nil || key != "tskey-auth-k1-secret" {
		t.Fatalf("key %q %v", key, err)
	}
	var asked struct {
		Capabilities struct {
			Devices struct {
				Create struct {
					Reusable      bool     `json:"reusable"`
					Ephemeral     bool     `json:"ephemeral"`
					Preauthorized bool     `json:"preauthorized"`
					Tags          []string `json:"tags"`
				} `json:"create"`
			} `json:"devices"`
		} `json:"capabilities"`
		ExpirySeconds int `json:"expirySeconds"`
	}
	if err := json.Unmarshal([]byte(fake.bodies["POST /api/v2/tailnet/-/keys"]), &asked); err != nil {
		t.Fatal(err)
	}
	create := asked.Capabilities.Devices.Create
	if create.Reusable || create.Ephemeral || !create.Preauthorized || !reflect.DeepEqual(create.Tags, []string{"tag:kry"}) || asked.ExpirySeconds != 600 {
		t.Fatalf("asked %+v", asked)
	}
}

func TestTheSecretIsInNoError(t *testing.T) {
	_, api := newFakeAPI(t)
	api.ID = "someone-else"
	_, err := api.Devices(context.Background())
	if err == nil || strings.Contains(err.Error(), clientSecret) || !strings.Contains(err.Error(), "invalid client credentials") {
		t.Fatalf("got %v", err)
	}
}
