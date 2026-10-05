package cloudflare_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/cloudflare"
	"github.com/Kleavox/krynodes/agent/internal/cloudflare/cftest"
)

func client(t *testing.T) (*cloudflare.Client, *cftest.API) {
	t.Helper()
	fake := cftest.New()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	return &cloudflare.Client{Token: "cf-token", Base: server.URL + "/client/v4", HTTP: server.Client()}, fake
}

func TestAWebAddressGetsATunnelRouteDNSAndLogin(t *testing.T) {
	cf, fake := client(t)
	ctx := context.Background()
	zone, err := cf.Zone(ctx, "kleavox.xyz")
	if err != nil || zone.ID != "zone-1" || zone.AccountID != "acc-1" {
		t.Fatalf("zone %#v %v", zone, err)
	}
	tunnel, err := cf.Tunnel(ctx, zone.AccountID, "krynodes-node-a")
	if err != nil {
		t.Fatal(err)
	}
	again, err := cf.Tunnel(ctx, zone.AccountID, "krynodes-node-a")
	if err != nil || again != tunnel || len(fake.Tunnels) != 1 {
		t.Fatalf("one tunnel per server: %s %s %v", tunnel, again, fake.Tunnels)
	}
	if token, err := cf.TunnelToken(ctx, zone.AccountID, tunnel); err != nil || token != "tunnel-token-"+tunnel {
		t.Fatalf("token %q %v", token, err)
	}
	if err := cf.Route(ctx, zone.AccountID, tunnel, "listmonk-pivox.kleavox.xyz", "http://listmonk-app-1:9000"); err != nil {
		t.Fatal(err)
	}
	if err := cf.Route(ctx, zone.AccountID, tunnel, "adguard-pivox.kleavox.xyz", "http://adguard-1:3000"); err != nil {
		t.Fatal(err)
	}
	rules := fake.Ingress[tunnel]
	if len(rules) != 3 || rules[2].Service != "http_status:404" || rules[2].Hostname != "" {
		t.Fatalf("rules %#v", rules)
	}
	if err := cf.Point(ctx, zone.ID, "listmonk-pivox.kleavox.xyz", tunnel); err != nil {
		t.Fatal(err)
	}
	if err := cf.Point(ctx, zone.ID, "listmonk-pivox.kleavox.xyz", tunnel); err != nil || len(fake.Records) != 1 {
		t.Fatalf("pointing twice keeps one record: %v %v", err, fake.Records)
	}
	for _, record := range fake.Records {
		if record.Content != tunnel+".cfargotunnel.com" || !record.Proxied || record.Type != "CNAME" || record.Comment != cloudflare.Mark {
			t.Fatalf("record %#v", record)
		}
	}
	if err := cf.Guard(ctx, zone.AccountID, "listmonk-pivox.kleavox.xyz/admin", "aud-1"); err != nil {
		t.Fatal(err)
	}
	var guarded cloudflare.App
	for _, app := range fake.Apps {
		if app.Domain == "listmonk-pivox.kleavox.xyz/admin" {
			guarded = app
		}
	}
	if guarded.Name != "krynodes listmonk-pivox.kleavox.xyz/admin" || guarded.Type != "self_hosted" || len(guarded.Policies) != 1 || guarded.Policies[0].ID != "pol-1" {
		t.Fatalf("app %#v", guarded)
	}
	if expires, err := cf.Expires(ctx, zone.AccountID); err != nil || expires != "2027-10-05T00:00:00Z" {
		t.Fatalf("expires %q %v", expires, err)
	}
}

func TestKrynodesNeverTakesAnotherRecordOrApp(t *testing.T) {
	cf, fake := client(t)
	ctx := context.Background()
	fake.Records["mine"] = cloudflare.Record{ID: "mine", Type: "A", Name: "blog.kleavox.xyz", Content: "203.0.113.5"}
	if err := cf.Point(ctx, "zone-1", "blog.kleavox.xyz", "tunnel-9"); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatalf("err %v", err)
	}
	if err := cf.Unpoint(ctx, "zone-1", "blog.kleavox.xyz"); err != nil || fake.Records["mine"].ID == "" {
		t.Fatalf("someone else's record stays: %v %v", err, fake.Records)
	}
	if err := cf.Unguard(ctx, "acc-1", "kry.kleavox.xyz"); err != nil || fake.Apps["dash"].ID == "" {
		t.Fatalf("the dashboard app stays: %v", err)
	}
}

func TestRemovingAnAddressTakesOnlyItsOwnParts(t *testing.T) {
	cf, fake := client(t)
	ctx := context.Background()
	tunnel, _ := cf.Tunnel(ctx, "acc-1", "krynodes-node-a")
	cf.Route(ctx, "acc-1", tunnel, "a.kleavox.xyz", "http://a:1")
	cf.Route(ctx, "acc-1", tunnel, "b.kleavox.xyz", "http://b:1")
	cf.Point(ctx, "zone-1", "a.kleavox.xyz", tunnel)
	cf.Guard(ctx, "acc-1", "a.kleavox.xyz", "aud-1")
	if err := cf.Unroute(ctx, "acc-1", tunnel, "a.kleavox.xyz"); err != nil {
		t.Fatal(err)
	}
	if err := cf.Unpoint(ctx, "zone-1", "a.kleavox.xyz"); err != nil {
		t.Fatal(err)
	}
	if err := cf.Unguard(ctx, "acc-1", "a.kleavox.xyz"); err != nil {
		t.Fatal(err)
	}
	rules := fake.Ingress[tunnel]
	if len(rules) != 2 || rules[0].Hostname != "b.kleavox.xyz" || len(fake.Records) != 0 || len(fake.Apps) != 1 {
		t.Fatalf("rules %#v records %v apps %v", rules, fake.Records, fake.Apps)
	}
}

func TestCleaningUpARemovedServer(t *testing.T) {
	cf, fake := client(t)
	ctx := context.Background()
	tunnel, _ := cf.Tunnel(ctx, "acc-1", "krynodes-node-b")
	cf.Point(ctx, "zone-1", "kuma-b.kleavox.xyz", tunnel)
	cf.Guard(ctx, "acc-1", "kuma-b.kleavox.xyz", "aud-1")
	other, _ := cf.Tunnel(ctx, "acc-1", "krynodes-node-a")
	cf.Point(ctx, "zone-1", "kuma-a.kleavox.xyz", other)
	if err := cf.Clean(ctx, "acc-1", "zone-1", "krynodes-node-b"); err != nil {
		t.Fatal(err)
	}
	if len(fake.Tunnels) != 1 || len(fake.Records) != 1 || len(fake.Apps) != 1 {
		t.Fatalf("tunnels %v records %v apps %v", fake.Tunnels, fake.Records, fake.Apps)
	}
}

func TestCloudflareErrorsAreReadable(t *testing.T) {
	cf, _ := client(t)
	cf.Token = "wrong"
	if _, err := cf.Zone(context.Background(), "kleavox.xyz"); err == nil || !strings.Contains(err.Error(), "Authentication error") {
		t.Fatalf("err %v", err)
	}
	cf.Token = "cf-token"
	if _, err := cf.Zone(context.Background(), "nowhere.example"); err == nil {
		t.Fatal("an unknown zone must fail")
	}
}
