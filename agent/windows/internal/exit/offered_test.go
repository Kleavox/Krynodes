package exit

import (
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

func TestOnlyAPublicServerWithExitOnIsOffered(t *testing.T) {
	endpoint := "203.0.113.1:51820"
	document := network.Document{Members: []network.Member{
		{Node: "public", Endpoint: &endpoint, Exit: true},
		{Node: "nat", Endpoint: &endpoint, NAT: true, Exit: true},
		{Node: "cut", Endpoint: &endpoint, Cut: true, Exit: true},
		{Node: "no-endpoint", Exit: true},
		{Node: "laptop", Endpoint: &endpoint, Kind: "laptop", Exit: true},
		{Node: "no-exit", Endpoint: &endpoint},
	}}
	for node, want := range map[string]bool{"public": true, "nat": false, "cut": false, "no-endpoint": false, "laptop": false, "no-exit": false, "unknown": false, "": false} {
		if got := Offered(document, nil, node); got != want {
			t.Errorf("%q offered %v, want %v", node, got, want)
		}
	}
	if Offered(document, []string{"public"}, "public") {
		t.Error("a held server is offered")
	}
}
