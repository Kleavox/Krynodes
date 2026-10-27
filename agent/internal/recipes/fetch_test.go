package recipes

import (
	"net/http"
	"testing"
)

func TestADownloadNeverLeavesHTTPS(t *testing.T) {
	for address, allowed := range map[string]bool{"https://cdn.example.com/key.gpg": true, "http://example.com/key.gpg": false} {
		next, err := http.NewRequest(http.MethodGet, address, nil)
		if err != nil {
			t.Fatal(err)
		}
		if fetchClient.CheckRedirect == nil || (fetchClient.CheckRedirect(next, nil) == nil) != allowed {
			t.Fatalf("a redirect to %s allowed: %v", address, !allowed)
		}
	}
}
