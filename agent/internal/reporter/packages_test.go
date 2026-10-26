package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestThePackagesReportMatchesTheSharedFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "protocol", "src", "fixtures", "packages-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var typed struct {
		Packages  PackagesReport  `json:"packages"`
		Tailscale TailscaleReport `json:"tailscale"`
	}
	if err := json.Unmarshal(raw, &typed); err != nil {
		t.Fatal(err)
	}
	again, err := json.Marshal(typed)
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(again, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the report did not survive the round trip:\n%s", again)
	}
}

func TestAServerWithoutAptSaysOnlyThat(t *testing.T) {
	encoded, err := json.Marshal(PackagesReport{System: "Fedora Linux 41", Codename: "x", Installed: 3})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"apt":false,"system":"Fedora Linux 41"}` {
		t.Fatalf("got %s", encoded)
	}
}
