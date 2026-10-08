package actions

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

type fakePoster struct {
	reports []reporter.ActionsReport
	hash    string
	err     error
}

func (f *fakePoster) PostActions(_ context.Context, report reporter.ActionsReport) (reporter.ActionsResponse, error) {
	f.reports = append(f.reports, report)
	if f.err != nil {
		return reporter.ActionsResponse{}, f.err
	}
	hash := f.hash
	return reporter.ActionsResponse{OK: true, InventoryHash: &hash}, nil
}

func newRelay(t *testing.T) (*Relay, *fakePoster) {
	t.Helper()
	base := t.TempDir()
	poster := &fakePoster{}
	return &Relay{
		RequestDir: filepath.Join(base, "actions"),
		StateDir:   filepath.Join(base, "exec"),
		NodeID:     "node-1",
		Server:     poster,
		Now:        func() time.Time { return executorNow },
	}, poster
}

func writeInventory(t *testing.T, relay *Relay, services []Service, taken time.Time) Inventory {
	t.Helper()
	inventory, err := inventoryOf(services, taken)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(relay.StateDir, "inventory.json", inventory, 0o640); err != nil {
		t.Fatal(err)
	}
	return inventory
}

func TestEnqueueWritesOneFilePerAction(t *testing.T) {
	relay, _ := newRelay(t)
	action := Request{ID: idA, Kind: "docker", Name: "adguard", Action: "restart", ExpiresAt: "2026-09-29T10:10:00.000Z"}
	if err := relay.Enqueue([]Request{action}); err != nil {
		t.Fatal(err)
	}
	var written Request
	if err := readJSON(filepath.Join(relay.RequestDir, idA+".json"), &written); err != nil || !reflect.DeepEqual(written, action) {
		t.Fatalf("written %#v err %v", written, err)
	}
	entries, _ := os.ReadDir(relay.RequestDir)
	if len(entries) != 1 {
		t.Fatalf("expected no temporary files, got %d entries", len(entries))
	}
	if err := relay.Enqueue([]Request{{ID: "../x", Kind: "docker", Name: "adguard", Action: "restart"}}); err == nil {
		t.Fatal("a malformed id must be refused")
	}
}

func TestRefreshLeavesNoMarkerBehind(t *testing.T) {
	relay, _ := newRelay(t)
	if err := relay.Refresh(); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(relay.RequestDir); len(entries) != 0 {
		t.Fatalf("expected an empty request directory, got %d entries", len(entries))
	}
}

func TestPollSendsAChangedInventoryOnceWithItsServices(t *testing.T) {
	relay, poster := newRelay(t)
	inventory := writeInventory(t, relay, []Service{{Kind: "docker", Name: "adguard", State: "running"}}, executorNow)
	poster.hash = inventory.Hash
	for range 2 {
		if err := relay.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(poster.reports) != 1 {
		t.Fatalf("expected one report, got %d", len(poster.reports))
	}
	sent := poster.reports[0].Inventory
	if sent == nil || sent.Hash != inventory.Hash || sent.Services == nil || len(*sent.Services) != 1 {
		t.Fatalf("unexpected inventory report %#v", sent)
	}
}

func TestPollSendsTheDockerState(t *testing.T) {
	relay, poster := newRelay(t)
	inventory, err := NewInventory(Parts{Docker: "ready"}, executorNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(relay.StateDir, "inventory.json", inventory, 0o640); err != nil {
		t.Fatal(err)
	}
	poster.hash = inventory.Hash
	if err := relay.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(poster.reports) != 1 || poster.reports[0].Inventory == nil || poster.reports[0].Inventory.Docker != "ready" {
		t.Fatalf("unexpected reports %#v", poster.reports)
	}
}

func TestAfterARefreshTheHashIsSentEvenWhenNothingChanged(t *testing.T) {
	relay, poster := newRelay(t)
	inventory := writeInventory(t, relay, nil, executorNow)
	poster.hash = inventory.Hash
	if err := relay.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := relay.Refresh(); err != nil {
		t.Fatal(err)
	}
	writeInventory(t, relay, nil, executorNow.Add(time.Second))
	if err := relay.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := relay.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(poster.reports) != 2 {
		t.Fatalf("expected two reports, got %d", len(poster.reports))
	}
	second := poster.reports[1].Inventory
	if second == nil || second.Hash != inventory.Hash || second.Services != nil {
		t.Fatalf("the refresh report must carry only the hash: %#v", second)
	}
}

func TestPollReportsResultsAndRemovesTheirRequests(t *testing.T) {
	relay, poster := newRelay(t)
	action := Request{ID: idA, Kind: "docker", Name: "adguard", Action: "restart", ExpiresAt: "2026-09-29T10:10:00.000Z"}
	if err := relay.Enqueue([]Request{action}); err != nil {
		t.Fatal(err)
	}
	code := 0
	if err := writeJSON(filepath.Join(relay.StateDir, "results"), idA+".json", Result{ID: idA, OK: true, ExitCode: &code, FinishedAt: "t"}, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(relay.StateDir, "results"), idB+".json", Result{ID: idB, OK: true, FinishedAt: "t"}, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := relay.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(poster.reports) != 1 || len(poster.reports[0].Results) != 1 || poster.reports[0].Results[0].ID != idA {
		t.Fatalf("unexpected reports %#v", poster.reports)
	}
	if _, err := os.Stat(filepath.Join(relay.RequestDir, idA+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a reported request must be removed")
	}
}

func TestAResultTooLargeForAReportIsReportedAsFailed(t *testing.T) {
	relay, poster := newRelay(t)
	if err := relay.Enqueue([]Request{{ID: idA, Kind: "compose", Name: "kuma", Action: "read", ExpiresAt: "2026-09-29T10:10:00.000Z"}}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(relay.StateDir, "results"), idA+".json", Result{ID: idA, OK: true, Output: strings.Repeat("😀", 40_000), FinishedAt: "t"}, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := relay.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := poster.reports[0].Results[0]
	if got.ID != idA || got.OK || !strings.Contains(got.Output, "larger than the 64 KB") || got.FinishedAt != "t" {
		t.Fatalf("result %#v", got)
	}
}

func TestAReportCarriesAtMostHalfAMegabyteOfResults(t *testing.T) {
	relay, poster := newRelay(t)
	for index := range 10 {
		id := fmt.Sprintf("0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a%02d", index)
		if err := relay.Enqueue([]Request{{ID: id, Kind: "compose", Name: "kuma", Action: "read", ExpiresAt: "2026-09-29T10:10:00.000Z"}}); err != nil {
			t.Fatal(err)
		}
		if err := writeJSON(filepath.Join(relay.StateDir, "results"), id+".json", Result{ID: id, OK: true, Output: strings.Repeat("a", 60_000), FinishedAt: "t"}, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := relay.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := relay.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(poster.reports) != 2 || len(poster.reports[0].Results) != 8 || len(poster.reports[1].Results) != 2 {
		t.Fatalf("reports of %d and %d", len(poster.reports[0].Results), len(poster.reports[len(poster.reports)-1].Results))
	}
}

func TestAFailedReportWaitsLongerEachTimeBeforeTryingAgain(t *testing.T) {
	relay, poster := newRelay(t)
	now := executorNow
	relay.Now = func() time.Time { return now }
	poster.err = errors.New("offline")
	writeInventory(t, relay, []Service{{Kind: "docker", Name: "adguard", State: "running"}}, executorNow)
	poll := func(after time.Duration, want int) {
		t.Helper()
		now = now.Add(after)
		_ = relay.Poll(context.Background())
		if len(poster.reports) != want {
			t.Fatalf("after +%s expected %d reports, got %d", after, want, len(poster.reports))
		}
	}
	poll(0, 1)
	poll(2*time.Second, 1)
	poll(4*time.Second, 2)
	poll(9*time.Second, 2)
	poll(2*time.Second, 3)
	poster.err = nil
	poll(30*time.Second, 4)
	writeInventory(t, relay, []Service{{Kind: "docker", Name: "adguard", State: "stopped"}}, now)
	poll(2*time.Second, 5)
}

func TestFailuresBackOffToTenMinutesAtMost(t *testing.T) {
	relay, poster := newRelay(t)
	now := executorNow
	relay.Now = func() time.Time { return now }
	poster.err = errors.New("offline")
	writeInventory(t, relay, nil, executorNow)
	for range 8 {
		_ = relay.Poll(context.Background())
		now = now.Add(10 * time.Minute)
	}
	if len(poster.reports) != 8 {
		t.Fatalf("a ten-minute gap must always allow a retry, got %d reports", len(poster.reports))
	}
}

func TestAFailedReportKeepsTheRequest(t *testing.T) {
	relay, poster := newRelay(t)
	poster.err = errors.New("offline")
	if err := relay.Enqueue([]Request{{ID: idA, Kind: "docker", Name: "adguard", Action: "restart", ExpiresAt: "t"}}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(relay.StateDir, "results"), idA+".json", Result{ID: idA, OK: true, FinishedAt: "t"}, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := relay.Poll(context.Background()); err == nil {
		t.Fatal("expected the post error")
	}
	if _, err := os.Stat(filepath.Join(relay.RequestDir, idA+".json")); err != nil {
		t.Fatal("the request must stay until its result is reported")
	}
}

func TestPollSendsTheSealKey(t *testing.T) {
	relay, poster := newRelay(t)
	inventory, err := NewInventory(Parts{SealKey: "B" + strings.Repeat("A", 86)}, executorNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(relay.StateDir, "inventory.json", inventory, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := relay.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(poster.reports) != 1 || poster.reports[0].Inventory == nil || poster.reports[0].Inventory.SealKey != inventory.SealKey {
		t.Fatalf("unexpected reports %#v", poster.reports)
	}
}
