package actions

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/stream"
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
	action := Request{ID: idA, Kind: "docker", Name: "resolver", Action: "restart", ExpiresAt: "2026-09-29T10:10:00.000Z"}
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
	if err := relay.Enqueue([]Request{{ID: "../x", Kind: "docker", Name: "resolver", Action: "restart"}}); err == nil {
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
	inventory := writeInventory(t, relay, []Service{{Kind: "docker", Name: "resolver", State: "running"}}, executorNow)
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
	action := Request{ID: idA, Kind: "docker", Name: "resolver", Action: "restart", ExpiresAt: "2026-09-29T10:10:00.000Z"}
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
	if err := relay.Enqueue([]Request{{ID: idA, Kind: "compose", Name: "panel", Action: "read", ExpiresAt: "2026-09-29T10:10:00.000Z"}}); err != nil {
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
		if err := relay.Enqueue([]Request{{ID: id, Kind: "compose", Name: "panel", Action: "read", ExpiresAt: "2026-09-29T10:10:00.000Z"}}); err != nil {
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
	writeInventory(t, relay, []Service{{Kind: "docker", Name: "resolver", State: "running"}}, executorNow)
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
	writeInventory(t, relay, []Service{{Kind: "docker", Name: "resolver", State: "stopped"}}, now)
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
	if err := relay.Enqueue([]Request{{ID: idA, Kind: "docker", Name: "resolver", Action: "restart", ExpiresAt: "t"}}); err != nil {
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

func watchingRelay(t *testing.T) *Relay {
	t.Helper()
	relay, _ := newRelay(t)
	relay.Dir = filepath.Join(filepath.Dir(relay.RequestDir), "relay")
	relay.Boot = func() string { return "4f0c6a3e-1d2b-4c5a-9e8f-7a6b5c4d3e2f" }
	events := eventLog{Events: []reporter.Event{
		{ID: "knock:10.88.0.1:1", Kind: "knock", At: "2026-09-29T09:59:00Z", Detail: map[string]string{"from": "10.88.0.1"}},
		{ID: "port:aa", Kind: "port", At: "2026-09-29T09:59:30Z", Detail: map[string]string{"port": "4444/tcp"}},
	}}
	if err := writeJSON(relay.StateDir, eventsFile, events, 0o640); err != nil {
		t.Fatal(err)
	}
	return relay
}

func eventIDs(beat reporter.Heartbeat) []string {
	var ids []string
	for _, event := range beat.Events {
		ids = append(ids, event.ID)
	}
	return ids
}

func TestTheRelaySendsEventsUntilTheyAreAcked(t *testing.T) {
	relay := watchingRelay(t)
	var beat reporter.Heartbeat
	relay.Report(&beat)
	if ids := eventIDs(beat); !reflect.DeepEqual(ids, []string{"knock:10.88.0.1:1", "port:aa"}) {
		t.Fatalf("events %v", ids)
	}
	if err := relay.Answer(reporter.HeartbeatResponse{Acked: []string{"knock:10.88.0.1:1", "unknown"}}); err != nil {
		t.Fatal(err)
	}
	restarted := &Relay{RequestDir: relay.RequestDir, StateDir: relay.StateDir, Dir: relay.Dir, Now: relay.Now}
	beat = reporter.Heartbeat{}
	restarted.Report(&beat)
	if ids := eventIDs(beat); !reflect.DeepEqual(ids, []string{"port:aa"}) {
		t.Fatalf("after the ack %v", ids)
	}
	var acked []string
	if err := readJSON(filepath.Join(relay.Dir, ackedFile), &acked); err != nil || !reflect.DeepEqual(acked, []string{"knock:10.88.0.1:1"}) {
		t.Fatalf("acked %v %v", acked, err)
	}
}

func TestTheBootCounterRisesOncePerReportAndSurvivesARestart(t *testing.T) {
	relay := watchingRelay(t)
	for want := int64(1); want <= 2; want++ {
		var beat reporter.Heartbeat
		relay.Report(&beat)
		if beat.Boot == nil || beat.Boot.ID != "4f0c6a3e-1d2b-4c5a-9e8f-7a6b5c4d3e2f" || beat.Boot.Count != want {
			t.Fatalf("boot %+v, want count %d", beat.Boot, want)
		}
	}
	restarted := &Relay{RequestDir: relay.RequestDir, StateDir: relay.StateDir, Dir: relay.Dir, Now: relay.Now, Boot: func() string { return "a-new-boot" }}
	var beat reporter.Heartbeat
	restarted.Report(&beat)
	if beat.Boot == nil || beat.Boot.ID != "a-new-boot" || beat.Boot.Count != 3 {
		t.Fatalf("after a restart %+v", beat.Boot)
	}
	silent := &Relay{RequestDir: relay.RequestDir, StateDir: relay.StateDir, Dir: relay.Dir, Now: relay.Now, Boot: func() string { return "" }}
	beat = reporter.Heartbeat{}
	silent.Report(&beat)
	if beat.Boot != nil {
		t.Fatalf("a boot with no id %+v", beat.Boot)
	}
}

func TestTheHeartbeatCarriesTheDenialsOnlyWhileTheLogIsRead(t *testing.T) {
	relay := watchingRelay(t)
	var beat reporter.Heartbeat
	relay.Report(&beat)
	if beat.Denials != nil {
		t.Fatalf("no denials read yet %+v", beat.Denials)
	}
	line := reporter.DenialLine{At: "2026-09-29T09:58:00Z", Program: "cat", Wanted: "read shadow", Stack: "panel"}
	hour := strconv.FormatInt(executorNow.Unix()/3600, 10)
	old := strconv.FormatInt(executorNow.Unix()/3600-30, 10)
	state := denialState{Readable: true, Hours: map[string]int{hour: 3, old: 9}, Lines: []reporter.DenialLine{line}}
	if err := writeJSON(relay.StateDir, denialsFile, state, 0o640); err != nil {
		t.Fatal(err)
	}
	relay.Report(&beat)
	if beat.Denials == nil || beat.Denials.Count != 3 || !reflect.DeepEqual(beat.Denials.Lines, []reporter.DenialLine{line}) {
		t.Fatalf("denials %+v", beat.Denials)
	}
}

func TestAPendingReleaseIsReportedUntilItEnds(t *testing.T) {
	relay := watchingRelay(t)
	pending := reporter.Release{Key: "a2V5", Signer: "c2lnbmVy", Seal: "c2VhbA", Token: strings.Repeat("a", 64), Expires: executorNow.Add(5 * time.Minute).Format(time.RFC3339)}
	if err := writeJSON(relay.StateDir, releaseFile, pending, 0o640); err != nil {
		t.Fatal(err)
	}
	var beat reporter.Heartbeat
	relay.Report(&beat)
	if beat.Release == nil || *beat.Release != pending {
		t.Fatalf("release %+v", beat.Release)
	}
	relay.Now = func() time.Time { return executorNow.Add(6 * time.Minute) }
	beat = reporter.Heartbeat{}
	relay.Report(&beat)
	if beat.Release != nil {
		t.Fatalf("an ended release %+v", beat.Release)
	}
}

func TestTheHeartbeatCarriesSetupWhileItRunsAndSaysWhereItStopped(t *testing.T) {
	relay := watchingRelay(t)
	boot := strings.TrimSpace(relay.Boot())
	report := func(progress *setupProgress) *reporter.Setup {
		t.Helper()
		if progress != nil {
			if err := writeJSON(relay.StateDir, setupFile, progress, 0o640); err != nil {
				t.Fatal(err)
			}
		}
		var beat reporter.Heartbeat
		relay.Report(&beat)
		return beat.Setup
	}
	if got := report(nil); got != nil {
		t.Fatalf("no setup yet %+v", got)
	}
	for _, step := range []struct {
		progress setupProgress
		want     *reporter.Setup
	}{
		{setupProgress{Phase: "upgrade", Step: 2, Of: 6, At: executorNow.Add(-30 * time.Second), Boot: boot}, &reporter.Setup{Phase: "upgrade", Step: 2, Of: 6}},
		{setupProgress{Phase: "upgrade", Step: 2, Of: 6, At: executorNow.Add(-61 * time.Second), Boot: boot}, &reporter.Setup{Phase: "upgrade", Step: 2, Of: 6, Stopped: true}},
		{setupProgress{Phase: "restart", Step: 6, Of: 6, At: executorNow.Add(-30 * time.Second), Boot: "an-earlier-boot"}, nil},
		{setupProgress{Phase: "docker", Step: 4, Of: 6, At: executorNow.Add(-30 * time.Second), Boot: "an-earlier-boot"}, &reporter.Setup{Phase: "docker", Step: 4, Of: 6, Stopped: true}},
		{setupProgress{Phase: "docker", Step: 4, Of: 6, At: executorNow.Add(-25 * time.Hour), Boot: "an-earlier-boot"}, nil},
		{setupProgress{Phase: "docker", Step: 4, Of: 6, At: executorNow.Add(-25 * time.Hour), Boot: boot}, nil},
	} {
		if got := report(&step.progress); !reflect.DeepEqual(got, step.want) {
			t.Fatalf("%+v: got %+v want %+v", step.progress, got, step.want)
		}
	}
}

func TestSettingUpGivesTheStepOnlyForAFreshSetupOfThisBoot(t *testing.T) {
	relay := watchingRelay(t)
	boot := strings.TrimSpace(relay.Boot())
	if relay.SettingUp() != nil {
		t.Fatal("no setup file means the server is not setting up")
	}
	upgrade := &reporter.Setup{Phase: "upgrade", Step: 2, Of: 6}
	for _, step := range []struct {
		progress setupProgress
		want     *reporter.Setup
	}{
		{setupProgress{Phase: "upgrade", Step: 2, Of: 6, At: executorNow.Add(-30 * time.Second), Boot: boot, Quiet: true}, upgrade},
		{setupProgress{Phase: "upgrade", Step: 2, Of: 6, At: executorNow.Add(-30 * time.Second), Boot: boot}, nil},
		{setupProgress{Phase: "upgrade", Step: 2, Of: 6, At: executorNow.Add(-61 * time.Second), Boot: boot, Quiet: true}, nil},
		{setupProgress{Phase: "restart", Step: 6, Of: 6, At: executorNow.Add(-5 * time.Second), Boot: "an-earlier-boot", Quiet: true}, nil},
	} {
		if err := writeJSON(relay.StateDir, setupFile, step.progress, 0o644); err != nil {
			t.Fatal(err)
		}
		if got := relay.SettingUp(); !reflect.DeepEqual(got, step.want) {
			t.Fatalf("%+v: got %+v", step.progress, got)
		}
	}
}

func TestASetupChangeWakesTheHeartbeatOnce(t *testing.T) {
	relay := watchingRelay(t)
	relay.Beat = make(chan struct{}, 1)
	relay.noticeSetup()
	if len(relay.Beat) != 0 {
		t.Fatal("woke the heartbeat with no setup running")
	}
	progress := setupProgress{Phase: "upgrade", Step: 2, Of: 6, At: executorNow, Boot: strings.TrimSpace(relay.Boot())}
	if err := writeJSON(relay.StateDir, setupFile, progress, 0o640); err != nil {
		t.Fatal(err)
	}
	relay.noticeSetup()
	relay.noticeSetup()
	if len(relay.Beat) != 1 {
		t.Fatalf("a new phase woke the heartbeat %d times", len(relay.Beat))
	}
	<-relay.Beat
	relay.Now = func() time.Time { return executorNow.Add(61 * time.Second) }
	relay.noticeSetup()
	if len(relay.Beat) != 1 {
		t.Fatal("a setup that stopped did not wake the heartbeat")
	}
}

func TestANewReleaseCodeWakesTheHeartbeatOnce(t *testing.T) {
	relay := watchingRelay(t)
	relay.Beat = make(chan struct{}, 1)
	relay.noticeRelease()
	if len(relay.Beat) != 0 {
		t.Fatal("woke the heartbeat with no release code made")
	}
	pending := reporter.Release{Key: "a2V5", Signer: "c2lnbmVy", Seal: "c2VhbA", Token: strings.Repeat("a", 64), Expires: executorNow.Add(5 * time.Minute).Format(time.RFC3339)}
	if err := writeJSON(relay.StateDir, releaseFile, pending, 0o644); err != nil {
		t.Fatal(err)
	}
	relay.noticeRelease()
	relay.noticeRelease()
	if len(relay.Beat) != 1 {
		t.Fatalf("a new code woke the heartbeat %d times", len(relay.Beat))
	}
	<-relay.Beat
	relay.noticeRelease()
	if len(relay.Beat) != 0 {
		t.Fatal("the same code woke the heartbeat again; it would beat every two seconds for ten minutes")
	}
	pending.Token = strings.Repeat("b", 64)
	if err := writeJSON(relay.StateDir, releaseFile, pending, 0o644); err != nil {
		t.Fatal(err)
	}
	relay.noticeRelease()
	if len(relay.Beat) != 1 {
		t.Fatal("a second code did not wake the heartbeat")
	}
}

func TestTheRelayMarksTheServerQuarantinedWhileTheWorkerSaysSo(t *testing.T) {
	relay := watchingRelay(t)
	mark := filepath.Join(relay.Dir, quarantinedFile)
	if err := relay.Answer(reporter.HeartbeatResponse{Quarantined: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mark); err != nil {
		t.Fatal(err)
	}
	if err := relay.Answer(reporter.HeartbeatResponse{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mark); !os.IsNotExist(err) {
		t.Fatalf("mark kept: %v", err)
	}
}

func TestEnqueueAndRefreshLeaveAWakeMarkerForExec(t *testing.T) {
	relay, _ := newRelay(t)
	wake := filepath.Join(relay.StateDir, WakeDir)
	if err := os.MkdirAll(wake, 0o750); err != nil {
		t.Fatal(err)
	}
	marked := func() bool {
		entries, _ := os.ReadDir(wake)
		return len(entries) > 0
	}
	if err := relay.Enqueue([]Request{{ID: idA, Kind: "docker", Name: "resolver", Action: "restart"}}); err != nil {
		t.Fatal(err)
	}
	if !marked() {
		t.Fatal("Enqueue left no wake marker")
	}
	if err := os.RemoveAll(wake); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(wake, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := relay.Refresh(); err != nil {
		t.Fatal(err)
	}
	if !marked() {
		t.Fatal("Refresh left no wake marker")
	}
}

func TestEnqueueStillWorksWithoutTheWakeFolder(t *testing.T) {
	relay, _ := newRelay(t)
	if err := relay.Enqueue([]Request{{ID: idA, Kind: "docker", Name: "resolver", Action: "restart"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(relay.RequestDir, idA+".json")); err != nil {
		t.Fatal(err)
	}
}

type channelPoster chan reporter.ActionsReport

func (posted channelPoster) PostActions(_ context.Context, report reporter.ActionsReport) (reporter.ActionsResponse, error) {
	posted <- report
	return reporter.ActionsResponse{OK: true}, nil
}

func TestAResultGoesOutWithoutWaitingForTheTick(t *testing.T) {
	relay, _ := newRelay(t)
	posted := make(channelPoster, 4)
	relay.Server = posted
	if err := relay.Enqueue([]Request{{ID: idA, Kind: "docker", Name: "resolver", Action: "restart"}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go relay.Watch(ctx, time.Hour)
	if err := writeJSON(filepath.Join(relay.StateDir, "results"), idA+".json", Result{ID: idA, OK: true, FinishedAt: "t"}, 0o640); err != nil {
		t.Fatal(err)
	}
	select {
	case report := <-posted:
		if len(report.Results) != 1 || report.Results[0].ID != idA {
			t.Fatalf("posted %#v", report)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the result waited for the slow tick")
	}
}

func TestPollSendsTheLeftovers(t *testing.T) {
	relay, poster := newRelay(t)
	inventory, err := NewInventory(Parts{Leftovers: []string{"panel"}}, executorNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(relay.StateDir, "inventory.json", inventory, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := relay.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sent := poster.reports[0].Inventory; sent.Leftovers == nil || !slices.Equal(*sent.Leftovers, []string{"panel"}) {
		t.Fatalf("leftovers %+v", sent.Leftovers)
	}
}

func TestAReportThatNeverLeftDoesNotBackOff(t *testing.T) {
	relay, poster := newRelay(t)
	now := executorNow
	relay.Now = func() time.Time { return now }
	poster.err = stream.ErrNotConnected
	writeInventory(t, relay, []Service{{Kind: "docker", Name: "resolver", State: "running"}}, executorNow)
	for range 8 {
		_ = relay.Poll(context.Background())
		now = now.Add(6 * time.Second)
	}
	if len(poster.reports) != 8 {
		t.Fatalf("expected a try every 5 seconds, got %d tries", len(poster.reports))
	}
}

func TestEnqueueKeepsTheActionsAfterAMalformedOne(t *testing.T) {
	relay, _ := newRelay(t)
	err := relay.Enqueue([]Request{{ID: "../bad", Kind: "docker", Name: "web"}, {ID: "01234567-89ab-cdef-0123-456789abcdef", Kind: "docker", Name: "web", Action: "restart"}})
	if err == nil {
		t.Fatal("expected the malformed action to be reported")
	}
	if _, err := os.Stat(filepath.Join(relay.RequestDir, "01234567-89ab-cdef-0123-456789abcdef.json")); err != nil {
		t.Fatalf("the valid action was dropped: %v", err)
	}
}

func TestASetupThatStalledOnceStaysLoudForTheRestOfIt(t *testing.T) {
	relay := watchingRelay(t)
	boot := strings.TrimSpace(relay.Boot())
	write := func(age time.Duration) {
		t.Helper()
		if err := writeJSON(relay.StateDir, setupFile, setupProgress{Phase: "upgrade", Step: 2, Of: 6, At: executorNow.Add(-age), Boot: boot, Quiet: true}, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(5 * time.Second)
	if relay.SettingUp() == nil {
		t.Fatal("a fresh quiet setup is quiet")
	}
	write(61 * time.Second)
	if relay.SettingUp() != nil {
		t.Fatal("a stalled setup is loud")
	}
	write(5 * time.Second)
	if relay.SettingUp() != nil {
		t.Fatal("the setup went quiet again after it had been loud")
	}
}

func TestNoInventoryGoesOutWhileTheServerSetsUpQuietly(t *testing.T) {
	relay := watchingRelay(t)
	poster := &fakePoster{}
	relay.Server = poster
	writeInventory(t, relay, []Service{{Kind: "docker", Name: "resolver", State: "running"}}, executorNow)
	if err := writeJSON(relay.StateDir, setupFile, setupProgress{Phase: "upgrade", Step: 2, Of: 6, At: executorNow.Add(-5 * time.Second), Boot: strings.TrimSpace(relay.Boot()), Quiet: true}, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := relay.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(poster.reports) != 0 {
		t.Fatalf("sent during a quiet setup: %+v", poster.reports)
	}
	if err := os.Remove(filepath.Join(relay.StateDir, setupFile)); err != nil {
		t.Fatal(err)
	}
	if err := relay.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(poster.reports) != 1 || poster.reports[0].Inventory == nil {
		t.Fatalf("not sent after setup: %+v", poster.reports)
	}
}
