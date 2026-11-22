package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

func writeEntry(t *testing.T, state, id string, e entry) {
	t.Helper()
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(state, "ledger"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "ledger", id+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func ledgerIDs(t *testing.T, state string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(state, "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, item := range entries {
		ids = append(ids, item.Name())
	}
	slices.Sort(ids)
	return ids
}

func TestOnlyAcknowledgedEntriesPastAWeekAndTheirExpiryAreRemovedAtStart(t *testing.T) {
	h := newHarness(t, true)
	now := h.clock
	done := &reporter.Result{Type: "result", OK: true, Message: "Restarting now."}
	writeEntry(t, h.daemon.State, "old-acked", entry{Digest: "a", Result: done, Acked: true, At: now.Add(-8 * 24 * time.Hour)})
	writeEntry(t, h.daemon.State, "old-acked-not-expired", entry{Digest: "b", Result: done, Acked: true, At: now.Add(-8 * 24 * time.Hour), ExpiresAt: now.Add(time.Hour)})
	writeEntry(t, h.daemon.State, "old-unacked", entry{Digest: "c", Result: done, At: now.Add(-30 * 24 * time.Hour)})
	writeEntry(t, h.daemon.State, "recent-acked", entry{Digest: "d", Result: done, Acked: true, At: now.Add(-6 * 24 * time.Hour)})
	h.daemon.Start(context.Background())
	want := []string{"old-acked-not-expired.json", "old-unacked.json", "recent-acked.json"}
	if got := ledgerIDs(t, h.daemon.State); !slices.Equal(got, want) {
		t.Fatalf("kept %v, want %v", got, want)
	}
}

func TestAnAcknowledgedEntryKeepsRefusingItsIDForAWeek(t *testing.T) {
	h := newHarness(t, true)
	runs := 0
	h.daemon.Handlers["host/restart"] = counting(&runs, "Restarting now.")
	h.daemon.Handle(context.Background(), h.fixture.Command)
	h.daemon.Ack(h.fixture.Command.ID)
	h.clock = h.clock.Add(6 * 24 * time.Hour)
	h.daemon.Start(context.Background())
	h.daemon.Handle(context.Background(), h.fixture.Command)
	if runs != 1 || len(h.wire.results()) != 2 || !h.wire.results()[1].OK {
		t.Fatalf("runs %d results %+v", runs, h.wire.results())
	}
}

func TestACommandInterruptedByShutdownIsFinishedAtTheNextStart(t *testing.T) {
	h := newHarness(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	h.daemon.Handlers["host/restart"] = func(ctx context.Context, _ trust.Command, _ func(string)) (string, error) {
		cancel()
		<-ctx.Done()
		return "", ctx.Err()
	}
	h.daemon.Handle(ctx, h.fixture.Command)
	if got := h.wire.results(); len(got) != 0 {
		t.Fatalf("a shutdown sent %+v", got)
	}
	h.daemon.Handle(context.Background(), h.fixture.Command)
	if got := h.wire.results(); len(got) != 0 {
		t.Fatalf("a pending command answered %+v", got)
	}

	restarted := h.build(h.daemon.State)
	var resumed trust.Command
	restarted.Resume = func(_ context.Context, command trust.Command) (string, error) {
		resumed = command
		return "", errors.New("the agent stopped before this finished")
	}
	restarted.Start(context.Background())
	got := h.wire.results()
	if resumed.ID != h.fixture.Command.ID || resumed.Action != "restart" {
		t.Fatalf("resumed %+v", resumed)
	}
	if len(got) != 1 || got[0].OK || got[0].Message != "the agent stopped before this finished" {
		t.Fatalf("results %+v", got)
	}
	restarted.Resend()
	if got := h.wire.results(); len(got) != 2 || got[1].ID != h.fixture.Command.ID {
		t.Fatalf("resent %+v", got)
	}
}

func TestAPendingCommandWithoutResumeSaysTheAgentStopped(t *testing.T) {
	h := newHarness(t, true)
	command := trust.Command{V: 1, ID: "pending-1", Kind: "host", Action: "restart"}
	writeEntry(t, h.daemon.State, "pending-1", entry{Digest: "a", Kind: "host", Command: &command, At: h.clock})
	h.daemon.Start(context.Background())
	got := h.wire.results()
	if len(got) != 1 || got[0].ID != "pending-1" || got[0].OK || got[0].Message != "the agent stopped before this finished" {
		t.Fatalf("results %+v", got)
	}
}

func ledgerFiles(t *testing.T, state string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(state, "ledger"))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestAThousandUnsignedIDsLeaveTheLedgerEmpty(t *testing.T) {
	h := newHarness(t, true)
	runs := 0
	h.daemon.Handlers["host/restart"] = counting(&runs, "Restarting now.")
	for index := range 1000 {
		command := h.fixture.Command
		command.ID = fmt.Sprintf("unsigned-%04d", index)
		command.Signed = ""
		h.daemon.Handle(context.Background(), command)
	}
	if files := ledgerFiles(t, h.daemon.State); files != 0 || runs != 0 || len(h.wire.results()) != 1000 {
		t.Fatalf("files %d runs %d results %d", files, runs, len(h.wire.results()))
	}
	h.daemon.Resend()
	resent := h.wire.results()[1000:]
	if len(resent) != maxRefused || resent[0].ID != "unsigned-0744" || resent[maxRefused-1].ID != "unsigned-0999" {
		t.Fatalf("resent %d, first %+v", len(resent), resent[0])
	}
}

func TestARefusalIsAnsweredAgainAfterReconnectUntilAcked(t *testing.T) {
	h := newHarness(t, true)
	h.daemon.Handlers["host/restart"] = counting(new(int), "Restarting now.")
	unsigned := h.fixture.Command
	unsigned.Signed = ""
	h.daemon.Handle(context.Background(), unsigned)
	h.daemon.Resend()
	if got := h.wire.results(); len(got) != 2 || got[1].ID != unsigned.ID || got[1].Message != "the command is not signed" {
		t.Fatalf("results %+v", got)
	}
	h.daemon.Ack(unsigned.ID)
	h.daemon.Resend()
	if got := h.wire.results(); len(got) != 2 {
		t.Fatalf("an acknowledged refusal was sent again: %+v", got[2:])
	}
	if files := ledgerFiles(t, h.daemon.State); files != 0 {
		t.Fatalf("the ledger holds %d entries", files)
	}
}

func TestATrustChangeIsVerifiedBeforeTheLedgerIsWritten(t *testing.T) {
	h := newHarness(t, false)
	saved := 0
	h.daemon.SaveTrust = func(trust.Trust) error {
		saved++
		return nil
	}
	tampered := h.fixture.Change
	tampered.Signed = strings.Replace(tampered.Signed, `"approvals":[`, `"approvals":[],"x":[`, 1)
	h.daemon.Handle(context.Background(), tampered)
	empty := h.fixture.Change
	empty.ID, empty.Signed = "6c1f5a52-30de-4c1e-9d1b-0d7c3f6f2a21", `{"change":"e30","approvals":[]}`
	h.daemon.Handle(context.Background(), empty)
	if files := ledgerFiles(t, h.daemon.State); files != 0 || saved != 0 {
		t.Fatalf("files %d saved %d results %+v", files, saved, h.wire.results())
	}
	for _, result := range h.wire.results() {
		if result.OK || result.Trust == nil || result.Trust.Version != 1 {
			t.Fatalf("result %+v", result)
		}
	}

	h.daemon.SaveTrust = func(next trust.Trust) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.current = next
		return nil
	}
	h.daemon.Handle(context.Background(), h.fixture.Change)
	stale := h.fixture.Change
	stale.ID = "6c1f5a52-30de-4c1e-9d1b-0d7c3f6f2a22"
	h.daemon.Handle(context.Background(), stale)
	if got := ledgerIDs(t, h.daemon.State); !slices.Equal(got, []string{h.fixture.Change.ID + ".json"}) {
		t.Fatalf("ledger %v", got)
	}
}
