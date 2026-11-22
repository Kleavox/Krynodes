package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/trust"
)

func TestRestartWaitsForTheAck(t *testing.T) {
	h := newHarness(t, true)
	rebooted := make(chan struct{})
	h.daemon.Handlers["host/restart"] = AfterAck(h.daemon, time.Hour, "Restarting now.", func() { close(rebooted) })
	h.daemon.Handle(context.Background(), h.fixture.Command)
	if got := h.wire.results(); len(got) != 1 || !got[0].OK || got[0].Message != "Restarting now." {
		t.Fatalf("results %+v", got)
	}
	select {
	case <-rebooted:
		t.Fatal("rebooted before the hub acknowledged the result")
	case <-time.After(100 * time.Millisecond):
	}
	h.daemon.Ack("6c1f5a52-30de-4c1e-9d1b-0d7c3f6f2a99")
	select {
	case <-rebooted:
		t.Fatal("another command's ack started the reboot")
	case <-time.After(50 * time.Millisecond):
	}
	h.daemon.Ack(h.fixture.Command.ID)
	select {
	case <-rebooted:
	case <-time.After(2 * time.Second):
		t.Fatal("no reboot after the ack")
	}
	h.daemon.Ack(h.fixture.Command.ID)
}

func TestRestartGoesAheadWhenNoAckComes(t *testing.T) {
	h := newHarness(t, true)
	rebooted := make(chan struct{})
	h.daemon.Handlers["host/restart"] = AfterAck(h.daemon, 50*time.Millisecond, "Restarting now.", func() { close(rebooted) })
	h.daemon.Handle(context.Background(), h.fixture.Command)
	select {
	case <-rebooted:
	case <-time.After(2 * time.Second):
		t.Fatal("no reboot after the wait ran out")
	}
}

func updateCommand(version string) trust.Command {
	return trust.Command{V: 1, ID: "u-1", Kind: "agent", Name: "server-1", Action: "update", Args: map[string]string{"version": version}}
}

func TestUpdateRefusesWhatIsNotANewerRelease(t *testing.T) {
	ran := false
	handler := Update("0.7.90", time.Second, func(context.Context, string) error {
		ran = true
		return nil
	})
	for version, reason := range map[string]string{
		"":         `"" is not a release version`,
		"0.7.90.1": `"0.7.90.1" is not a release version`,
		"latest":   `"latest" is not a release version`,
		"0.7.90":   "this server already runs 0.7.90",
		"0.7.89":   "this server already runs 0.7.90",
	} {
		if _, err := handler(context.Background(), updateCommand(version), func(string) {}); err == nil || err.Error() != reason {
			t.Errorf("%q: %v", version, err)
		}
	}
	if ran {
		t.Fatal("an update ran")
	}
}

func TestUpdateHandsTheVersionToTheUpdaterAndReportsItsFailure(t *testing.T) {
	var lines []string
	var asked string
	handler := Update("0.7.90", 10*time.Millisecond, func(_ context.Context, target string) error {
		asked = target
		return errors.New("signature does not match the release key")
	})
	_, err := handler(context.Background(), updateCommand("0.7.91"), func(line string) { lines = append(lines, line) })
	if asked != "0.7.91" || err == nil || err.Error() != "signature does not match the release key" {
		t.Fatalf("asked %q err %v", asked, err)
	}
	if len(lines) != 1 || lines[0] != "Updating to 0.7.91" {
		t.Fatalf("progress %q", lines)
	}
}

func TestAnUpdaterThatDiesWithTheAgentLeavesTheCommandForTheNextStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handler := Update("0.7.90", 2*time.Second, func(context.Context, string) error {
		time.AfterFunc(20*time.Millisecond, cancel)
		return errors.New("the update did not run: signal: terminated")
	})
	started := time.Now()
	_, err := handler(ctx, updateCommand("0.7.91"), func(string) {})
	if ctx.Err() == nil || err == nil {
		t.Fatalf("err %v while the agent was %v", err, ctx.Err())
	}
	if time.Since(started) > time.Second {
		t.Fatalf("waited %s", time.Since(started))
	}
}

func TestAnUpdaterThatFailsWhileTheAgentKeepsRunningIsReportedAfterTheWait(t *testing.T) {
	handler := Update("0.7.90", 30*time.Millisecond, func(context.Context, string) error {
		return errors.New("the update did not run: no space left")
	})
	started := time.Now()
	_, err := handler(context.Background(), updateCommand("0.7.91"), func(string) {})
	if err == nil || err.Error() != "the update did not run: no space left" {
		t.Fatalf("err %v", err)
	}
	if time.Since(started) < 30*time.Millisecond {
		t.Fatalf("answered after %s", time.Since(started))
	}
}

func TestResumeTellsAnUpdateByTheVersionNowRunning(t *testing.T) {
	resume := Resume("0.7.91", func() string { return "the new agent did not stay up; rolled back to 0.7.90" })
	if message, err := resume(context.Background(), updateCommand("0.7.91")); err != nil || message != "Updated to 0.7.91." {
		t.Fatalf("message %q err %v", message, err)
	}
	if _, err := resume(context.Background(), updateCommand("0.7.92")); err == nil || err.Error() != "the new agent did not stay up; rolled back to 0.7.90" {
		t.Fatalf("err %v", err)
	}
	if _, err := resume(context.Background(), trust.Command{Kind: "host", Action: "restart"}); err == nil || err.Error() != "the agent stopped before this finished" {
		t.Fatalf("err %v", err)
	}
}
