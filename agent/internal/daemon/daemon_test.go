package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

type browserFixture struct {
	Origin  string           `json:"origin"`
	RPID    string           `json:"rpId"`
	NodeID  string           `json:"nodeId"`
	Now     string           `json:"now"`
	Tokens  []string         `json:"tokens"`
	Change  reporter.Command `json:"change"`
	Command reporter.Command `json:"command"`
}

type wire struct {
	mu   sync.Mutex
	sent []any
}

func (w *wire) send(message any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sent = append(w.sent, message)
	return nil
}

func (w *wire) results() []reporter.Result {
	w.mu.Lock()
	defer w.mu.Unlock()
	var found []reporter.Result
	for _, message := range w.sent {
		if result, ok := message.(reporter.Result); ok {
			found = append(found, result)
		}
	}
	return found
}

type harness struct {
	daemon  *Daemon
	wire    *wire
	fixture browserFixture
	first   trust.Trust
	mu      sync.Mutex
	current trust.Trust
	clock   time.Time
}

func newHarness(t *testing.T, changed bool) *harness {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "protocol", "src", "fixtures", "browser-signed.json"))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{wire: &wire{}}
	if err := json.Unmarshal(raw, &h.fixture); err != nil {
		t.Fatal(err)
	}
	if h.clock, err = time.Parse(time.RFC3339Nano, h.fixture.Now); err != nil {
		t.Fatal(err)
	}
	if h.first, err = trust.FirstTrust(h.fixture.NodeID, h.fixture.Origin, h.fixture.Tokens); err != nil {
		t.Fatal(err)
	}
	h.current = h.first
	if changed {
		if h.current, err = trust.ApplyTrustChange(h.first, []byte(h.fixture.Change.Signed), h.clock); err != nil {
			t.Fatal(err)
		}
	}
	h.daemon = h.build(t.TempDir())
	return h
}

func (h *harness) build(state string) *Daemon {
	d := &Daemon{
		State: state,
		Trust: func() trust.Trust {
			h.mu.Lock()
			defer h.mu.Unlock()
			return h.current
		},
		SaveTrust: func(next trust.Trust) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.current = next
			return nil
		},
		Send: h.wire.send,
		Now: func() time.Time {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.clock = h.clock.Add(time.Millisecond)
			return h.clock
		},
		Handlers: map[string]Handler{},
	}
	d.Handlers["trust/apply"] = d.ApplyTrust
	return d
}

func counting(runs *int, message string) Handler {
	return func(context.Context, trust.Command, func(string)) (string, error) {
		*runs++
		return message, nil
	}
}

func TestACommandSeenTwiceRunsOnceAndAnswersAgain(t *testing.T) {
	h := newHarness(t, true)
	runs := 0
	h.daemon.Handlers["host/restart"] = counting(&runs, "Restarting now.")
	h.daemon.Handle(context.Background(), h.fixture.Command)
	h.daemon.Handle(context.Background(), h.fixture.Command)
	again := h.build(h.daemon.State)
	again.Handlers["host/restart"] = counting(&runs, "Restarting now.")
	again.Handle(context.Background(), h.fixture.Command)
	if runs != 1 {
		t.Fatalf("ran %d times", runs)
	}
	results := h.wire.results()
	if len(results) != 3 {
		t.Fatalf("results %+v", results)
	}
	for _, result := range results {
		if result.Type != "result" || result.ID != h.fixture.Command.ID || !result.OK || result.Message != "Restarting now." || result.Trust != nil {
			t.Fatalf("result %+v", result)
		}
	}
}

func TestAReusedIDWithOtherContentIsRefused(t *testing.T) {
	h := newHarness(t, true)
	runs := 0
	h.daemon.Handlers["host/restart"] = counting(&runs, "Restarting now.")
	h.daemon.Handlers["agent/update"] = counting(&runs, "Updated.")
	h.daemon.Handle(context.Background(), h.fixture.Command)
	other := h.fixture.Command
	other.Kind, other.Action = "agent", "update"
	h.daemon.Handle(context.Background(), other)
	tampered := h.fixture.Command
	tampered.Signed += " "
	h.daemon.Handle(context.Background(), tampered)
	if runs != 1 {
		t.Fatalf("ran %d times", runs)
	}
	results := h.wire.results()
	if len(results) != 3 || !results[0].OK {
		t.Fatalf("results %+v", results)
	}
	for _, result := range results[1:] {
		if result.OK || result.Message != "this command id was already used" {
			t.Fatalf("result %+v", result)
		}
	}
}

func TestAnUnacknowledgedResultIsSentAgainAfterReconnect(t *testing.T) {
	h := newHarness(t, false)
	runs := 0
	h.daemon.Handlers["host/restart"] = counting(&runs, "Restarting now.")
	h.daemon.Handle(context.Background(), h.fixture.Change)
	h.daemon.Handle(context.Background(), h.fixture.Command)
	if got := h.wire.results(); len(got) != 2 || !got[0].OK || !got[1].OK {
		t.Fatalf("results %+v", got)
	}

	h.daemon.Resend()
	got := h.wire.results()[2:]
	if len(got) != 2 || got[0].ID != h.fixture.Change.ID || got[1].ID != h.fixture.Command.ID {
		t.Fatalf("resent %+v", got)
	}
	if got[0].Trust == nil || got[0].Trust.Version != 2 {
		t.Fatalf("the resent trust result carries %+v", got[0].Trust)
	}

	h.daemon.Ack(h.fixture.Change.ID)
	restarted := h.build(h.daemon.State)
	restarted.Resend()
	got = h.wire.results()[4:]
	if len(got) != 1 || got[0].ID != h.fixture.Command.ID {
		t.Fatalf("after one ack and a restart, resent %+v", got)
	}

	restarted.Ack(h.fixture.Command.ID)
	restarted.Resend()
	if extra := h.wire.results()[5:]; len(extra) != 0 {
		t.Fatalf("acknowledged results were sent again: %+v", extra)
	}
	if runs != 1 {
		t.Fatalf("ran %d times", runs)
	}
}

func TestAnUnsignedCommandIsRefusedWithItsReason(t *testing.T) {
	h := newHarness(t, true)
	runs := 0
	h.daemon.Handlers["host/restart"] = counting(&runs, "Restarting now.")
	unsigned := h.fixture.Command
	unsigned.Signed = ""
	h.daemon.Handle(context.Background(), unsigned)
	forged := h.fixture.Command
	forged.ID = "6c1f5a52-30de-4c1e-9d1b-0d7c3f6f2a09"
	h.daemon.Handle(context.Background(), forged)
	results := h.wire.results()
	if runs != 0 || len(results) != 2 {
		t.Fatalf("runs %d results %+v", runs, results)
	}
	if results[0].OK || results[0].Message != "the command is not signed" {
		t.Fatalf("unsigned %+v", results[0])
	}
	if results[1].OK || results[1].Message != "the command does not match the request" {
		t.Fatalf("forged %+v", results[1])
	}
}

func TestATrustChangeIsSavedAndReported(t *testing.T) {
	h := newHarness(t, false)
	h.daemon.Handle(context.Background(), h.fixture.Change)
	results := h.wire.results()
	if len(results) != 1 {
		t.Fatalf("results %+v", results)
	}
	result := results[0]
	if !result.OK || result.ID != h.fixture.Change.ID || result.Message != "This server trusts 2 passkeys; 2 reach it." {
		t.Fatalf("result %+v", result)
	}
	if result.Trust == nil || result.Trust.Version != 2 || len(result.Trust.Core) != 2 || len(result.Trust.Access) != 2 {
		t.Fatalf("trust %+v", result.Trust)
	}
	if saved := h.daemon.Trust(); saved.Version != 2 || len(saved.Keys) != 2 {
		t.Fatalf("saved %+v", saved)
	}

	stale := h.fixture.Change
	stale.ID = "6c1f5a52-30de-4c1e-9d1b-0d7c3f6f2a08"
	h.daemon.Handle(context.Background(), stale)
	refused := h.wire.results()[1]
	if refused.OK || refused.Message != "the version is not newer than the stored one" || refused.Trust == nil || refused.Trust.Version != 2 {
		t.Fatalf("a replayed change %+v", refused)
	}
}

func TestAnUnknownKindIsRefused(t *testing.T) {
	h := newHarness(t, true)
	for _, command := range []reporter.Command{
		{Type: "command", ID: "6c1f5a52-30de-4c1e-9d1b-0d7c3f6f2a11", Kind: "host", Name: "server-1", Action: "dance", Signed: h.fixture.Command.Signed},
		{Type: "command", ID: "6c1f5a52-30de-4c1e-9d1b-0d7c3f6f2a12", Kind: "trust", Name: "server-1", Action: "drop", Signed: h.fixture.Change.Signed},
		{Type: "command", ID: "6c1f5a52-30de-4c1e-9d1b-0d7c3f6f2a13", Kind: "stack", Name: "web", Action: "restart", Signed: "x"},
	} {
		h.daemon.Handle(context.Background(), command)
	}
	results := h.wire.results()
	want := []string{"this server cannot run host/dance", "this server cannot run trust/drop", "this server cannot run stack/restart"}
	if len(results) != len(want) {
		t.Fatalf("results %+v", results)
	}
	for index, result := range results {
		if result.OK || result.Message != want[index] {
			t.Fatalf("result %d %+v", index, result)
		}
	}
}

func TestAnIDThatCannotNameAFileIsRefused(t *testing.T) {
	h := newHarness(t, true)
	runs := 0
	h.daemon.Handlers["host/restart"] = counting(&runs, "Restarting now.")
	bad := h.fixture.Command
	bad.ID = "../trust"
	h.daemon.Handle(context.Background(), bad)
	results := h.wire.results()
	if runs != 0 || len(results) != 1 || results[0].OK || results[0].Message != "the command id is not valid" {
		t.Fatalf("runs %d results %+v", runs, results)
	}
	if entries, _ := os.ReadDir(filepath.Join(h.daemon.State, "ledger")); len(entries) != 0 {
		t.Fatalf("the ledger holds %d entries", len(entries))
	}
}

func TestProgressAndLongMessagesFitTheWire(t *testing.T) {
	h := newHarness(t, true)
	long := make([]byte, 3000)
	for index := range long {
		long[index] = 'x'
	}
	long[2047], long[2048] = 0xc3, 0xa9
	h.daemon.Handlers["host/restart"] = func(_ context.Context, _ trust.Command, progress func(string)) (string, error) {
		progress(string(long))
		return string(long), nil
	}
	h.daemon.Handle(context.Background(), h.fixture.Command)
	h.wire.mu.Lock()
	defer h.wire.mu.Unlock()
	if len(h.wire.sent) != 2 {
		t.Fatalf("sent %d messages", len(h.wire.sent))
	}
	line, ok := h.wire.sent[0].(reporter.Progress)
	if !ok || line.Type != "progress" || line.ID != h.fixture.Command.ID || len(line.Line) != 512 {
		t.Fatalf("progress %T %d", h.wire.sent[0], len(line.Line))
	}
	result := h.wire.sent[1].(reporter.Result)
	if len(result.Message) != 2047 {
		t.Fatalf("message is %d bytes", len(result.Message))
	}
}

func TestAnOutputTravelsWithItsResultUntilItIsAcknowledged(t *testing.T) {
	h := newHarness(t, true)
	h.daemon.Handlers["host/restart"] = func(ctx context.Context, _ trust.Command, _ func(string)) (string, error) {
		Output(ctx, "line 1\nline 2\n")
		return "Two lines.", nil
	}
	h.daemon.Handle(context.Background(), h.fixture.Command)
	results := h.wire.results()
	if len(results) != 1 || results[0].Output != "line 1\nline 2\n" || results[0].Message != "Two lines." {
		t.Fatalf("results %+v", results)
	}
	h.daemon.Ack(h.fixture.Command.ID)
	stored, _, err := h.daemon.read(h.fixture.Command.ID)
	if err != nil || stored.Result == nil || stored.Result.Output != "" || !stored.Acked {
		t.Fatalf("the ledger kept %+v %v", stored.Result, err)
	}
	h.daemon.Handlers["host/restart"] = func(ctx context.Context, _ trust.Command, _ func(string)) (string, error) {
		Output(ctx, "half")
		return "", errors.New("it failed")
	}
	again := newHarness(t, true)
	again.daemon.Handlers = h.daemon.Handlers
	again.daemon.Handle(context.Background(), again.fixture.Command)
	if failed := again.wire.results(); len(failed) != 1 || failed[0].OK || failed[0].Output != "" {
		t.Fatalf("a failure carried output: %+v", failed)
	}
}
