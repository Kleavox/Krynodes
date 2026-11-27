package stacks

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

const (
	marker        = "s3cr3t-marker"
	markedCompose = "services:\n  app:\n    image: nginx:1.27\n    environment:\n      SECRET: s3cr3t-marker\n"
	hostCompose   = "services:\n  app:\n    image: nginx:1.27\n    volumes:\n      - /srv/example-data:/data\n"
	hostConfig    = `{"name":"web","networks":{"default":{"name":"web_default","ipam":{}}},"services":{"app":{"command":null,"entrypoint":null,"image":"nginx:1.27","networks":{"default":null},"volumes":[{"type":"bind","source":"/srv/example-data","target":"/data"}]}}}`
)

func progressOf(traffic []any) []string {
	var lines []string
	for _, message := range traffic {
		if line, ok := message.(reporter.Progress); ok {
			lines = append(lines, line.Line)
		}
	}
	return lines
}

func TestAFailedDeployCarriesNoComposeTextInTheMessage(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	args := saving("full", "")
	args["compose"] = sealedCompose(markedCompose)
	managed(t, e, args)
	key, to := browserKey(t)
	f.on(namesOf, "web-app-1\n")
	f.fail(" pull", "service app: SECRET: s3cr3t-marker is not accepted\n")
	trusted, message := signed(t, command("stack", "web", "deploy", map[string]string{"to": to}))
	traffic, result := throughWire(t, e, trusted, message)
	if result.OK || result.Message != "Deploy of web failed." {
		t.Fatalf("result %+v", result)
	}
	body, _ := json.Marshal(traffic)
	if strings.Contains(string(body), marker) {
		t.Fatalf("the wire carries the marker: %s", body)
	}
	lines := progressOf(traffic)
	if !slices.Equal(lines, []string{stepChecking, stepPulling}) {
		t.Fatalf("progress %q", lines)
	}
	detail := opened(t, e, key, result)
	if detail != "pull failed: service app: SECRET: s3cr3t-marker is not accepted" {
		t.Fatalf("detail %q", detail)
	}
}

func TestAVetRefusalIsSealed(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	f.config = hostConfig
	key, to := browserKey(t)
	args := saving("contained", "")
	args["compose"], args["to"] = sealedCompose(hostCompose), to
	trusted, message := signed(t, command("stack", "web", "create", args))
	traffic, result := throughWire(t, e, trusted, message)
	if result.OK || result.Message != "Create of web failed." {
		t.Fatalf("result %+v", result)
	}
	body, _ := json.Marshal(traffic)
	if strings.Contains(string(body), "example-data") {
		t.Fatalf("the wire carries the host path: %s", body)
	}
	if detail := opened(t, e, key, result); detail != "service app mounts /srv/example-data from the server; a Contained stack keeps its data in named volumes" {
		t.Fatalf("detail %q", detail)
	}
	if f.called(" pull") > 0 || f.called(" up ") > 0 {
		t.Fatalf("a refused stack ran: %q", f.calls)
	}
}

func TestAComposeThatDoesNotParseIsSealedToo(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	f.broken = 1
	key, to := browserKey(t)
	args := saving("full", "")
	args["to"] = to
	trusted, message := signed(t, command("stack", "web", "create", args))
	traffic, result := throughWire(t, e, trusted, message)
	body, _ := json.Marshal(traffic)
	if result.OK || result.Message != "Create of web failed." || strings.Contains(string(body), "yaml") {
		t.Fatalf("result %+v", result)
	}
	if detail := opened(t, e, key, result); detail != "compose could not read the file: yaml: line 3: did not find expected key" {
		t.Fatalf("detail %q", detail)
	}
}

func TestEveryStackAndContainerFailureIsOneFixedSentence(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	managed(t, e, saving("full", ""))
	key, _ := testBrowser()
	f.fail("docker", "token=hunter2 at 203.0.113.9\n")
	for _, step := range []struct {
		command trust.Command
		message string
	}{
		{command("stack", "web", "deploy", nil), "Deploy of web failed."},
		{command("stack", "web", "start", nil), "Start of web failed."},
		{command("stack", "web", "stop", nil), "Stop of web failed."},
		{command("stack", "web", "restart", nil), "Restart of web failed."},
		{command("stack", "web", "rollback", nil), "Rollback of web failed."},
		{command("stack", "web", "remove", nil), "Remove of web failed."},
		{command("stack", "web", "restore", nil), "Restore of web failed."},
		{command("stack", "web", "purge", nil), "Delete of web failed."},
		{command("stack", "legacy", "adopt", map[string]string{"access": "full"}), "Adopt of legacy failed."},
		{command("stack", "web", "edit", saving("full", "")), "Edit of web failed."},
		{command("stack", "web", "logs", map[string]string{"lines": "5"}), "Logs of web failed."},
		{command("container", "web-app-1", "start", nil), "Start of web-app-1 failed."},
		{command("container", "web-app-1", "stop", nil), "Stop of web-app-1 failed."},
		{command("container", "web-app-1", "restart", nil), "Restart of web-app-1 failed."},
		{command("container", "web-app-1", "logs", map[string]string{"lines": "5"}), "Logs of web-app-1 failed."},
	} {
		trusted, message := signed(t, step.command)
		traffic, result := throughWire(t, e, trusted, message)
		body, _ := json.Marshal(traffic)
		if result.OK || result.Message != step.message || strings.Contains(string(body), "hunter2") || strings.Contains(string(body), "203.0.113.9") {
			t.Fatalf("%s %s: %+v", step.command.Kind, step.command.Action, result)
		}
		if detail := opened(t, e, key, result); detail == "" {
			t.Fatalf("%s %s: the details are empty", step.command.Kind, step.command.Action)
		}
	}
}

func TestOnlyFixedLinesLeaveAsProgress(t *testing.T) {
	e := testEnv(t, newFake())
	var lines []string
	handle := e.guarded(func(_ context.Context, _ trust.Command, progress func(string)) (string, error) {
		progress(stepPulling)
		progress("pull access denied for " + marker)
		progress(stepStarting)
		return "Done.", nil
	})
	if _, err := handle(context.Background(), command("stack", "web", "deploy", nil), func(line string) { lines = append(lines, line) }); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(lines, []string{stepPulling, stepStarting}) {
		t.Fatalf("progress %q", lines)
	}
}

func TestAFailedUnitKeepsItsOwnWords(t *testing.T) {
	f := newFake()
	e := testEnv(t, f)
	f.fail("systemctl restart -- nginx.service", "Failed to restart nginx.service: Unit nginx.service not found.\n")
	trusted, message := signed(t, command("unit", "nginx.service", "restart", nil))
	result := through(t, e, trusted, message)
	if result.OK || result.Output != "" || !strings.Contains(result.Message, "Unit nginx.service not found.") {
		t.Fatalf("result %+v", result)
	}
}
