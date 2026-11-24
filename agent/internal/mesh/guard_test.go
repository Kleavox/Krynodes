package mesh

import (
	"bytes"
	"context"
	"log"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/relay"
)

func logged(t *testing.T) *bytes.Buffer {
	t.Helper()
	var output bytes.Buffer
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &output
}

func TestTheGuardPutsBackAMissingJump(t *testing.T) {
	n := joinedNet(t)
	was := n.tables.String()
	said := map[string]string{}
	n.m.keep(t.Context(), said)
	if n.tables.String() != was || len(n.run.called("iptables -w -I")) != 0 || len(n.run.called("iptables-restore")) != 0 {
		t.Fatalf("a guard with every rule in place changed something: %v", n.run.calls)
	}
	output := logged(t)
	jump := "-A INPUT -i kry0 -j KRY-IN"
	for _, tool := range []string{"iptables", "ip6tables"} {
		n.tables.rules[tool+" filter INPUT"] = slices.DeleteFunc(n.tables.rules[tool+" filter INPUT"], func(line string) bool { return line == jump })
	}
	n.run.calls = nil
	n.m.keep(t.Context(), said)
	for _, tool := range []string{"iptables", "ip6tables"} {
		if input := n.tables.chain(tool, "filter", "INPUT"); input[0] != jump {
			t.Fatalf("%s INPUT %q", tool, input)
		}
	}
	if n.tables.String() != was || strings.Count(output.String(), "jumps to its rules were missing") != 2 {
		t.Fatalf("log %q", output.String())
	}
	output.Reset()
	n.m.keep(t.Context(), said)
	if output.Len() != 0 {
		t.Fatalf("a guard with nothing to put back said %q", output.String())
	}
}

func TestTheGuardAddsTheDockerJumpWhenDockerAppears(t *testing.T) {
	n := joinedNet(t)
	for _, tool := range []string{"iptables", "ip6tables"} {
		delete(n.tables.rules, tool+" filter "+network.DockerUser)
	}
	n.m.keep(t.Context(), map[string]string{})
	for _, tool := range []string{"iptables", "ip6tables"} {
		if !slices.Equal(n.tables.chain(tool, "filter", network.DockerUser), []string{"-A DOCKER-USER -i kry0 -j KRY-FWD"}) {
			t.Fatalf("%s:\n%s", tool, n.tables)
		}
	}
	n.tables.rules["iptables filter "+network.DockerUser] = []string{"-A DOCKER-USER -j RETURN"}
	n.m.keep(t.Context(), map[string]string{})
	if got := n.tables.chain("iptables", "filter", network.DockerUser); !slices.Equal(got, []string{"-A DOCKER-USER -i kry0 -j KRY-FWD", "-A DOCKER-USER -j RETURN"}) {
		t.Fatalf("DOCKER-USER %q", got)
	}
}

func TestTheGuardRestoresChainsAFirewallReloadRemoved(t *testing.T) {
	n := joinedNet(t)
	n.apply(t, exitOn)
	was := n.tables.String()
	output := logged(t)
	for key := range n.tables.rules {
		if strings.Contains(key, " KRY-") {
			delete(n.tables.rules, key)
			continue
		}
		n.tables.rules[key] = slices.DeleteFunc(n.tables.rules[key], func(line string) bool { return strings.Contains(line, "-j KRY-") })
	}
	n.tables.rules["iptables filter "+network.InChain] = []string{"-A KRY-IN -j ACCEPT"}
	n.m.keep(t.Context(), map[string]string{})
	if now := n.tables.String(); now != was {
		t.Fatalf("the guard did not put the rules back:\n%s\nwas\n%s", now, was)
	}
	if strings.Count(output.String(), "were changed from outside") != 2 {
		t.Fatalf("log %q", output.String())
	}
}

func TestTheGuardSaysAFailureOnce(t *testing.T) {
	n := joinedNet(t)
	output := logged(t)
	n.run.failing["ip6tables -w -S"] = "ip6tables: Permission denied"
	said := map[string]string{}
	for range 3 {
		n.m.keep(t.Context(), said)
	}
	if strings.Count(output.String(), "ip6tables cannot list its rules") != 1 {
		t.Fatalf("log %q", output.String())
	}
}

func TestAnUnreadableRecordKeepsThePairsTheRelayCarries(t *testing.T) {
	n := joinedNet(t)
	n.apply(t, asIs)
	sets := make(chan []relay.Pair, 64)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		n.m.guard(ctx, 5*time.Millisecond, func(pairs []relay.Pair) { sets <- pairs })
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()
	if pairs := <-sets; len(pairs) != 1 || pairs[0].Port != 51920 {
		t.Fatalf("pairs %+v", pairs)
	}
	cancel()
	<-done
	saved, err := os.ReadFile(n.m.statePath())
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(n.m.statePath())
	if err := os.Mkdir(n.m.statePath(), 0o700); err != nil {
		t.Fatal(err)
	}
	if pairs, ok := n.m.keep(t.Context(), map[string]string{}); ok || pairs != nil {
		t.Fatalf("an unreadable record set the pairs to %+v", pairs)
	}
	os.Remove(n.m.statePath())
	if err := os.WriteFile(n.m.statePath(), saved, 0o600); err != nil {
		t.Fatal(err)
	}
	if pairs, ok := n.m.keep(t.Context(), map[string]string{}); !ok || len(pairs) != 1 {
		t.Fatalf("a readable record carries the pairs again: %+v", pairs)
	}
	os.Remove(n.m.statePath())
	if pairs, ok := n.m.keep(t.Context(), map[string]string{}); !ok || pairs != nil {
		t.Fatalf("a server that left carries nothing: %+v", pairs)
	}
}
