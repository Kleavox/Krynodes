package docker

import (
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

var start = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)

func running(name, health string) reporter.ContainerEntry {
	entry := reporter.ContainerEntry{Name: name, Image: "busybox", State: "running", Ports: []string{}}
	if health != "" {
		entry.Health = &health
	}
	return entry
}

func stopped(name string) reporter.ContainerEntry {
	return reporter.ContainerEntry{Name: name, Image: "busybox", State: "stopped", Ports: []string{}}
}

func machine(containers ...reporter.ContainerEntry) reporter.Inventory {
	return reporter.Inventory{Type: "inventory", Docker: "ready", Containers: containers}
}

func look(checks *Checks, inventory reporter.Inventory, at time.Time) []reporter.Check {
	checks.observe(inventory, at)
	sent := checks.due(at)
	for _, check := range sent {
		checks.sent(check, at)
	}
	return sent
}

func one(t *testing.T, got []reporter.Check, state string) reporter.Check {
	t.Helper()
	if len(got) != 1 || got[0].State != state {
		t.Fatalf("want one %s transition, got %+v", state, got)
	}
	return got[0]
}

func TestAContainerWithAHealthcheckIsUpOnlyWhenHealthy(t *testing.T) {
	cases := []struct {
		container reporter.ContainerEntry
		state     string
		detail    string
	}{
		{running("web-1", ""), "up", "running"},
		{running("web-1", "healthy"), "up", "healthy"},
		{running("web-1", "starting"), "down", "starting"},
		{running("web-1", "unhealthy"), "down", "unhealthy"},
		{stopped("web-1"), "down", "stopped"},
		{reporter.ContainerEntry{Name: "web-1", State: "restarting", Ports: []string{}}, "down", "restarting"},
		{reporter.ContainerEntry{Name: "web-1", State: "paused", Ports: []string{}}, "down", "paused"},
	}
	for _, each := range cases {
		checks := NewChecks()
		checks.Choose([]string{"web-1"})
		got := one(t, look(checks, machine(each.container), start), each.state)
		if got.Detail != each.detail || got.Cause != nil || got.At != "2026-11-24T10:00:00Z" || got.Type != "check" || got.Name != "web-1" {
			t.Fatalf("%+v gave %+v", each.container, got)
		}
	}
}

func TestARemovedContainerIsGone(t *testing.T) {
	checks := NewChecks()
	checks.Choose([]string{"web-1"})
	one(t, look(checks, machine(running("web-1", "")), start), "up")
	gone := one(t, look(checks, machine(), start.Add(2*time.Minute)), "gone")
	if gone.Detail != "" {
		t.Fatalf("gone %+v", gone)
	}
	missing := NewChecks()
	missing.Choose([]string{"web-1"})
	one(t, look(missing, reporter.Inventory{Docker: "missing"}, start), "gone")
	halted := NewChecks()
	halted.Choose([]string{"web-1"})
	one(t, look(halted, reporter.Inventory{Docker: "stopped"}, start), "down")
}

func TestAFlappingContainerSendsOneTransitionPerMinute(t *testing.T) {
	checks := NewChecks()
	checks.Choose([]string{"web-1"})
	one(t, look(checks, machine(running("web-1", "")), start), "up")
	flip := start.Add(5 * time.Minute)
	var sent []reporter.Check
	for index := range 10 {
		state := machine(stopped("web-1"))
		if index%2 == 1 {
			state = machine(running("web-1", ""))
		}
		sent = append(sent, look(checks, state, flip.Add(time.Duration(index)*6*time.Second))...)
	}
	if len(sent) != 1 || sent[0].State != "down" {
		t.Fatalf("ten flips in a minute send one transition, got %+v", sent)
	}
	if at, ok := checks.next(flip.Add(59 * time.Second)); !ok || !at.Equal(flip.Add(time.Minute)) {
		t.Fatalf("the next transition is due at +60 s, got %v %v", at, ok)
	}
	if got := look(checks, machine(running("web-1", "")), flip.Add(59*time.Second)); len(got) != 0 {
		t.Fatalf("still inside the minute: %+v", got)
	}
	last := one(t, look(checks, machine(running("web-1", "")), flip.Add(time.Minute)), "up")
	if last.At != flip.Add(54*time.Second).Format(time.RFC3339) {
		t.Fatalf("the transition carries the time its state began, got %s", last.At)
	}
	if got := look(checks, machine(stopped("web-1")), flip.Add(70*time.Second)); len(got) != 0 {
		t.Fatalf("one per minute: %+v", got)
	}
	one(t, look(checks, machine(stopped("web-1")), flip.Add(2*time.Minute)), "down")
	if _, ok := checks.next(flip.Add(2 * time.Minute)); ok {
		t.Fatal("nothing is waiting once the latest state is sent")
	}
}

func TestAFlapThatEndsWhereItBeganSendsNothingMore(t *testing.T) {
	checks := NewChecks()
	checks.Choose([]string{"web-1"})
	one(t, look(checks, machine(running("web-1", "")), start), "up")
	one(t, look(checks, machine(stopped("web-1")), start.Add(time.Minute)), "down")
	look(checks, machine(running("web-1", "")), start.Add(70*time.Second))
	if got := look(checks, machine(stopped("web-1")), start.Add(2*time.Minute)); len(got) != 0 {
		t.Fatalf("down was already sent: %+v", got)
	}
}

func TestAnOwnersStopIsMarkedOwner(t *testing.T) {
	checks := NewChecks()
	checks.Choose([]string{"web-1", "web-2"})
	look(checks, machine(running("web-1", ""), running("web-2", "")), start)
	checks.owner["web-1"] = start.Add(5 * time.Minute)
	got := look(checks, machine(stopped("web-1"), stopped("web-2")), start.Add(2*time.Minute))
	if len(got) != 2 || got[0].Name != "web-1" || got[0].Cause == nil || *got[0].Cause != "owner" || got[1].Cause != nil {
		t.Fatalf("got %+v", got)
	}
	up := one(t, look(checks, machine(running("web-1", ""), stopped("web-2")), start.Add(4*time.Minute)), "up")
	if up.Cause == nil || *up.Cause != "owner" {
		t.Fatalf("every transition before the mark's time is the owner's: %+v", up)
	}
	late := one(t, look(checks, machine(stopped("web-1"), stopped("web-2")), start.Add(6*time.Minute)), "down")
	if late.Cause != nil {
		t.Fatalf("a transition past the mark's time is not the owner's: %+v", late)
	}
	if _, kept := checks.owner["web-1"]; kept {
		t.Fatal("a mark past its time is forgotten")
	}
}

func TestARestateSendsEveryStateAgainButKeepsTheMinute(t *testing.T) {
	checks := NewChecks()
	checks.Choose([]string{"web-1"})
	one(t, look(checks, machine(stopped("web-1")), start), "down")
	checks.Restate()
	if !checks.restated() || checks.restated() {
		t.Fatal("a restate is taken once")
	}
	if got := look(checks, machine(stopped("web-1")), start.Add(30*time.Second)); len(got) != 0 {
		t.Fatalf("the minute still holds: %+v", got)
	}
	again := one(t, look(checks, machine(stopped("web-1")), start.Add(time.Minute)), "down")
	if again.At != "2026-11-24T10:00:00Z" {
		t.Fatalf("again %+v", again)
	}
	if got := look(checks, machine(stopped("web-1")), start.Add(3*time.Minute)); len(got) != 0 {
		t.Fatalf("restated once: %+v", got)
	}
}

func TestAnUnsentTransitionIsTriedAgain(t *testing.T) {
	checks := NewChecks()
	checks.Choose([]string{"web-1"})
	checks.observe(machine(running("web-1", "")), start)
	if got := checks.due(start); len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	if got := checks.due(start.Add(time.Second)); len(got) != 1 || got[0].At != "2026-11-24T10:00:00Z" {
		t.Fatalf("a transition that was not sent stays due: %+v", got)
	}
}

func TestChoosingAgainForgetsWhatWasDropped(t *testing.T) {
	checks := NewChecks()
	checks.Choose([]string{"web-1"})
	one(t, look(checks, machine(running("web-1", "")), start), "up")
	checks.Choose(nil)
	if got := look(checks, machine(running("web-1", "")), start.Add(time.Second)); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
	checks.Choose([]string{"web-1"})
	one(t, look(checks, machine(running("web-1", "")), start.Add(2*time.Second)), "up")
}
