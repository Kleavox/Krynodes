package service

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/windows/internal/pipe"
)

func TestDisconnectLastsUntilTheServiceRestarts(t *testing.T) {
	f := newFixture(t)
	f.joined()
	if err := f.service.Connect(false); err != nil {
		t.Fatal(err)
	}
	if down := f.last(); !reflect.DeepEqual(down, Wanted{}) || f.service.Status(0).Connected {
		t.Fatalf("disconnected tunnel %+v", down)
	}
	raw, err := os.ReadFile(filepath.Join(f.service.Dir, stateFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.service.Dir, stateFile), append(bytes.TrimSuffix(raw, []byte("}")), []byte(`,"off":true}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	var restarted []Wanted
	again := &Service{Dir: f.service.Dir, Secrets: f.secrets, Now: f.service.Now, Apply: func(wanted Wanted) error { restarted = append(restarted, wanted); return nil }}
	again.mu.Lock()
	again.refresh()
	again.mu.Unlock()
	again.push()
	if len(restarted) != 1 || len(restarted[0].Peers) != 2 || !again.Status(0).Connected {
		t.Fatalf("a restart did not connect: %+v", restarted)
	}
	if err := f.service.Connect(true); err != nil {
		t.Fatal(err)
	}
	if up := f.last(); len(up.Peers) != 2 {
		t.Fatalf("connected tunnel %+v", up)
	}
}

func TestOldNotesAreDropped(t *testing.T) {
	f := newFixture(t)
	now := testNow
	f.service.Now = func() time.Time { return now }
	f.service.say("server-1 stopped answering, so the exit node is off.")
	now = now.Add(30 * time.Second)
	f.service.say("server-1 went offline.")
	now = now.Add(31 * time.Second)
	if notes := f.service.Status(0).Notes; !slices.Equal(notes, []string{"server-1 went offline."}) {
		t.Fatalf("notes %v", notes)
	}
	now = now.Add(30 * time.Second)
	if notes := f.service.Status(0).Notes; len(notes) != 0 {
		t.Fatalf("a note older than a minute is still shown: %v", notes)
	}
}

func TestEveryTrayShowsEachNoteOnce(t *testing.T) {
	f := newFixture(t)
	now := testNow
	f.service.Now = func() time.Time { return now }
	if status := f.service.Status(0); len(status.Notes) != 0 || status.Last != 0 {
		t.Fatalf("no note yet: %+v", status.Notes)
	}
	f.service.say("server-1 stopped answering, so the exit node is off.")
	first := f.service.Status(0)
	if !slices.Equal(first.Notes, []string{"server-1 stopped answering, so the exit node is off."}) {
		t.Fatalf("the first tray got %v", first.Notes)
	}
	if again := f.service.Status(first.Last); len(again.Notes) != 0 || again.Last != first.Last {
		t.Fatalf("the first tray was shown the same note again: %v", again.Notes)
	}
	now = now.Add(20 * time.Second)
	if other := f.service.Status(0); !slices.Equal(other.Notes, first.Notes) {
		t.Fatalf("a second tray missed the note: %v", other.Notes)
	}
	now = now.Add(time.Second)
	f.service.say("server-1 went offline.")
	next := f.service.Status(first.Last)
	if !slices.Equal(next.Notes, []string{"server-1 went offline."}) || next.Last <= first.Last {
		t.Fatalf("the first tray got %v, last %d after %d", next.Notes, next.Last, first.Last)
	}
	restarted := &Service{Dir: f.service.Dir, Secrets: f.secrets, Now: func() time.Time { return now.Add(time.Minute) }}
	restarted.say("server-3 went offline.")
	if notes := restarted.Status(next.Last).Notes; !slices.Equal(notes, []string{"server-3 went offline."}) {
		t.Fatalf("after a service restart the tray missed %v", notes)
	}
}

func TestTheTrayChoosesOnlyAnOfferedExit(t *testing.T) {
	f := newFixture(t)
	f.twoPublic()
	for _, server := range []string{server2, server3, laptop1} {
		if err := f.service.Exit(server); !errors.Is(err, pipe.ErrNotOffered) {
			t.Errorf("exit through %s answered %v", server, err)
		}
	}
	if err := f.service.Exit(server1); err != nil || f.last().Exit != server1 {
		t.Fatalf("exit through server-1: %v, %+v", err, f.last().Exit)
	}
	if err := f.service.Exit(""); err != nil || f.last().Exit != "" {
		t.Fatalf("None: %v, %+v", err, f.last().Exit)
	}
	if err := f.service.Exit(server1); err != nil {
		t.Fatal(err)
	}
	if err := f.service.Connect(false); err != nil || f.service.exit != "" {
		t.Fatalf("disconnect kept the exit %q: %v", f.service.exit, err)
	}
	if err := f.service.Exit(server1); !errors.Is(err, errOff) {
		t.Fatalf("an exit while disconnected answered %v", err)
	}
}

func TestStatusNamesTheServersAndTheirMeetingPoint(t *testing.T) {
	f := newFixture(t)
	f.twoPublic()
	f.service.observe(second(0), map[string]answer{server1: {30 * time.Millisecond, true}, server2: {}, server3: {10 * time.Millisecond, true}})
	status := f.service.Status(0)
	if status.Name != "laptop-1" || status.Address != "10.88.0.10" || !status.Connected || status.Dashboard != testOrigin || status.Exit != "" {
		t.Fatalf("status %+v", status)
	}
	var names []string
	for _, server := range status.Servers {
		names = append(names, server.Name+" "+server.Address+" via "+server.Via)
	}
	if want := []string{"server-1 10.88.0.1 via ", "server-2 10.88.0.2 via server-3", "server-3 10.88.0.3 via "}; !slices.Equal(names, want) {
		t.Fatalf("servers %v", names)
	}
	if server := status.Servers[0]; server.Online == nil || !*server.Online || server.RTT == nil || *server.RTT != 30 {
		t.Fatalf("server-1 %+v", server)
	}
	if server := status.Servers[1]; server.Online != nil || server.RTT != nil {
		t.Fatalf("an unanswered server is reported as measured: %+v", server)
	}
	if len(status.Exits) != 1 || status.Exits[0].Node != server1 {
		t.Fatalf("exits %+v", status.Exits)
	}
	f.service.Connect(false)
	if status := f.service.Status(0); status.Connected || status.Servers[0].Online != nil {
		t.Fatalf("a disconnected laptop still measures: %+v", status.Servers[0])
	}
}

func TestAServerGoingOfflineIsToldOnlyWhenAsked(t *testing.T) {
	for _, asked := range []bool{false, true} {
		f := newFixture(t)
		f.twoPublic()
		if err := f.service.NotifyOffline(asked); err != nil {
			t.Fatal(err)
		}
		f.service.observe(second(0), map[string]answer{server1: {30 * time.Millisecond, true}, server3: {10 * time.Millisecond, true}})
		for at := 1; at <= 40; at++ {
			f.service.observe(second(at), map[string]answer{server1: {}, server3: {10 * time.Millisecond, true}})
		}
		want := []string(nil)
		if asked {
			want = []string{"server-1 went offline."}
		}
		status := f.service.Status(0)
		if !slices.Equal(status.Notes, want) || status.NotifyOffline != asked || *status.Servers[0].Online {
			t.Fatalf("asked %v: notes %v, server-1 %+v", asked, status.Notes, status.Servers[0])
		}
		if notes := f.service.Status(status.Last).Notes; len(notes) != 0 {
			t.Fatalf("a shown note came back: %v", notes)
		}
		for at := 41; at <= 100; at++ {
			f.service.observe(second(at), map[string]answer{server1: {}, server3: {}})
		}
		if notes := f.service.Status(status.Last).Notes; len(notes) != 0 {
			t.Fatalf("a laptop that lost its own connection was told a server went offline: %v", notes)
		}
	}
}

func TestStatusDoesNotWaitForTheTunnel(t *testing.T) {
	f := newFixture(t)
	f.joined()
	entered, release := make(chan struct{}), make(chan struct{})
	f.service.Apply = func(Wanted) error {
		close(entered)
		<-release
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- f.service.Exit(server1) }()
	<-entered
	answered := make(chan pipe.Status, 1)
	go func() { answered <- f.service.Status(0) }()
	select {
	case status := <-answered:
		if status.Exit != server1 {
			t.Fatalf("status during the change %+v", status.Exit)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("status waited for the tunnel")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
