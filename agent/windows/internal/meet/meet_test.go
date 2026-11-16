package meet

import (
	"testing"
	"time"
)

var start = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

type round map[string]time.Duration

func (c *Chooser) second(t *testing.T, at int, answers round, servers ...string) string {
	t.Helper()
	for _, name := range servers {
		rtt, answered := answers[name]
		c.Observe(start.Add(time.Duration(at)*time.Second), name, rtt, answered)
	}
	return c.Current(true)
}

func TestTheChooserMovesAfterThreeMisses(t *testing.T) {
	var c Chooser
	both := round{"server-1": 10 * time.Millisecond, "server-2": 20 * time.Millisecond}
	if got := c.second(t, 0, both, "server-1", "server-2"); got != "server-1" {
		t.Fatalf("starts on %q, want the faster server-1", got)
	}
	onlyTwo := round{"server-2": 20 * time.Millisecond}
	for at := 1; at <= 2; at++ {
		if got := c.second(t, at, onlyTwo, "server-1", "server-2"); got != "server-1" {
			t.Fatalf("after %d misses moved to %q", at, got)
		}
	}
	if got := c.second(t, 3, onlyTwo, "server-1", "server-2"); got != "server-2" {
		t.Fatalf("after 3 misses still on %q", got)
	}
}

func TestTheChooserDoesNotFlapBackBeforeSixtySteadySeconds(t *testing.T) {
	var c Chooser
	both := round{"server-1": 10 * time.Millisecond, "server-2": 20 * time.Millisecond}
	c.second(t, 0, both, "server-1", "server-2")
	for at := 1; at <= 3; at++ {
		c.second(t, at, round{"server-2": 20 * time.Millisecond}, "server-1", "server-2")
	}
	for at := 4; at < 64; at++ {
		if got := c.second(t, at, both, "server-1", "server-2"); got != "server-2" {
			t.Fatalf("moved back to %q after %d steady seconds", got, at-4)
		}
	}
	if got := c.second(t, 64, both, "server-1", "server-2"); got != "server-1" {
		t.Fatalf("after 60 steady seconds still on %q", got)
	}
	if got := c.second(t, 65, round{"server-2": 20 * time.Millisecond}, "server-1", "server-2"); got != "server-1" {
		t.Fatalf("one miss moved it to %q", got)
	}
}

func TestTheChooserNeedsTwentyPercentToMoveBack(t *testing.T) {
	var c Chooser
	c.second(t, 0, round{"server-1": 20 * time.Millisecond}, "server-1")
	near := round{"server-1": 20 * time.Millisecond, "server-2": 17 * time.Millisecond}
	for at := 1; at <= 120; at++ {
		if got := c.second(t, at, near, "server-1", "server-2"); got != "server-1" {
			t.Fatalf("moved to %q for 15%% at %d s", got, at)
		}
	}
	far := round{"server-1": 20 * time.Millisecond, "server-2": 15 * time.Millisecond}
	for at := 121; at <= 180; at++ {
		c.second(t, at, far, "server-1", "server-2")
	}
	if got := c.Current(true); got != "server-2" {
		t.Fatalf("25%% faster for 60 s and still on %q", got)
	}
}

func TestTheChooserNeverPicksAHeldServer(t *testing.T) {
	var c Chooser
	c.Only([]string{"server-2"})
	both := round{"server-1": 10 * time.Millisecond, "server-2": 30 * time.Millisecond}
	if got := c.second(t, 0, both, "server-1", "server-2"); got != "server-2" {
		t.Fatalf("chose %q while server-1 is held", got)
	}
	for at := 1; at <= 120; at++ {
		c.second(t, at, both, "server-1", "server-2")
	}
	if got := c.Current(true); got != "server-2" {
		t.Fatalf("moved to held %q", got)
	}

	var d Chooser
	d.second(t, 0, both, "server-1", "server-2")
	d.Only([]string{"server-2"})
	if got := d.Current(true); got != "server-2" {
		t.Fatalf("stayed on %q after it was held", got)
	}
	d.Only([]string{"server-1"})
	if got := d.second(t, 1, round{}, "server-1", "server-2"); got != "" {
		t.Fatalf("chose %q with no allowed server answering", got)
	}
}

func TestTheChooserMovesForSpeedOnlyWhileConnected(t *testing.T) {
	var c Chooser
	c.second(t, 0, round{"server-1": 20 * time.Millisecond}, "server-1")
	far := round{"server-1": 20 * time.Millisecond, "server-2": 15 * time.Millisecond}
	for at := 1; at <= 61; at++ {
		for _, name := range []string{"server-1", "server-2"} {
			c.Observe(start.Add(time.Duration(at)*time.Second), name, far[name], true)
		}
		if got := c.Current(false); got != "server-1" {
			t.Fatalf("moved to %q for speed while the stream was down at %d s", got, at)
		}
	}
	if got := c.Current(true); got != "server-2" {
		t.Fatalf("connected again and still on %q", got)
	}

	var d Chooser
	both := round{"server-1": 10 * time.Millisecond, "server-2": 20 * time.Millisecond}
	d.second(t, 0, both, "server-1", "server-2")
	for at := 1; at <= 3; at++ {
		for _, name := range []string{"server-1", "server-2"} {
			rtt, answered := round{"server-2": 20 * time.Millisecond}[name]
			d.Observe(start.Add(time.Duration(at)*time.Second), name, rtt, answered)
		}
	}
	if got := d.Current(false); got != "server-2" {
		t.Fatalf("stayed on a dead %q while the stream was down", got)
	}
}
