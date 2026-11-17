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

func TestABrokenRelayIsLeftAfterThreeMissesThroughIt(t *testing.T) {
	var c Chooser
	both := round{"server-1": 10 * time.Millisecond, "server-2": 20 * time.Millisecond}
	at := func(second int) time.Time { return start.Add(time.Duration(second) * time.Second) }
	c.second(t, 0, both, "server-1", "server-2")
	for second := 1; second < 20; second++ {
		c.Through(at(second), "server-1", false)
		if got := c.second(t, second, both, "server-1", "server-2"); got != "server-1" {
			t.Fatalf("left %q at %d s, while the member behind NAT may not have the hint yet", got, second)
		}
	}
	for second := 20; second <= 21; second++ {
		c.Through(at(second), "server-1", false)
		if got := c.second(t, second, both, "server-1", "server-2"); got != "server-1" {
			t.Fatalf("left after %d misses", second-19)
		}
	}
	c.Through(at(22), "server-1", true)
	c.Through(at(23), "server-1", false)
	c.Through(at(24), "server-1", false)
	if got := c.second(t, 24, both, "server-1", "server-2"); got != "server-1" {
		t.Fatalf("an answer did not start the count again: %q", got)
	}
	c.Through(at(25), "server-1", false)
	if got := c.second(t, 25, both, "server-1", "server-2"); got != "server-2" {
		t.Fatalf("3 misses in a row through server-1 and still on %q", got)
	}
	for second := 26; second < 86; second++ {
		c.Through(at(second), "server-2", true)
		if got := c.second(t, second, both, "server-1", "server-2"); got != "server-2" {
			t.Fatalf("went back to the broken relay at %d s", second)
		}
	}
	c.Through(at(86), "server-2", true)
	if got := c.second(t, 86, both, "server-1", "server-2"); got != "server-1" {
		t.Fatalf("after 60 s of steady answers the faster point is not tried again: %q", got)
	}
}

func (c *Chooser) moves(t *testing.T, from, to int, answers func(second int, point string) bool) []int {
	t.Helper()
	both := round{"server-1": 10 * time.Millisecond, "server-2": 20 * time.Millisecond}
	current := c.second(t, from, both, "server-1", "server-2")
	var moved []int
	for second := from + 1; second <= to; second++ {
		c.Through(start.Add(time.Duration(second)*time.Second), current, answers(second, current))
		if got := c.second(t, second, both, "server-1", "server-2"); got != current {
			current, moved = got, append(moved, second)
		}
	}
	return moved
}

func TestALaptopOnADeadRelayReturnsToAMendedPointWithinTheFirstBackoff(t *testing.T) {
	var c Chooser
	moved := c.moves(t, 0, 600, func(second int, point string) bool {
		return point == "server-1" && second > 30
	})
	if len(moved) != 2 || moved[0] != 22 || moved[1] > 22+60+missesToLeave {
		t.Fatalf("moves at %v s; want one to server-2 at 22 s and one back to the mended server-1 within the first backoff", moved)
	}
	if got := c.Current(true); got != "server-1" {
		t.Fatalf("ended on %q", got)
	}
}

func TestAMemberUnreachableEverywhereForAnHourMovesTheLaptopAFewTimesWithGrowingGaps(t *testing.T) {
	var c Chooser
	moved := c.moves(t, 0, 3600, func(int, string) bool { return false })
	want := []int{22, 84, 206, 448, 930, 1892}
	if len(moved) != len(want) {
		t.Fatalf("moves at %v s; want exactly %v", moved, want)
	}
	for i := range want {
		if moved[i] != want[i] {
			t.Fatalf("moves at %v s; want exactly %v", moved, want)
		}
		if i > 1 && moved[i]-moved[i-1] <= moved[i-1]-moved[i-2] {
			t.Fatalf("the gaps between moves %v do not grow", moved)
		}
	}
	more := c.moves(t, 3600, 3600+4*int(longestWait/time.Second), func(int, string) bool { return false })
	if len(more) < 3 {
		t.Fatalf("past the first hour moves at %v s; want one about every %v", more, longestWait)
	}
	for i := 1; i < len(more); i++ {
		if gap := time.Duration(more[i]-more[i-1]) * time.Second; gap > longestWait+missesToLeave*time.Second {
			t.Fatalf("a gap of %v between moves passes the cap of %v", gap, longestWait)
		}
	}
}

func TestALossyMemberMovesTheLaptopAsRarelyAsAnUnreachableOne(t *testing.T) {
	var lossy, gone Chooser
	moved := lossy.moves(t, 0, 3600, func(second int, _ string) bool { return second%4 == 0 })
	unreachable := gone.moves(t, 0, 3600, func(int, string) bool { return false })
	want := []int{23, 87, 211, 455, 939, 1903}
	if len(moved) != len(unreachable) || len(moved) != len(want) {
		t.Fatalf("a member answering 1 round in 4 moved the laptop at %v s; unreachable at %v s; want exactly %v", moved, unreachable, want)
	}
	for i := range want {
		if moved[i] != want[i] {
			t.Fatalf("moves at %v s; want exactly %v", moved, want)
		}
		if i > 1 && moved[i]-moved[i-1] <= moved[i-1]-moved[i-2] {
			t.Fatalf("the gaps between moves %v do not grow", moved)
		}
	}
}

func TestSixtySecondsOfSteadyAnswersResetTheBackoff(t *testing.T) {
	steadyFor := func(miss int) []int {
		var c Chooser
		return c.moves(t, 0, 500, func(second int, _ string) bool {
			return second >= 85 && second <= 145 && second != miss
		})
	}
	same := func(got, want []int) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range want {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}
	if moved, want := steadyFor(0), []int{22, 84, 148, 210, 332}; !same(moved, want) {
		t.Fatalf("answers from 85 s to 145 s, moves at %v s; want %v, the window back at 60 s", moved, want)
	}
	if moved, want := steadyFor(100), []int{22, 84, 206, 448}; !same(moved, want) {
		t.Fatalf("answers from 85 s to 145 s but a miss at 100 s, moves at %v s; want %v, the window still doubling", moved, want)
	}
	if moved, want := steadyFor(85), []int{22, 84, 206, 448}; !same(moved, want) {
		t.Fatalf("59 s of answers, moves at %v s; want %v, the window still doubling", moved, want)
	}
}
