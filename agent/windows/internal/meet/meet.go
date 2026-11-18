package meet

import (
	"slices"
	"time"
)

const (
	missesToLeave = 3
	steady        = 60 * time.Second
	settle        = 20 * time.Second
	longestWait   = 30 * time.Minute
)

type server struct {
	rtt     time.Duration
	seen    bool
	misses  int
	since   time.Time
	through int
	broken  time.Time
}

type Chooser struct {
	servers map[string]*server
	only    []string
	limited bool
	current string
	chosen  time.Time
	now     time.Time
	outage  time.Time
	wait    time.Duration
	answers time.Time
}

func (c *Chooser) Only(servers []string) {
	c.only, c.limited = slices.Clone(servers), true
	for name := range c.servers {
		if !slices.Contains(servers, name) {
			delete(c.servers, name)
		}
	}
}

func (c *Chooser) Observe(now time.Time, name string, rtt time.Duration, answered bool) {
	if c.limited && !slices.Contains(c.only, name) {
		return
	}
	if c.servers == nil {
		c.servers = map[string]*server{}
	}
	entry := c.servers[name]
	if entry == nil {
		entry = &server{}
		c.servers[name] = entry
	}
	if now.After(c.now) {
		c.now = now
	}
	if !answered {
		entry.misses++
		entry.since = time.Time{}
		return
	}
	if entry.since.IsZero() {
		entry.since = now
	}
	entry.misses = 0
	if !entry.seen {
		entry.rtt, entry.seen = rtt, true
		return
	}
	entry.rtt += (rtt - entry.rtt) / 8
}

func (c *Chooser) Through(now time.Time, name string, answered bool) {
	if now.After(c.now) {
		c.now = now
	}
	entry := c.servers[name]
	if answered {
		if c.answers.IsZero() {
			c.answers = now
		}
		if now.Sub(c.answers) >= steady {
			c.wait = 0
		}
		if entry != nil {
			entry.through = 0
		}
		return
	}
	c.answers = time.Time{}
	if entry == nil || c.waiting() || now.Sub(c.chosen) < settle {
		return
	}
	entry.through++
	if entry.through < missesToLeave {
		return
	}
	entry.through, entry.broken, c.outage = 0, now, now
	c.wait = min(max(2*c.wait, steady), longestWait)
}

func (c *Chooser) waiting() bool {
	return c.wait > 0 && c.now.Sub(c.outage) < c.wait
}

func (c *Chooser) live(entry *server) bool {
	return entry != nil && entry.seen && entry.misses < missesToLeave && (entry.broken.IsZero() || c.now.Sub(entry.broken) >= steady)
}

func (c *Chooser) Current(connected bool) string {
	best := ""
	for name, entry := range c.servers {
		if !c.live(entry) {
			continue
		}
		if chosen := c.servers[best]; best == "" || entry.rtt < chosen.rtt || (entry.rtt == chosen.rtt && name < best) {
			best = name
		}
	}
	current, was := c.servers[c.current], c.current
	switch {
	case best == "":
		if current == nil {
			c.current = ""
		}
	case !c.live(current):
		c.current = best
	case connected && c.wait == 0 && best != c.current && c.servers[best].rtt*5 <= current.rtt*4 && c.now.Sub(c.servers[best].since) >= steady:
		c.current = best
	}
	if c.current != was {
		c.chosen = c.now
	}
	return c.current
}
