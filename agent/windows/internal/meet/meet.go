package meet

import (
	"slices"
	"time"
)

const (
	missesToLeave = 3
	steady        = 60 * time.Second
)

type server struct {
	rtt    time.Duration
	seen   bool
	misses int
	since  time.Time
}

type Chooser struct {
	servers map[string]*server
	only    []string
	limited bool
	current string
	now     time.Time
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

func live(entry *server) bool {
	return entry != nil && entry.seen && entry.misses < missesToLeave
}

func (c *Chooser) Current(connected bool) string {
	best := ""
	for name, entry := range c.servers {
		if !live(entry) {
			continue
		}
		if chosen := c.servers[best]; best == "" || entry.rtt < chosen.rtt || (entry.rtt == chosen.rtt && name < best) {
			best = name
		}
	}
	current := c.servers[c.current]
	switch {
	case best == "":
		if current == nil {
			c.current = ""
		}
	case !live(current):
		c.current = best
	case connected && best != c.current && c.servers[best].rtt*5 <= current.rtt*4 && c.now.Sub(c.servers[best].since) >= steady:
		c.current = best
	}
	return c.current
}
