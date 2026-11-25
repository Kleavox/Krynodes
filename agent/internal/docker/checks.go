package docker

import (
	"slices"
	"sync"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const rate = time.Minute

type observed struct {
	state  string
	detail string
	at     time.Time
	owner  bool
}

type report struct {
	state string
	at    time.Time
}

type Checks struct {
	mu     sync.Mutex
	names  []string
	owner  map[string]time.Time
	seen   map[string]observed
	last   map[string]report
	wake   chan struct{}
	fresh  bool
	urgent bool
}

func NewChecks() *Checks {
	return &Checks{owner: map[string]time.Time{}, seen: map[string]observed{}, last: map[string]report{}, wake: make(chan struct{}, 1)}
}

func (c *Checks) Choose(names []string) {
	c.mu.Lock()
	c.names = slices.Clone(names)
	for name := range c.seen {
		if !slices.Contains(names, name) {
			delete(c.seen, name)
			delete(c.last, name)
		}
	}
	c.mu.Unlock()
	c.poke()
}

func (c *Checks) Owner(container string, until time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.owner[container] = until
}

func (c *Checks) Restate() {
	c.mu.Lock()
	for name, last := range c.last {
		c.last[name] = report{at: last.at}
	}
	c.fresh = true
	c.mu.Unlock()
	c.poke()
}

func (c *Checks) restated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	fresh := c.fresh
	c.fresh = false
	return fresh
}

func (c *Checks) Changed() {
	c.mu.Lock()
	c.urgent = true
	c.mu.Unlock()
	c.poke()
}

func (c *Checks) hurried() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	urgent := c.urgent
	c.urgent = false
	return urgent
}

func (c *Checks) poke() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func stateOf(inventory reporter.Inventory, name string) (string, string) {
	switch inventory.Docker {
	case "missing":
		return "gone", ""
	case "stopped":
		return "down", "Docker did not answer"
	}
	for _, container := range inventory.Containers {
		if container.Name != name {
			continue
		}
		switch {
		case container.State != "running":
			return "down", container.State
		case container.Health == nil:
			return "up", "running"
		case *container.Health == "healthy":
			return "up", "healthy"
		}
		return "down", *container.Health
	}
	return "gone", ""
}

func (c *Checks) observe(inventory reporter.Inventory, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, name := range c.names {
		state, detail := stateOf(inventory, name)
		if previous, ok := c.seen[name]; ok && previous.state == state {
			continue
		}
		c.seen[name] = observed{state: state, detail: detail, at: now, owner: now.Before(c.owner[name])}
	}
	for name, until := range c.owner {
		if !now.Before(until) {
			delete(c.owner, name)
		}
	}
}

func (c *Checks) due(now time.Time) []reporter.Check {
	c.mu.Lock()
	defer c.mu.Unlock()
	var due []reporter.Check
	for _, name := range c.names {
		current, ok := c.seen[name]
		last, reported := c.last[name]
		if !ok || (reported && (last.state == current.state || now.Before(last.at.Add(rate)))) {
			continue
		}
		var cause *string
		if current.owner {
			owner := "owner"
			cause = &owner
		}
		due = append(due, reporter.Check{Type: "check", Name: name, State: current.state, Cause: cause, At: current.at.UTC().Format(time.RFC3339), Detail: current.detail})
	}
	return due
}

func (c *Checks) sent(check reporter.Check, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, chosen := c.seen[check.Name]; chosen {
		c.last[check.Name] = report{state: check.State, at: now}
	}
}

func (c *Checks) next(now time.Time) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var earliest time.Time
	for _, name := range c.names {
		current, ok := c.seen[name]
		last, reported := c.last[name]
		if !ok || !reported || last.state == current.state {
			continue
		}
		if at := last.at.Add(rate); at.After(now) && (earliest.IsZero() || at.Before(earliest)) {
			earliest = at
		}
	}
	return earliest, !earliest.IsZero()
}
