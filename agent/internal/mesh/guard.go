package mesh

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/relay"
)

var guarded = []string{network.InChain, network.ForwardChain, network.ExitChain, network.EdgeChain}

func (m *Mesh) Guard(ctx context.Context, every time.Duration) {
	carrier := relay.New(m.Run)
	defer carrier.Close()
	m.guard(ctx, every, carrier.Set)
}

func (m *Mesh) guard(ctx context.Context, every time.Duration, set func([]relay.Pair)) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	said := map[string]string{}
	for {
		if pairs, ok := m.keep(ctx, said); ok {
			set(pairs)
		}
		m.holdMeetings(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func whole(listing, body string) bool {
	count := func(text, prefix string) int {
		found := 0
		for line := range strings.SplitSeq(text, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line)+" ", prefix) {
				found++
			}
		}
		return found
	}
	for _, chain := range guarded {
		if count(listing, "-N "+chain+" ") != 1 || count(listing, "-A "+chain+" ") != count(body, "-A "+chain+" ") {
			return false
		}
	}
	return true
}

func (m *Mesh) keep(ctx context.Context, said map[string]string) ([]relay.Pair, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	note := func(key string, err error) {
		text := ""
		if err != nil {
			text = err.Error()
		}
		if said[key] != text && text != "" {
			log.Printf("private network: %s", text)
		}
		said[key] = text
	}
	current, err := m.load()
	note("record", err)
	if err != nil {
		return nil, false
	}
	self := m.Trust().NodeID
	if self == "" {
		return nil, false
	}
	if document, dropped, ok := m.boot(current); ok {
		m.keepRules(ctx, document, dropped, note)
	}
	if !current.Joined || current.Document == nil {
		return nil, true
	}
	view := m.view(current)
	me, _ := member(view, self)
	note("exit", m.exit(ctx, view, me))
	if !slices.Equal(current.Relays, relayPorts(view, me)) {
		note("relay ports", m.syncRelayPorts(ctx, &current, view, me))
		note("save", m.save(current))
	}
	return relayPairs(view, me), true
}

func (m *Mesh) keepRules(ctx context.Context, document network.Document, dropped []string, note func(string, error)) {
	for _, entry := range families {
		listing, listed := m.output(ctx, entry.tool, "-w", "-S")
		if !listed {
			note(entry.tool, fmt.Errorf("%s cannot list its rules", entry.tool))
			continue
		}
		restored, inserted, err := m.rules(ctx, entry, document, dropped, func(body string) bool { return whole(listing, body) })
		note(entry.tool, err)
		if restored && err == nil {
			log.Printf("private network: the rules in %s were changed from outside; they are back", entry.tool)
		}
		if inserted > 0 {
			log.Printf("private network: %d jumps to its rules were missing in %s; they are back", inserted, entry.tool)
		}
	}
}
