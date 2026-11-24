package mesh

import (
	"context"
	"maps"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const maxLinks = 32

func (m *Mesh) answers(link network.Link) bool {
	return link.Handshake != nil && m.Now().Unix()-*link.Handshake < network.AnswerSeconds
}

func (m *Mesh) SendLinks(ctx context.Context) error {
	links := []reporter.NetworkLink{}
	current, err := m.load()
	if err == nil && current.Joined && current.Document != nil {
		addresses := map[string]string{}
		for _, entry := range withAnnounced(*current.Document, current.Announced).Members {
			addresses[entry.Key] = entry.Address
		}
		for _, link := range m.dump(ctx) {
			address, known := addresses[link.Key]
			if !known || len(links) == maxLinks {
				continue
			}
			if m.answers(link) {
				output, _ := m.output(ctx, "ping", "-n", "-c", "1", "-W", "1", "-I", network.Interface, address)
				link.MS = network.PingMS(output)
			}
			links = append(links, reporter.NetworkLink(link))
		}
	}
	return m.Send(reporter.Links{Type: "links", Links: links})
}

func (m *Mesh) answering(ctx context.Context) map[string]bool {
	state := map[string]bool{}
	for _, link := range m.dump(ctx) {
		state[link.Key] = m.answers(link)
	}
	return state
}

func (m *Mesh) flip(ctx context.Context, last map[string]bool) map[string]bool {
	state := m.answering(ctx)
	if last != nil && maps.Equal(state, last) {
		return last
	}
	if m.SendLinks(ctx) != nil {
		return last
	}
	return state
}

func (m *Mesh) WatchLinks(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	var last map[string]bool
	for {
		last = m.flip(ctx, last)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
