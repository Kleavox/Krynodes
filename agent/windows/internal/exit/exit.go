package exit

import (
	"slices"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

const (
	silence = 30 * time.Second
	gap     = 5 * time.Second
)

type ExitWatch struct {
	last time.Time
	seen time.Time
}

func (w *ExitWatch) Observe(now time.Time, answered bool, held bool) bool {
	if held {
		return false
	}
	if answered || w.last.IsZero() || now.Sub(w.seen) > gap {
		w.last = now
	}
	w.seen = now
	return now.Sub(w.last) < silence
}

func Offered(document network.Document, held []string, node string) bool {
	index := slices.IndexFunc(document.Members, func(entry network.Member) bool { return entry.Node == node })
	return index >= 0 && document.Members[index].Exit && network.MeetingPoint(document.Members[index]) && !slices.Contains(held, node)
}
