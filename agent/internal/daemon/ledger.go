package daemon

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/safefile"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

const keepAcked = 7 * 24 * time.Hour

type entry struct {
	Digest    string           `json:"digest"`
	Kind      string           `json:"kind"`
	Command   *trust.Command   `json:"command,omitempty"`
	Result    *reporter.Result `json:"result"`
	Acked     bool             `json:"acked"`
	At        time.Time        `json:"at"`
	ExpiresAt time.Time        `json:"expiresAt"`
}

func (d *Daemon) ledger() string {
	return filepath.Join(d.State, "ledger")
}

func (d *Daemon) read(id string) (entry, bool, error) {
	raw, err := os.ReadFile(filepath.Join(d.ledger(), id+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return entry{}, false, nil
	}
	if err != nil {
		return entry{}, false, err
	}
	var stored entry
	if err := json.Unmarshal(raw, &stored); err != nil {
		return entry{}, false, err
	}
	return stored, true, nil
}

func (d *Daemon) write(id string, stored entry) error {
	raw, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d.ledger(), 0o700); err != nil {
		return err
	}
	return safefile.Write(filepath.Join(d.ledger(), id+".json"), raw, 0o600)
}

type named struct {
	id string
	entry
}

func (d *Daemon) all() []named {
	files, err := os.ReadDir(d.ledger())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("read the ledger: %v", err)
	}
	var found []named
	for _, file := range files {
		id, ok := strings.CutSuffix(file.Name(), ".json")
		if !ok || !commandID.MatchString(id) {
			continue
		}
		stored, present, err := d.read(id)
		if err != nil {
			log.Printf("read the ledger entry %s: %v", id, err)
			continue
		}
		if present {
			found = append(found, named{id, stored})
		}
	}
	slices.SortFunc(found, func(a, b named) int {
		return cmp.Or(a.At.Compare(b.At), strings.Compare(a.id, b.id))
	})
	return found
}

func (d *Daemon) Start(ctx context.Context) {
	now := d.Now()
	var pending []named
	d.mu.Lock()
	for _, item := range d.all() {
		switch {
		case item.Result == nil:
			pending = append(pending, item)
		case item.Acked && now.Sub(item.At) > keepAcked && now.After(item.ExpiresAt):
			if err := os.Remove(filepath.Join(d.ledger(), item.id+".json")); err != nil {
				log.Printf("remove the ledger entry %s: %v", item.id, err)
			}
		}
	}
	d.mu.Unlock()
	for _, item := range pending {
		message, err := "", errStopped
		if d.Resume != nil && item.Command != nil {
			message, err = d.Resume(ctx, *item.Command)
		}
		if ctx.Err() != nil {
			return
		}
		d.finish(item.id, outcome(item.id, message, err))
	}
}

func (d *Daemon) Resend() {
	d.mu.Lock()
	items := append(d.all(), d.refused...)
	d.mu.Unlock()
	slices.SortStableFunc(items, func(a, b named) int { return a.At.Compare(b.At) })
	for _, item := range items {
		if item.Result != nil && !item.Acked {
			d.send(item.Kind, *item.Result)
		}
	}
}
