//go:build windows

package tray

import (
	"os/exec"
	"sync"
	"time"

	"fyne.io/systray"

	"github.com/Kleavox/krynodes/agent/windows/internal/bundle"
	"github.com/Kleavox/krynodes/agent/windows/internal/pipe"
)

type tray struct {
	mu        sync.Mutex
	version   string
	leaving   bool
	shape     string
	items     map[string]*systray.MenuItem
	entries   map[string]entry
	connected *bool
	seen      uint64
}

func Run(version string) {
	detach()
	if !single() {
		return
	}
	t := &tray{version: version}
	systray.Run(t.ready, nil)
}

func (t *tray) relaunch() bool {
	t.mu.Lock()
	tried := t.leaving
	t.leaving = true
	t.mu.Unlock()
	if tried {
		return false
	}
	program, err := bundle.Program()
	if err != nil {
		return false
	}
	if exec.Command(program, "tray").Start() != nil {
		return false
	}
	release()
	systray.Quit()
	return true
}

func (t *tray) ready() {
	t.refresh()
	go func() {
		for range time.Tick(2 * time.Second) {
			t.refresh()
		}
	}()
}

func (t *tray) refresh() {
	t.mu.Lock()
	seen := t.seen
	t.mu.Unlock()
	reply, err := pipe.Ask(pipe.Request{Request: "status", Seen: &seen})
	reachable := err == nil && reply.Status != nil
	var status pipe.Status
	if reachable {
		status = *reply.Status
		if newer(status.Version, t.version) && t.relaunch() {
			return
		}
	}
	t.show(menu(status, reachable), reachable && status.Connected && status.Joined && !status.Removed)
	if !reachable {
		return
	}
	t.mu.Lock()
	fresh := t.seen == seen
	if fresh {
		t.seen = status.Last
	}
	t.mu.Unlock()
	if line := shown(status.Notes); fresh && line != "" {
		balloon(line)
	}
}

func (t *tray) show(entries []entry, connected bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.connected == nil || *t.connected != connected {
		systray.SetIcon(icon(connected))
		tooltip := "Krynodes · Disconnected"
		if connected {
			tooltip = "Krynodes · Connected"
		}
		systray.SetTooltip(tooltip)
		t.connected = &connected
	}
	if next := shape(entries); next != t.shape {
		systray.ResetMenu()
		t.shape, t.items, t.entries = next, map[string]*systray.MenuItem{}, nil
		for _, wanted := range entries {
			parent := t.items[wanted.Parent]
			if wanted.Separator {
				if parent == nil {
					systray.AddSeparator()
				} else {
					parent.AddSeparator()
				}
				continue
			}
			var item *systray.MenuItem
			switch {
			case parent == nil && wanted.Checkbox:
				item = systray.AddMenuItemCheckbox(wanted.Title, wanted.Tooltip, wanted.Checked)
			case parent == nil:
				item = systray.AddMenuItem(wanted.Title, wanted.Tooltip)
			case wanted.Checkbox:
				item = parent.AddSubMenuItemCheckbox(wanted.Title, wanted.Tooltip, wanted.Checked)
			default:
				item = parent.AddSubMenuItem(wanted.Title, wanted.Tooltip)
			}
			t.items[wanted.Key] = item
			go t.listen(wanted.Key, item)
		}
	}
	previous := t.entries
	t.entries = map[string]entry{}
	for _, wanted := range entries {
		t.entries[wanted.Key] = wanted
		item := t.items[wanted.Key]
		was, known := previous[wanted.Key]
		if item == nil || (known && was.Title == wanted.Title && was.Tooltip == wanted.Tooltip && was.Checked == wanted.Checked && was.Disabled == wanted.Disabled) {
			continue
		}
		item.SetTitle(wanted.Title)
		item.SetTooltip(wanted.Tooltip)
		if wanted.Checked {
			item.Check()
		} else {
			item.Uncheck()
		}
		if wanted.Disabled {
			item.Disable()
		} else {
			item.Enable()
		}
	}
}

func (t *tray) listen(key string, item *systray.MenuItem) {
	for range item.ClickedCh {
		t.act(key)
	}
}

func (t *tray) act(key string) {
	t.mu.Lock()
	chosen, ok := t.entries[key]
	t.mu.Unlock()
	if !ok || chosen.Disabled {
		return
	}
	failed := ""
	switch {
	case chosen.Quit:
		pipe.Ask(pipe.Request{Request: "disconnect"})
		systray.Quit()
		return
	case chosen.Copy != "":
		if err := copyText(chosen.Copy); err != nil {
			failed = err.Error()
		}
	case chosen.Open != "":
		if err := open(chosen.Open); err != nil {
			failed = err.Error()
		}
	case chosen.Ask != nil:
		reply, err := pipe.Ask(*chosen.Ask)
		switch {
		case err != nil:
			failed = notRunning
		case reply.Error != "":
			failed = reply.Error
		}
	}
	if failed != "" {
		balloon(failed)
	}
	t.refresh()
}
