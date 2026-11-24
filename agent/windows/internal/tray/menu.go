package tray

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/update"
	"github.com/Kleavox/krynodes/agent/windows/internal/pipe"
)

var releaseVersion = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

const (
	notRunning = "The Krynodes service is not running."
	firewall   = "Windows Firewall is off, so this laptop accepts connections from the network."
	notYet     = "This laptop is not on the private network yet."
	copyHint   = "Click to copy the address."
)

type entry struct {
	Key       string
	Parent    string
	Title     string
	Tooltip   string
	Checkbox  bool
	Checked   bool
	Disabled  bool
	Separator bool
	Ask       *pipe.Request
	Copy      string
	Show      string
	Open      string
	Quit      bool
}

func ask(name string) *pipe.Request {
	return &pipe.Request{Request: name}
}

func flag(on bool) *bool {
	return &on
}

func text(value string) *string {
	return &value
}

func line(key, title string) entry {
	return entry{Key: key, Title: title, Disabled: true}
}

func separator(key, parent string) entry {
	return entry{Key: key, Parent: parent, Separator: true}
}

func dot(server pipe.Server) string {
	switch {
	case server.Online == nil:
		return "–"
	case *server.Online:
		return "●"
	}
	return "○"
}

func rtt(server pipe.Server) string {
	if server.RTT == nil {
		return "--"
	}
	return fmt.Sprintf("%d ms", *server.RTT)
}

func menu(status pipe.Status, reachable bool) []entry {
	quit := entry{Key: "quit", Title: "Quit", Quit: true}
	if !reachable {
		return []entry{line("service", notRunning), separator("end", ""), quit}
	}
	connect := ask("connect")
	if status.Connected {
		connect = ask("disconnect")
	}
	entries := []entry{{Key: "connected", Title: "Connected", Checkbox: true, Checked: status.Connected, Disabled: !status.Joined, Ask: connect}}
	switch {
	case !status.Joined:
		entries = append(entries, line("joining", notYet))
	case status.FirewallOff:
		entries = append(entries, line("firewall", firewall))
	}
	entries = append(entries, separator("head", ""))
	if status.Joined {
		entries = append(entries, entry{Key: "laptop", Title: "This Laptop · " + status.Name + " · " + status.Address, Tooltip: copyHint, Copy: status.Address})
		chosen := "None"
		for _, server := range status.Exits {
			if server.Node == status.Exit {
				chosen = server.Name
			}
		}
		entries = append(entries,
			entry{Key: "exit", Title: "Exit Node · " + chosen, Disabled: !status.Connected},
			entry{Key: "exit:", Parent: "exit", Title: "None", Checkbox: true, Checked: status.Exit == "", Ask: &pipe.Request{Request: "exit", Server: text("")}},
		)
		for _, server := range status.Exits {
			entries = append(entries, entry{Key: "exit:" + server.Node, Parent: "exit", Title: server.Name + " · " + rtt(server), Checkbox: true, Checked: status.Exit == server.Node, Ask: &pipe.Request{Request: "exit", Server: text(server.Node)}})
		}
		entries = append(entries,
			separator("exit-end", "exit"),
			entry{Key: "local", Parent: "exit", Title: "Allow Local Network", Tooltip: "Printers and other devices on this network stay reachable while an exit node is on.", Checkbox: true, Checked: status.Local, Ask: &pipe.Request{Request: "local", On: flag(!status.Local)}},
		)
		servers, online, measured := "Servers", 0, false
		for _, server := range status.Servers {
			if server.Online != nil {
				measured = true
				if *server.Online {
					online++
				}
			}
		}
		if measured {
			servers = fmt.Sprintf("Servers · %d Reachable", online)
		}
		entries = append(entries, entry{Key: "servers", Title: servers, Disabled: len(status.Servers) == 0})
		for _, server := range status.Servers {
			parts := []string{dot(server) + " " + server.Name, server.Address}
			if server.Via != "" {
				parts = append(parts, "via "+server.Via)
			}
			entries = append(entries, entry{Key: "server:" + server.Node, Parent: "servers", Title: strings.Join(parts, " · "), Tooltip: copyHint, Copy: server.Address})
		}
		entries = append(entries,
			separator("servers-end", "servers"),
			entry{Key: "servers-hint", Parent: "servers", Title: "Click a server to copy its address.", Disabled: true},
			separator("network", ""),
		)
	}
	shown := ""
	if status.Fingerprint != "" {
		shown = "This laptop's network fingerprint is " + status.Fingerprint + ". Approve it only if the dashboard shows the same one."
	}
	entries = append(entries,
		entry{Key: "fingerprint", Title: "Fingerprint", Disabled: shown == "", Show: shown},
		entry{Key: "dashboard", Title: "Open Dashboard", Disabled: status.Dashboard == "", Open: status.Dashboard},
		separator("tail", ""),
		entry{Key: "settings", Title: "Settings"},
		entry{Key: "start", Parent: "settings", Title: "Start with Windows", Checkbox: true, Checked: status.StartWithWindows, Ask: &pipe.Request{Request: "settings", Settings: pipe.Settings{StartWithWindows: flag(!status.StartWithWindows)}}},
		entry{Key: "offline", Parent: "settings", Title: "Notify When a Server Goes Offline", Checkbox: true, Checked: status.NotifyOffline, Ask: &pipe.Request{Request: "settings", Settings: pipe.Settings{NotifyOffline: flag(!status.NotifyOffline)}}},
		entry{Key: "update", Parent: "settings", Title: "Update Agent", Ask: ask("update")},
		quit,
	)
	return entries
}

func newer(service, own string) bool {
	if !releaseVersion.MatchString(service) {
		return false
	}
	found, err := update.IsNewer(service, own)
	return err == nil && found
}

func shape(entries []entry) string {
	var keys []string
	for _, item := range entries {
		keys = append(keys, item.Parent+"/"+item.Key)
	}
	return strings.Join(keys, "\n")
}
