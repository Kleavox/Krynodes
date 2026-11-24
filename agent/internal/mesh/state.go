package mesh

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/safefile"
)

const maxRecord = 1 << 20

type prepared struct {
	Range  string `json:"range"`
	Port   int    `json:"port"`
	MTU    *int   `json:"mtu"`
	Parent string `json:"parent,omitempty"`
}

type announcement struct {
	Key       string `json:"key"`
	Signature string `json:"signature"`
}

type record struct {
	Applied   network.Applied   `json:"applied"`
	Document  *network.Document `json:"document,omitempty"`
	Announced map[string]string `json:"announced,omitempty"`
	Announce  *announcement     `json:"announce,omitempty"`
	Prepared  *prepared         `json:"prepared,omitempty"`
	Joined    bool              `json:"joined,omitempty"`
	Port      int               `json:"port,omitempty"`
	Firewall  string            `json:"firewall,omitempty"`
	Tools     bool              `json:"tools,omitempty"`
	Dropped   []string          `json:"dropped,omitempty"`
	Meetings  map[string]string `json:"meetings,omitempty"`
	Relays    []int             `json:"relays,omitempty"`
	Held      bool              `json:"held,omitempty"`
	NoExit    bool              `json:"noExit,omitempty"`
	Next      *staged           `json:"next,omitempty"`
}

type staged struct {
	Document network.Document `json:"document"`
	Dropped  []string         `json:"dropped,omitempty"`
}

const (
	routeUp     = 0x0001
	routeReject = 0x0200
)

var families = []family{
	{family: 4, tool: "iptables", restore: "iptables-restore", routes: "/proc/net/route", device: func(fields []string) (string, string, string, int, bool) {
		if len(fields) < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
			return "", "", "", 0, false
		}
		return fields[0], fields[3], fields[6], 10, true
	}},
	{family: 6, tool: "ip6tables", restore: "ip6tables-restore", routes: "/proc/net/ipv6_route", device: func(fields []string) (string, string, string, int, bool) {
		if len(fields) != 10 || strings.Trim(fields[0], "0") != "" || fields[1] != "00" {
			return "", "", "", 0, false
		}
		return fields[9], fields[8], fields[5], 16, true
	}},
}

func (m *Mesh) statePath() string {
	return filepath.Join(m.State, "network.json")
}

func (m *Mesh) load() (record, error) {
	var current record
	raw, err := safefile.Read(m.statePath(), maxRecord)
	if errors.Is(err, os.ErrNotExist) {
		return current, nil
	}
	if err != nil {
		return current, err
	}
	if err := json.Unmarshal(raw, &current); err != nil {
		return record{}, fmt.Errorf("network.json is unreadable: %w", err)
	}
	return current, nil
}

func (m *Mesh) save(current record) error {
	encoded, err := json.Marshal(current)
	if err != nil {
		return err
	}
	return safefile.Write(m.statePath(), encoded, 0o600)
}

func (m *Mesh) Rules(ctx context.Context) error {
	current, err := m.load()
	if err != nil {
		return err
	}
	document, dropped, ok := m.boot(current)
	if !ok {
		return errors.New("this server has no applied network document, so kry0 stays down")
	}
	return m.enforce(ctx, document, dropped)
}

func (m *Mesh) boot(current record) (network.Document, []string, bool) {
	if current.Next != nil {
		return withHeld(current.Next.Document, current.Held || current.NoExit, m.Trust().NodeID), current.Next.Dropped, true
	}
	if current.Joined && current.Document != nil {
		return m.view(current), current.Dropped, true
	}
	return network.Document{}, nil, false
}

func (m *Mesh) uplinks(family int) []string {
	type route struct {
		name   string
		metric uint64
	}
	var routes []route
	for _, entry := range families {
		if entry.family != family {
			continue
		}
		body, _ := os.ReadFile(m.path(entry.routes))
		for line := range strings.SplitSeq(string(body), "\n") {
			name, flags, metric, base, ok := entry.device(strings.Fields(line))
			bits, flagsErr := strconv.ParseUint(flags, 16, 32)
			cost, metricErr := strconv.ParseUint(metric, base, 32)
			if ok && flagsErr == nil && metricErr == nil && bits&routeUp != 0 && bits&routeReject == 0 && name != "lo" && name != network.Interface {
				routes = append(routes, route{name, cost})
			}
		}
	}
	slices.SortStableFunc(routes, func(a, b route) int { return cmp.Compare(a.metric, b.metric) })
	var found []string
	for _, entry := range routes {
		if !slices.Contains(found, entry.name) {
			found = append(found, entry.name)
		}
	}
	return found
}

func (m *Mesh) uplink(family int) string {
	if found := m.uplinks(family); len(found) > 0 {
		return found[0]
	}
	return ""
}

type family struct {
	family        int
	tool, restore string
	routes        string
	device        func(fields []string) (name, flags, metric string, base int, ok bool)
}

func (m *Mesh) enforce(ctx context.Context, document network.Document, dropped []string) error {
	for _, entry := range families {
		if _, _, err := m.rules(ctx, entry, document, dropped, nil); err != nil {
			return err
		}
	}
	return nil
}

func (m *Mesh) rules(ctx context.Context, entry family, document network.Document, dropped []string, whole func(body string) bool) (bool, int, error) {
	self := m.Trust().NodeID
	me, _ := member(document, self)
	uplink := m.uplink(entry.family)
	body := network.RenderRules(document, self, dropped, entry.family, uplink)
	restored := whole == nil || !whole(body)
	if restored {
		if err := m.restore(ctx, entry.restore, body); err != nil {
			return false, 0, fmt.Errorf("%s: %w", entry.restore, err)
		}
	}
	exit, _ := network.Exit(me, document.Members, uplink, entry.family)
	inserted, err := m.jumps(ctx, entry.tool, exit != nil)
	return restored, inserted, err
}

func (m *Mesh) restore(ctx context.Context, tool, body string) error {
	file, err := os.CreateTemp(m.State, "rules-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, err = file.WriteString(body)
	if closed := file.Close(); err == nil {
		err = closed
	}
	if err != nil {
		return err
	}
	return m.command(ctx, tool, "-w", "--noflush", file.Name())
}

func (m *Mesh) jumps(ctx context.Context, tool string, exit bool) (int, error) {
	if err := network.EnsureDockerUser(ctx, m.Run, tool); err != nil {
		return 0, err
	}
	specs := network.Jumps()
	if exit {
		specs = append(specs, network.ExitJumps...)
	}
	inserted := 0
	for _, spec := range specs {
		if m.command(ctx, tool, append([]string{"-w", "-C"}, spec...)...) == nil {
			continue
		}
		if err := m.command(ctx, tool, append([]string{"-w", "-I", spec[0], "1"}, spec[1:]...)...); err != nil {
			return inserted, fmt.Errorf("%s cannot insert %s: %w", tool, strings.Join(spec, " "), err)
		}
		inserted++
	}
	return inserted, nil
}

func member(document network.Document, node string) (network.Member, bool) {
	for _, entry := range document.Members {
		if entry.Node == node {
			return entry, true
		}
	}
	return network.Member{}, false
}
