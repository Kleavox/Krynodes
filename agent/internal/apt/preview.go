package apt

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const (
	maxMatches = 20
	maxOpened  = 50 << 20
)

type Change struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Port struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Open     *bool  `json:"open,omitempty"`
}

type Unit struct {
	Unit  string `json:"unit"`
	Ports []Port `json:"ports"`
}

type InstallPreview struct {
	What     string   `json:"what"`
	Name     string   `json:"name"`
	Installs []Change `json:"installs"`
	Upgrades []Change `json:"upgrades"`
	Removes  []string `json:"removes"`
	Download *int64   `json:"download"`
	Disk     *int64   `json:"disk"`
	Services []Unit   `json:"services"`
	Unread   bool     `json:"unread"`
	Firewall *string  `json:"firewall"`
	Refused  *string  `json:"refused"`
}

type RemovePreview struct {
	What    string   `json:"what"`
	Name    string   `json:"name"`
	Removes []string `json:"removes"`
	Stops   []string `json:"stops"`
	Refused *string  `json:"refused"`
}

type UpgradePreview struct {
	What     string   `json:"what"`
	Upgrades []Change `json:"upgrades"`
	Adds     []Change `json:"adds"`
	Restarts []string `json:"restarts"`
}

type Match struct {
	Name      string  `json:"name"`
	Version   string  `json:"version"`
	Summary   string  `json:"summary"`
	From      *string `json:"from"`
	Installed *string `json:"installed"`
}

var searchWord = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]{0,63}$`)

func changes(names []string, versions map[string]string) []Change {
	found := []Change{}
	for _, name := range slices.Sorted(slices.Values(names)) {
		found = append(found, Change{Name: name, Version: versions[name]})
	}
	return found
}

func refusal(err error) *string {
	if err == nil {
		return nil
	}
	return text(err.Error())
}

func (j Job) PreviewInstall(ctx context.Context, name, scratch string) InstallPreview {
	defer os.RemoveAll(scratch)
	simulation := j.tried(ctx, "install", name)
	preview := InstallPreview{
		What: "install", Name: name, Services: []Unit{},
		Installs: changes(simulation.New, simulation.Versions),
		Upgrades: changes(slices.Collect(maps.Keys(simulation.Upgrades)), simulation.Upgrades),
		Removes:  slices.Sorted(slices.Values(append([]string{}, simulation.Removes...))),
	}
	preview.Refused = refusal(j.Removable(preview.Removes))
	var downloads, disk int64
	sized := map[string]bool{}
	shown, _ := output(ctx, j.Run, "apt-cache", append([]string{"show", "--no-all-versions"}, append(slices.Clone(simulation.New), slices.Sorted(maps.Keys(simulation.Upgrades))...)...)...)
	for _, stanza := range stanzas(shown) {
		size, sizeErr := strconv.ParseInt(stanza["size"], 10, 64)
		installed, installedErr := strconv.ParseInt(stanza["installed-size"], 10, 64)
		if sizeErr != nil || installedErr != nil || sized[stanza["package"]] {
			continue
		}
		sized[stanza["package"]] = true
		downloads += size
		if slices.Contains(simulation.New, stanza["package"]) {
			disk += installed * 1024
		}
	}
	if len(sized) == len(simulation.New)+len(simulation.Upgrades) {
		preview.Download, preview.Disk = &downloads, &disk
	}
	if preview.Download == nil || downloads > maxOpened {
		preview.Unread = true
		return preview
	}
	units, err := j.opened(ctx, scratch, simulation)
	if err != nil {
		preview.Unread = true
		return preview
	}
	preview.Services = units
	return preview
}

func (j Job) opened(ctx context.Context, scratch string, simulation Simulation) ([]Unit, error) {
	if len(simulation.New) == 0 {
		return []Unit{}, nil
	}
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		return nil, err
	}
	var wanted []string
	for _, name := range simulation.New {
		wanted = append(wanted, name+"="+simulation.Versions[name])
	}
	if _, _, err := j.Run(ctx, "env", append([]string{"-C", scratch, "LC_ALL=C", "apt-get", "-q", "download"}, wanted...)...); err != nil {
		return nil, err
	}
	debs, _ := filepath.Glob(filepath.Join(scratch, "*.deb"))
	inside := filepath.Join(scratch, "root")
	for _, deb := range debs {
		if _, _, err := j.Run(ctx, "dpkg-deb", "-x", deb, inside); err != nil {
			return nil, err
		}
	}
	return startingUnits(inside), nil
}

func startingUnits(root string) []Unit {
	units := []Unit{}
	for _, directory := range []string{"/lib/systemd/system", "/usr/lib/systemd/system"} {
		entries, _ := os.ReadDir(at(root, directory))
		for _, entry := range entries {
			name := entry.Name()
			socket := strings.HasSuffix(name, ".socket")
			if strings.Contains(name, "@") || !(socket || strings.HasSuffix(name, ".service")) || slices.ContainsFunc(units, func(unit Unit) bool { return unit.Unit == name }) {
				continue
			}
			body, err := os.ReadFile(filepath.Join(at(root, directory), name))
			if err != nil {
				continue
			}
			ports, wanted := unitFacts(string(body))
			if !wanted {
				continue
			}
			unit := Unit{Unit: name}
			if socket {
				unit.Ports = ports
			}
			units = append(units, unit)
		}
	}
	slices.SortFunc(units, func(a, b Unit) int { return cmp.Compare(a.Unit, b.Unit) })
	return units
}

func unitFacts(body string) ([]Port, bool) {
	ports := []Port{}
	section, wanted := "", false
	for raw := range strings.SplitSeq(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if section == "[Install]" && (key == "WantedBy" || key == "RequiredBy") && value != "" {
			wanted = true
		}
		protocol := map[string]string{"ListenStream": "tcp", "ListenDatagram": "udp"}[key]
		if section != "[Socket]" || protocol == "" {
			continue
		}
		port, err := strconv.Atoi(value[strings.LastIndex(value, ":")+1:])
		if err != nil || port < 1 || port > 65535 || slices.ContainsFunc(ports, func(seen Port) bool { return seen.Port == port && seen.Protocol == protocol }) {
			continue
		}
		ports = append(ports, Port{Port: port, Protocol: protocol})
	}
	return ports, wanted
}

func (j Job) unitsOf(names []string) []string {
	var units []string
	for _, name := range names {
		lists, _ := filepath.Glob(at(j.Root, "/var/lib/dpkg/info/"+name+":*.list"))
		lists = append(lists, at(j.Root, "/var/lib/dpkg/info/"+name+".list"))
		for _, list := range lists {
			body, _ := os.ReadFile(list)
			for path := range strings.SplitSeq(string(body), "\n") {
				path = strings.TrimSpace(path)
				unit := filepath.Base(path)
				shipped := strings.HasPrefix(path, "/lib/systemd/system/") || strings.HasPrefix(path, "/usr/lib/systemd/system/")
				if shipped && !strings.Contains(unit, "@") && (strings.HasSuffix(unit, ".service") || strings.HasSuffix(unit, ".socket")) && !slices.Contains(units, unit) {
					units = append(units, unit)
				}
			}
		}
	}
	slices.Sort(units)
	return units
}

func (j Job) active(ctx context.Context, units []string) []string {
	running := []string{}
	if len(units) == 0 {
		return running
	}
	text, _, _ := j.Run(ctx, "systemctl", append([]string{"is-active"}, units...)...)
	states := strings.Fields(string(text))
	for index, unit := range units {
		if index < len(states) && states[index] == "active" {
			running = append(running, unit)
		}
	}
	return running
}

func (j Job) PreviewRemove(ctx context.Context, name string, purge bool) RemovePreview {
	verb := "remove"
	if purge {
		verb = "purge"
	}
	simulation := j.tried(ctx, verb, name)
	preview := RemovePreview{What: verb, Name: name, Removes: slices.Sorted(slices.Values(append([]string{}, simulation.Removes...))), Stops: []string{}}
	if len(preview.Removes) == 0 {
		preview.Refused = text(name + " is not installed")
		return preview
	}
	preview.Refused = refusal(j.Removable(append([]string{name}, preview.Removes...)))
	preview.Stops = j.active(ctx, j.unitsOf(preview.Removes))
	return preview
}

func (j Job) PreviewUpgrade(ctx context.Context) UpgradePreview {
	simulation := j.tried(ctx, "--with-new-pkgs", "upgrade")
	upgraded := slices.Sorted(maps.Keys(simulation.Upgrades))
	return UpgradePreview{
		What: "upgrade", Upgrades: changes(upgraded, simulation.Upgrades), Adds: changes(simulation.New, simulation.Versions),
		Restarts: j.active(ctx, j.unitsOf(upgraded)),
	}
}

func rankOf(name, first string) int {
	switch {
	case name == first:
		return 0
	case strings.HasPrefix(name, first):
		return 1
	case strings.Contains(name, first):
		return 2
	}
	return 3
}

func (j Job) Find(ctx context.Context, term string, sources []reporter.SourceEntry) ([]Match, error) {
	words := strings.Fields(strings.ToLower(term))
	if len(words) == 0 || len(words) > 5 || len(term) > 64 {
		return nil, errors.New("search for one to five words")
	}
	var patterns []string
	for _, word := range words {
		if !searchWord.MatchString(word) {
			return nil, errors.New("a search word has letters, digits and + . _ - only")
		}
		patterns = append(patterns, regexp.QuoteMeta(word))
	}
	found, ok := output(ctx, j.Run, "apt-cache", append(append(slices.Clone(noCache), "search"), patterns...)...)
	if !ok {
		return nil, errors.New("apt could not search its lists")
	}
	matches := []Match{}
	for line := range strings.SplitSeq(found, "\n") {
		name, summary, cut := strings.Cut(strings.TrimSpace(line), " - ")
		if cut && ValidName(name) && !slices.ContainsFunc(matches, func(match Match) bool { return match.Name == name }) {
			matches = append(matches, Match{Name: name, Summary: summary})
		}
	}
	slices.SortFunc(matches, func(a, b Match) int {
		return cmp.Or(cmp.Compare(rankOf(a.Name, words[0]), rankOf(b.Name, words[0])), cmp.Compare(a.Name, b.Name))
	})
	matches = matches[:min(len(matches), maxMatches)]
	if len(matches) == 0 {
		return matches, nil
	}
	var names []string
	for _, match := range matches {
		names = append(names, match.Name)
	}
	policyText, _ := output(ctx, j.Run, "apt-cache", append(append(slices.Clone(noCache), "policy"), names...)...)
	policies := ParsePolicy(policyText)
	installed := present(j.Root)
	for index := range matches {
		policy := policies[matches[index].Name]
		matches[index].Version = policy.Candidate
		matches[index].From = sourceName(sources, policy.To)
		if version, has := installed[matches[index].Name]; has {
			matches[index].Installed = &version
		}
	}
	return matches, nil
}
