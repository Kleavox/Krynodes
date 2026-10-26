package apt

import (
	"net/url"
	"strings"
)

type Simulation struct {
	Upgrades map[string]string
	Versions map[string]string
	New      []string
	Removes  []string
	Kept     []string
	Phased   []string
}

type Origin struct {
	Host  string
	Suite string
}

type Policy struct {
	Installed string
	Candidate string
	From      []Origin
	To        []Origin
}

func bare(name string) string {
	name, _, _ = strings.Cut(name, ":")
	return name
}

func ParseSimulation(text string) Simulation {
	simulation := Simulation{Upgrades: map[string]string{}, Versions: map[string]string{}}
	var list *[]string
	for line := range strings.SplitSeq(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if list != nil && strings.HasPrefix(line, " ") {
			for name := range strings.FieldsSeq(line) {
				*list = append(*list, bare(name))
			}
			continue
		}
		list = nil
		fields := strings.Fields(line)
		switch {
		case strings.HasPrefix(line, "The following packages have been kept back"):
			list = &simulation.Kept
		case strings.HasPrefix(line, "The following upgrades have been deferred due to phasing"):
			list = &simulation.Phased
		case len(fields) >= 3 && fields[0] == "Inst":
			name := bare(fields[1])
			version := ""
			if _, inside, found := strings.Cut(line, "("); found {
				if words := strings.Fields(inside); len(words) > 0 {
					version = words[0]
				}
			}
			simulation.Versions[name] = version
			if !strings.HasPrefix(fields[2], "[") {
				simulation.New = append(simulation.New, name)
			} else if version != "" {
				simulation.Upgrades[name] = version
			}
		case len(fields) >= 2 && (fields[0] == "Remv" || fields[0] == "Purg"):
			simulation.Removes = append(simulation.Removes, bare(fields[1]))
		}
	}
	return simulation
}

func ParsePolicy(text string) map[string]Policy {
	policies := map[string]Policy{}
	name, version := "", ""
	var current Policy
	save := func() {
		if name != "" {
			policies[name] = current
		}
	}
	for line := range strings.SplitSeq(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " "))
		fields := strings.Fields(trimmed)
		switch {
		case trimmed == "", trimmed == "Version table:":
		case indent == 0 && strings.HasSuffix(trimmed, ":"):
			save()
			name, version, current = bare(strings.TrimSuffix(trimmed, ":")), "", Policy{}
		case strings.HasPrefix(trimmed, "Installed:"):
			current.Installed = strings.TrimSpace(strings.TrimPrefix(trimmed, "Installed:"))
		case strings.HasPrefix(trimmed, "Candidate:"):
			current.Candidate = strings.TrimSpace(strings.TrimPrefix(trimmed, "Candidate:"))
		case strings.HasPrefix(trimmed, "***") && len(fields) >= 2:
			version = fields[1]
		case indent > 0 && indent < 8 && len(fields) == 2:
			version = fields[0]
		case indent >= 8 && len(fields) >= 3:
			parsed, err := url.Parse(fields[1])
			if err != nil || parsed.Host == "" {
				continue
			}
			suite, _, _ := strings.Cut(fields[2], "/")
			origin := Origin{Host: parsed.Hostname(), Suite: suite}
			if version == current.Installed {
				current.From = append(current.From, origin)
			}
			if version == current.Candidate {
				current.To = append(current.To, origin)
			}
		}
	}
	save()
	return policies
}
