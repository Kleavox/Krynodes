package apt

import (
	"path/filepath"
	"regexp"
	"strings"
)

type Package struct {
	Name      string
	Version   string
	Held      bool
	Essential bool
	Protected bool
}

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}$`)

func ValidName(name string) bool {
	return validName.MatchString(name)
}

func at(root, name string) string {
	return filepath.Join(root, filepath.FromSlash(name))
}

func stanzas(text string) []map[string]string {
	var found []map[string]string
	current := map[string]string{}
	last := ""
	flush := func() {
		if len(current) > 0 {
			found = append(found, current)
		}
		current, last = map[string]string{}, ""
	}
	for line := range strings.SplitSeq(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		switch {
		case strings.TrimSpace(line) == "":
			flush()
		case strings.HasPrefix(line, "#"):
		case line[0] == ' ' || line[0] == '\t':
			if last != "" {
				more := line[1:]
				if strings.TrimSpace(more) == "." {
					more = ""
				}
				current[last] += "\n" + more
			}
		default:
			key, value, found := strings.Cut(line, ":")
			if !found {
				continue
			}
			last = strings.ToLower(strings.TrimSpace(key))
			current[last] = strings.TrimSpace(value)
		}
	}
	flush()
	return found
}

func ParseStatus(text string) []Package {
	var packages []Package
	seen := map[string]bool{}
	for _, stanza := range stanzas(text) {
		state := strings.Fields(stanza["status"])
		name := stanza["package"]
		if len(state) != 3 || state[2] != "installed" || name == "" || seen[name] {
			continue
		}
		seen[name] = true
		packages = append(packages, Package{
			Name:      name,
			Version:   stanza["version"],
			Held:      state[0] == "hold",
			Essential: stanza["essential"] == "yes",
			Protected: stanza["protected"] == "yes",
		})
	}
	return packages
}
