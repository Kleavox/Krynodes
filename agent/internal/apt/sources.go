package apt

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const (
	sourcesList = "/etc/apt/sources.list"
	sourcesDir  = "/etc/apt/sources.list.d"
	maxSources  = 50
)

var systemFiles = []string{"debian", "ubuntu", "raspi", "raspbian"}

var notName = regexp.MustCompile(`[^a-z0-9+.-]+`)

type line struct {
	uri        string
	suites     []string
	components []string
	key        string
}

func oneLine(text string) []line {
	var found []line
	for raw := range strings.SplitSeq(text, "\n") {
		raw, _, _ = strings.Cut(raw, "#")
		fields := strings.Fields(raw)
		if len(fields) < 3 || fields[0] != "deb" {
			continue
		}
		fields = fields[1:]
		key := ""
		if strings.HasPrefix(fields[0], "[") {
			end := slices.IndexFunc(fields, func(field string) bool { return strings.HasSuffix(field, "]") })
			if end < 0 {
				continue
			}
			for _, option := range fields[:end+1] {
				name, value, _ := strings.Cut(strings.Trim(option, "[]"), "=")
				if name == "signed-by" {
					key = value
				}
			}
			fields = fields[end+1:]
		}
		if len(fields) < 2 {
			continue
		}
		found = append(found, line{uri: fields[0], suites: []string{fields[1]}, components: fields[2:], key: key})
	}
	return found
}

func deb822(text string) []line {
	var found []line
	for _, stanza := range stanzas(text) {
		if !slices.Contains(strings.Fields(stanza["types"]), "deb") || strings.EqualFold(stanza["enabled"], "no") {
			continue
		}
		for uri := range strings.FieldsSeq(stanza["uris"]) {
			found = append(found, line{uri: uri, suites: strings.Fields(stanza["suites"]), components: strings.Fields(stanza["components"]), key: strings.TrimSpace(stanza["signed-by"])})
		}
	}
	return found
}

func keyOf(root, signedBy string) *string {
	data := []byte(signedBy)
	if !strings.Contains(signedBy, "-----BEGIN") {
		first, _, _ := strings.Cut(strings.TrimSpace(signedBy), ",")
		if !strings.HasPrefix(first, "/") {
			return nil
		}
		body, err := os.ReadFile(at(root, first))
		if err != nil {
			return nil
		}
		data = body
	}
	keys, err := ReadKeys(data)
	if err != nil {
		return nil
	}
	short := Short(keys[0].Fingerprint)
	return &short
}

func ReadSources(root, distro string, ours []string) []reporter.SourceEntry {
	files := []string{sourcesList}
	entries, _ := os.ReadDir(at(root, sourcesDir))
	for _, entry := range entries {
		if name := entry.Name(); entry.Type().IsRegular() && (strings.HasSuffix(name, ".list") || strings.HasSuffix(name, ".sources")) {
			files = append(files, sourcesDir+"/"+name)
		}
	}
	var sources []reporter.SourceEntry
	for _, file := range files {
		body, err := os.ReadFile(at(root, file))
		if err != nil {
			continue
		}
		lines := oneLine(string(body))
		if strings.HasSuffix(file, ".sources") {
			lines = deb822(string(body))
		}
		stem := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(file), ".list"), ".sources")
		if file == sourcesList {
			stem = distro
		}
		stem = strings.Trim(notName.ReplaceAllString(strings.ToLower(stem), "-"), "-")
		system := file == sourcesList || slices.Contains(systemFiles, stem)
		var mine []reporter.SourceEntry
		var uris []string
		for _, found := range lines {
			parsed, err := url.Parse(found.uri)
			if err != nil || parsed.Host == "" {
				continue
			}
			if index := slices.Index(uris, found.uri); index >= 0 {
				for _, suite := range found.suites {
					if !slices.Contains(mine[index].Suites, suite) {
						mine[index].Suites = append(mine[index].Suites, suite)
					}
				}
				continue
			}
			uris = append(uris, found.uri)
			mine = append(mine, reporter.SourceEntry{Name: stem, Host: parsed.Hostname(), Suites: slices.Clone(found.suites), Key: keyOf(root, found.key), Krynodes: slices.Contains(ours, file), File: file, System: system})
		}
		for index := range mine {
			if system && !slices.ContainsFunc(mine[index].Suites, func(suite string) bool { return !strings.HasSuffix(suite, "-security") }) {
				mine[index].Name += "-security"
			}
			if mine[index].Suites == nil {
				mine[index].Suites = []string{}
			}
		}
		sources = append(sources, mine...)
	}
	if len(sources) > maxSources {
		sources = sources[:maxSources]
	}
	return sources
}

func sourceName(sources []reporter.SourceEntry, origins []Origin) *string {
	if len(origins) == 0 {
		return nil
	}
	first := origins[0]
	for _, exact := range []bool{true, false} {
		for _, source := range sources {
			if source.Host == first.Host && (!exact || slices.Contains(source.Suites, first.Suite)) {
				name := source.Name
				return &name
			}
		}
	}
	return nil
}
