package apt

import (
	"cmp"
	"compress/gzip"
	"io"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
)

type Added struct {
	By   string
	With []string
}

const maxHistoryBytes = 32 << 20

func ReadHistory(root string) []string {
	directory := at(root, "/var/log/apt")
	entries, _ := os.ReadDir(directory)
	type rotated struct {
		number int
		name   string
	}
	var files []rotated
	for _, entry := range entries {
		rest, found := strings.CutPrefix(entry.Name(), "history.log")
		if !found {
			continue
		}
		rest = strings.TrimSuffix(strings.TrimPrefix(rest, "."), ".gz")
		number := 0
		if rest != "" {
			parsed, err := strconv.Atoi(rest)
			if err != nil {
				continue
			}
			number = parsed
		}
		files = append(files, rotated{number, entry.Name()})
	}
	slices.SortFunc(files, func(a, b rotated) int { return cmp.Compare(b.number, a.number) })
	var logs []string
	for _, file := range files {
		handle, err := os.Open(at(root, "/var/log/apt/"+file.name))
		if err != nil {
			continue
		}
		var reader io.Reader = handle
		if strings.HasSuffix(file.name, ".gz") {
			unpacked, err := gzip.NewReader(handle)
			if err != nil {
				handle.Close()
				continue
			}
			reader = unpacked
		}
		body, _ := io.ReadAll(io.LimitReader(reader, maxHistoryBytes))
		handle.Close()
		logs = append(logs, string(body))
	}
	return logs
}

func listed(field string) (explicit, automatic []string) {
	for item := range strings.SplitSeq(field, "),") {
		item = strings.TrimSpace(item)
		name, details, found := strings.Cut(item, " (")
		if !found {
			continue
		}
		name, _, _ = strings.Cut(name, ":")
		if strings.Contains(details, "automatic") {
			automatic = append(automatic, name)
		} else {
			explicit = append(explicit, name)
		}
	}
	return explicit, automatic
}

func installCommand(line string) bool {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	program := path.Base(fields[0])
	return (program == "apt" || program == "apt-get") && slices.Contains(fields[1:], "install")
}

func ParseHistory(logs ...string) map[string]Added {
	added := map[string]Added{}
	for _, log := range logs {
		for _, entry := range stanzas(log) {
			for _, field := range []string{"remove", "purge"} {
				explicit, automatic := listed(entry[field])
				for _, name := range append(explicit, automatic...) {
					delete(added, name)
				}
			}
			if !installCommand(entry["commandline"]) {
				continue
			}
			explicit, automatic := listed(entry["install"])
			by := "root"
			if requested, _, _ := strings.Cut(entry["requested-by"], " ("); strings.TrimSpace(requested) != "" {
				by = strings.TrimSpace(requested)
			}
			for index, name := range explicit {
				record := Added{By: by}
				if index == 0 {
					record.With = automatic
				}
				added[name] = record
			}
		}
	}
	return added
}
