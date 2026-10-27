package watch

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var accepted = regexp.MustCompile(`Accepted publickey for (\S+) from (\S+) port \d+ ssh2: (\S+) (SHA256:\S+)`)

var keyTypes = map[string]string{
	"ssh-ed25519":                        "ED25519",
	"ssh-rsa":                            "RSA",
	"ssh-dss":                            "DSA",
	"ecdsa-sha2-nistp256":                "ECDSA",
	"ecdsa-sha2-nistp384":                "ECDSA",
	"ecdsa-sha2-nistp521":                "ECDSA",
	"sk-ssh-ed25519@openssh.com":         "ED25519-SK",
	"sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA-SK",
}

type Key struct {
	User        string `json:"user"`
	File        string `json:"file"`
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type,omitempty"`
	Comment     string `json:"comment,omitempty"`
}

func (key Key) Item() string {
	return key.User + ":" + key.File + ":" + key.Fingerprint
}

type State struct {
	Keys  []Key    `json:"keys"`
	Users []string `json:"users"`
	Sudo  []string `json:"sudo"`
	Ports []string `json:"ports"`
}

type Change struct {
	Kind   string
	Item   string
	Detail map[string]string
}

func lines(root, name string) ([]string, error) {
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		return nil, err
	}
	return strings.Split(string(body), "\n"), nil
}

func Read(root string) (State, error) {
	passwd, err := lines(root, "/etc/passwd")
	if err != nil {
		return State{}, err
	}
	group, err := lines(root, "/etc/group")
	if err != nil {
		return State{}, err
	}
	state := State{Keys: []Key{}, Users: []string{}, Sudo: []string{}, Ports: []string{}}
	for _, line := range passwd {
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil || (uid != 0 && uid < 1000) || uid == 65534 {
			continue
		}
		state.Users = append(state.Users, fields[0])
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			file := path.Join(fields[5], ".ssh", name)
			found, _ := lines(root, file)
			for _, entry := range found {
				if key, ok := parseKey(entry); ok {
					key.User, key.File = fields[0], file
					state.Keys = append(state.Keys, key)
				}
			}
		}
	}
	files := []string{"/etc/sudoers"}
	entries, _ := os.ReadDir(filepath.Join(root, "etc", "sudoers.d"))
	for _, entry := range entries {
		if name := entry.Name(); !entry.IsDir() && !strings.Contains(name, ".") && !strings.HasSuffix(name, "~") {
			files = append(files, "/etc/sudoers.d/"+name)
		}
	}
	for _, file := range files {
		if body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file))); err == nil {
			sum := sha256.Sum256(body)
			state.Sudo = append(state.Sudo, "file:"+file+":"+hex.EncodeToString(sum[:8]))
		}
	}
	for _, line := range group {
		fields := strings.Split(line, ":")
		if len(fields) != 4 || !slices.Contains([]string{"sudo", "wheel", "admin"}, fields[0]) {
			continue
		}
		for member := range strings.SplitSeq(fields[3], ",") {
			if member = strings.TrimSpace(member); member != "" {
				state.Sudo = append(state.Sudo, "group:"+fields[0]+":"+member)
			}
		}
	}
	slices.SortFunc(state.Keys, func(a, b Key) int { return strings.Compare(a.Item(), b.Item()) })
	slices.Sort(state.Users)
	slices.Sort(state.Sudo)
	return state, nil
}

func parseKey(line string) (Key, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return Key{}, false
	}
	fields := strings.Fields(line)
	for index := 0; index+1 < len(fields); index++ {
		kind, known := keyTypes[fields[index]]
		if !known {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(fields[index+1])
		if err != nil {
			continue
		}
		sum := sha256.Sum256(blob)
		comment := strings.Join(fields[index+2:], " ")
		if len(comment) > 100 {
			comment = comment[:100]
		}
		return Key{Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), Type: kind, Comment: comment}, true
	}
	return Key{}, false
}

func Compare(start, now State) []Change {
	var changes []Change
	known := map[string]bool{}
	for _, key := range start.Keys {
		known[key.Item()] = true
	}
	for _, key := range now.Keys {
		if !known[key.Item()] {
			changes = append(changes, Change{Kind: "ssh-key", Item: key.Item(), Detail: map[string]string{"user": key.User, "file": key.File, "key": strings.TrimSpace(key.Type + " " + key.Fingerprint + " " + key.Comment)}})
		}
	}
	for _, user := range now.Users {
		if !slices.Contains(start.Users, user) {
			changes = append(changes, Change{Kind: "user", Item: user, Detail: map[string]string{"user": user}})
		}
	}
	for _, item := range now.Sudo {
		if !slices.Contains(start.Sudo, item) {
			changes = append(changes, Change{Kind: "sudo", Item: item, Detail: map[string]string{"rule": sudoRule(item)}})
		}
	}
	for _, item := range now.Ports {
		if !slices.Contains(start.Ports, item) {
			port, process, _ := strings.Cut(item, " ")
			changes = append(changes, Change{Kind: "port", Item: item, Detail: map[string]string{"port": port, "process": process}})
		}
	}
	for index := range changes {
		changes[index].Detail["item"] = changes[index].Item
	}
	return changes
}

func sudoRule(item string) string {
	if rest, found := strings.CutPrefix(item, "file:"); found {
		return rest[:max(strings.LastIndex(rest, ":"), 0)]
	}
	parts := strings.SplitN(item, ":", 3)
	if len(parts) != 3 {
		return item
	}
	return parts[2] + " in " + parts[1]
}

func Logins(journal string, start, now State) []Change {
	admins := []string{"root"}
	for _, item := range now.Sudo {
		if parts := strings.SplitN(item, ":", 3); len(parts) == 3 && parts[0] == "group" {
			admins = append(admins, parts[2])
		}
	}
	var changes []Change
	for line := range strings.SplitSeq(journal, "\n") {
		match := accepted.FindStringSubmatch(line)
		if match == nil || !slices.Contains(admins, match[1]) || slices.ContainsFunc(start.Keys, func(key Key) bool { return key.Fingerprint == match[4] }) {
			continue
		}
		stamp, _, _ := strings.Cut(line, " ")
		seconds, _, _ := strings.Cut(stamp, ".")
		unix, err := strconv.ParseInt(seconds, 10, 64)
		if err != nil {
			continue
		}
		changes = append(changes, Change{Kind: "ssh-login", Item: match[4], Detail: map[string]string{
			"user": match[1], "from": match[2], "key": match[3] + " " + match[4], "at": time.Unix(unix, 0).UTC().Format(time.RFC3339), "item": match[4],
		}})
	}
	return changes
}

func (s *State) Accept(kind, item string) bool {
	if item == "" || len(item) > 500 {
		return false
	}
	switch kind {
	case "ssh-key":
		parts := strings.SplitN(item, ":", 3)
		if len(parts) != 3 || !strings.HasPrefix(parts[2], "SHA256:") || slices.ContainsFunc(s.Keys, func(key Key) bool { return key.Item() == item }) {
			return false
		}
		s.Keys = append(s.Keys, Key{User: parts[0], File: parts[1], Fingerprint: parts[2]})
	case "ssh-login":
		if !strings.HasPrefix(item, "SHA256:") || slices.ContainsFunc(s.Keys, func(key Key) bool { return key.Fingerprint == item }) {
			return false
		}
		s.Keys = append(s.Keys, Key{Fingerprint: item})
	case "user", "sudo", "port":
		list := map[string]*[]string{"user": &s.Users, "sudo": &s.Sudo, "port": &s.Ports}[kind]
		if slices.Contains(*list, item) {
			return false
		}
		*list = append(*list, item)
		slices.Sort(*list)
	default:
		return false
	}
	return true
}
