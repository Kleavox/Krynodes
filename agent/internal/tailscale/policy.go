package tailscale

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	Tag         = "tag:kry"
	beginMarker = "// krynodes: begin · kept by Krynodes, change it there"
	endMarker   = "// krynodes: end"
)

var portPattern = regexp.MustCompile(`^(\*|([0-9]{1,5})(-([0-9]{1,5}))?(/(tcp|udp))?)$`)

type Rule struct {
	From  string   `json:"from,omitempty"`
	To    string   `json:"to,omitempty"`
	Ports []string `json:"ports,omitempty"`
	Raw   string   `json:"raw,omitempty"`
}

type Policy struct {
	Tags      []string
	Kry       bool
	Open      string
	OpenSpan  [2]int
	Block     []string
	BlockSpan [2]int
	GrantsAt  int

	openComma int
	closeAt   int
	needComma bool
	indent    string
}

type scanned struct {
	blank    []byte
	commas   map[int]bool
	comments [][2]int
}

func space(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func skipString(src []byte, i int) int {
	for i++; i < len(src) && src[i] != '"'; i++ {
		if src[i] == '\\' {
			i++
		}
	}
	return i
}

func scan(src []byte) scanned {
	s := scanned{blank: slices.Clone(src), commas: map[int]bool{}}
	for i := 0; i < len(src); i++ {
		switch {
		case src[i] == '"':
			i = skipString(src, i)
		case src[i] == '/' && i+1 < len(src) && src[i+1] == '/':
			start := i
			for ; i < len(src) && src[i] != '\n'; i++ {
				s.blank[i] = ' '
			}
			s.comments = append(s.comments, [2]int{start, i})
		case src[i] == '/' && i+1 < len(src) && src[i+1] == '*':
			start, stop := i, len(src)
			if end := bytes.Index(src[i+2:], []byte("*/")); end >= 0 {
				stop = i + 2 + end + 2
			}
			for ; i < stop; i++ {
				if src[i] != '\n' {
					s.blank[i] = ' '
				}
			}
			s.comments = append(s.comments, [2]int{start, stop})
			i--
		}
	}
	for i := 0; i < len(s.blank); i++ {
		switch s.blank[i] {
		case '"':
			i = skipString(s.blank, i)
		case ',':
			next := i + 1
			for next < len(s.blank) && space(s.blank[next]) {
				next++
			}
			if next < len(s.blank) && (s.blank[next] == ']' || s.blank[next] == '}') {
				s.blank[i] = ' '
				s.commas[i] = true
			}
		}
	}
	return s
}

func allowsAll(key string, raw json.RawMessage) bool {
	want := map[string]string{"src": `["*"]`, "dst": `["*"]`, "ip": `["*"]`}
	if key == "acls" {
		want = map[string]string{"action": `"accept"`, "src": `["*"]`, "dst": `["*:*"]`}
	}
	var rule map[string]json.RawMessage
	if json.Unmarshal(raw, &rule) != nil || len(rule) != len(want) {
		return false
	}
	for name, value := range want {
		var compact bytes.Buffer
		if json.Compact(&compact, rule[name]) != nil || compact.String() != value {
			return false
		}
	}
	return true
}

func blockLines(text []byte) []string {
	lines := []string{}
	for line := range strings.SplitSeq(string(text), "\n") {
		if trimmed := trimLine(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

func trimLine(line string) string {
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ","))
}

func Read(src []byte) (Policy, error) {
	s := scan(src)
	p := Policy{Tags: []string{}, GrantsAt: -1, openComma: -1}
	broken := errors.New("Tailscale's policy file could not be read")
	begin, end := -1, -1
	for index, comment := range s.comments {
		text := strings.TrimSpace(string(src[comment[0]:comment[1]]))
		switch {
		case strings.HasPrefix(text, "// krynodes: begin") && begin < 0:
			begin = index
		case text == endMarker && begin >= 0 && end < 0:
			end = index
		case strings.HasPrefix(text, "// krynodes:"):
			return p, errors.New("Krynodes' rules in your policy file are marked twice or not closed; fix the krynodes: begin and end lines in Tailscale's admin console")
		}
	}
	if begin >= 0 && end < 0 {
		return p, errors.New("Krynodes' rules in your policy file have no krynodes: end line; add it back in Tailscale's admin console")
	}
	if begin >= 0 {
		p.BlockSpan = [2]int{s.comments[begin][0], s.comments[end][1]}
		p.Block = blockLines(src[s.comments[begin][1]:s.comments[end][0]])
	}
	decoder := json.NewDecoder(bytes.NewReader(s.blank))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return p, broken
	}
	first := int(decoder.InputOffset())
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return p, broken
		}
		key, _ := token.(string)
		switch key {
		case "tagOwners":
			var owners map[string]json.RawMessage
			if err := decoder.Decode(&owners); err != nil {
				return p, broken
			}
			p.Tags = slices.Sorted(maps.Keys(owners))
		case "acls", "grants":
			if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
				return p, broken
			}
			if key == "grants" {
				p.GrantsAt = int(decoder.InputOffset())
			}
			for decoder.More() {
				var raw json.RawMessage
				if err := decoder.Decode(&raw); err != nil {
					return p, broken
				}
				stop := int(decoder.InputOffset())
				start := stop - len(raw)
				inBlock := p.Block != nil && start > p.BlockSpan[0] && start < p.BlockSpan[1]
				if p.Open == "" && !inBlock && allowsAll(key, raw) {
					p.Open, p.OpenSpan = key, [2]int{start, stop}
				}
			}
			if _, err := decoder.Token(); err != nil {
				return p, broken
			}
		default:
			var skip json.RawMessage
			if err := decoder.Decode(&skip); err != nil {
				return p, broken
			}
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return p, broken
	}
	p.Kry = slices.Contains(p.Tags, Tag)
	closing := int(decoder.InputOffset()) - 1
	p.closeAt = closing
	for p.closeAt > 0 && space(s.blank[p.closeAt-1]) && !s.commas[p.closeAt-1] {
		p.closeAt--
	}
	p.needComma = p.closeAt > 0 && !s.commas[p.closeAt-1] && s.blank[p.closeAt-1] != '{'
	if quote := bytes.IndexByte(s.blank[first:], '"'); quote >= 0 {
		p.indent = lineIndent(src, first+quote, "")
	}
	if p.Open != "" {
		for i := p.OpenSpan[1]; i < len(s.blank); i++ {
			if s.commas[i] || s.blank[i] == ',' {
				p.openComma = i
				break
			}
			if !space(s.blank[i]) {
				break
			}
		}
	}
	return p, nil
}

func lineIndent(src []byte, at int, fallback string) string {
	start := bytes.LastIndexByte(src[:at], '\n') + 1
	if strings.Trim(string(src[start:at]), " \t") != "" {
		return fallback
	}
	return string(src[start:at])
}

func blankRun(src []byte, from, to int) bool {
	return strings.Trim(string(src[from:to]), " \t\r") == ""
}

func Splice(src []byte, p Policy, lines []string, dropOpen bool) []byte {
	type edit struct {
		at, end int
		text    string
		newline bool
	}
	inner := p.indent + p.indent
	block := func(indent string) string {
		var text strings.Builder
		text.WriteString(beginMarker + "\n")
		for _, line := range lines {
			text.WriteString(indent + line + ",\n")
		}
		text.WriteString(indent + endMarker)
		return text.String()
	}
	var edits []edit
	switch {
	case p.Block != nil:
		indent := lineIndent(src, p.BlockSpan[0], inner)
		edits = append(edits, edit{at: p.BlockSpan[0], end: p.BlockSpan[1], text: block(indent)})
	case p.GrantsAt >= 0:
		edits = append(edits, edit{at: p.GrantsAt, end: p.GrantsAt, text: "\n" + inner + block(inner), newline: true})
	default:
		lead := ""
		if p.needComma {
			lead = ","
		}
		edits = append(edits, edit{at: p.closeAt, end: p.closeAt, text: lead + "\n" + p.indent + `"grants": [` + "\n" + inner + block(inner) + "\n" + p.indent + "]"})
	}
	if dropOpen && p.Open != "" {
		start, stop := p.OpenSpan[0], p.OpenSpan[1]
		lineStart := bytes.LastIndexByte(src[:start], '\n') + 1
		lineEnd := bytes.IndexByte(src[stop:], '\n')
		if lineEnd < 0 {
			lineEnd = len(src)
		} else {
			lineEnd += stop
		}
		tail := stop
		if p.openComma >= 0 && p.openComma < lineEnd && blankRun(src, stop, p.openComma) {
			tail = p.openComma + 1
		}
		switch {
		case lineStart > 0 && blankRun(src, lineStart, start) && blankRun(src, tail, lineEnd) && (p.openComma < 0 || tail > p.openComma):
			edits = append(edits, edit{at: lineStart - 1, end: lineEnd})
		default:
			edits = append(edits, edit{at: start, end: stop})
			if p.openComma >= 0 {
				edits = append(edits, edit{at: p.openComma, end: p.openComma + 1})
			}
		}
	}
	slices.SortFunc(edits, func(a, b edit) int {
		if a.at != b.at {
			return b.at - a.at
		}
		return b.end - a.end
	})
	out := slices.Clone(src)
	for _, change := range edits {
		text := change.text
		if change.newline && (change.end >= len(out) || (out[change.end] != '\n' && out[change.end] != '\r')) {
			text += "\n" + p.indent
		}
		out = slices.Concat(out[:change.at], []byte(text), out[change.end:])
	}
	return out
}

func BlockHash(lines []string) string {
	if lines == nil {
		return ""
	}
	hash := sha256.New()
	for _, line := range lines {
		if trimmed := trimLine(line); trimmed != "" {
			hash.Write([]byte(trimmed + "\n"))
		}
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func ports(list []string) ([]string, error) {
	if len(list) == 0 {
		return nil, errors.New("a rule needs at least one port")
	}
	ip := []string{}
	for _, port := range list {
		match := portPattern.FindStringSubmatch(port)
		if match == nil {
			return nil, fmt.Errorf("%q is not a port", port)
		}
		if port == "*" {
			ip = append(ip, "*")
			continue
		}
		first, _ := strconv.Atoi(match[2])
		last := first
		if match[4] != "" {
			last, _ = strconv.Atoi(match[4])
		}
		if first < 1 || last > 65535 || first > last {
			return nil, fmt.Errorf("%q is not a port", port)
		}
		span := match[2] + match[3]
		switch match[6] {
		case "":
			ip = append(ip, "tcp:"+span, "udp:"+span)
		default:
			ip = append(ip, match[6]+":"+span)
		}
	}
	return ip, nil
}

func Grants(rules []Rule, servers map[string][]string, rest []string) ([]string, error) {
	all := []string{}
	for _, id := range slices.Sorted(maps.Keys(servers)) {
		all = append(all, servers[id]...)
	}
	side := func(name string) ([]string, error) {
		switch name {
		case "devices":
			return []string{"autogroup:member"}, nil
		case "servers":
			return all, nil
		}
		if addresses := servers[name]; len(addresses) > 0 {
			return addresses, nil
		}
		return nil, fmt.Errorf("%s is not one of your servers on Tailscale", name)
	}
	lines := []string{}
	for _, rule := range rules {
		if rule.Raw != "" {
			if strings.ContainsAny(rule.Raw, "\r\n") || !strings.HasPrefix(rule.Raw, "{") || !json.Valid([]byte(rule.Raw)) {
				return nil, errors.New("a kept rule is not one grant on one line")
			}
			lines = append(lines, rule.Raw)
			continue
		}
		src, err := side(rule.From)
		if err != nil {
			return nil, err
		}
		var dst, ip []string
		switch {
		case rule.To == "rest" && rule.From == "devices":
			dst, ip = rest, []string{"*"}
		case rule.To == "rest" || rule.To == "devices":
			return nil, errors.New("your servers never reach your devices")
		default:
			if dst, err = side(rule.To); err != nil {
				return nil, err
			}
			if ip, err = ports(rule.Ports); err != nil {
				return nil, err
			}
		}
		line, err := json.Marshal(struct {
			Src []string `json:"src"`
			Dst []string `json:"dst"`
			IP  []string `json:"ip"`
		}{src, dst, ip})
		if err != nil {
			return nil, err
		}
		lines = append(lines, string(line))
	}
	return lines, nil
}

func Rest(devices []Device, tags []string) []string {
	routes := []string{}
	for _, device := range devices {
		for _, route := range device.Routes {
			if route != "0.0.0.0/0" && route != "::/0" && !slices.Contains(routes, route) {
				routes = append(routes, route)
			}
		}
	}
	slices.Sort(routes)
	rest := append([]string{"autogroup:member", "autogroup:internet"}, routes...)
	for _, tag := range slices.Sorted(slices.Values(tags)) {
		if tag != Tag {
			rest = append(rest, tag)
		}
	}
	return rest
}
