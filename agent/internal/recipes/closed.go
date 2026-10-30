package recipes

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

type Rules struct {
	Tool   string
	Active bool
	Zone   string
	Lines  []string
}

type Adopted struct {
	Open    []network.Opening
	Other   []string
	managed []string
}

var (
	ufwComment   = regexp.MustCompile(`\s+comment\s+'[^']*'\s*$`)
	ufwEveryone  = regexp.MustCompile(`^allow (\d{1,5})(?:/(tcp|udp))?$`)
	ufwTailscale = regexp.MustCompile(`^allow in on ` + network.TailscaleInterface + ` to any port (\d{1,5}) proto (tcp|udp)$`)
	ufwFrom      = regexp.MustCompile(`^allow from (\S+) to any port (\d{1,5}) proto (tcp|udp)$`)
	richAccept   = regexp.MustCompile(`^rule (?:family="ipv[46]" )?source address="([^"]+)" port port="(\d{1,5})" protocol="(tcp|udp)" accept$`)
	zoneName     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	ufwFiles     = []string{"/etc/ufw/user.rules", "/etc/ufw/user6.rules", "/etc/default/ufw"}
)

func RouteInterfaces(env Env) []string {
	var names []string
	add := func(name string) {
		if name != "" && name != "lo" && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	if body, err := os.ReadFile(env.path("/proc/net/route")); err == nil {
		for line := range strings.SplitSeq(string(body), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 7 && fields[1] == "00000000" && fields[7] == "00000000" {
				add(fields[0])
			}
		}
	}
	if body, err := os.ReadFile(env.path("/proc/net/ipv6_route")); err == nil {
		for line := range strings.SplitSeq(string(body), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 10 && strings.Trim(fields[0], "0") == "" && fields[1] == "00" {
				add(fields[9])
			}
		}
	}
	return names
}

func InfoField(output, name string) []string {
	for line := range strings.SplitSeq(output, "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), name+":"); ok {
			return strings.Fields(value)
		}
	}
	return nil
}

func ReadRules(ctx context.Context, env Env) Rules {
	return readRules(ctx, env, false)
}

func LiveRules(ctx context.Context, env Env) Rules {
	return readRules(ctx, env, true)
}

func readRules(ctx context.Context, env Env, live bool) Rules {
	if Detect(env).Family == RHEL {
		return readFirewalld(ctx, env, live)
	}
	if _, err := env.output(ctx, "ufw", "version"); err != nil {
		return Rules{}
	}
	status, _ := env.output(ctx, "ufw", "status")
	rules := Rules{Tool: "ufw", Active: strings.Contains(status, "Status: active"), Lines: []string{}}
	added, _ := env.output(ctx, "ufw", "show", "added")
	for line := range strings.SplitSeq(added, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "ufw "); ok {
			rules.Lines = append(rules.Lines, ufwComment.ReplaceAllString(rest, ""))
		}
	}
	return rules
}

func readFirewalld(ctx context.Context, env Env, live bool) Rules {
	if !env.has(ctx, "firewalld") {
		return Rules{}
	}
	state, _ := env.output(ctx, "firewall-cmd", "--state")
	rules := Rules{Tool: "firewalld", Active: strings.TrimSpace(state) == "running", Lines: []string{}}
	tool := "firewall-offline-cmd"
	if rules.Active {
		tool = "firewall-cmd"
	}
	if routed := RouteInterfaces(env); len(routed) > 0 {
		zone, _ := env.output(ctx, tool, "--get-zone-of-interface="+routed[0])
		rules.Zone = strings.TrimSpace(zone)
	}
	if !zoneName.MatchString(rules.Zone) {
		zone, _ := env.output(ctx, tool, "--get-default-zone")
		rules.Zone = strings.TrimSpace(zone)
	}
	if !zoneName.MatchString(rules.Zone) {
		rules.Zone = "public"
	}
	for _, kind := range []string{"port", "service", "rich"} {
		list := "--list-" + kind + "s"
		if kind == "rich" {
			list = "--list-rich-rules"
		}
		tool, args := rules.zone(list)
		if live && rules.Active {
			args = slices.DeleteFunc(args, func(arg string) bool { return arg == "--permanent" })
		}
		output, _ := env.output(ctx, tool, args...)
		entries := strings.Fields(output)
		if kind == "rich" {
			entries = slices.DeleteFunc(strings.Split(output, "\n"), func(line string) bool { return strings.TrimSpace(line) == "" })
		}
		for _, entry := range entries {
			rules.Lines = append(rules.Lines, kind+":"+strings.TrimSpace(entry))
		}
	}
	return rules
}

func (r Rules) zone(args ...string) (string, []string) {
	if r.Active {
		return "firewall-cmd", append([]string{"--permanent", "--zone=" + r.Zone}, args...)
	}
	return "firewall-offline-cmd", append([]string{"--zone=" + r.Zone}, args...)
}

func (r Rules) system(line string, ssh []string, networkPort string) bool {
	if r.Tool == "firewalld" {
		kind, value, _ := strings.Cut(line, ":")
		return (kind == "port" && (slices.Contains(ssh, value) || value == networkPort+"/udp")) ||
			(kind == "service" && (value == "ssh" || value == "dhcpv6-client"))
	}
	for _, port := range ssh {
		if line == "allow "+port || line == "limit "+port {
			return true
		}
	}
	return line == "allow "+networkPort+"/udp" || line == "allow in on "+network.Interface
}

func (r Rules) openings(ctx context.Context, env Env, line string) []network.Opening {
	parse := func(port, protocol, from string) []network.Opening {
		opening, err := network.ParseOpening(port, protocol, from)
		if err != nil {
			return nil
		}
		return []network.Opening{opening}
	}
	if r.Tool == "ufw" {
		if match := ufwEveryone.FindStringSubmatch(line); match != nil {
			if match[2] != "" {
				return parse(match[1], match[2], network.FromEveryone)
			}
			return append(parse(match[1], "tcp", network.FromEveryone), parse(match[1], "udp", network.FromEveryone)...)
		}
		if match := ufwTailscale.FindStringSubmatch(line); match != nil {
			return parse(match[1], match[2], network.FromTailscale)
		}
		if match := ufwFrom.FindStringSubmatch(line); match != nil {
			return parse(match[2], match[3], match[1])
		}
		return nil
	}
	kind, value, _ := strings.Cut(line, ":")
	switch kind {
	case "port":
		port, protocol, _ := strings.Cut(value, "/")
		return parse(port, protocol, network.FromEveryone)
	case "service":
		tool := "firewall-offline-cmd"
		if r.Active {
			tool = "firewall-cmd"
		}
		info, err := env.output(ctx, tool, "--info-service="+value)
		ports := InfoField(info, "ports")
		if err != nil || len(ports) == 0 || len(InfoField(info, "protocols")) > 0 || len(InfoField(info, "source-ports")) > 0 {
			return nil
		}
		var open []network.Opening
		for _, entry := range ports {
			port, protocol, _ := strings.Cut(entry, "/")
			opening := parse(port, protocol, network.FromEveryone)
			if opening == nil {
				return nil
			}
			open = append(open, opening...)
		}
		return open
	case "rich":
		match := richAccept.FindStringSubmatch(value)
		if match == nil {
			return nil
		}
		if slices.Contains(network.TailscaleRanges, match[1]) {
			return parse(match[2], match[3], network.FromTailscale)
		}
		return parse(match[2], match[3], match[1])
	}
	return nil
}

func OpeningOf(tool, line string) (network.Opening, bool) {
	rules := Rules{Tool: tool}
	if strings.HasPrefix(line, "service:") {
		return network.Opening{}, false
	}
	open := rules.openings(context.Background(), Env{}, line)
	if len(open) != 1 || !slices.Equal(linesOf(rules, open[0]), []string{line}) {
		return network.Opening{}, false
	}
	return open[0], true
}

func Drift(ctx context.Context, env Env, rules Rules, known []string, networkPort string) []string {
	var ssh []string
	drift := []string{}
	for _, line := range rules.Lines {
		if slices.Contains(known, line) || !lets(line) {
			continue
		}
		if ssh == nil {
			ssh = sshPorts(ctx, env)
		}
		if !rules.system(line, ssh, networkPort) {
			drift = append(drift, line)
		}
	}
	return drift
}

func lets(line string) bool {
	for _, verb := range []string{"allow ", "limit ", "port:", "service:"} {
		if strings.HasPrefix(line, verb) {
			return true
		}
	}
	return strings.HasPrefix(line, "rich:") && strings.HasSuffix(line, " accept")
}

func merge(open []network.Opening, add network.Opening) ([]network.Opening, bool) {
	at := slices.IndexFunc(open, func(other network.Opening) bool { return other.Key() == add.Key() })
	switch {
	case at < 0:
		return append(open, add), true
	case open[at].From == network.FromEveryone || open[at].From == add.From && add.From == network.FromTailscale:
		return open, true
	case add.From == network.FromEveryone:
		open[at] = add
		return open, true
	case open[at].From == network.FromAddresses && add.From == network.FromAddresses:
		joined, err := network.ParseOpening(strconv.Itoa(add.Port), add.Protocol, strings.Join(append(slices.Clone(open[at].Addresses), add.Addresses...), "+"))
		if err != nil {
			return open, false
		}
		open[at] = joined
		return open, true
	}
	return open, false
}

func Adopt(ctx context.Context, env Env, rules Rules, networkPort string) Adopted {
	ssh := sshPorts(ctx, env)
	adopted := Adopted{Open: []network.Opening{}, Other: []string{}}
	for _, line := range rules.Lines {
		if rules.system(line, ssh, networkPort) || !lets(line) {
			continue
		}
		openings := rules.openings(ctx, env, line)
		merged := len(openings) > 0
		next := slices.Clone(adopted.Open)
		for _, opening := range openings {
			if slices.Contains(ssh, opening.Key()) {
				continue
			}
			var ok bool
			if next, ok = merge(next, opening); !ok {
				merged = false
			}
		}
		if !merged {
			adopted.Other = append(adopted.Other, line)
			continue
		}
		adopted.Open = next
		adopted.managed = append(adopted.managed, line)
	}
	return adopted
}

type wantedLine struct{ line, comment string }

func (r Rules) wanted(ssh []string, networkPort string, open []network.Opening) []wantedLine {
	var wanted []wantedLine
	add := func(comment string, lines ...string) {
		for _, line := range lines {
			if !slices.ContainsFunc(wanted, func(w wantedLine) bool { return w.line == line }) {
				wanted = append(wanted, wantedLine{line, comment})
			}
		}
	}
	for _, port := range ssh {
		if r.Tool == "firewalld" {
			add("", "port:"+port)
		} else {
			add("krynodes", "allow "+port)
		}
	}
	if _, err := strconv.Atoi(networkPort); err == nil {
		if r.Tool == "firewalld" {
			add("", "port:"+networkPort+"/udp")
		} else {
			add(network.Comment, "allow "+networkPort+"/udp", "allow in on "+network.Interface)
		}
	}
	for _, opening := range open {
		if r.Tool == "firewalld" {
			add("", opening.FirewalldRules()...)
		} else {
			add("krynodes", opening.UfwRules()...)
		}
	}
	return wanted
}

func ufwFields(line string) []string {
	var fields []string
	for i, part := range strings.Split(line, "'") {
		if i%2 == 1 {
			fields = append(fields, part)
		} else {
			fields = append(fields, strings.Fields(part)...)
		}
	}
	return fields
}

func (r Rules) change(ctx context.Context, env Env, verb, line, comment string) error {
	if r.Tool == "ufw" {
		if verb == "add" {
			return env.run(ctx, "ufw", append(ufwFields(line), "comment", comment)...)
		}
		return env.run(ctx, "ufw", append([]string{"--force", "delete"}, ufwFields(line)...)...)
	}
	kind, value, _ := strings.Cut(line, ":")
	flag := map[string]string{"port": "port", "service": "service", "rich": "rich-rule"}[kind]
	if flag == "" {
		return fmt.Errorf("%.60q is not a firewalld rule", line)
	}
	tool, args := r.zone("--" + verb + "-" + flag + "=" + value)
	return env.run(ctx, tool, args...)
}

func (r Rules) reload(ctx context.Context, env Env) error {
	if r.Tool == "firewalld" && r.Active {
		return env.run(ctx, "firewall-cmd", "--reload")
	}
	return nil
}

func snapshot(env Env, saved map[string]string, files ...string) {
	for _, file := range files {
		if body, err := os.ReadFile(env.path(file)); err == nil {
			saved["file:"+file] = string(body)
		} else {
			saved["gone:"+file] = "1"
		}
	}
}

func closeFirewall(ctx context.Context, env Env, list, networkPort string) (map[string]string, error) {
	open, err := network.ParseOpenings(list)
	if err != nil {
		return nil, err
	}
	saved := map[string]string{"closed": "1"}
	rules := ReadRules(ctx, env)
	if rules.Tool == "" {
		pkg := "ufw"
		if Detect(env).Family == RHEL {
			pkg = "firewalld"
		}
		fresh, err := env.install(ctx, pkg)
		if err != nil {
			return nil, err
		}
		if fresh != "" {
			saved["installed"] = fresh
		}
		if rules = ReadRules(ctx, env); rules.Tool == "" {
			return nil, errors.New("the firewall could not be read after installing it")
		}
	}
	if rules.Tool == "firewalld" {
		saved["zone"] = rules.Zone
		saved["wasRunning"] = fmt.Sprint(rules.Active)
		snapshot(env, saved, "/etc/firewalld/zones/"+rules.Zone+".xml")
	} else {
		saved["wasActive"] = fmt.Sprint(rules.Active)
		snapshot(env, saved, ufwFiles...)
	}
	ssh := sshPorts(ctx, env)
	wanted := rules.wanted(ssh, networkPort, open)
	failed := func(err error) (map[string]string, error) {
		if back := undoClosed(ctx, env, saved); back != nil {
			return nil, fmt.Errorf("%w; putting the firewall back also failed: %v", err, back)
		}
		return nil, err
	}
	for _, want := range wanted {
		if !slices.Contains(rules.Lines, want.line) {
			if err := rules.change(ctx, env, "add", want.line, want.comment); err != nil {
				return failed(err)
			}
		}
	}
	for _, line := range Adopt(ctx, env, rules, networkPort).managed {
		if !slices.ContainsFunc(wanted, func(w wantedLine) bool { return w.line == line }) {
			if err := rules.change(ctx, env, "remove", line, ""); err != nil {
				return failed(err)
			}
		}
	}
	if rules.Tool == "firewalld" {
		tool, args := rules.zone("--get-target")
		if target, _ := env.output(ctx, tool, args...); strings.TrimSpace(target) == "ACCEPT" {
			if tool, args := rules.zone("--set-target=default"); env.run(ctx, tool, args...) != nil {
				return failed(errors.New("the firewall zone lets everything in and could not be changed"))
			}
		}
		if rules.Active {
			err = env.run(ctx, "firewall-cmd", "--reload")
		} else {
			err = env.run(ctx, "systemctl", "enable", "--now", "firewalld")
		}
		if err != nil {
			return failed(err)
		}
		if slices.ContainsFunc(ssh, func(port string) bool {
			return env.run(ctx, "firewall-cmd", "--zone="+rules.Zone, "--query-port="+port) != nil
		}) {
			return nil, firewallBack(undoClosed(ctx, env, saved))
		}
		return saved, nil
	}
	steps := [][]string{{"default", "deny", "incoming"}}
	if !rules.Active {
		steps = append(steps, []string{"default", "allow", "outgoing"}, []string{"--force", "enable"})
	}
	for _, step := range steps {
		if err := env.run(ctx, "ufw", step...); err != nil {
			return failed(err)
		}
	}
	if status, _ := env.output(ctx, "ufw", "status"); !sshAllowed(status, ssh) {
		return nil, firewallBack(undoClosed(ctx, env, saved))
	}
	return saved, nil
}

func undoClosed(ctx context.Context, env Env, saved map[string]string) error {
	keys := make([]string, 0, len(saved))
	for key := range saved {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if file, ok := strings.CutPrefix(key, "file:"); ok {
			mode := os.FileMode(0o644)
			if info, err := os.Stat(env.path(file)); err == nil {
				mode = info.Mode().Perm()
			}
			if err := env.write(file, saved[key], mode); err != nil {
				return err
			}
		} else if file, ok := strings.CutPrefix(key, "gone:"); ok {
			if err := env.remove(file); err != nil {
				return err
			}
		}
	}
	if _, firewalld := saved["zone"]; firewalld {
		if saved["wasRunning"] == "true" {
			return env.run(ctx, "firewall-cmd", "--reload")
		}
		return env.run(ctx, "systemctl", "disable", "--now", "firewalld")
	}
	if saved["wasActive"] == "true" {
		return env.run(ctx, "ufw", "reload")
	}
	return env.run(ctx, "ufw", "--force", "disable")
}

func alwaysOpen(ctx context.Context, env Env, opening network.Opening, networkPort string) error {
	if slices.Contains(sshPorts(ctx, env), opening.Key()) {
		return errors.New("SSH stays open to everyone")
	}
	if opening.Key() == networkPort+"/udp" {
		return errors.New("the private network's port stays open")
	}
	return nil
}

func linesOf(rules Rules, opening network.Opening) []string {
	if rules.Tool == "firewalld" {
		return opening.FirewalldRules()
	}
	return opening.UfwRules()
}

func OpenPort(ctx context.Context, env Env, before *network.Opening, after network.Opening, networkPort string) error {
	if err := alwaysOpen(ctx, env, after, networkPort); err != nil {
		return err
	}
	rules := ReadRules(ctx, env)
	if rules.Tool == "" {
		return errors.New("this server has no firewall")
	}
	added := linesOf(rules, after)
	for _, line := range added {
		if !slices.Contains(rules.Lines, line) {
			if err := rules.change(ctx, env, "add", line, "krynodes"); err != nil {
				return err
			}
		}
	}
	if before != nil {
		for _, line := range linesOf(rules, *before) {
			if !slices.Contains(added, line) {
				if err := rules.change(ctx, env, "remove", line, ""); err != nil {
					return err
				}
			}
		}
	}
	return rules.reload(ctx, env)
}

func ClosePort(ctx context.Context, env Env, opening network.Opening, networkPort string) error {
	if err := alwaysOpen(ctx, env, opening, networkPort); err != nil {
		return err
	}
	rules := ReadRules(ctx, env)
	if rules.Tool == "" {
		return errors.New("this server has no firewall")
	}
	for _, line := range linesOf(rules, opening) {
		if err := rules.change(ctx, env, "remove", line, ""); err != nil {
			return err
		}
	}
	return rules.reload(ctx, env)
}

func RemoveRule(ctx context.Context, env Env, line, networkPort string) error {
	rules := ReadRules(ctx, env)
	saved := slices.Contains(rules.Lines, line)
	if !saved && !slices.Contains(LiveRules(ctx, env).Lines, line) {
		return errors.New("that rule is no longer in the firewall")
	}
	if rules.system(line, sshPorts(ctx, env), networkPort) {
		return errors.New("Krynodes keeps that rule so SSH and the private network stay reachable")
	}
	if saved {
		if err := rules.change(ctx, env, "remove", line, ""); err != nil {
			return err
		}
	}
	return rules.reload(ctx, env)
}
