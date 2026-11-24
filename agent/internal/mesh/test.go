package mesh

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/platform"
)

const (
	unit       = "wg-quick@kry0.service"
	maxUsed    = 200
	maxOthers  = 16
	largeTries = 8
)

var (
	probeListen = 20 * time.Second
	probeOn     = netip.IPv6Unspecified()
	pingSent    = regexp.MustCompile(`(\d+) packets transmitted, (\d+) (?:packets )?received`)
	pingAverage = regexp.MustCompile(`= [0-9.]+/([0-9.]+)/`)
	ufwEnabled  = regexp.MustCompile(`(?m)^\s*ENABLED\s*=\s*"?yes"?\s*$`)
	inputPolicy = regexp.MustCompile(`(?m)^\s*DEFAULT_INPUT_POLICY\s*=\s*"?(\w+)"?\s*$`)
)

func (m *Mesh) inspect(ctx context.Context, args map[string]string) (string, error) {
	if err := none(args, "inspect"); err != nil {
		return "", err
	}
	found, _, err := m.read(ctx)
	if err != nil {
		return "", err
	}
	found.Used = found.Used[:min(len(found.Used), maxUsed)]
	found.Others = found.Others[:min(len(found.Others), maxOthers)]
	for {
		encoded, err := json.Marshal(found)
		if err != nil || len(encoded) <= maxMessage {
			return string(encoded), err
		}
		switch {
		case len(found.Used) > 0:
			found.Used = found.Used[:len(found.Used)-1]
		case len(found.Others) > 0:
			found.Others = found.Others[:len(found.Others)-1]
		default:
			return "", errors.New("the answer does not fit in one message")
		}
	}
}

func (m *Mesh) probe(ctx context.Context, args map[string]string) (string, error) {
	port, peers, err := network.ProbeArgs(args)
	if err != nil {
		return "", err
	}
	arrived, listened := network.Probe(ctx, netip.AddrPortFrom(probeOn, uint16(port)), peers, probeListen)
	return answer(struct {
		Listened bool     `json:"listened"`
		Arrived  []string `json:"arrived"`
	}{listened, arrived})
}

func (m *Mesh) dump(ctx context.Context) []network.Link {
	output, ok := m.output(ctx, "wg", "show", network.Interface, "dump")
	if !ok {
		return []network.Link{}
	}
	return network.ParseDump(output)
}

func linkOf(links []network.Link, key string) network.Link {
	for _, link := range links {
		if link.Key == key {
			return link
		}
	}
	return network.Link{}
}

type pingCount struct {
	sent, received int
	ms             *float64
}

func (m *Mesh) ping(ctx context.Context, args ...string) pingCount {
	output, _ := m.output(ctx, "ping", args...)
	var count pingCount
	if found := pingSent.FindStringSubmatch(output); found != nil {
		count.sent, _ = strconv.Atoi(found[1])
		count.received, _ = strconv.Atoi(found[2])
	}
	if found := pingAverage.FindStringSubmatch(output); found != nil {
		if ms, err := strconv.ParseFloat(found[1], 64); err == nil {
			count.ms = &ms
		}
	}
	return count
}

type linkTest struct {
	Up            bool    `json:"up"`
	HasKey        bool    `json:"hasKey"`
	Version       *int    `json:"version"`
	Clock         int64   `json:"clock"`
	PublicAddress *string `json:"publicAddress"`
	Firewall      struct {
		Lets bool  `json:"lets"`
		Rule *bool `json:"rule"`
	} `json:"firewall"`
	Handshakes struct {
		Sent     int64 `json:"sent"`
		Received int64 `json:"received"`
		Answered int   `json:"answered"`
		Third    *bool `json:"third"`
	} `json:"handshakes"`
	Small struct {
		Sent int      `json:"sent"`
		Lost int      `json:"lost"`
		MS   *float64 `json:"ms"`
	} `json:"small"`
	Large struct {
		Passed *int  `json:"passed"`
		Tried  []int `json:"tried"`
	} `json:"large"`
}

func withAnnounced(document network.Document, announced map[string]string) network.Document {
	document.Members = slices.Clone(document.Members)
	for index, entry := range document.Members {
		if key, ok := announced[entry.Node]; ok {
			document.Members[index].Key = key
		}
	}
	return document
}

func (m *Mesh) linkTest(ctx context.Context, args map[string]string) (string, error) {
	peer, address, mtu, err := network.LinkTestArgs(args)
	if err != nil {
		return "", err
	}
	current, err := m.load()
	if err != nil {
		return "", err
	}
	var found linkTest
	found.Clock = m.Now().Unix()
	found.Large.Tried = []int{}
	if current.Applied.Version > 0 {
		version := current.Applied.Version
		found.Version = &version
	}
	key := ""
	if current.Document != nil {
		if entry, ok := member(withAnnounced(*current.Document, current.Announced), peer); ok {
			key = entry.Key
		}
	}
	state, _ := m.output(ctx, "systemctl", "is-active", unit)
	found.Up = strings.TrimSpace(state) == "active"
	m.firewallLets(ctx, current.Port, &found)
	first := linkOf(m.dump(ctx), key)
	found.HasKey = key != "" && first.Key == key
	if first.Endpoint != nil {
		if endpoint, err := netip.ParseAddrPort(*first.Endpoint); err == nil {
			found.PublicAddress = m.sourceFor(ctx, endpoint.Addr().String())
		}
	}
	small := m.ping(ctx, "-n", "-c", "5", "-i", "0.2", "-W", "1", "-I", network.Interface, address)
	found.Small.Sent, found.Small.Lost, found.Small.MS = small.sent, small.sent-small.received, small.ms
	for size := mtu; size >= 1280 && len(found.Large.Tried) < largeTries; size -= 20 {
		found.Large.Tried = append(found.Large.Tried, size)
		if m.ping(ctx, "-n", "-c", "2", "-W", "1", "-M", "do", "-s", strconv.Itoa(size-28), "-I", network.Interface, address).received > 0 {
			passed := size
			found.Large.Passed = &passed
			break
		}
	}
	after := m.dump(ctx)
	last := linkOf(after, key)
	found.Handshakes.Sent, found.Handshakes.Received = max(last.TX-first.TX, 0), max(last.RX-first.RX, 0)
	if last.Handshake != nil && (first.Handshake == nil || *last.Handshake > *first.Handshake) {
		found.Handshakes.Answered = 1
	}
	for _, other := range after {
		if other.Key == key {
			continue
		}
		recent := other.Handshake != nil && m.Now().Unix()-*other.Handshake < network.AnswerSeconds
		found.Handshakes.Third = &recent
		if recent {
			break
		}
	}
	return answer(found)
}

func (m *Mesh) sourceFor(ctx context.Context, address string) *string {
	output, ok := m.output(ctx, "ip", "-j", "route", "get", address)
	if !ok {
		return nil
	}
	var routes []struct {
		Source string `json:"prefsrc"`
	}
	if json.Unmarshal([]byte(output), &routes) != nil || len(routes) == 0 || routes[0].Source == "" || len(routes[0].Source) > 45 {
		return nil
	}
	return &routes[0].Source
}

type firewall struct {
	active, firewalld bool
}

func (m *Mesh) path(name string) string {
	return filepath.Join(m.Root, filepath.FromSlash(name))
}

func (m *Mesh) firewallOf(ctx context.Context) firewall {
	ufw, _ := os.ReadFile(m.path("/etc/ufw/ufw.conf"))
	state := firewall{active: ufwEnabled.Match(ufw)}
	if platform.Detect(m.platform()).Family == platform.RHEL {
		running, _ := m.output(ctx, "firewall-cmd", "--state")
		state.firewalld = strings.TrimSpace(running) == "running"
		state.active = state.active || state.firewalld
	}
	return state
}

func (m *Mesh) firewallLets(ctx context.Context, port int, found *linkTest) {
	state := m.firewallOf(ctx)
	if !state.active {
		found.Firewall.Lets = true
		return
	}
	var open []openPort
	rule := false
	if state.firewalld {
		open = m.firewalldOpen(ctx)
		_, rule = m.output(ctx, "firewall-cmd", "--query-port="+strconv.Itoa(port)+"/udp")
	} else {
		open = m.ufwOpen()
		rule = m.ufwRule(port, "udp", network.Comment)
	}
	found.Firewall.Lets = slices.ContainsFunc(open, func(entry openPort) bool { return entry.lets(port, "udp") })
	found.Firewall.Rule = &rule
}

type openPort struct {
	low, high int
	protocol  string
}

func (p openPort) lets(port int, protocol string) bool {
	return port >= p.low && port <= p.high && (p.protocol == "any" || p.protocol == protocol)
}

func portRanges(text, separator, protocol string) []openPort {
	var open []openPort
	for item := range strings.SplitSeq(text, ",") {
		low, high, ranged := strings.Cut(item, separator)
		if !ranged {
			high = low
		}
		from, errLow := strconv.Atoi(low)
		to, errHigh := strconv.Atoi(high)
		if errLow == nil && errHigh == nil && from <= to {
			open = append(open, openPort{low: from, high: to, protocol: protocol})
		}
	}
	return open
}

func (m *Mesh) routed() []string {
	found := m.uplinks(4)
	for _, name := range m.uplinks(6) {
		if !slices.Contains(found, name) {
			found = append(found, name)
		}
	}
	return found
}

func (m *Mesh) ufwOpen() []openPort {
	policy, _ := os.ReadFile(m.path("/etc/default/ufw"))
	if match := inputPolicy.FindSubmatch(policy); match != nil && strings.EqualFold(string(match[1]), "ACCEPT") {
		return []openPort{{low: 0, high: 65535, protocol: "any"}}
	}
	routed := m.routed()
	var open []openPort
	for _, file := range []string{"/etc/ufw/user.rules", "/etc/ufw/user6.rules"} {
		body, _ := os.ReadFile(m.path(file))
		for line := range strings.SplitSeq(string(body), "\n") {
			rest, ok := strings.CutPrefix(strings.TrimSpace(line), "### tuple ### ")
			if !ok {
				continue
			}
			fields := slices.DeleteFunc(strings.Fields(rest), func(field string) bool { return strings.HasPrefix(field, "comment=") })
			if len(fields) != 7 && len(fields) != 9 {
				continue
			}
			action, _, _ := strings.Cut(fields[0], "_")
			protocol, ports, sourcePort, source, direction := fields[1], fields[2], fields[4], fields[5], fields[len(fields)-1]
			if action != "allow" && action != "limit" || sourcePort != "any" || (source != "0.0.0.0/0" && source != "::/0") {
				continue
			}
			if iface, bound := strings.CutPrefix(direction, "in_"); direction != "in" && (!bound || !slices.Contains(routed, iface)) {
				continue
			}
			if protocol != "any" && protocol != "tcp" && protocol != "udp" {
				continue
			}
			if ports == "any" {
				open = append(open, openPort{low: 0, high: 65535, protocol: protocol})
			} else {
				open = append(open, portRanges(ports, ":", protocol)...)
			}
		}
	}
	return open
}

func (m *Mesh) ufwRule(port int, protocol, comment string) bool {
	mark := "comment=" + hex.EncodeToString([]byte(comment))
	for _, file := range []string{"/etc/ufw/user.rules", "/etc/ufw/user6.rules"} {
		body, _ := os.ReadFile(m.path(file))
		for line := range strings.SplitSeq(string(body), "\n") {
			rest, ok := strings.CutPrefix(strings.TrimSpace(line), "### tuple ### ")
			fields := strings.Fields(rest)
			if ok && len(fields) > 2 && fields[1] == protocol && fields[2] == strconv.Itoa(port) && slices.Contains(fields, mark) {
				return true
			}
		}
	}
	return false
}

func infoField(output, name string) []string {
	for line := range strings.SplitSeq(output, "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), name+":"); ok {
			return strings.Fields(value)
		}
	}
	return nil
}

func firewalldPorts(entries []string) []openPort {
	var open []openPort
	for _, entry := range entries {
		if ports, protocol, ok := strings.Cut(entry, "/"); ok {
			open = append(open, portRanges(ports, "-", protocol)...)
		}
	}
	return open
}

func (m *Mesh) firewalldOpen(ctx context.Context) []openPort {
	zone := ""
	if routed := m.routed(); len(routed) > 0 {
		zone, _ = m.output(ctx, "firewall-cmd", "--get-zone-of-interface="+routed[0])
	}
	if zone = strings.TrimSpace(zone); zone == "" {
		zone, _ = m.output(ctx, "firewall-cmd", "--get-default-zone")
		zone = strings.TrimSpace(zone)
	}
	info, _ := m.output(ctx, "firewall-cmd", "--info-zone="+zone)
	if slices.Contains(infoField(info, "target"), "ACCEPT") {
		return []openPort{{low: 0, high: 65535, protocol: "any"}}
	}
	open := firewalldPorts(infoField(info, "ports"))
	for _, service := range infoField(info, "services") {
		described, _ := m.output(ctx, "firewall-cmd", "--info-service="+service)
		open = append(open, firewalldPorts(infoField(described, "ports"))...)
	}
	return open
}
