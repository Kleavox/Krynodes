package tailscale

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const (
	socketPath = "/var/run/tailscale/tailscaled.sock"
	maxReach   = 64
	maxFrom    = 32
	maxPorts   = 32
	maxNames   = 64
	maxInUse   = 200
)

type filterRule struct {
	SrcIPs   []string `json:"SrcIPs"`
	DstPorts []struct {
		IP    string `json:"IP"`
		Ports struct {
			First int `json:"First"`
			Last  int `json:"Last"`
		} `json:"Ports"`
	} `json:"DstPorts"`
	IPProto []int `json:"IPProto"`
}

type portRange struct {
	first, last int
	tcp, udp    bool
}

func Socket(ctx context.Context, path string) ([]byte, error) {
	client := http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", socketPath)
	}}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local-tailscaled.sock"+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Sec-Tailscale", "localapi")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tailscaled answered %s", response.Status)
	}
	return body, err
}

func bare(address string) string {
	if host, bits, found := strings.Cut(address, "/"); found && (bits == "32" || bits == "128") {
		return host
	}
	return address
}

func protocols(numbers []int) (bool, bool) {
	if len(numbers) == 0 {
		return true, true
	}
	return slices.Contains(numbers, 6), slices.Contains(numbers, 17)
}

func (r portRange) String() string {
	if r.first == 0 && r.last == 65535 {
		return "*"
	}
	text := strconv.Itoa(r.first)
	if r.last != r.first {
		text += "-" + strconv.Itoa(r.last)
	}
	switch {
	case r.tcp && !r.udp:
		text += "/tcp"
	case r.udp && !r.tcp:
		text += "/udp"
	}
	return text
}

func Reach(body []byte, self []string, peers map[string]string) ([]reporter.TailscaleReach, map[string]string) {
	names := map[string]string{}
	var rules []filterRule
	if err := json.Unmarshal(body, &rules); err != nil {
		return nil, names
	}
	own := map[string]bool{"*": true, "0.0.0.0/0": true, "::/0": true}
	for _, address := range self {
		own[bare(address)] = true
	}
	sources := map[string][]string{}
	ranges := map[string]map[[2]int]*portRange{}
	for _, rule := range rules {
		tcp, udp := protocols(rule.IPProto)
		if !tcp && !udp {
			continue
		}
		from := []string{}
		for _, source := range rule.SrcIPs {
			from = append(from, bare(source))
		}
		slices.Sort(from)
		from = slices.Compact(from)
		key := strings.Join(from, ",")
		for _, destination := range rule.DstPorts {
			if !own[bare(destination.IP)] {
				continue
			}
			if ranges[key] == nil {
				ranges[key], sources[key] = map[[2]int]*portRange{}, from
			}
			span := [2]int{destination.Ports.First, destination.Ports.Last}
			entry := ranges[key][span]
			if entry == nil {
				entry = &portRange{first: span[0], last: span[1]}
				ranges[key][span] = entry
			}
			entry.tcp, entry.udp = entry.tcp || tcp, entry.udp || udp
		}
	}
	keys := make([]string, 0, len(ranges))
	for key := range ranges {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	reach := []reporter.TailscaleReach{}
	for _, key := range keys {
		if len(reach) == maxReach {
			break
		}
		spans := make([]*portRange, 0, len(ranges[key]))
		for _, entry := range ranges[key] {
			spans = append(spans, entry)
		}
		slices.SortFunc(spans, func(a, b *portRange) int {
			return cmp.Or(cmp.Compare(a.first, b.first), cmp.Compare(a.last, b.last))
		})
		ports := []string{}
		for _, entry := range spans[:min(len(spans), maxPorts)] {
			ports = append(ports, entry.String())
		}
		from := sources[key][:min(len(sources[key]), maxFrom)]
		for _, address := range from {
			if name, known := peers[address]; known && name != "" && len(names) < maxNames {
				names[address] = name
			}
		}
		reach = append(reach, reporter.TailscaleReach{From: from, Ports: ports})
	}
	return reach, names
}

func hostPort(text string) (string, string, error) {
	colon := strings.LastIndex(text, ":")
	if colon < 0 {
		return "", "", errors.New("no port")
	}
	host := strings.Trim(text[:colon], "[]")
	if percent := strings.Index(host, "%"); percent >= 0 {
		host = host[:percent]
	}
	return host, text[colon+1:], nil
}

func Listening(ss string) []string {
	listening := []string{}
	for line := range strings.SplitSeq(ss, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || (fields[0] != "tcp" && fields[0] != "udp") {
			continue
		}
		host, port, err := hostPort(fields[4])
		if err != nil || strings.HasPrefix(host, "127.") || host == "::1" {
			continue
		}
		listening = append(listening, port+"/"+fields[0])
	}
	slices.Sort(listening)
	return slices.Compact(listening)
}

func field(fields []string, prefix string) string {
	for _, entry := range fields {
		if value, found := strings.CutPrefix(entry, prefix); found {
			return value
		}
	}
	return ""
}

func InUse(established, conntrack string, self []string, listening []string) []reporter.TailscaleUse {
	own := map[string]bool{}
	for _, address := range self {
		own[bare(address)] = true
	}
	used := []reporter.TailscaleUse{}
	add := func(from, port string) {
		use := reporter.TailscaleUse{From: from, Port: port}
		if own[from] || !slices.Contains(listening, port) || slices.Contains(used, use) {
			return
		}
		used = append(used, use)
	}
	for line := range strings.SplitSeq(established, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		local, port, err := hostPort(fields[2])
		peer, _, peerErr := hostPort(fields[3])
		if err == nil && peerErr == nil && own[local] {
			add(peer, port+"/tcp")
		}
	}
	for line := range strings.SplitSeq(conntrack, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[2] != "udp" {
			continue
		}
		if destination := field(fields, "dst="); own[destination] {
			add(field(fields, "src="), field(fields, "dport=")+"/udp")
		}
	}
	slices.SortFunc(used, func(a, b reporter.TailscaleUse) int {
		return cmp.Or(cmp.Compare(a.Port, b.Port), cmp.Compare(a.From, b.From))
	})
	return used[:min(len(used), maxInUse)]
}
