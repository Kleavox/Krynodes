package network

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	ServeChain  = "KRY-SERVE"
	ReachChain  = "KRY-REACH"
	Variable    = "KRY_PRIVATE_IP"
	MaxServes   = 16
	MaxPlaces   = 32
	maxChosen   = 32
	replyReturn = "-A " + ReachChain + " -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN"
)

var (
	portText  = regexp.MustCompile(`^(\d{1,5})/(tcp|udp)$`)
	placeText = regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})/(tcp|udp)$`)
)

type Serve struct {
	Port string   `json:"port"`
	All  bool     `json:"all,omitempty"`
	To   []string `json:"to,omitempty"`
}

type StackRules struct {
	Project string
	Bridges []string
	Serves  []Serve
	Reaches []string
}

func validPortText(text string) bool {
	match := portText.FindStringSubmatch(text)
	if match == nil {
		return false
	}
	number, _ := strconv.Atoi(match[1])
	return number >= 1 && number <= 65535
}

func ParseServes(text string) ([]Serve, error) {
	var serves []Serve
	for entry := range strings.SplitSeq(text, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		port, who, _ := strings.Cut(entry, "=")
		if !validPortText(port) {
			return nil, fmt.Errorf("%s is not a port such as 5432/tcp", port)
		}
		if slices.ContainsFunc(serves, func(serve Serve) bool { return serve.Port == port }) {
			return nil, fmt.Errorf("%s is listed twice", port)
		}
		serve := Serve{Port: port}
		if who == "all" {
			serve.All = true
		} else {
			serve.To = strings.Fields(who)
			if len(serve.To) == 0 || len(serve.To) > maxChosen || slices.ContainsFunc(serve.To, func(node string) bool { return !nodeID.MatchString(node) }) {
				return nil, fmt.Errorf("%s names no servers it may be reached from", port)
			}
		}
		serves = append(serves, serve)
	}
	if len(serves) > MaxServes {
		return nil, fmt.Errorf("a stack may serve at most %d ports to the network", MaxServes)
	}
	return serves, nil
}

func ParsePlaces(text, networkRange, own string) ([]string, error) {
	prefix, err := netip.ParsePrefix(networkRange)
	if err != nil {
		return nil, errors.New("the private network has no range")
	}
	var places []string
	for entry := range strings.SplitSeq(text, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		match := placeText.FindStringSubmatch(entry)
		var address netip.Addr
		number := 0
		if match != nil {
			address, err = netip.ParseAddr(match[1])
			number, _ = strconv.Atoi(match[2])
		}
		switch {
		case match == nil || err != nil || number < 1 || number > 65535:
			return nil, fmt.Errorf("%s is not a place such as 10.88.0.2:5432/tcp", entry)
		case address.String() == own:
			return nil, fmt.Errorf("%s is this server; use Reach This Server On", own)
		case !prefix.Contains(address):
			return nil, fmt.Errorf("%s is outside the private network", address)
		}
		if !slices.Contains(places, entry) {
			places = append(places, entry)
		}
	}
	if len(places) > MaxPlaces {
		return nil, fmt.Errorf("a stack may reach at most %d places", MaxPlaces)
	}
	return places, nil
}

func Jumps(networkRange string) [][]string {
	return [][]string{
		{"-i", Interface, "-j", ServeChain},
		{"-d", networkRange, "-i", "krc+", "-j", ReachChain},
	}
}

func Rules(own string, members []Member, stacks []StackRules) ([]string, []string) {
	addresses := map[string]string{}
	for _, entry := range members {
		addresses[entry.Node] = entry.Address
	}
	serve := []string{}
	reach := []string{replyReturn}
	for _, stack := range stacks {
		for _, entry := range stack.Serves {
			if entry.All {
				continue
			}
			number, protocol, _ := strings.Cut(entry.Port, "/")
			match := fmt.Sprintf("-p %s -m conntrack --ctorigdst %s/32 --ctorigdstport %s", protocol, own, number)
			for _, node := range entry.To {
				if address, ok := addresses[node]; ok && address != own {
					serve = append(serve, fmt.Sprintf("-A %s -s %s/32 %s -j RETURN", ServeChain, address, match))
				}
			}
			serve = append(serve, fmt.Sprintf("-A %s %s -m comment --comment kry-serve:%s -j DROP", ServeChain, match, stack.Project))
		}
		for _, bridge := range stack.Bridges {
			for _, place := range stack.Reaches {
				address, port, _ := strings.Cut(place, ":")
				number, protocol, _ := strings.Cut(port, "/")
				reach = append(reach, fmt.Sprintf("-A %s -d %s/32 -i %s -p %s -m %s --dport %s -j RETURN", ReachChain, address, bridge, protocol, protocol, number))
			}
		}
		for _, bridge := range stack.Bridges {
			reach = append(reach, fmt.Sprintf("-A %s -i %s -m comment --comment kry-reach:%s -j DROP", ReachChain, bridge, stack.Project))
		}
	}
	return serve, append(reach, "-A "+ReachChain+" -j DROP")
}

func Restore(serve, reach []string) string {
	var text strings.Builder
	text.WriteString("*filter\n:" + ServeChain + " - [0:0]\n:" + ReachChain + " - [0:0]\n")
	for _, line := range append(slices.Clone(serve), reach...) {
		text.WriteString(line + "\n")
	}
	text.WriteString("COMMIT\n")
	return text.String()
}
