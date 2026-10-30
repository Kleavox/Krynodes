package network

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

const (
	PublishChain       = "KRY-PUBLISH"
	FromEveryone       = "everyone"
	FromTailscale      = "tailscale"
	FromAddresses      = "addresses"
	TailscaleInterface = "tailscale0"
	maxAddresses       = 8
)

var TailscaleRanges = []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"}

type Opening struct {
	Port      int      `json:"port"`
	Protocol  string   `json:"protocol"`
	From      string   `json:"from"`
	Addresses []string `json:"addresses,omitempty"`
}

func (o Opening) Key() string {
	return fmt.Sprintf("%d/%s", o.Port, o.Protocol)
}

func (o Opening) String() string {
	from := o.From
	if o.From == FromAddresses {
		from = strings.Join(o.Addresses, "+")
	}
	return o.Key() + "@" + from
}

func ParseOpening(port, protocol, from string) (Opening, error) {
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return Opening{}, fmt.Errorf("%.12q is not a port between 1 and 65535", port)
	}
	if protocol != "tcp" && protocol != "udp" {
		return Opening{}, errors.New("the protocol is tcp or udp")
	}
	opening := Opening{Port: number, Protocol: protocol, From: from}
	if from == FromEveryone || from == FromTailscale {
		return opening, nil
	}
	opening.From = FromAddresses
	for _, field := range strings.FieldsFunc(from, func(r rune) bool { return r == ',' || r == '+' || r == ' ' }) {
		prefix, err := netip.ParsePrefix(field)
		if err != nil {
			address, addressErr := netip.ParseAddr(field)
			if addressErr != nil {
				return Opening{}, fmt.Errorf("%.48q is not an address or a range written as address/bits", field)
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		if text := prefix.Masked().String(); !slices.Contains(opening.Addresses, text) {
			opening.Addresses = append(opening.Addresses, text)
		}
	}
	if len(opening.Addresses) == 0 || len(opening.Addresses) > maxAddresses {
		return Opening{}, fmt.Errorf("a port opens to everyone, to Tailscale, or to 1 to %d addresses", maxAddresses)
	}
	return opening, nil
}

func ParseOpenings(list string) ([]Opening, error) {
	openings := []Opening{}
	for entry := range strings.SplitSeq(list, ",") {
		if entry = strings.TrimSpace(entry); entry == "" {
			continue
		}
		port, from, found := strings.Cut(entry, "@")
		number, protocol, _ := strings.Cut(port, "/")
		if !found {
			return nil, fmt.Errorf("%.40q is not written as number/tcp@from", entry)
		}
		opening, err := ParseOpening(number, protocol, from)
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(openings, func(other Opening) bool { return other.Key() == opening.Key() }) {
			return nil, fmt.Errorf("%s is listed twice", opening.Key())
		}
		openings = append(openings, opening)
	}
	return openings, nil
}

func (o Opening) sources() []string {
	switch o.From {
	case FromTailscale:
		return TailscaleRanges
	case FromAddresses:
		return o.Addresses
	}
	return nil
}

func (o Opening) UfwRules() []string {
	port := strconv.Itoa(o.Port)
	switch o.From {
	case FromEveryone:
		return []string{"allow " + o.Key()}
	case FromTailscale:
		return []string{"allow in on " + TailscaleInterface + " to any port " + port + " proto " + o.Protocol}
	}
	rules := []string{}
	for _, source := range o.Addresses {
		rules = append(rules, "allow from "+source+" to any port "+port+" proto "+o.Protocol)
	}
	return rules
}

func (o Opening) FirewalldRules() []string {
	if o.From == FromEveryone {
		return []string{"port:" + o.Key()}
	}
	rules := []string{}
	for _, source := range o.sources() {
		family := "ipv4"
		if strings.Contains(source, ":") {
			family = "ipv6"
		}
		rules = append(rules, fmt.Sprintf(`rich:rule family="%s" source address="%s" port port="%d" protocol="%s" accept`, family, source, o.Port, o.Protocol))
	}
	return rules
}

func Publish(open []Opening, ipv6 bool) []string {
	prefix := "-A " + PublishChain + " "
	rules := []string{
		prefix + "-m conntrack ! --ctstate NEW -j RETURN",
		prefix + "-m conntrack ! --ctstate DNAT -j RETURN",
	}
	for _, bridge := range []string{"docker0", "br-+", "krc+", Interface} {
		rules = append(rules, prefix+"-i "+bridge+" -j RETURN")
	}
	for _, opening := range open {
		allow := fmt.Sprintf("-p %s -m conntrack --ctorigdstport %d -j RETURN", opening.Protocol, opening.Port)
		switch opening.From {
		case FromEveryone:
			rules = append(rules, prefix+allow)
		case FromTailscale:
			rules = append(rules, prefix+"-i "+TailscaleInterface+" "+allow)
		default:
			for _, source := range opening.Addresses {
				if strings.Contains(source, ":") == ipv6 {
					rules = append(rules, prefix+"-s "+source+" "+allow)
				}
			}
		}
	}
	return append(rules, prefix+"-j DROP")
}
