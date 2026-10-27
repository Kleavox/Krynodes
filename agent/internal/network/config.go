package network

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	ConfigPath = "/etc/wireguard/kry0.conf"
	HostsPath  = "/etc/hosts"
	DropInPath = "/etc/systemd/system/docker.service.d/krynodes-network.conf"
	DropInBody = "[Unit]\nAfter=wg-quick@kry0.service\nWants=wg-quick@kry0.service\n"
	hostsBegin = "# BEGIN krynodes-network"
	hostsEnd   = "# END krynodes-network"
)

var notLabel = regexp.MustCompile(`[^a-z0-9]+`)

func DNSName(name string) string {
	label := strings.Trim(notLabel.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(label) > 63 {
		label = strings.TrimRight(label[:63], "-")
	}
	if label == "" {
		return "server"
	}
	return label
}

func Render(document Document, self Member, private string, psk map[string]string) string {
	mtu := document.MTU
	if self.MTU != nil {
		mtu = *self.MTU
	}
	var config strings.Builder
	fmt.Fprintf(&config, "[Interface]\nPrivateKey = %s\nAddress = %s/24\nListenPort = %d\nMTU = %d\n", private, self.Address, self.Port, mtu)
	if self.MTU != nil {
		clamp := fmt.Sprintf("-t mangle %%s POSTROUTING -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d", Interface, mtu-40)
		fmt.Fprintf(&config, "PostUp = iptables -w "+clamp+"\nPostDown = iptables -w "+clamp+"\n", "-A", "-D")
	}
	for _, peer := range document.Members {
		if peer.Node == self.Node || peer.Cut {
			continue
		}
		fmt.Fprintf(&config, "\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", peer.Key, psk[peer.Node], peer.Address)
		if !peer.NAT && peer.Endpoint != nil {
			fmt.Fprintf(&config, "Endpoint = %s\n", *peer.Endpoint)
		}
		fmt.Fprintf(&config, "PersistentKeepalive = %d\n", Keepalive)
	}
	return config.String()
}

func quickOnly(line string) bool {
	return strings.HasPrefix(line, "Address = ") || strings.HasPrefix(line, "MTU = ") || strings.HasPrefix(line, "PostUp = ") || strings.HasPrefix(line, "PostDown = ")
}

func split(config string) (string, string) {
	var kept, dropped strings.Builder
	for _, line := range strings.SplitAfter(config, "\n") {
		if quickOnly(line) {
			dropped.WriteString(line)
		} else {
			kept.WriteString(line)
		}
	}
	return kept.String(), dropped.String()
}

func Strip(config string) string {
	kept, _ := split(config)
	return kept
}

func NeedsRestart(before, after string) bool {
	_, was := split(before)
	_, is := split(after)
	return was != is
}

func Hosts(current string, members []Member) string {
	var kept []string
	inside := false
	for _, line := range strings.Split(strings.TrimRight(current, "\n"), "\n") {
		switch {
		case line == hostsBegin:
			inside = true
		case line == hostsEnd:
			inside = false
		case !inside:
			kept = append(kept, line)
		}
	}
	text := strings.Join(kept, "\n") + "\n"
	if len(members) == 0 {
		return text
	}
	text += hostsBegin + "\n"
	for _, member := range members {
		text += member.Address + " " + DNSName(member.Name) + ".kry\n"
	}
	return text + hostsEnd + "\n"
}
