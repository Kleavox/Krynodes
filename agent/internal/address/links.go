package address

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
)

type link struct {
	name                 string
	up, loopback, bridge bool
	addrs                []netip.Addr
}

type Interface struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

func usable(links []link) []Interface {
	found := []Interface{}
	for _, entry := range links {
		if !entry.up || entry.loopback {
			continue
		}
		for _, addr := range entry.addrs {
			if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
				continue
			}
			if entry.bridge && addr.IsPrivate() {
				continue
			}
			found = append(found, Interface{Name: entry.name, Address: addr.String()})
		}
	}
	return found
}

func readLinks() []link {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	links := make([]link, 0, len(interfaces))
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		entry := link{
			name:     iface.Name,
			up:       iface.Flags&net.FlagUp != 0,
			loopback: iface.Flags&net.FlagLoopback != 0,
		}
		if _, err := os.Stat(filepath.Join("/sys/class/net", iface.Name, "bridge")); err == nil {
			entry.bridge = true
		}
		for _, address := range addresses {
			network, ok := address.(*net.IPNet)
			if !ok {
				continue
			}
			if addr, ok := netip.AddrFromSlice(network.IP); ok {
				entry.addrs = append(entry.addrs, addr.Unmap())
			}
		}
		links = append(links, entry)
	}
	return links
}
