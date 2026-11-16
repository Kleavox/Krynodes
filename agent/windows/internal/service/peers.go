package service

import (
	"slices"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

type Peer struct {
	Node                string
	Key                 string
	PresharedKey        string
	Endpoint            string
	Pin                 string
	AllowedIPs          []string
	PersistentKeepalive int
}

type Wanted struct {
	Peers   []Peer
	Address string
	DNS     []string
	Exit    string
	Held    []string
	Key     []byte
	MTU     int
	Local   bool
}

func member(document network.Document, node string) (network.Member, bool) {
	index := slices.IndexFunc(document.Members, func(entry network.Member) bool { return entry.Node == node })
	if index < 0 {
		return network.Member{}, false
	}
	return document.Members[index], true
}

func meetingOf(signed network.Document, meeting string, held []string) string {
	signed.Members = slices.DeleteFunc(slices.Clone(signed.Members), func(entry network.Member) bool { return slices.Contains(held, entry.Node) })
	if point, ok := member(signed, meeting); ok && network.MeetingPoint(point) {
		return meeting
	}
	return network.DefaultMeeting(signed)
}

func laptopPeers(document network.Document, self network.Member, meeting string, exit string, psk map[string]string) []Peer {
	var behind []string
	for _, entry := range document.Members {
		if entry.NAT && !entry.IsLaptop() && !entry.Cut {
			behind = append(behind, entry.Address+"/32")
		}
	}
	var peers []Peer
	for _, entry := range document.Members {
		if entry.Node == self.Node || entry.Cut || entry.Endpoint == nil || !network.Links(self, entry) {
			continue
		}
		allowed := []string{entry.Address + "/32"}
		if entry.Node == meeting {
			allowed = append(allowed, behind...)
		}
		if entry.Node == exit && entry.Exit {
			allowed = append(allowed, "0.0.0.0/0", "::/0")
		}
		peers = append(peers, Peer{
			Node:                entry.Node,
			Key:                 entry.Key,
			PresharedKey:        psk[entry.Node],
			Endpoint:            *entry.Endpoint,
			AllowedIPs:          allowed,
			PersistentKeepalive: network.Keepalive,
		})
	}
	return peers
}
