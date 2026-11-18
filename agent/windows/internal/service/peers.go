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
	Relay               bool
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

func laptopPeers(document, signed network.Document, self network.Member, meeting string, exit string, psk map[string]string) []Peer {
	var peers []Peer
	for _, entry := range document.Members {
		if entry.Node == self.Node || entry.Cut || !network.Links(self, entry) || (!entry.NAT && entry.Endpoint == nil) {
			continue
		}
		peer := Peer{
			Node:                entry.Node,
			Key:                 entry.Key,
			PresharedKey:        psk[entry.Node],
			AllowedIPs:          []string{entry.Address + "/32"},
			PersistentKeepalive: network.Keepalive,
		}
		switch {
		case entry.NAT:
			peer.Relay = true
			if endpoint, ok := network.RelayEndpoint(signed, meeting, self.Node, entry.Node); ok && meeting != "" {
				peer.Endpoint, peer.Pin = endpoint, endpoint
			}
		default:
			peer.Endpoint = *entry.Endpoint
			if listed, ok := member(signed, entry.Node); ok && listed.Endpoint != nil && !listed.NAT {
				peer.Pin = *listed.Endpoint
			}
		}
		if entry.Node == exit && entry.Exit {
			peer.AllowedIPs = append(peer.AllowedIPs, "0.0.0.0/0", "::/0")
		}
		peers = append(peers, peer)
	}
	return peers
}
