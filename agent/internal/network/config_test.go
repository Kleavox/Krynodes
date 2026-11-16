package network

import (
	"strings"
	"testing"
)

func TestTheConfigGivesEachPeerOnlyItsOwnAddress(t *testing.T) {
	document := fixture(t)
	listening := Render(document, document.Members[0], "cHJpdmF0ZQ==", map[string]string{nodeB: "cHNrLWFi"}, nil, false)
	want := `[Interface]
PrivateKey = cHJpdmF0ZQ==
Address = 10.88.0.1/24
ListenPort = 51820
MTU = 1420

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
PresharedKey = cHNrLWFi
AllowedIPs = 10.88.0.2/32
PersistentKeepalive = 25
`
	if listening != want {
		t.Fatalf("vps-1's config:\n%s\nwant:\n%s", listening, want)
	}
	behindNAT := Render(document, document.Members[1], "cHJpdmF0ZQ==", map[string]string{nodeA: "cHNrLWFi"}, nil, false)
	want = `[Interface]
PrivateKey = cHJpdmF0ZQ==
Address = 10.88.0.2/24
ListenPort = 51821
MTU = 1380
PostUp = iptables -w -t mangle -A POSTROUTING -o kry0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340
PostDown = iptables -w -t mangle -D POSTROUTING -o kry0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340

[Peer]
PublicKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
PresharedKey = cHNrLWFi
AllowedIPs = 10.88.0.1/32
Endpoint = 203.0.113.21:51820
PersistentKeepalive = 25
`
	if behindNAT != want {
		t.Fatalf("server-1's config:\n%s\nwant:\n%s", behindNAT, want)
	}
}

func TestTheStrippedConfigKeepsOnlyWhatWireGuardReads(t *testing.T) {
	document := fixture(t)
	stripped := Strip(Render(document, document.Members[1], "cHJpdmF0ZQ==", map[string]string{nodeA: "cHNrLWFi"}, nil, false))
	want := `[Interface]
PrivateKey = cHJpdmF0ZQ==
ListenPort = 51821

[Peer]
PublicKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
PresharedKey = cHNrLWFi
AllowedIPs = 10.88.0.1/32
Endpoint = 203.0.113.21:51820
PersistentKeepalive = 25
`
	if stripped != want {
		t.Fatalf("stripped:\n%s", stripped)
	}
}

func TestTheHostsBlockIsReplacedNotDuplicated(t *testing.T) {
	document := fixture(t)
	original := "127.0.0.1 localhost\n10.0.0.5 db.lan"
	once := Hosts(original, document.Members)
	want := "127.0.0.1 localhost\n10.0.0.5 db.lan\n# BEGIN krynodes-network\n10.88.0.1 vps-1.kry\n10.88.0.2 server-1.kry\n# END krynodes-network\n"
	if once != want {
		t.Fatalf("once:\n%q", once)
	}
	document.Members[1].Name = "Server-1 Home"
	twice := Hosts(once, document.Members)
	if twice != "127.0.0.1 localhost\n10.0.0.5 db.lan\n# BEGIN krynodes-network\n10.88.0.1 vps-1.kry\n10.88.0.2 server-1-home.kry\n# END krynodes-network\n" {
		t.Fatalf("twice:\n%q", twice)
	}
	if gone := Hosts(twice, nil); gone != "127.0.0.1 localhost\n10.0.0.5 db.lan\n" {
		t.Fatalf("gone:\n%q", gone)
	}
}

func TestANameBecomesOneDNSLabel(t *testing.T) {
	for name, want := range map[string]string{"VPS_2 (Singapore)": "vps-2-singapore", "---": "server", "server-2": "server-2"} {
		if got := DNSName(name); got != want {
			t.Errorf("%q: %q", name, got)
		}
	}
}

func laptopNetwork() Document {
	endpoint := func(text string) *string { return &text }
	return Document{V: 1, Version: 4, Range: "10.88.0.0/24", Port: 51820, MTU: 1420, Members: []Member{
		{Node: nodeA, Name: "server-2", Address: "10.88.0.1", Key: "key-a", Port: 51820, Endpoint: endpoint("203.0.113.1:51820")},
		{Node: nodeB, Name: "server-3", Address: "10.88.0.2", Key: "key-b", Port: 51820, Endpoint: endpoint("203.0.113.2:51820")},
		{Node: nodeC, Name: "server-1", Address: "10.88.0.3", Key: "key-c", Port: 51820, NAT: true},
		{Node: nodeL, Name: "laptop-1", Address: "10.88.0.9", Key: "key-l", Port: 51820, NAT: true, Kind: "laptop", Endpoint: endpoint("203.0.113.9:51820")},
	}}
}

var laptopPSK = map[string]string{nodeA: "psk-a", nodeB: "psk-b", nodeC: "psk-c", nodeL: "psk-l"}

func TestRenderOnANATMemberPutsLaptopsOnTheMeetingPeer(t *testing.T) {
	document := laptopNetwork()
	config := Render(document, document.Members[2], "private", laptopPSK, map[string]string{nodeL: nodeB}, false)
	want := `[Interface]
PrivateKey = private
Address = 10.88.0.3/24
ListenPort = 51820
MTU = 1420

[Peer]
PublicKey = key-a
PresharedKey = psk-a
AllowedIPs = 10.88.0.1/32
Endpoint = 203.0.113.1:51820
PersistentKeepalive = 25

[Peer]
PublicKey = key-b
PresharedKey = psk-b
AllowedIPs = 10.88.0.2/32, 10.88.0.9/32
Endpoint = 203.0.113.2:51820
PersistentKeepalive = 25
`
	if config != want {
		t.Fatalf("server-1's config:\n%s\nwant:\n%s", config, want)
	}
}

func TestRenderOnANATMemberFallsBackToTheDefaultMeeting(t *testing.T) {
	onA := "AllowedIPs = 10.88.0.1/32, 10.88.0.9/32\n"
	onB := "AllowedIPs = 10.88.0.2/32, 10.88.0.9/32\n"
	cases := []struct {
		name     string
		change   func(*Document)
		meetings map[string]string
		want     string
	}{
		{"no hint", func(*Document) {}, nil, onA},
		{"a hint naming a NAT member", func(*Document) {}, map[string]string{nodeL: nodeC}, onA},
		{"a hint naming a laptop", func(*Document) {}, map[string]string{nodeL: nodeL}, onA},
		{"a hint naming a stranger", func(*Document) {}, map[string]string{nodeL: "44444444-4444-4444-8444-444444444444"}, onA},
		{"a hint naming a cut member", func(document *Document) { document.Members[1].Cut = true }, map[string]string{nodeL: nodeB}, onA},
		{"the first public member cut", func(document *Document) { document.Members[0].Cut = true }, nil, onB},
		{"the first public member without an endpoint", func(document *Document) { document.Members[0].Endpoint = nil }, nil, onB},
		{"no public member", func(document *Document) { document.Members[0].NAT, document.Members[1].NAT = true, true }, nil, ""},
	}
	for _, entry := range cases {
		document := laptopNetwork()
		entry.change(&document)
		config := Render(document, document.Members[2], "private", laptopPSK, entry.meetings, false)
		if entry.want == "" {
			if strings.Contains(config, "10.88.0.9") || DefaultMeeting(document) != "" {
				t.Errorf("%s:\n%s", entry.name, config)
			}
			continue
		}
		if !strings.Contains(config, entry.want) || strings.Count(config, "10.88.0.9") != 1 || strings.Contains(config, "key-l") {
			t.Errorf("%s:\n%s", entry.name, config)
		}
	}
}

func TestRenderOnAPublicMemberAddsLaptopsWithoutEndpoint(t *testing.T) {
	document := laptopNetwork()
	config := Render(document, document.Members[0], "private", laptopPSK, map[string]string{nodeL: nodeA}, false)
	laptop := "\n[Peer]\nPublicKey = key-l\nPresharedKey = psk-l\nAllowedIPs = 10.88.0.9/32\nPersistentKeepalive = 25\n"
	if !strings.HasSuffix(config, laptop) || strings.Contains(config, "203.0.113.9") || strings.Count(config, "10.88.0.9") != 1 || !strings.Contains(config, "AllowedIPs = 10.88.0.3/32\n") {
		t.Fatalf("server-2's config:\n%s", config)
	}
}

func TestLaptopPeersGetASixAddressOnlyOnAnIPv6Exit(t *testing.T) {
	document := laptopNetwork()
	document.Members[0].Exit = true
	if config := Render(document, document.Members[0], "private", laptopPSK, nil, false); strings.Contains(config, "fd88") {
		t.Fatalf("without IPv6:\n%s", config)
	}
	config := Render(document, document.Members[0], "private", laptopPSK, nil, true)
	if !strings.Contains(config, "AllowedIPs = 10.88.0.9/32, fd88:88::9/128\n") || strings.Count(config, "/128") != 1 {
		t.Fatalf("with IPv6:\n%s", config)
	}
}
