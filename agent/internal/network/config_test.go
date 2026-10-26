package network

import "testing"

func TestTheConfigGivesEachPeerOnlyItsOwnAddress(t *testing.T) {
	document := fixture(t)
	listening := Render(document, document.Members[0], "cHJpdmF0ZQ==", map[string]string{nodeB: "cHNrLWFi"})
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
	behindNAT := Render(document, document.Members[1], "cHJpdmF0ZQ==", map[string]string{nodeA: "cHNrLWFi"})
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
Endpoint = 141.95.0.21:51820
PersistentKeepalive = 25
`
	if behindNAT != want {
		t.Fatalf("pivox's config:\n%s\nwant:\n%s", behindNAT, want)
	}
}

func TestTheStrippedConfigKeepsOnlyWhatWireGuardReads(t *testing.T) {
	document := fixture(t)
	stripped := Strip(Render(document, document.Members[1], "cHJpdmF0ZQ==", map[string]string{nodeA: "cHNrLWFi"}))
	want := `[Interface]
PrivateKey = cHJpdmF0ZQ==
ListenPort = 51821

[Peer]
PublicKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
PresharedKey = cHNrLWFi
AllowedIPs = 10.88.0.1/32
Endpoint = 141.95.0.21:51820
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
	want := "127.0.0.1 localhost\n10.0.0.5 db.lan\n# BEGIN krynodes-network\n10.88.0.1 vps-1.kry\n10.88.0.2 pivox.kry\n# END krynodes-network\n"
	if once != want {
		t.Fatalf("once:\n%q", once)
	}
	document.Members[1].Name = "Pivox Home"
	twice := Hosts(once, document.Members)
	if twice != "127.0.0.1 localhost\n10.0.0.5 db.lan\n# BEGIN krynodes-network\n10.88.0.1 vps-1.kry\n10.88.0.2 pivox-home.kry\n# END krynodes-network\n" {
		t.Fatalf("twice:\n%q", twice)
	}
	if gone := Hosts(twice, nil); gone != "127.0.0.1 localhost\n10.0.0.5 db.lan\n" {
		t.Fatalf("gone:\n%q", gone)
	}
}

func TestANameBecomesOneDNSLabel(t *testing.T) {
	for name, want := range map[string]string{"VPS_2 (Singapore)": "vps-2-singapore", "---": "server", "io": "io"} {
		if got := DNSName(name); got != want {
			t.Errorf("%q: %q", name, got)
		}
	}
}
