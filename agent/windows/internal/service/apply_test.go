package service

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

func reach() (network.Document, network.Member, map[string]string) {
	self := network.Member{Node: laptop1, Address: "10.88.0.10", Key: wgKey(10), Kind: "laptop", Relay: map[string]int{server2: network.FirstRelayPort}}
	document := network.Document{Members: []network.Member{
		{Node: server1, Address: "10.88.0.1", Key: wgKey(1), Endpoint: endpoint("203.0.113.1:51820"), Exit: true},
		{Node: server2, Address: "10.88.0.2", Key: wgKey(2), NAT: true},
		{Node: server3, Address: "10.88.0.3", Key: wgKey(3), Endpoint: endpoint("203.0.113.3:51821")},
		{Node: server4, Address: "10.88.0.4", Key: wgKey(4), Endpoint: endpoint("203.0.113.4:51820"), Cut: true},
		{Node: laptop2, Address: "10.88.0.11", Key: wgKey(11), Endpoint: endpoint("203.0.113.9:51820"), Kind: "laptop"},
		self,
	}}
	return document, self, map[string]string{server1: "psk-1", server2: "psk-2", server3: "psk-3"}
}

func allowed(peers []Peer) map[string][]string {
	found := map[string][]string{}
	for _, peer := range peers {
		found[peer.Node] = peer.AllowedIPs
	}
	return found
}

func peerOf(t *testing.T, peers []Peer, node string) Peer {
	t.Helper()
	index := slices.IndexFunc(peers, func(peer Peer) bool { return peer.Node == node })
	if index < 0 {
		t.Fatalf("no peer for %s in %+v", node, peers)
	}
	return peers[index]
}

func TestLaptopPeersSkipCutMembersAndOtherLaptops(t *testing.T) {
	document, self, psk := reach()
	peers := laptopPeers(document, document, self, server1, "", psk)
	var nodes []string
	for _, peer := range peers {
		nodes = append(nodes, peer.Node)
		if peer.PersistentKeepalive != 25 || peer.PresharedKey != psk[peer.Node] {
			t.Errorf("peer %s keepalive %d psk %q", peer.Node, peer.PersistentKeepalive, peer.PresharedKey)
		}
	}
	if !slices.Equal(nodes, []string{server1, server2, server3}) {
		t.Fatalf("peers %v, want server-1, server-2 and server-3", nodes)
	}
	if peers[2].Endpoint != "203.0.113.3:51821" || peers[2].Key != wgKey(3) || peers[2].Relay {
		t.Errorf("server-3 peer %+v", peers[2])
	}
}

func TestEachMemberBehindNATIsItsOwnPeerThroughTheMeetingPoint(t *testing.T) {
	document, self, psk := reach()
	for _, test := range []struct {
		meeting, via string
		held         []string
	}{
		{server3, "203.0.113.3:51920", nil},
		{"", "203.0.113.1:51920", nil},
		{server2, "203.0.113.1:51920", nil},
		{server4, "203.0.113.1:51920", nil},
		{laptop2, "203.0.113.1:51920", nil},
		{server3, "203.0.113.1:51920", []string{server3}},
		{"", "203.0.113.3:51920", []string{server1}},
		{server1, "203.0.113.3:51920", []string{server1}},
		{server3, "", []string{server1, server3}},
		{"", "", []string{server1, server3}},
	} {
		peers := laptopPeers(document, document, self, meetingOf(document, test.meeting, test.held), "", psk)
		for node, ips := range allowed(peers) {
			want := []string{document.Members[slices.IndexFunc(document.Members, func(entry network.Member) bool { return entry.Node == node })].Address + "/32"}
			if !slices.Equal(ips, want) {
				t.Errorf("meeting %q: %s allows %v, want %v", test.meeting, node, ips, want)
			}
		}
		behind := peerOf(t, peers, server2)
		if behind.Key != wgKey(2) || behind.PresharedKey != "psk-2" || !behind.Relay || behind.Endpoint != test.via || behind.Pin != test.via || behind.PersistentKeepalive != 25 {
			t.Errorf("meeting %q held %v: the member behind NAT is %+v, want endpoint %q", test.meeting, test.held, behind, test.via)
		}
	}
}

func TestTheRelayEndpointIsTheSignedHostNeverAHintedOne(t *testing.T) {
	signed, self, psk := reach()
	hinted := current(signed, nil, map[string]string{wgKey(3): "198.51.100.3:51821"})
	peers := laptopPeers(hinted, signed, self, server3, "", psk)
	if meeting := peerOf(t, peers, server3); meeting.Endpoint != "198.51.100.3:51821" || meeting.Pin != "203.0.113.3:51821" {
		t.Fatalf("meeting point %+v", meeting)
	}
	if behind := peerOf(t, peers, server2); behind.Endpoint != "203.0.113.3:51920" || behind.Pin != "203.0.113.3:51920" {
		t.Fatalf("the member behind NAT went to a hinted host: %+v", behind)
	}
}

func TestTheLaptopAndTheMemberBehindNATMeetOnTheSamePairPort(t *testing.T) {
	document, self, psk := reach()
	nat, _ := member(document, server2)
	for _, test := range []struct {
		meet, want string
		hint       map[string]string
	}{
		{"", "203.0.113.1:51920", nil},
		{server3, "203.0.113.3:51920", map[string]string{laptop1: server3}},
	} {
		behind := peerOf(t, laptopPeers(document, document, self, meetingOf(document, test.meet, nil), "", psk), server2)
		config := network.Render(document, nat, wgKey(2), map[string]string{laptop1: "psk-2"}, test.hint, false)
		laptop := config[strings.Index(config, "PublicKey = "+wgKey(10)):]
		if behind.Endpoint != test.want || !strings.Contains(laptop, "Endpoint = "+test.want+"\n") {
			t.Fatalf("meeting %q: the laptop sends to %q, the member behind NAT to\n%s", test.meet, behind.Endpoint, laptop)
		}
	}
}

func TestTheExitPeerCarriesBothDefaultRoutes(t *testing.T) {
	document, self, psk := reach()
	found := allowed(laptopPeers(document, document, self, meetingOf(document, server3, nil), server1, psk))
	if !slices.Equal(found[server1], []string{"10.88.0.1/32", "0.0.0.0/0", "::/0"}) {
		t.Errorf("exit allows %v", found[server1])
	}
	if !slices.Equal(found[server3], []string{"10.88.0.3/32"}) || !slices.Equal(found[server2], []string{"10.88.0.2/32"}) {
		t.Errorf("meeting point allows %v, the member behind NAT %v", found[server3], found[server2])
	}
	for node, ips := range allowed(laptopPeers(document, document, self, "", server3, psk)) {
		if slices.Contains(ips, "0.0.0.0/0") || slices.Contains(ips, "::/0") {
			t.Errorf("%s carries a default route without being an exit: %v", node, ips)
		}
	}
}

func TestADocumentWithoutThisLaptopTakesTheTunnelDown(t *testing.T) {
	for _, deleted := range []bool{false, true} {
		f := newFixture(t)
		first := f.document(1, "", true)
		f.deliver(1, f.sign(first))
		up := f.last()
		if up.Address != "10.88.0.10" || len(up.Peers) != 2 || up.Peers[0].Node != server1 || up.Peers[1].Node != server2 || !slices.Equal(up.DNS, []string{"10.88.0.1"}) {
			t.Fatalf("joined tunnel %+v", up)
		}
		if up.Peers[0].PresharedKey != base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)) {
			t.Fatalf("psk %q was not opened", up.Peers[0].PresharedKey)
		}
		if !slices.Equal(up.Peers[0].AllowedIPs, []string{"10.88.0.1/32"}) || !slices.Equal(up.Peers[1].AllowedIPs, []string{"10.88.0.2/32"}) {
			t.Fatalf("allowed %v and %v", up.Peers[0].AllowedIPs, up.Peers[1].AllowedIPs)
		}
		if behind := up.Peers[1]; behind.Endpoint != "203.0.113.1:51920" || behind.Pin != behind.Endpoint || !behind.Relay || behind.PresharedKey != up.Peers[0].PresharedKey {
			t.Fatalf("the member behind NAT %+v", behind)
		}
		second := f.document(2, network.BodyHash(first), false)
		if deleted {
			second = f.edited(f.document(2, network.BodyHash(first), true), func(document *network.Document) { document.Deleted = true })
		}
		if got := f.deliver(2, f.sign(second)); got != (reporter.Applied{Type: "applied", Version: 2, OK: true, Message: "Left the private network."}) {
			t.Fatalf("deleted=%v: %+v", deleted, got)
		}
		if down := f.last(); len(down.Peers) != 0 || down.Address != "" {
			t.Fatalf("deleted=%v: the tunnel stays up: %+v", deleted, down)
		}
		record := f.record()
		if record.Joined || record.Document != nil || record.Applied.Version != 2 || record.NodeID != laptop1 || record.Endpoint != testOrigin {
			t.Errorf("deleted=%v: state %+v", deleted, record)
		}
		keys, err := f.service.keys()
		if err != nil || keys.Public == f.keys.Public || keys.Signer == f.keys.Signer || f.hub.hellos != 1 {
			t.Fatalf("deleted=%v: keys %+v, %v, hellos %d", deleted, keys, err, f.hub.hellos)
		}
		hello := f.service.hello("0.7.92")
		if hello.Kind != "laptop" || hello.Network == nil || hello.Network.Key != keys.Public || hello.Network.Signer != keys.Signer || hello.Network.Version != 2 || !hello.Network.Ready || hello.Network.Reason != nil {
			t.Fatalf("deleted=%v: hello %+v", deleted, hello.Network)
		}
		if got := f.deliver(3, f.sign(f.document(3, network.BodyHash(second), false))); !got.OK || got.Message != "This laptop is not in the private network." || f.hub.hellos != 1 {
			t.Fatalf("deleted=%v: a later document without it %+v", deleted, got)
		}
	}
}

func TestTheHelloSaysWhatTheLaptopIs(t *testing.T) {
	f := newFixture(t)
	f.service.Kernel = "10.0.19045"
	hello := f.service.hello("0.7.92")
	if hello.Type != "hello" || hello.V != 1 || hello.Version != "0.7.92" || hello.Kind != "laptop" || hello.Kernel != "10.0.19045" || hello.SealKey != f.seal || hello.Hostname == "" || hello.OS == "" || hello.Arch == "" {
		t.Fatalf("hello %+v", hello)
	}
	if hello.Trust == nil || hello.Trust.Version != 1 || !slices.Equal(hello.Trust.Core, []string{"cred-1"}) {
		t.Fatalf("trust %+v", hello.Trust)
	}
	if want := (reporter.NetworkHello{Version: 0, Key: f.keys.Public, Signer: f.keys.Signer, Ready: true}); hello.Network == nil || *hello.Network != want {
		t.Fatalf("network %+v", hello.Network)
	}
	delete(f.secrets, wireguardSecret)
	if hello := f.service.hello("0.7.92"); hello.Network != nil || f.service.Status(0).Fingerprint != "" {
		t.Fatalf("a laptop without keys %+v", hello.Network)
	}
}

func TestARekeyedLaptopMakesANewKeyAndAnnouncesIt(t *testing.T) {
	f := newFixture(t)
	first := f.document(1, "", true)
	f.deliver(1, f.sign(first))
	second := f.edited(f.document(2, network.BodyHash(first), true), func(document *network.Document) { document.Members[2].Rekey = true })
	f.hub.sent = nil
	if got := f.deliver(2, f.sign(second)); !got.OK {
		t.Fatalf("rekey %+v", got)
	}
	keys, err := f.service.keys()
	if err != nil || keys.Public == f.keys.Public || keys.Signer != f.keys.Signer {
		t.Fatalf("keys %+v, %v", keys, err)
	}
	announced := sentOf[reporter.Announce](f.hub)
	if len(announced) != 1 || announced[0].Type != "announce" || announced[0].Key != keys.Public || !network.Announced(f.keys.Signer, laptop1, keys.Public, announced[0].Signature) {
		t.Fatalf("announce %+v", announced)
	}
	f.hub.sent = nil
	f.service.reconnected()
	if again := sentOf[reporter.Announce](f.hub); !slices.Equal(again, announced) {
		t.Fatalf("a new connection carried %+v", again)
	}
	third := f.document(3, network.BodyHash(second), true)
	if got := f.deliver(3, f.sign(third)); !got.OK {
		t.Fatalf("a document still naming the old key while the new one is announced %+v", got)
	}
	fourth := f.edited(f.document(4, network.BodyHash(third), true), func(document *network.Document) { document.Members[2].Key = keys.Public })
	if got := f.deliver(4, f.sign(fourth)); !got.OK || f.record().Announce != nil {
		t.Fatalf("the new key %+v, announce %+v", got, f.record().Announce)
	}
	fifth := f.document(5, network.BodyHash(fourth), true)
	if got := f.deliver(5, f.sign(fifth)); got.OK || got.Message != "the document names another key for laptop-1" {
		t.Fatalf("the old key after the new one was taken %+v", got)
	}
}

func (f *fixture) joined() []byte {
	f.t.Helper()
	first := f.document(1, "", true)
	if got := f.deliver(1, f.sign(first)); !got.OK {
		f.t.Fatal(got.Message)
	}
	return first
}

func (f *fixture) hint(hints reporter.Hints) {
	f.t.Helper()
	hints.Type = "hints"
	for _, list := range []*[]string{&hints.Held, &hints.Connected} {
		if *list == nil {
			*list = []string{}
		}
	}
	f.service.receive(hints)
}

func TestHubHintsNeverWidenTheSignedPeers(t *testing.T) {
	f := newFixture(t)
	first := f.joined()
	before := f.last()
	forged := serverKeys(t, 7)
	stranger, err := network.KeysOf(bytes.Repeat([]byte{8}, 32), bytes.Repeat([]byte{22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.hint(reporter.Hints{
		Announced: []reporter.HintAnnounced{
			{Node: server1, Key: forged.Public, Signature: stranger.Announce(server1)},
			{Node: server1, Key: forged.Public, Signature: "c2lnbmVk"},
			{Node: laptop1, Key: forged.Public, Signature: forged.Announce(laptop1)},
		},
		Endpoints: []reporter.HintEndpoint{
			{Key: wgKey(2), Endpoint: "203.0.113.20:51820"},
			{Key: f.keys.Public, Endpoint: "203.0.113.21:51820"},
			{Key: f.server.Public, Endpoint: "203.0.113.22:22"},
			{Key: wgKey(99), Endpoint: "203.0.113.23:51820"},
		},
	})
	if now := f.last(); !reflect.DeepEqual(now, before) {
		t.Fatalf("unsigned or out-of-bounds hints changed the tunnel: %+v", now)
	}
	if record := f.record(); len(record.Announced) != 0 || len(record.Endpoints) != 0 {
		t.Fatalf("hints were kept: %+v %+v", record.Announced, record.Endpoints)
	}

	second := f.edited(f.document(2, network.BodyHash(first), true), func(document *network.Document) { document.Blocked = []string{forged.Public} })
	if got := f.deliver(2, f.sign(second)); !got.OK {
		t.Fatal(got.Message)
	}
	f.hint(reporter.Hints{Announced: []reporter.HintAnnounced{{Node: server1, Key: forged.Public, Signature: forged.Announce(server1)}}})
	if peer := f.last().Peers[0]; peer.Key != f.server.Public {
		t.Fatalf("a blocked key was taken: %+v", peer)
	}

	rotated := serverKeys(t, 3)
	f.hint(reporter.Hints{
		Announced: []reporter.HintAnnounced{{Node: server1, Key: rotated.Public, Signature: rotated.Announce(server1)}},
		Endpoints: []reporter.HintEndpoint{{Key: rotated.Public, Endpoint: "203.0.113.30:51830"}},
	})
	after := f.last()
	if len(after.Peers) != 2 || after.Peers[0].Key != rotated.Public || after.Peers[0].Endpoint != "203.0.113.30:51830" || !slices.Equal(after.Peers[0].AllowedIPs, before.Peers[0].AllowedIPs) {
		t.Fatalf("a signed new key and its endpoint: %+v", after)
	}
}

func TestAHeldServerIsNoExit(t *testing.T) {
	f := newFixture(t)
	f.joined()
	f.service.mu.Lock()
	f.service.exit = server1
	f.service.refresh()
	f.service.mu.Unlock()
	f.service.push()
	if exit := f.last(); exit.Exit != server1 || !slices.Contains(exit.Peers[0].AllowedIPs, "0.0.0.0/0") {
		t.Fatalf("exit %+v", exit)
	}
	f.hint(reporter.Hints{Held: []string{server1}})
	held := f.last()
	if held.Exit != "" || slices.Contains(held.Peers[0].AllowedIPs, "0.0.0.0/0") || slices.Contains(held.Peers[0].AllowedIPs, "::/0") || !slices.Equal(held.Held, []string{server1}) {
		t.Fatalf("held exit %+v", held)
	}
	f.hint(reporter.Hints{Meetings: []reporter.HintMeeting{{Laptop: laptop1, Via: server1}}, Held: []string{server1}})
	if still := f.last(); !slices.Equal(still.Held, []string{server1}) {
		t.Fatalf("a meetings hint still holding the server released it: %+v", still)
	}
	f.hint(reporter.Hints{})
	if back := f.last(); back.Exit != server1 {
		t.Fatalf("released exit %+v", back)
	}
}
