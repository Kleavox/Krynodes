package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/trust"
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
		f.service.answer(reporter.HeartbeatResponse{Network: &reporter.NetworkReply{Document: f.sign(first)}})
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
		key := f.secrets[wireguardSecret]
		var second []byte
		if deleted {
			var document network.Document
			if err := json.Unmarshal(f.document(2, network.BodyHash(first), true), &document); err != nil {
				t.Fatal(err)
			}
			document.Deleted = true
			second, _ = json.Marshal(document)
		} else {
			second = f.document(2, network.BodyHash(first), false)
		}
		f.service.answer(reporter.HeartbeatResponse{Network: &reporter.NetworkReply{Document: f.sign(second)}})
		if down := f.last(); len(down.Peers) != 0 || down.Address != "" {
			t.Fatalf("deleted=%v: the tunnel stays up: %+v", deleted, down)
		}
		record := f.record()
		if record.Joined || record.Document != nil || record.Applied.Version != 2 {
			t.Errorf("deleted=%v: state %+v", deleted, record)
		}
		if !bytes.Equal(f.secrets[wireguardSecret], key) {
			t.Errorf("deleted=%v: the key was not kept", deleted)
		}
	}
}

func TestAnUnsignedOrOlderDocumentIsRefused(t *testing.T) {
	f := newFixture(t)
	first := f.document(1, "", true)
	if err := f.service.applyDocument(nil); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("unsigned: %v", err)
	}
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.service.applyDocument(f.signWith("cred-1", stranger, first)); err == nil {
		t.Fatal("a document signed by an untrusted passkey applied")
	}
	if f.record().Applied.Version != 0 {
		t.Fatal("a refused document was recorded")
	}
	if err := f.service.applyDocument(f.sign(first)); err != nil {
		t.Fatal(err)
	}
	second := f.document(2, network.BodyHash(first), true)
	if err := f.service.applyDocument(f.sign(second)); err != nil {
		t.Fatal(err)
	}
	if err := f.service.applyDocument(f.sign(first)); err == nil || !strings.Contains(err.Error(), "not newer") {
		t.Fatalf("older: %v", err)
	}
	if record := f.record(); record.Applied.Version != 2 || !record.Joined {
		t.Fatalf("state %+v", record)
	}
}

func TestARekeyedLaptopMakesANewKeyAndAnnouncesIt(t *testing.T) {
	f := newFixture(t)
	first := f.document(1, "", true)
	if err := f.service.applyDocument(f.sign(first)); err != nil {
		t.Fatal(err)
	}
	var document network.Document
	if err := json.Unmarshal(f.document(2, network.BodyHash(first), true), &document); err != nil {
		t.Fatal(err)
	}
	document.Members[2].Rekey = true
	second, _ := json.Marshal(document)
	if err := f.service.applyDocument(f.sign(second)); err != nil {
		t.Fatal(err)
	}
	keys, err := f.service.keys()
	if err != nil || keys.Public == f.keys.Public || keys.Signer != f.keys.Signer {
		t.Fatalf("keys %+v, %v", keys, err)
	}
	server := &fakeServer{}
	f.service.cycle(context.Background(), server, reporter.Host{})
	announce := server.beats[0].Network.Announce
	if announce == nil || announce.Key != keys.Public || !network.Announced(f.keys.Signer, laptop1, announce.Key, announce.Signature) {
		t.Fatalf("announce %+v", announce)
	}
}

func TestOnlyTrustActionsRunOnALaptop(t *testing.T) {
	f := newFixture(t)
	before := f.secrets[wireguardSecret]
	trusted := f.change("77777777-7777-4777-8777-000000000001", 2, nil)
	requests := []reporter.ActionRequest{
		{ID: "77777777-7777-4777-8777-000000000002", Kind: "compose", Name: "listmonk", Action: "deploy", ExpiresAt: trusted.ExpiresAt, Signed: trusted.Signed},
		{ID: "77777777-7777-4777-8777-000000000003", Kind: "network", Name: "kry0", Action: "rekey", ExpiresAt: trusted.ExpiresAt, Signed: trusted.Signed},
		{ID: "77777777-7777-4777-8777-000000000004", Kind: "host", Name: "server", Action: "reboot", ExpiresAt: trusted.ExpiresAt},
		{ID: "77777777-7777-4777-8777-000000000005", Kind: "trust", Name: "devices", Action: "reset", ExpiresAt: trusted.ExpiresAt, Signed: trusted.Signed},
		{ID: "77777777-7777-4777-8777-000000000006", Kind: "trust", Name: "other", Action: "trust", ExpiresAt: trusted.ExpiresAt, Signed: trusted.Signed},
	}
	server := &fakeServer{response: reporter.HeartbeatResponse{Actions: requests}}
	f.service.cycle(context.Background(), server, reporter.Host{Hostname: "laptop-1"})
	report := server.reports[0]
	if len(report.Results) != len(requests) {
		t.Fatalf("results %+v", report.Results)
	}
	for _, result := range report.Results {
		if result.OK || result.Output != "refused: unknown action" {
			t.Errorf("result %+v", result)
		}
	}
	current, err := trust.Load(f.service.Dir)
	if err != nil || current.Version != 1 || !bytes.Equal(f.secrets[wireguardSecret], before) {
		t.Fatalf("something ran: trust %+v, %v", current, err)
	}
	encoded, err := json.Marshal(report.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	var sent map[string]any
	if err := json.Unmarshal(encoded, &sent); err != nil || len(sent) != 2 || sent["trust"] == nil || sent["hash"] == nil {
		t.Fatalf("inventory %s", encoded)
	}
	beat, err := json.Marshal(server.beats[0].Network)
	if err != nil || !strings.Contains(string(beat), `"links":[]`) || !strings.Contains(string(beat), f.keys.Public) {
		t.Fatalf("beat %s", beat)
	}
}

func TestASignedTrustChangeIsAppliedOnTheLaptop(t *testing.T) {
	f := newFixture(t)
	second, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	added := trust.TrustKey{ID: "cred-2", Name: "Laptop", Alg: -7, PublicKey: spki(t, second)}
	request := f.change("77777777-7777-4777-8777-000000000010", 2, []trust.TrustKey{f.device, added})
	server := &fakeServer{response: reporter.HeartbeatResponse{Actions: []reporter.ActionRequest{request}}}
	f.service.cycle(context.Background(), server, reporter.Host{})
	result := server.reports[0].Results[0]
	if !result.OK || result.ID != request.ID {
		t.Fatalf("result %+v", result)
	}
	current, err := trust.Load(f.service.Dir)
	if err != nil || current.Version != 2 || len(current.Core) != 2 || current.NodeID != laptop1 {
		t.Fatalf("trust %+v, %v", current, err)
	}
	if devices := server.reports[0].Inventory.Trust; devices == nil || devices.Version != 2 || len(devices.Core) != 2 {
		t.Fatalf("inventory %+v", server.reports[0].Inventory)
	}
	f.service.cycle(context.Background(), server, reporter.Host{})
	if len(server.reports) != 2 || len(server.reports[1].Results) != 0 {
		t.Fatalf("the change ran twice: %+v", server.reports)
	}
}

func (f *fixture) joined() []byte {
	f.t.Helper()
	first := f.document(1, "", true)
	if err := f.service.applyDocument(f.sign(first)); err != nil {
		f.t.Fatal(err)
	}
	f.service.mu.Lock()
	f.service.refresh()
	f.service.mu.Unlock()
	f.service.push()
	return first
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
	f.service.answer(reporter.HeartbeatResponse{Network: &reporter.NetworkReply{
		Announced: []reporter.NetworkAnnounced{
			{Node: server1, Key: forged.Public, Signature: stranger.Announce(server1)},
			{Node: server1, Key: forged.Public},
			{Node: laptop1, Key: forged.Public, Signature: forged.Announce(laptop1)},
		},
		Endpoints: []reporter.NetworkEndpoint{
			{Key: wgKey(2), Endpoint: "203.0.113.20:51820"},
			{Key: f.keys.Public, Endpoint: "203.0.113.21:51820"},
			{Key: f.server.Public, Endpoint: "203.0.113.22:22"},
			{Key: wgKey(99), Endpoint: "203.0.113.23:51820"},
		},
	}})
	if now := f.last(); !reflect.DeepEqual(now, before) {
		t.Fatalf("unsigned or out-of-bounds hints changed the tunnel: %+v", now)
	}
	if record := f.record(); len(record.Announced) != 0 || len(record.Endpoints) != 0 {
		t.Fatalf("hints were kept: %+v %+v", record.Announced, record.Endpoints)
	}

	var document network.Document
	if err := json.Unmarshal(f.document(2, network.BodyHash(first), true), &document); err != nil {
		t.Fatal(err)
	}
	document.Blocked = []string{forged.Public}
	second, _ := json.Marshal(document)
	if err := f.service.applyDocument(f.sign(second)); err != nil {
		t.Fatal(err)
	}
	f.service.answer(reporter.HeartbeatResponse{Network: &reporter.NetworkReply{Announced: []reporter.NetworkAnnounced{{Node: server1, Key: forged.Public, Signature: forged.Announce(server1)}}}})
	if peer := f.last().Peers[0]; peer.Key != f.server.Public {
		t.Fatalf("a blocked key was taken: %+v", peer)
	}

	rotated := serverKeys(t, 3)
	f.service.answer(reporter.HeartbeatResponse{Network: &reporter.NetworkReply{
		Announced: []reporter.NetworkAnnounced{{Node: server1, Key: rotated.Public, Signature: rotated.Announce(server1)}},
		Endpoints: []reporter.NetworkEndpoint{{Key: rotated.Public, Endpoint: "203.0.113.30:51830"}},
	}})
	after := f.last()
	if len(after.Peers) != 2 || after.Peers[0].Key != rotated.Public || after.Peers[0].Endpoint != "203.0.113.30:51830" || !slices.Equal(after.Peers[0].AllowedIPs, before.Peers[0].AllowedIPs) {
		t.Fatalf("a signed new key and its endpoint: %+v", after)
	}
}

func TestARemovedLaptopKeepsItsKeysAndStaysDown(t *testing.T) {
	f := newFixture(t)
	f.joined()
	key := f.secrets[wireguardSecret]
	f.service.gone(true)
	if down := f.last(); !reflect.DeepEqual(down, Wanted{}) {
		t.Fatalf("the tunnel stays up: %+v", down)
	}
	if !bytes.Equal(f.secrets[wireguardSecret], key) || !f.service.Removed() {
		t.Fatal("the keys were dropped or the removal was not kept")
	}
	var restarted []Wanted
	again := &Service{Dir: f.service.Dir, Secrets: f.secrets, Now: f.service.Now, Apply: func(wanted Wanted) { restarted = append(restarted, wanted) }}
	again.mu.Lock()
	again.refresh()
	again.mu.Unlock()
	again.push()
	if len(restarted) != 0 {
		t.Fatalf("a restart brought the tunnel up: %+v", restarted)
	}
	f.service.gone(false)
	if up := f.last(); len(up.Peers) != 2 {
		t.Fatalf("the tunnel did not come back: %+v", up)
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
	f.service.answer(reporter.HeartbeatResponse{Network: &reporter.NetworkReply{Held: []string{server1}}})
	held := f.last()
	if held.Exit != "" || slices.Contains(held.Peers[0].AllowedIPs, "0.0.0.0/0") || slices.Contains(held.Peers[0].AllowedIPs, "::/0") || !slices.Equal(held.Held, []string{server1}) {
		t.Fatalf("held exit %+v", held)
	}
	f.service.answer(reporter.HeartbeatResponse{Network: &reporter.NetworkReply{Held: []string{}}})
	if back := f.last(); back.Exit != server1 {
		t.Fatalf("released exit %+v", back)
	}
}

func TestAMalformedDocumentIsRefused(t *testing.T) {
	f := newFixture(t)
	for _, body := range []string{
		`{"v":1,"version":1,"range":"10.88.0.0/24","port":51820,"mtu":1420,"members":[],"blocked":[],"extra":true}`,
		`{"v":1,"version":1,"range":"10.99.0.0/24","port":51820,"mtu":1420,"members":[],"blocked":[]}`,
		`not json`,
	} {
		if err := f.service.applyDocument(f.sign([]byte(body))); err == nil {
			t.Errorf("%s was applied", body)
		}
	}
	if record := f.record(); record.Applied.Version != 0 || record.Joined {
		t.Fatalf("state %+v", record)
	}
}

func TestAnAppliedTrustChangeIsNotRefusedAfterARestart(t *testing.T) {
	f := newFixture(t)
	second, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := f.change("77777777-7777-4777-8777-000000000020", 2, []trust.TrustKey{f.device, {ID: "cred-2", Name: "Laptop", Alg: -7, PublicKey: spki(t, second)}})
	f.service.deliver([]reporter.ActionRequest{request})
	f.service.mu.Lock()
	f.service.report(laptop1)
	f.service.mu.Unlock()
	again := &Service{Dir: f.service.Dir, Secrets: f.secrets, Now: f.service.Now}
	server := &fakeServer{response: reporter.HeartbeatResponse{Actions: []reporter.ActionRequest{request}}}
	again.cycle(context.Background(), server, reporter.Host{})
	results := server.reports[0].Results
	if len(results) != 1 || !results[0].OK || results[0].ID != request.ID {
		t.Fatalf("results %+v", results)
	}
	again.cycle(context.Background(), server, reporter.Host{})
	if len(server.reports) > 1 && len(server.reports[1].Results) != 0 {
		t.Fatalf("posted twice: %+v", server.reports[1].Results)
	}
	if record := f.record(); len(record.Results) != 0 || record.Ledger[request.ID].IsZero() {
		t.Fatalf("ledger %+v results %+v", record.Ledger, record.Results)
	}
}
