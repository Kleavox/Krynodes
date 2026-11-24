package service

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

func (f *fixture) twoPublic() {
	f.t.Helper()
	var document network.Document
	if err := json.Unmarshal(f.document(1, "", true), &document); err != nil {
		f.t.Fatal(err)
	}
	document.Members[0].PSK[server3] = "c2VhbGVk"
	document.Members[1].PSK[server3] = "c2VhbGVk"
	document.Members[2].PSK[server3] = f.psk()
	document.Members = append(document.Members, network.Member{Node: server3, Name: "server-3", Address: "10.88.0.3", Key: wgKey(3), Signer: wgKey(13), SealKey: otherSealKey, Port: network.FirstPort, Endpoint: endpoint("203.0.113.3:51820"), PSK: map[string]string{server1: "c2VhbGVk", server2: "c2VhbGVk", laptop1: "c2VhbGVk"}})
	body, err := json.Marshal(document)
	if err != nil {
		f.t.Fatal(err)
	}
	if got := f.deliver(1, f.sign(body)); !got.OK {
		f.t.Fatal(got.Message)
	}
}

func second(at int) time.Time {
	return testNow.Add(time.Duration(at) * time.Second)
}

func (f *fixture) behind() Peer {
	f.t.Helper()
	peers := f.last().Peers
	for node, ips := range allowed(peers) {
		if want := []string{map[string]string{server1: "10.88.0.1/32", server2: "10.88.0.2/32", server3: "10.88.0.3/32"}[node]}; !slices.Equal(ips, want) {
			f.t.Fatalf("%s allows %v, want %v", node, ips, want)
		}
	}
	return peerOf(f.t, peers, server2)
}

func TestTheMeetingPointFollowsThePings(t *testing.T) {
	f := newFixture(t)
	f.twoPublic()
	if behind := f.behind(); behind.Endpoint != "203.0.113.1:51920" || behind.Pin != behind.Endpoint || !behind.Relay {
		t.Fatalf("before any ping the member behind NAT is reached through the default meeting point: %+v", behind)
	}
	f.service.observe(second(0), map[string]answer{server1: {30 * time.Millisecond, true}, server2: {40 * time.Millisecond, true}, server3: {10 * time.Millisecond, true}})
	if behind := f.behind(); behind.Endpoint != "203.0.113.3:51920" || behind.Pin != behind.Endpoint {
		t.Fatalf("the member behind NAT did not follow the switch: %+v", behind)
	}
	if meets := sentOf[reporter.Meet](f.hub); len(meets) != 1 || meets[0].Via != server3 {
		t.Fatalf("meets %+v", meets)
	}
	if via := f.service.Status(0).Servers[1]; via.Node != server2 || via.Via != "server-3" {
		t.Fatalf("the member behind NAT is shown %+v", via)
	}
	f.hint(reporter.Hints{Held: []string{server3}})
	f.service.observe(second(1), map[string]answer{server1: {30 * time.Millisecond, true}, server2: {40 * time.Millisecond, true}, server3: {10 * time.Millisecond, true}})
	if f.service.meet != server1 {
		t.Fatalf("a held server stays the meeting point: %q", f.service.meet)
	}
	if behind := f.behind(); behind.Endpoint != "203.0.113.1:51920" {
		t.Fatalf("the member behind NAT stays on a held meeting point: %+v", behind)
	}
}

func TestTheMeetingPointMovesForSpeedOnlyWhileTheStreamIsUp(t *testing.T) {
	f := newFixture(t)
	f.twoPublic()
	f.service.setLinked(false)
	f.service.observe(second(0), map[string]answer{server1: {20 * time.Millisecond, true}})
	faster := map[string]answer{server1: {20 * time.Millisecond, true}, server3: {15 * time.Millisecond, true}}
	for at := 1; at <= 62; at++ {
		f.service.observe(second(at), faster)
	}
	if f.service.meet != server1 {
		t.Fatalf("moved to %q for speed while the Worker was unreachable", f.service.meet)
	}
	f.service.reconnected()
	f.service.observe(second(63), faster)
	if f.service.meet != server3 {
		t.Fatalf("the stream is up again and the meeting point stays %q", f.service.meet)
	}
	f.service.setLinked(false)
	for at := 64; at <= 66; at++ {
		f.service.observe(second(at), map[string]answer{server1: {20 * time.Millisecond, true}, server3: {}})
	}
	if f.service.meet != server1 {
		t.Fatalf("stayed on a dead %q while the Worker was unreachable", f.service.meet)
	}
}

func TestASilentOrHeldExitTurnsOffWithOneNotification(t *testing.T) {
	f := newFixture(t)
	f.twoPublic()
	choose := func() {
		f.service.mu.Lock()
		f.service.exit = server1
		f.service.refresh()
		f.service.mu.Unlock()
		f.service.push()
	}
	choose()
	for at := 0; at < 30; at++ {
		f.service.observe(second(at), map[string]answer{server1: {}, server3: {10 * time.Millisecond, true}})
	}
	if f.last().Exit != server1 || len(f.service.notes) != 0 {
		t.Fatalf("dropped before 30 s: %+v %v", f.last().Exit, f.service.notes)
	}
	for at := 30; at < 40; at++ {
		f.service.observe(second(at), map[string]answer{server1: {}, server3: {10 * time.Millisecond, true}})
	}
	if f.last().Exit != "" || !slices.Equal(f.service.Status(0).Notes, []string{"server-1 stopped answering, so the exit node is off."}) {
		t.Fatalf("after 30 silent seconds exit %q, notifications %v", f.last().Exit, f.service.notes)
	}

	f.service.notes = nil
	choose()
	f.service.observe(second(41), map[string]answer{server1: {20 * time.Millisecond, true}, server3: {10 * time.Millisecond, true}})
	if f.last().Exit != server1 {
		t.Fatal("choosing the exit again did not start a new watch")
	}
	f.hint(reporter.Hints{Held: []string{server1}})
	for at := 42; at < 45; at++ {
		f.service.observe(second(at), map[string]answer{server1: {20 * time.Millisecond, true}, server3: {10 * time.Millisecond, true}})
	}
	if f.service.exit != "" || !slices.Equal(f.service.Status(0).Notes, []string{"server-1 was cut off, so the exit node is off."}) {
		t.Fatalf("held exit %q, notifications %v", f.service.exit, f.service.notes)
	}
}

func TestAnExitWithoutDNSIsNone(t *testing.T) {
	f := newFixture(t)
	var document network.Document
	if err := json.Unmarshal(f.document(1, "", true), &document); err != nil {
		t.Fatal(err)
	}
	document.DNS = nil
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.deliver(1, f.sign(body)); !got.OK {
		t.Fatal(got.Message)
	}
	f.service.mu.Lock()
	f.service.exit = server1
	f.service.refresh()
	f.service.mu.Unlock()
	f.service.push()
	if last := f.last(); last.Exit != "" || slices.Contains(last.Peers[0].AllowedIPs, "0.0.0.0/0") || f.service.exit != "" {
		t.Fatalf("an exit without DNS: %+v, chosen %q", last, f.service.exit)
	}
}

func TestAHintedEndpointIsUsedButNeverPinned(t *testing.T) {
	f := newFixture(t)
	f.joined()
	f.hint(reporter.Hints{Endpoints: []reporter.HintEndpoint{{Key: f.server.Public, Endpoint: "198.51.100.7:51820"}}})
	peer := f.last().Peers[0]
	if peer.Endpoint != "198.51.100.7:51820" || peer.Pin != "203.0.113.1:51820" {
		t.Fatalf("peer %+v", peer)
	}
}

func TestTheDefaultMeetingPointComesFromTheSignedDocumentAndIsNeverHeld(t *testing.T) {
	f := newFixture(t)
	var document network.Document
	if err := json.Unmarshal(f.document(1, "", true), &document); err != nil {
		t.Fatal(err)
	}
	document.Members[0].Endpoint, document.Members[0].Exit = nil, false
	document.Members[0].PSK[server3] = "c2VhbGVk"
	document.Members[1].PSK[server3] = "c2VhbGVk"
	document.Members[2].PSK[server3] = f.psk()
	document.Members = append(document.Members, network.Member{Node: server3, Name: "server-3", Address: "10.88.0.3", Key: wgKey(3), Signer: wgKey(13), SealKey: otherSealKey, Port: network.FirstPort, Endpoint: endpoint("203.0.113.3:51820"), PSK: map[string]string{server1: "c2VhbGVk", server2: "c2VhbGVk", laptop1: "c2VhbGVk"}})
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.deliver(1, f.sign(body)); !got.OK {
		t.Fatal(got.Message)
	}
	f.hint(reporter.Hints{Endpoints: []reporter.HintEndpoint{{Key: f.server.Public, Endpoint: "198.51.100.7:51820"}}})
	if behind := f.behind(); behind.Endpoint != "203.0.113.3:51920" {
		t.Fatalf("the default meeting point was taken from a hinted endpoint: %+v", behind)
	}
	f.hint(reporter.Hints{Held: []string{server3}})
	if behind := f.behind(); behind.Endpoint != "" || behind.Pin != "" || !behind.Relay {
		t.Fatalf("the member behind NAT keeps an endpoint with every meeting point held: %+v", behind)
	}
	if via := f.service.Status(0).Servers[1].Via; via != "" {
		t.Fatalf("the member behind NAT is shown via %q", via)
	}
}

func (f *fixture) natRound(from, to int, behind bool) {
	f.t.Helper()
	for at := from; at <= to; at++ {
		answers := map[string]answer{server1: {30 * time.Millisecond, true}, server3: {10 * time.Millisecond, true}, server2: {}}
		if behind {
			answers[server2] = answer{40 * time.Millisecond, true}
		}
		f.service.observe(second(at), answers)
	}
}

func TestABrokenRelayIsLeftWhenAConnectedMemberBehindNATMissesThrough(t *testing.T) {
	f := newFixture(t)
	f.twoPublic()
	f.hint(reporter.Hints{Connected: []string{server2}})
	f.natRound(0, 21, false)
	if f.service.meet != server3 || f.behind().Endpoint != "203.0.113.3:51920" {
		t.Fatalf("left %q before 3 counted misses", f.service.meet)
	}
	f.hint(reporter.Hints{Meetings: []reporter.HintMeeting{{Laptop: laptop1, Via: server3}}, Connected: []string{server2}})
	f.natRound(22, 22, false)
	if f.service.meet != server1 || f.behind().Endpoint != "203.0.113.1:51920" {
		t.Fatalf("still on %q with its relay broken", f.service.meet)
	}
	if meets := sentOf[reporter.Meet](f.hub); len(meets) == 0 || meets[len(meets)-1].Via != server1 {
		t.Fatalf("meets %+v", meets)
	}
}

func TestEveryHintSaysWhoIsConnected(t *testing.T) {
	f := newFixture(t)
	f.twoPublic()
	f.hint(reporter.Hints{Connected: []string{server2}})
	f.natRound(0, 21, false)
	f.hint(reporter.Hints{Meetings: []reporter.HintMeeting{{Laptop: laptop1, Via: server3}}})
	f.hub.sent = nil
	f.natRound(22, 200, false)
	if meets := sentOf[reporter.Meet](f.hub); len(meets) != 0 || f.service.meet != server3 {
		t.Fatalf("a member a later hint called offline moved the laptop: %+v", meets)
	}
	f.hint(reporter.Hints{Connected: []string{server2}})
	f.natRound(201, 222, false)
	if meets := sentOf[reporter.Meet](f.hub); len(meets) == 0 || meets[0].Via != server1 {
		t.Fatalf("a member a later hint called connected was not counted: %+v", meets)
	}
}

func TestAMemberBehindNATTheWorkerReportsOfflineNeverMovesTheLaptop(t *testing.T) {
	f := newFixture(t)
	f.twoPublic()
	f.hint(reporter.Hints{Connected: []string{}})
	f.natRound(0, 200, false)
	if f.service.meet != server3 {
		t.Fatalf("a switched-off member behind NAT moved the laptop to %q", f.service.meet)
	}
}

func TestAnUnreachableWorkerFreezesTheCountThroughTheMeetingPoint(t *testing.T) {
	f := newFixture(t)
	f.twoPublic()
	f.hint(reporter.Hints{Connected: []string{server2}})
	f.natRound(0, 21, false)
	f.service.setLinked(false)
	f.natRound(22, 120, false)
	if f.service.meet != server3 {
		t.Fatalf("counted misses while the Worker was unreachable and moved to %q", f.service.meet)
	}
	f.service.setLinked(true)
	f.natRound(121, 121, false)
	if f.service.meet != server1 {
		t.Fatalf("the frozen count did not resume: still on %q", f.service.meet)
	}
}

func TestAnAnswerThroughTheMeetingPointKeepsIt(t *testing.T) {
	f := newFixture(t)
	f.twoPublic()
	f.hint(reporter.Hints{Connected: []string{server2}})
	f.natRound(0, 200, true)
	if f.service.meet != server3 {
		t.Fatalf("a member answering through server-3 moved the laptop to %q", f.service.meet)
	}
}
