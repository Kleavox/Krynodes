package service

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/stream"
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
	document.Members = append(document.Members, network.Member{Node: server3, Name: "server-3", Address: "10.88.0.3", Key: wgKey(3), Signer: wgKey(13), Port: network.FirstPort, Endpoint: endpoint("203.0.113.3:51820"), PSK: map[string]string{server1: "c2VhbGVk", server2: "c2VhbGVk", laptop1: "c2VhbGVk"}})
	body, err := json.Marshal(document)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.service.applyDocument(f.sign(body)); err != nil {
		f.t.Fatal(err)
	}
	f.service.wake = make(chan struct{}, 1)
	f.service.mu.Lock()
	f.service.refresh()
	f.service.mu.Unlock()
	f.service.push()
}

func second(at int) time.Time {
	return testNow.Add(time.Duration(at) * time.Second)
}

func TestTheMeetingPointFollowsThePings(t *testing.T) {
	f := newFixture(t)
	f.twoPublic()
	f.service.observe(second(0), map[string]answer{server1: {30 * time.Millisecond, true}, server3: {10 * time.Millisecond, true}})
	select {
	case <-f.service.wake:
	default:
		t.Fatal("a new meeting point sent no beat")
	}
	carried := allowed(f.last().Peers)
	if !slices.Contains(carried[server3], "10.88.0.2/32") || slices.Contains(carried[server1], "10.88.0.2/32") {
		t.Fatalf("the member behind NAT is not on the meeting point: %v", carried)
	}
	if beat, ok := f.service.beat(reporter.Host{}); !ok || beat.Network.Meet != server3 {
		t.Fatalf("beat %+v", beat.Network)
	}
	f.service.answer(reporter.HeartbeatResponse{Network: &reporter.NetworkReply{Held: []string{server3}}})
	f.service.observe(second(1), map[string]answer{server1: {30 * time.Millisecond, true}, server3: {10 * time.Millisecond, true}})
	if f.service.meet != server1 {
		t.Fatalf("a held server stays the meeting point: %q", f.service.meet)
	}
}

type unreachable struct{ fakeServer }

func (*unreachable) SendHeartbeat(context.Context, reporter.Heartbeat) (reporter.HeartbeatResponse, error) {
	return reporter.HeartbeatResponse{}, stream.ErrNotConnected
}

func TestTheMeetingPointMovesForSpeedOnlyWhileTheStreamIsUp(t *testing.T) {
	f := newFixture(t)
	f.twoPublic()
	f.service.answer(reporter.HeartbeatResponse{})
	f.service.cycle(context.Background(), &unreachable{}, reporter.Host{})
	f.service.observe(second(0), map[string]answer{server1: {20 * time.Millisecond, true}})
	faster := map[string]answer{server1: {20 * time.Millisecond, true}, server3: {15 * time.Millisecond, true}}
	for at := 1; at <= 62; at++ {
		f.service.observe(second(at), faster)
	}
	if f.service.meet != server1 {
		t.Fatalf("moved to %q for speed while the Worker was unreachable", f.service.meet)
	}
	f.service.answer(reporter.HeartbeatResponse{})
	f.service.observe(second(63), faster)
	if f.service.meet != server3 {
		t.Fatalf("the stream is up again and the meeting point stays %q", f.service.meet)
	}
	f.service.cycle(context.Background(), &unreachable{}, reporter.Host{})
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
	f.service.answer(reporter.HeartbeatResponse{Network: &reporter.NetworkReply{Held: []string{server1}}})
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
	if err := f.service.applyDocument(f.sign(body)); err != nil {
		t.Fatal(err)
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
	f.service.answer(reporter.HeartbeatResponse{Network: &reporter.NetworkReply{
		Endpoints: []reporter.NetworkEndpoint{{Key: f.server.Public, Endpoint: "198.51.100.7:51820"}},
	}})
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
	document.Members = append(document.Members, network.Member{Node: server3, Name: "server-3", Address: "10.88.0.3", Key: wgKey(3), Signer: wgKey(13), Port: network.FirstPort, Endpoint: endpoint("203.0.113.3:51820"), PSK: map[string]string{server1: "c2VhbGVk", server2: "c2VhbGVk", laptop1: "c2VhbGVk"}})
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.service.applyDocument(f.sign(body)); err != nil {
		t.Fatal(err)
	}
	f.service.answer(reporter.HeartbeatResponse{Network: &reporter.NetworkReply{
		Endpoints: []reporter.NetworkEndpoint{{Key: f.server.Public, Endpoint: "198.51.100.7:51820"}},
	}})
	carried := allowed(f.last().Peers)
	if !slices.Contains(carried[server3], "10.88.0.2/32") || slices.Contains(carried[server1], "10.88.0.2/32") {
		t.Fatalf("the default meeting point was taken from a hinted endpoint: %v", carried)
	}
	f.service.answer(reporter.HeartbeatResponse{Network: &reporter.NetworkReply{Held: []string{server3}}})
	for node, ips := range allowed(f.last().Peers) {
		if slices.Contains(ips, "10.88.0.2/32") {
			t.Fatalf("%s carries the member behind NAT with every meeting point held: %v", node, ips)
		}
	}
	if via := f.service.Status(0).Servers[1].Via; via != "" {
		t.Fatalf("the member behind NAT is shown via %q", via)
	}
}
