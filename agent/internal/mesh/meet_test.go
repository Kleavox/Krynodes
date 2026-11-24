package mesh

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

func meetings(hints ...reporter.HintMeeting) reporter.Hints {
	return reporter.Hints{Type: "hints", Meetings: hints}
}

func TestAnAnnouncedKeyIsTakenOnlyWithTheMembersSignature(t *testing.T) {
	n := newNet(t)
	dir := filepath.Join(t.TempDir(), "peer")
	var err error
	if n.peer, err = network.Load(dir, true); err != nil {
		t.Fatal(err)
	}
	n.apply(t, pair)
	fresh, err := network.Next(dir)
	if err != nil {
		t.Fatal(err)
	}
	stranger := peerKeys(t)
	n.run.calls = nil
	for _, bad := range []reporter.HintAnnounced{
		{Node: peerNode, Key: fresh.Public, Signature: stranger.Announce(peerNode)},
		{Node: selfNode, Key: stranger.Public, Signature: stranger.Announce(selfNode)},
		{Node: strangeNode, Key: stranger.Public, Signature: stranger.Announce(strangeNode)},
	} {
		n.m.Hints(t.Context(), reporter.Hints{Announced: []reporter.HintAnnounced{bad}})
	}
	if config := readRoot(t, n.m, network.ConfigPath); !strings.Contains(config, "PublicKey = "+n.peer.Public) || len(n.run.calls) != 0 {
		t.Fatalf("a bad announcement changed the key: %v", n.run.calls)
	}
	n.m.Hints(t.Context(), reporter.Hints{Announced: []reporter.HintAnnounced{{Node: peerNode, Key: fresh.Public, Signature: fresh.Announce(peerNode)}}})
	if config := readRoot(t, n.m, network.ConfigPath); !strings.Contains(config, "PublicKey = "+fresh.Public) || strings.Contains(config, n.peer.Public) {
		t.Fatalf("config:\n%s", config)
	}
	if len(n.run.called("wg syncconf kry0 ")) != 1 {
		t.Fatalf("the running kry0 was not told: %v", n.run.calls)
	}
	n.run.calls = nil
	n.m.Hints(t.Context(), reporter.Hints{Announced: []reporter.HintAnnounced{{Node: peerNode, Key: fresh.Public, Signature: fresh.Announce(peerNode)}}})
	if len(n.run.calls) != 0 {
		t.Fatalf("a key in use was taken again: %v", n.run.calls)
	}
	n.apply(t, pair)
	if config := readRoot(t, n.m, network.ConfigPath); !strings.Contains(config, "PublicKey = "+fresh.Public) {
		t.Fatalf("a document that does not name the new key yet forgot it:\n%s", config)
	}
}

func TestEndpointsChangeOnlyThePeersOfTheNetwork(t *testing.T) {
	n := joinedNet(t)
	n.apply(t, behindNAT)
	n.run.calls = nil
	n.m.Hints(t.Context(), reporter.Hints{Endpoints: []reporter.HintEndpoint{
		{Key: n.peer.Public, Endpoint: "203.0.113.41:51830"},
		{Key: n.third.Public, Endpoint: "203.0.113.43:40000"},
		{Key: n.behind.Public, Endpoint: "203.0.113.44:51820"},
		{Key: n.laptop.Public, Endpoint: "203.0.113.45:51820"},
		{Key: n.keys.Public, Endpoint: "203.0.113.46:51820"},
		{Key: peerKeys(t).Public, Endpoint: "203.0.113.47:51820"},
		{Key: n.peer.Public, Endpoint: "server-2"},
	}})
	if want := []string{"wg set kry0 peer " + n.peer.Public + " endpoint 203.0.113.41:51830"}; !slices.Equal(n.run.calls, want) {
		t.Fatalf("want %q, got %q", want, n.run.calls)
	}
}

func TestAHintNamingANATMemberOrAStrangerIsIgnored(t *testing.T) {
	n := joinedNet(t)
	n.apply(t, asIs)
	n.run.calls = nil
	n.m.Hints(t.Context(), meetings(reporter.HintMeeting{Laptop: laptopNode, Via: thirdNode}))
	if current, _ := n.m.load(); len(n.run.calls) != 0 || current.Meetings != nil {
		t.Fatalf("a public server follows no meeting point: %v", n.run.calls)
	}
	n.apply(t, behindNAT)
	n.run.calls = nil
	n.m.Hints(t.Context(), meetings(
		reporter.HintMeeting{Laptop: laptopNode, Via: behindNode},
		reporter.HintMeeting{Laptop: laptopNode, Via: strangeNode},
		reporter.HintMeeting{Laptop: laptopNode, Via: laptopNode},
		reporter.HintMeeting{Laptop: peerNode, Via: thirdNode},
		reporter.HintMeeting{Laptop: strangeNode, Via: thirdNode},
	))
	if current, _ := n.m.load(); len(n.run.calls) != 0 || current.Meetings != nil {
		t.Fatalf("a refused hint moved a peer: %v %v", n.run.calls, current.Meetings)
	}
}

func TestTheRootUnitRefusesAMeetingPointItMayNotFollow(t *testing.T) {
	cutLaptop := func(self *network.Member, members []network.Member) []network.Member {
		behindNAT(self, members)
		members[3].Cut = true
		return members
	}
	cutVia := func(self *network.Member, members []network.Member) []network.Member {
		behindNAT(self, members)
		members[1].Cut = true
		return members
	}
	for name, change := range map[string]change{"cut laptop": cutLaptop, "cut via": cutVia, "public self": asIs} {
		t.Run(name, func(t *testing.T) {
			n := joinedNet(t)
			n.apply(t, change)
			n.run.calls = nil
			n.m.Hints(t.Context(), meetings(reporter.HintMeeting{Laptop: laptopNode, Via: thirdNode}))
			if len(n.run.called("wg set")) != 0 {
				t.Fatalf("a refused meeting point moved a peer: %v", n.run.calls)
			}
			if current, _ := n.m.load(); current.Meetings != nil {
				t.Fatal("a refused meeting point was recorded")
			}
		})
	}
}

func TestAHintMovesTheLaptopToTheNamedPeer(t *testing.T) {
	n := joinedNet(t)
	n.apply(t, behindNAT)
	laptopPeer := func() string {
		config := readRoot(t, n.m, network.ConfigPath)
		if !strings.Contains(config, "AllowedIPs = 10.88.0.1/32\n") || !strings.Contains(config, "AllowedIPs = 10.88.0.3/32\n") || strings.Count(config, "10.88.0.9") != 1 {
			t.Fatalf("a meeting peer carries the laptop:\n%s", config)
		}
		return config[strings.Index(config, "PublicKey = "+n.laptop.Public):]
	}
	if peer := laptopPeer(); !strings.Contains(peer, "AllowedIPs = 10.88.0.9/32\nEndpoint = 203.0.113.21:51921\nPersistentKeepalive = 25\n") {
		t.Fatalf("the laptop starts on the default meeting point's pair port:\n%s", peer)
	}
	hint := meetings(reporter.HintMeeting{Laptop: laptopNode, Via: thirdNode})
	n.run.calls = nil
	n.m.Hints(t.Context(), hint)
	if want := []string{"wg set kry0 peer " + n.laptop.Public + " endpoint 203.0.113.23:51921"}; !slices.Equal(n.run.called("wg "), want) {
		t.Fatalf("want %q, got %q", want, n.run.calls)
	}
	if peer := laptopPeer(); !strings.Contains(peer, "Endpoint = 203.0.113.23:51921\n") {
		t.Fatalf("kry0.conf does not follow the hint:\n%s", peer)
	}
	n.run.calls = nil
	n.m.Hints(t.Context(), hint)
	if len(n.run.calls) != 0 {
		t.Fatalf("a hint already followed was followed again: %v", n.run.calls)
	}
	n.apply(t, behindNAT)
	if peer := laptopPeer(); !strings.Contains(peer, "Endpoint = 203.0.113.23:51921\n") {
		t.Fatalf("a newer document forgot the meeting point:\n%s", peer)
	}
}

func TestRoamingNeverMovesALaptopOffItsMeetingPoint(t *testing.T) {
	n := joinedNet(t)
	n.apply(t, behindNAT)
	sets := func(endpoint string) []string {
		t.Helper()
		n.run.respond["wg show kry0 dump"] = "cHJpdmF0ZQ==\tcHVibGlj\t51820\toff\n" + n.laptop.Public + "\t(none)\t" + endpoint + "\t10.88.0.9/32\t0\t0\t0\t25\n"
		n.run.calls = nil
		n.m.holdMeetings(t.Context())
		return n.run.called("wg set")
	}
	back := func(endpoint string) []string {
		return []string{"wg set kry0 peer " + n.laptop.Public + " endpoint " + endpoint}
	}
	if got := sets("203.0.113.21:51921"); len(got) != 0 {
		t.Fatalf("an endpoint in place is set again: %q", got)
	}
	if got := sets("[::ffff:203.0.113.21]:51921"); len(got) != 0 {
		t.Fatalf("a mapped form of the same endpoint is set again: %q", got)
	}
	if got, want := sets("203.0.113.23:51921"), back("203.0.113.21:51921"); !slices.Equal(got, want) {
		t.Fatalf("want %q, got %q", want, got)
	}
	n.m.Hints(t.Context(), meetings(reporter.HintMeeting{Laptop: laptopNode, Via: thirdNode}))
	if got, want := sets("203.0.113.21:51921"), back("203.0.113.23:51921"); !slices.Equal(got, want) {
		t.Fatalf("a datagram through the old meeting point undid the hint: want %q, got %q", want, got)
	}
	if got, want := sets("(none)"), back("203.0.113.23:51921"); !slices.Equal(got, want) {
		t.Fatalf("want %q, got %q", want, got)
	}
	n.run.respond["wg show kry0 dump"] = "cHJpdmF0ZQ==\tcHVibGlj\t51820\toff\n"
	n.run.calls = nil
	n.m.holdMeetings(t.Context())
	if len(n.run.called("wg set")) != 0 {
		t.Fatalf("a laptop kry0 does not hold yet was set: %q", n.run.calls)
	}
	n.apply(t, asIs)
	n.run.calls = nil
	n.m.holdMeetings(t.Context())
	if len(n.run.calls) != 0 {
		t.Fatalf("a meeting point follows no meeting point: %q", n.run.calls)
	}
}
