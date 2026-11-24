package mesh

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

func dumpOf(n *testNet, handshake int64) string {
	return "cHJpdmF0ZQ==\tcHVibGlj\t51821\toff\n" +
		n.peer.Public + "\t(none)\t" + peerEndpoint + "\t10.88.0.1/32\t" + fmt.Sprint(handshake) + "\t100\t200\t25\n"
}

func TestTheLinksSayWhichPeersAnswerAndHowFast(t *testing.T) {
	n := joinedNet(t)
	n.sent = nil
	n.run.respond["wg show kry0 dump"] = dumpOf(n, testNow.Unix()-10) + peerKeys(t).Public + "\t(none)\t(none)\t10.88.0.7/32\t0\t0\t0\t25\n"
	n.run.respond["ping -n -c 1 -W 1 -I kry0 10.88.0.1"] = "64 bytes from 10.88.0.1: icmp_seq=1 ttl=64 time=4.20 ms\n"
	if err := n.m.SendLinks(t.Context()); err != nil {
		t.Fatal(err)
	}
	sent := n.messages()
	links, ok := sent[0].(reporter.Links)
	if len(sent) != 1 || !ok || links.Type != "links" || len(links.Links) != 1 {
		t.Fatalf("sent %+v", sent)
	}
	if link := links.Links[0]; link.Key != n.peer.Public || link.MS == nil || *link.MS != 4.2 || link.RX != 100 || link.TX != 200 {
		t.Fatalf("link %+v", link)
	}
	n.run.respond["wg show kry0 dump"] = dumpOf(n, testNow.Unix()-600)
	n.run.calls = nil
	n.m.SendLinks(t.Context())
	if links := n.messages()[1].(reporter.Links); links.Links[0].MS != nil || len(n.run.called("ping")) != 0 {
		t.Fatalf("a silent peer was pinged: %+v", links)
	}
	other := newNet(t)
	if err := other.m.SendLinks(t.Context()); err != nil {
		t.Fatal(err)
	}
	if links := other.messages()[0].(reporter.Links); links.Links == nil || len(links.Links) != 0 {
		t.Fatalf("a server outside the network sent %+v", links)
	}
}

func TestLinksAreSentOnlyWhenAPeerFlips(t *testing.T) {
	n := joinedNet(t)
	n.sent = nil
	n.run.respond["wg show kry0 dump"] = dumpOf(n, testNow.Unix()-10)
	last := n.m.flip(t.Context(), nil)
	if len(n.messages()) != 1 || !last[n.peer.Public] {
		t.Fatalf("the first look sends the links: %v %d", last, len(n.messages()))
	}
	n.run.respond["wg show kry0 dump"] = dumpOf(n, testNow.Unix()-170)
	if last = n.m.flip(t.Context(), last); len(n.messages()) != 1 {
		t.Fatal("links were sent while no peer flipped")
	}
	n.run.respond["wg show kry0 dump"] = dumpOf(n, testNow.Unix()-180)
	failing := true
	n.m.Send = func(message any) error {
		if failing {
			return errors.New("not connected")
		}
		return n.send(message)
	}
	if last = n.m.flip(t.Context(), last); !last[n.peer.Public] {
		t.Fatal("a flip that could not be sent was taken as sent")
	}
	failing = false
	if last = n.m.flip(t.Context(), last); last[n.peer.Public] || len(n.messages()) != 2 {
		t.Fatalf("a peer that stopped answering was not sent: %v %d", last, len(n.messages()))
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	n.m.WatchLinks(ctx, time.Hour)
	if len(n.messages()) != 3 {
		t.Fatal("watching starts with one look")
	}
}
