package network

import "testing"

func TestTheDumpGivesEachPeerAndNeverThePrivateKey(t *testing.T) {
	dump := "cHJpdmF0ZQ==\tyAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\t51820\toff\n" +
		"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\tcHNr\t203.0.113.7:41641\t10.88.0.2/32\t1793000000\t310\t1200\t25\n" +
		"TW9yZVNpZ25lcktleUZvclRoZVNlY29uZE1lbWJlcjE=\t(none)\t(none)\t10.88.0.3/32\t0\t0\t0\t25\n"
	links := ParseDump(dump)
	if len(links) != 2 {
		t.Fatalf("links %+v", links)
	}
	first, second := links[0], links[1]
	if first.Key != "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=" || first.Handshake == nil || *first.Handshake != 1793000000 || first.RX != 310 || first.TX != 1200 || first.Endpoint == nil || *first.Endpoint != "203.0.113.7:41641" {
		t.Fatalf("first %+v", first)
	}
	if second.Handshake != nil || second.Endpoint != nil || second.RX != 0 {
		t.Fatalf("a peer never seen: %+v", second)
	}
}

func TestOnePingGivesItsTime(t *testing.T) {
	ms := PingMS("PING 10.88.0.2 (10.88.0.2) 56(84) bytes of data.\n64 bytes from 10.88.0.2: icmp_seq=1 ttl=64 time=4.12 ms\n")
	if ms == nil || *ms != 4.12 {
		t.Fatalf("ms %v", ms)
	}
	if PingMS("1 packets transmitted, 0 received, 100% packet loss") != nil {
		t.Fatal("a lost ping has no time")
	}
}
