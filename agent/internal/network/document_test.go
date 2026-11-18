package network

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	nodeA = "11111111-1111-4111-8111-111111111111"
	nodeB = "22222222-2222-4222-8222-222222222222"
	nodeC = "33333333-3333-4333-8333-333333333333"
)

func fixtureNamed(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "protocol", "src", "fixtures", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return raw
}

func fixtureBytes(t *testing.T) []byte {
	t.Helper()
	return fixtureNamed(t, "network-document.json")
}

func fixture(t *testing.T) Document {
	t.Helper()
	document, err := Parse(fixtureBytes(t))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return document
}

func edited(t *testing.T, change func(map[string]any)) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(fixtureBytes(t), &document); err != nil {
		t.Fatal(err)
	}
	change(document)
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func member(document map[string]any, index int) map[string]any {
	return document["members"].([]any)[index].(map[string]any)
}

func TestTheSharedFixtureParses(t *testing.T) {
	document := fixture(t)
	if document.Version != 3 || len(document.Members) != 2 || document.Members[1].Name != "server-1" || !document.Members[1].NAT {
		t.Fatalf("document %+v", document)
	}
	if document.Members[1].MTU == nil || *document.Members[1].MTU != 1380 || document.Members[0].MTU != nil {
		t.Fatalf("mtu %v %v", document.Members[0].MTU, document.Members[1].MTU)
	}
}

func TestAPeerThatIsNotOneAddressInsideTheRangeIsRefused(t *testing.T) {
	for _, address := range []string{"10.88.0.0/24", "10.88.0.2/32", "0.0.0.0/0", "::/0", "10.89.0.2", "10.88.0.0", "10.88.0.255", "fd00::2", ""} {
		raw := edited(t, func(document map[string]any) { member(document, 1)["address"] = address })
		if _, err := Parse(raw); err == nil {
			t.Errorf("address %q was accepted", address)
		}
	}
}

func TestADocumentThatBreaksItsOwnRulesIsRefused(t *testing.T) {
	cases := map[string]func(map[string]any){
		"two members share an address": func(document map[string]any) { member(document, 1)["address"] = "10.88.0.1" },
		"two members share a key":      func(document map[string]any) { member(document, 1)["key"] = member(document, 0)["key"] },
		"a preshared key for a stranger": func(document map[string]any) {
			member(document, 0)["psk"] = map[string]any{nodeC: "eyJ2IjoxfQ"}
		},
		"a missing preshared key": func(document map[string]any) { member(document, 0)["psk"] = map[string]any{} },
		"a member key blocked":    func(document map[string]any) { document["blocked"] = []any{member(document, 0)["key"]} },
		"a range outside the pool": func(document map[string]any) {
			document["range"] = "10.0.0.0/24"
		},
		"a range wider than /24": func(document map[string]any) { document["range"] = "10.88.0.0/16" },
		"a key that is not 32 bytes": func(document map[string]any) {
			member(document, 1)["key"] = "c2hvcnQ="
		},
		"a port outside the network's": func(document map[string]any) { member(document, 1)["port"] = 53 },
		"an unknown field":             func(document map[string]any) { document["allowedIPs"] = "0.0.0.0/0" },
		"a member field unknown":       func(document map[string]any) { member(document, 1)["allowedIPs"] = "0.0.0.0/0" },
		"an endpoint that is a name":   func(document map[string]any) { member(document, 0)["endpoint"] = "vps-1.example.com:51820" },
		"a parent that is not a hash":  func(document map[string]any) { document["parent"] = "abc" },
		"a scan outside the choices":   func(document map[string]any) { document["knocks"] = map[string]any{"scan": 7, "stop": true} },
	}
	for name, change := range cases {
		if _, err := Parse(edited(t, change)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

const (
	nodeL = "99999999-9999-4999-8999-999999999999"
	nodeM = "88888888-8888-4888-8888-888888888888"
	nodeN = "44444444-4444-4444-8444-444444444444"
)

func withLaptop(document map[string]any) {
	laptop := map[string]any{
		"node": nodeL, "name": "laptop-1", "address": "10.88.0.9",
		"key":    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		"signer": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{10}, 32)),
		"port":   51822, "mtu": nil, "endpoint": nil, "nat": true, "kind": "laptop",
		"psk":   map[string]any{nodeA: "eyJ2IjozfQ", nodeB: "eyJ2Ijo2fQ"},
		"relay": map[string]any{nodeB: FirstRelayPort},
	}
	document["members"] = append(document["members"].([]any), laptop)
	member(document, 0)["psk"].(map[string]any)[nodeL] = "eyJ2Ijo0fQ"
	member(document, 1)["psk"].(map[string]any)[nodeL] = "eyJ2Ijo1fQ"
}

func TestTheSharedFixturesMarshalBackByteForByte(t *testing.T) {
	for _, name := range []string{"network-document.json", "network-document-laptop.json"} {
		raw := fixtureNamed(t, name)
		var want bytes.Buffer
		if err := json.Compact(&want, raw); err != nil {
			t.Fatal(err)
		}
		document, err := Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := json.Marshal(document)
		if err != nil || !bytes.Equal(got, want.Bytes()) {
			t.Fatalf("%s: got\n%s\nwant\n%s", name, got, want.Bytes())
		}
	}
}

func TestTheLaptopFixtureCarriesItsRelayPort(t *testing.T) {
	document, err := Parse(fixtureNamed(t, "network-document-laptop.json"))
	if err != nil || len(document.Members) != 3 {
		t.Fatalf("document %+v err %v", document, err)
	}
	if port, ok := RelayPort(document, nodeL, nodeB); !ok || port != FirstRelayPort {
		t.Fatalf("port %d %v", port, ok)
	}
	for _, pair := range [][2]string{{nodeL, nodeA}, {nodeA, nodeB}, {nodeB, nodeL}, {nodeC, nodeB}} {
		if port, ok := RelayPort(document, pair[0], pair[1]); ok || port != 0 {
			t.Errorf("%v: %d %v", pair, port, ok)
		}
	}
}

func TestOnlyALaptopMarshalsItsRelay(t *testing.T) {
	laptop, err := json.Marshal(Member{Kind: laptopKind})
	if err != nil || !strings.Contains(string(laptop), `"relay":{}`) {
		t.Fatalf("laptop %s %v", laptop, err)
	}
	server, err := json.Marshal(Member{})
	if err != nil || strings.Contains(string(server), "relay") {
		t.Fatalf("server %s %v", server, err)
	}
}

func TestParseWantsAPskForEveryLinkedPairAndNoOther(t *testing.T) {
	document, err := Parse(edited(t, withLaptop))
	if err != nil {
		t.Fatal(err)
	}
	laptop := document.Members[2]
	if !laptop.IsLaptop() || !Links(document.Members[0], laptop) || !Links(document.Members[1], laptop) || !Links(laptop, document.Members[1]) || !Links(document.Members[0], document.Members[1]) || Links(laptop, laptop) {
		t.Fatalf("laptop %+v", laptop)
	}
	refused := map[string]func(map[string]any){
		"a laptop without its public peer's key": func(document map[string]any) {
			withLaptop(document)
			delete(member(document, 2)["psk"].(map[string]any), nodeA)
		},
		"a public member without the laptop's key": func(document map[string]any) {
			withLaptop(document)
			delete(member(document, 0)["psk"].(map[string]any), nodeL)
		},
		"a laptop without its NAT peer's key": func(document map[string]any) {
			withLaptop(document)
			delete(member(document, 2)["psk"].(map[string]any), nodeB)
		},
		"a NAT member without the laptop's key": func(document map[string]any) {
			withLaptop(document)
			delete(member(document, 1)["psk"].(map[string]any), nodeL)
		},
		"a laptop holding a stranger's key": func(document map[string]any) {
			withLaptop(document)
			member(document, 2)["psk"].(map[string]any)[nodeC] = "eyJ2Ijo5fQ"
		},
	}
	for name, change := range refused {
		if _, err := Parse(edited(t, change)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func twoLaptops(document map[string]any) {
	withLaptop(document)
	second := map[string]any{}
	for key, value := range member(document, 2) {
		second[key] = value
	}
	second["node"], second["name"], second["address"] = nodeM, "laptop-2", "10.88.0.10"
	second["key"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{11}, 32))
	second["signer"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{12}, 32))
	second["psk"] = map[string]any{nodeA: "eyJ2Ijo2fQ", nodeB: "eyJ2Ijo3fQ"}
	second["relay"] = map[string]any{nodeB: FirstRelayPort + 1}
	document["members"] = append(document["members"].([]any), second)
	member(document, 0)["psk"].(map[string]any)[nodeM] = "eyJ2Ijo3fQ"
	member(document, 1)["psk"].(map[string]any)[nodeM] = "eyJ2Ijo4fQ"
}

func TestParseRefusesAPskBetweenTwoLaptops(t *testing.T) {
	if _, err := Parse(edited(t, twoLaptops)); err != nil {
		t.Fatalf("two laptops: %v", err)
	}
	raw := edited(t, func(document map[string]any) {
		twoLaptops(document)
		member(document, 2)["psk"].(map[string]any)[nodeM] = "eyJ2Ijo4fQ"
		member(document, 3)["psk"].(map[string]any)[nodeL] = "eyJ2Ijo5fQ"
	})
	if _, err := Parse(raw); err == nil {
		t.Fatal("a psk between two laptops was accepted")
	}
}

func withSecondNAT(document map[string]any, cut bool) {
	withLaptop(document)
	second := map[string]any{
		"node": nodeN, "name": "server-2", "address": "10.88.0.4",
		"key":    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{13}, 32)),
		"signer": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{14}, 32)),
		"port":   51823, "mtu": nil, "endpoint": nil, "nat": true,
		"psk": map[string]any{nodeA: "eyJ2Ijo7fQ", nodeB: "eyJ2Ijo8fQ", nodeL: "eyJ2Ijo5fQ"},
	}
	if cut {
		second["cut"] = true
	}
	document["members"] = append(document["members"].([]any), second)
	for _, index := range []int{0, 1, 2} {
		member(document, index)["psk"].(map[string]any)[nodeN] = "eyJ2Ijo1fQ"
	}
	if !cut {
		member(document, 2)["relay"].(map[string]any)[nodeN] = FirstRelayPort + 1
	}
}

func TestParseHoldsRelayPortsToTheirRules(t *testing.T) {
	accepted := map[string]func(map[string]any){
		"the first relay port": func(document map[string]any) {
			withLaptop(document)
			member(document, 2)["relay"] = map[string]any{nodeB: FirstRelayPort}
		},
		"the last relay port": func(document map[string]any) {
			withLaptop(document)
			member(document, 2)["relay"] = map[string]any{nodeB: LastRelayPort}
		},
		"one port for each laptop and NAT pair": twoLaptops,
		"a port for each of two NAT members":    func(document map[string]any) { withSecondNAT(document, false) },
		"no port for a cut NAT member":          func(document map[string]any) { withSecondNAT(document, true) },
		"an empty relay without a NAT member": func(document map[string]any) {
			withLaptop(document)
			member(document, 1)["nat"], member(document, 1)["endpoint"] = false, "203.0.113.22:51821"
			member(document, 2)["relay"] = map[string]any{}
		},
	}
	for name, change := range accepted {
		if _, err := Parse(edited(t, change)); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
	refused := map[string]func(map[string]any){
		"a laptop without relay": func(document map[string]any) {
			withLaptop(document)
			delete(member(document, 2), "relay")
		},
		"a laptop with a null relay": func(document map[string]any) {
			withLaptop(document)
			member(document, 2)["relay"] = nil
		},
		"a missing port": func(document map[string]any) {
			withLaptop(document)
			member(document, 2)["relay"] = map[string]any{}
		},
		"a missing port for the second NAT member": func(document map[string]any) {
			withSecondNAT(document, false)
			delete(member(document, 2)["relay"].(map[string]any), nodeN)
		},
		"a port below the relay range": func(document map[string]any) {
			withLaptop(document)
			member(document, 2)["relay"] = map[string]any{nodeB: FirstRelayPort - 1}
		},
		"a port above the relay range": func(document map[string]any) {
			withLaptop(document)
			member(document, 2)["relay"] = map[string]any{nodeB: LastRelayPort + 1}
		},
		"a port of zero": func(document map[string]any) {
			withLaptop(document)
			member(document, 2)["relay"] = map[string]any{nodeB: 0}
		},
		"a port that is not a whole number": func(document map[string]any) {
			withLaptop(document)
			member(document, 2)["relay"] = map[string]any{nodeB: 51920.5}
		},
		"a duplicate port on one laptop": func(document map[string]any) {
			withSecondNAT(document, false)
			member(document, 2)["relay"] = map[string]any{nodeB: FirstRelayPort, nodeN: FirstRelayPort}
		},
		"a duplicate port across laptops": func(document map[string]any) {
			twoLaptops(document)
			member(document, 3)["relay"] = map[string]any{nodeB: FirstRelayPort}
		},
		"a port for a public member": func(document map[string]any) {
			withLaptop(document)
			member(document, 2)["relay"] = map[string]any{nodeB: FirstRelayPort, nodeA: FirstRelayPort + 1}
		},
		"a port for a stranger": func(document map[string]any) {
			withLaptop(document)
			member(document, 2)["relay"] = map[string]any{nodeB: FirstRelayPort, nodeC: FirstRelayPort + 1}
		},
		"a port for a cut NAT member": func(document map[string]any) {
			withSecondNAT(document, true)
			member(document, 2)["relay"].(map[string]any)[nodeN] = FirstRelayPort + 1
		},
		"a port for another laptop": func(document map[string]any) {
			twoLaptops(document)
			member(document, 2)["relay"].(map[string]any)[nodeM] = FirstRelayPort + 2
		},
		"a null relay on a public member": func(document map[string]any) { member(document, 0)["relay"] = nil },
		"a null relay on a NAT member":    func(document map[string]any) { member(document, 1)["relay"] = nil },
		"relay on a public member":        func(document map[string]any) { member(document, 0)["relay"] = map[string]any{nodeB: FirstRelayPort} },
		"empty relay on a NAT member":     func(document map[string]any) { member(document, 1)["relay"] = map[string]any{} },
	}
	for name, change := range refused {
		if _, err := Parse(edited(t, change)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestTheRelayRangeIsPinned(t *testing.T) {
	if FirstRelayPort != 51920 || LastRelayPort != 52175 {
		t.Fatalf("relay range %d-%d", FirstRelayPort, LastRelayPort)
	}
}

func TestExitAndDNSAreReadOnlyWhereTheyMayBe(t *testing.T) {
	document, err := Parse(edited(t, func(document map[string]any) {
		withLaptop(document)
		member(document, 0)["exit"] = true
		document["dns"] = []any{"1.1.1.1", "10.88.0.1"}
	}))
	if err != nil || !document.Members[0].Exit || !slices.Equal(document.DNS, []string{"1.1.1.1", "10.88.0.1"}) {
		t.Fatalf("document %+v err %v", document, err)
	}
	refused := map[string]func(map[string]any){
		"an exit on a laptop":     func(document map[string]any) { withLaptop(document); member(document, 2)["exit"] = true },
		"an exit behind NAT":      func(document map[string]any) { member(document, 1)["exit"] = true },
		"a kind that is not one":  func(document map[string]any) { member(document, 1)["kind"] = "lite" },
		"no DNS address":          func(document map[string]any) { document["dns"] = []any{} },
		"three DNS addresses":     func(document map[string]any) { document["dns"] = []any{"1.1.1.1", "1.0.0.1", "9.9.9.9"} },
		"an IPv6 DNS address":     func(document map[string]any) { document["dns"] = []any{"2606:4700:4700::1111"} },
		"a DNS address with zero": func(document map[string]any) { document["dns"] = []any{"01.1.1.1"} },
		"a DNS name":              func(document map[string]any) { document["dns"] = []any{"dns.example.com"} },
	}
	for name, change := range refused {
		if _, err := Parse(edited(t, change)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestALaptopsSixAddressIsItsLastTwoOctetsInHex(t *testing.T) {
	for address, want := range map[string]string{"10.88.3.9": "fd88:88::3:9", "10.88.0.254": "fd88:88::fe", "10.88.255.10": "fd88:88::ff:a", "192.168.0.9": ""} {
		if got := Address6(address); got != want {
			t.Errorf("%s: %q", address, got)
		}
	}
}

func TestOnlyANewerVersionIsApplied(t *testing.T) {
	document := fixture(t)
	for _, applied := range []int{3, 4, 9} {
		if _, err := Accept(document, Applied{Version: applied}, nodeA, false); err == nil || !strings.Contains(err.Error(), "not newer") {
			t.Errorf("applied %d: %v", applied, err)
		}
	}
	own, err := Accept(document, Applied{Version: 1}, nodeA, false)
	if err != nil || own.Name != "vps-1" {
		t.Fatalf("own %+v err %v", own, err)
	}
}

func TestABlockedKeyNeverComesBack(t *testing.T) {
	document := fixture(t)
	_, err := Accept(document, Applied{Version: 1, Blocked: []string{document.Members[1].Key}}, nodeA, false)
	if err == nil || !strings.Contains(err.Error(), "cannot come back") {
		t.Fatalf("err %v", err)
	}
}

func TestADocumentWithoutThisServerSaysLeave(t *testing.T) {
	document := fixture(t)
	if _, err := Accept(document, Applied{}, nodeC, false); !errors.Is(err, ErrLeave) {
		t.Fatalf("not a member: %v", err)
	}
	document.Deleted = true
	if _, err := Accept(document, Applied{}, nodeA, false); !errors.Is(err, ErrLeave) {
		t.Fatalf("deleted: %v", err)
	}
}

func TestAppliedKeepsEveryBlockedKey(t *testing.T) {
	document := fixture(t)
	next := Applied{Version: 1, Blocked: []string{"old"}}.After(document, "")
	if next.Version != 3 || strings.Join(next.Blocked, ",") != "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=,old" {
		t.Fatalf("next %+v", next)
	}
}

func TestAJoinedServerAppliesOnlyTheNextVersionOnTopOfWhatItApplied(t *testing.T) {
	document := fixture(t)
	applied := Applied{Version: 2, Hash: BodyHash([]byte("two"))}
	document.Parent = BodyHash([]byte("doctored"))
	if _, err := Accept(document, applied, nodeA, true); err == nil || err.Error() != "version 3 does not follow the version this server applied" {
		t.Fatalf("wrong parent: %v", err)
	}
	document.Parent = applied.Hash
	if own, err := Accept(document, applied, nodeA, true); err != nil || own.Name != "vps-1" {
		t.Fatalf("next: %+v %v", own, err)
	}
	if _, err := Accept(document, Applied{Version: 1, Hash: applied.Hash}, nodeA, true); err == nil || err.Error() != "version 3 is not the next one after 1" {
		t.Fatalf("jump: %v", err)
	}
}

func TestAServerThatIsNotJoinedTakesAnyNewerVersion(t *testing.T) {
	if _, err := Accept(fixture(t), Applied{Version: 1, Hash: BodyHash([]byte("one"))}, nodeA, false); err != nil {
		t.Fatal(err)
	}
}

func TestTheBodyHashIsSHA256InBase64URL(t *testing.T) {
	if got := BodyHash([]byte("abc")); got != "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0" {
		t.Fatal(got)
	}
}

func TestACutMemberRendersNoPeerAndItsKeyCountsAsBlocked(t *testing.T) {
	document := fixture(t)
	cut := document.Members[1].Key
	document.Members[1].Cut = true
	if config := Render(document, document.Members[0], "private", map[string]string{}, nil, false); strings.Contains(config, cut) {
		t.Fatalf("config %s", config)
	}
	applied := Applied{}.After(document, "h")
	if !slices.Contains(applied.Blocked, cut) || applied.Hash != "h" || applied.Version != 3 {
		t.Fatalf("applied %+v", applied)
	}
	document.Version, document.Parent = 4, "h"
	if _, err := Accept(document, applied, nodeA, true); err != nil {
		t.Fatalf("still cut: %v", err)
	}
	document.Members[1].Cut = false
	if _, err := Accept(document, applied, nodeA, true); err == nil || !strings.Contains(err.Error(), "cannot come back") {
		t.Fatalf("back uncut: %v", err)
	}
}

func TestTheStricterKnockSettingWins(t *testing.T) {
	document := fixture(t)
	if got := Effective(document, nil); got != (Knocks{Scan: 10, Stop: true}) {
		t.Fatalf("default %+v", got)
	}
	document.Knocks = &Knocks{Scan: 20, Stop: false}
	if got := Effective(document, nil); got != (Knocks{Scan: 20, Stop: false}) {
		t.Fatalf("document %+v", got)
	}
	if got := Effective(document, &Knocks{Scan: 5, Stop: true}); got != (Knocks{Scan: 5, Stop: true}) {
		t.Fatalf("tightened %+v", got)
	}
}

func TestSameEndpointUnmapsAndComparesThePort(t *testing.T) {
	for _, same := range [][2]string{{"203.0.113.1:51920", "203.0.113.1:51920"}, {"[::ffff:203.0.113.1]:51920", "203.0.113.1:51920"}, {"[2001:db8::1]:51920", "[2001:db8::1]:51920"}} {
		if !SameEndpoint(same[0], same[1]) {
			t.Errorf("%q and %q differ", same[0], same[1])
		}
	}
	for _, other := range [][2]string{{"203.0.113.1:51920", "203.0.113.1:51921"}, {"203.0.113.1:51920", "203.0.113.2:51920"}, {"(none)", "203.0.113.1:51920"}, {"", ""}} {
		if SameEndpoint(other[0], other[1]) {
			t.Errorf("%q and %q are the same", other[0], other[1])
		}
	}
}
