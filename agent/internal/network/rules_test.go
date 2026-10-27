package network

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

var ruleMembers = []Member{
	{Node: nodeA, Name: "io", Address: "10.88.0.1"},
	{Node: nodeB, Name: "vps-2", Address: "10.88.0.2"},
	{Node: nodeC, Name: "pivox", Address: "10.88.0.3"},
}

func TestServingToAllServersAddsNoServeRule(t *testing.T) {
	serve, _ := Rules("10.88.0.2", ruleMembers, []StackRules{{Project: "db", Serves: []Serve{{Port: "5432/tcp", All: true}}}})
	if len(serve) != 0 {
		t.Fatalf("serve %q", serve)
	}
}

func TestChosenServersPassThenTheRestIsDropped(t *testing.T) {
	serve, _ := Rules("10.88.0.2", ruleMembers, []StackRules{{Project: "db", Serves: []Serve{{Port: "5432/tcp", To: []string{nodeA, nodeC}}}}})
	match := "-p tcp -m conntrack --ctorigdst 10.88.0.2/32 --ctorigdstport 5432"
	want := []string{
		"-A KRY-SERVE -s 10.88.0.1/32 " + match + " -j RETURN",
		"-A KRY-SERVE -s 10.88.0.3/32 " + match + " -j RETURN",
		"-A KRY-SERVE " + match + " -m limit --limit 600/min -j LOG --log-prefix \"kry-knock \" --log-level 6",
		"-A KRY-SERVE " + match + " -m comment --comment kry-serve:db -j DROP",
	}
	if !slices.Equal(serve, want) {
		t.Fatalf("serve\n%s\nwant\n%s", strings.Join(serve, "\n"), strings.Join(want, "\n"))
	}
}

func TestAnUnknownOrOwnChosenServerIsSkipped(t *testing.T) {
	serve, _ := Rules("10.88.0.2", ruleMembers, []StackRules{{Project: "db", Serves: []Serve{{Port: "53/udp", To: []string{"44444444-4444-4444-8444-444444444444", nodeB}}}}})
	match := "-A KRY-SERVE -p udp -m conntrack --ctorigdst 10.88.0.2/32 --ctorigdstport 53"
	if !slices.Equal(serve, []string{match + " -m limit --limit 600/min -j LOG --log-prefix \"kry-knock \" --log-level 6", match + " -m comment --comment kry-serve:db -j DROP"}) {
		t.Fatalf("serve %q", serve)
	}
}

func TestRepliesPassFirstAndAPlaceIsReachedFromEveryBridge(t *testing.T) {
	_, reach := Rules("10.88.0.2", ruleMembers, []StackRules{
		{Project: "umami", Bridges: []string{"krc111111111111", "krc222222222222"}, Reaches: []string{"10.88.0.1:5432/tcp"}},
		{Project: "lone", Bridges: []string{"krc333333333333"}},
	})
	want := []string{
		"-A KRY-REACH -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
		"-A KRY-REACH -d 10.88.0.1/32 -i krc111111111111 -p tcp -m tcp --dport 5432 -j RETURN",
		"-A KRY-REACH -d 10.88.0.1/32 -i krc222222222222 -p tcp -m tcp --dport 5432 -j RETURN",
		"-A KRY-REACH -i krc111111111111 -m limit --limit 600/min -j LOG --log-prefix \"kry-reach \" --log-level 6",
		"-A KRY-REACH -i krc111111111111 -m comment --comment kry-reach:umami -j DROP",
		"-A KRY-REACH -i krc222222222222 -m limit --limit 600/min -j LOG --log-prefix \"kry-reach \" --log-level 6",
		"-A KRY-REACH -i krc222222222222 -m comment --comment kry-reach:umami -j DROP",
		"-A KRY-REACH -i krc333333333333 -m limit --limit 600/min -j LOG --log-prefix \"kry-reach \" --log-level 6",
		"-A KRY-REACH -i krc333333333333 -m comment --comment kry-reach:lone -j DROP",
		"-A KRY-REACH -j DROP",
	}
	if !slices.Equal(reach, want) {
		t.Fatalf("reach\n%s\nwant\n%s", strings.Join(reach, "\n"), strings.Join(want, "\n"))
	}
}

func TestTheJumpsEnterFromKry0AndFromContainedBridgesToTheRange(t *testing.T) {
	jumps := Jumps("10.88.0.0/24")
	if len(jumps) != 3 || strings.Join(jumps[0], " ") != "-i kry0 -j KRY-SERVE" || strings.Join(jumps[1], " ") != "-d 10.88.0.0/24 -i krc+ -j KRY-REACH" || strings.Join(jumps[2], " ") != "-i kry0 -j KRY-DROP" {
		t.Fatalf("jumps %q", jumps)
	}
	input := InputJumps()
	if len(input) != 2 || strings.Join(input[0], " ") != "-i kry0 -m conntrack --ctstate NEW -j KRY-KNOCK" || strings.Join(input[1], " ") != "-i kry0 -j KRY-DROP" {
		t.Fatalf("input %q", input)
	}
}

func TestTheWatchChainsDropAndLogOnlyClosedPorts(t *testing.T) {
	tcp := []int{22, 80}
	for port := 1000; port < 1014; port++ {
		tcp = append(tcp, port)
	}
	drop, knock := Watch([]string{"10.88.0.9"}, tcp, []int{53})
	if !slices.Equal(drop, []string{"-A KRY-DROP -s 10.88.0.9/32 -j DROP"}) {
		t.Fatalf("drop %q", drop)
	}
	want := []string{
		"-A KRY-KNOCK -p icmp -j RETURN",
		"-A KRY-KNOCK -p tcp -m multiport --dports 22,80,1000,1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,1011,1012 -j RETURN",
		"-A KRY-KNOCK -p tcp -m multiport --dports 1013 -j RETURN",
		"-A KRY-KNOCK -p udp -m multiport --dports 53 -j RETURN",
		"-A KRY-KNOCK -m limit --limit 600/min -j LOG --log-prefix \"kry-knock \" --log-level 6",
	}
	if !slices.Equal(knock, want) {
		t.Fatalf("knock\n%s", strings.Join(knock, "\n"))
	}
}

func TestTheRestoreFileDeclaresOnlyItsFourChains(t *testing.T) {
	text := Restore([]string{"-A KRY-SERVE -j RETURN"}, []string{"-A KRY-REACH -j DROP"}, []string{"-A KRY-DROP -s 10.88.0.9/32 -j DROP"}, []string{"-A KRY-KNOCK -p icmp -j RETURN"})
	want := "*filter\n:KRY-SERVE - [0:0]\n:KRY-REACH - [0:0]\n:KRY-DROP - [0:0]\n:KRY-KNOCK - [0:0]\n-A KRY-SERVE -j RETURN\n-A KRY-REACH -j DROP\n-A KRY-DROP -s 10.88.0.9/32 -j DROP\n-A KRY-KNOCK -p icmp -j RETURN\nCOMMIT\n"
	if text != want {
		t.Fatalf("restore %q", text)
	}
}

func TestPlacesAndServesAreReadFromTheirArgs(t *testing.T) {
	serves, err := ParseServes("5432/tcp=all, 9090/tcp=" + nodeA + " " + nodeC)
	if err != nil || len(serves) != 2 || !serves[0].All || !slices.Equal(serves[1].To, []string{nodeA, nodeC}) {
		t.Fatalf("serves %#v err %v", serves, err)
	}
	for _, bad := range []string{"5432=all", "5432/tcp=some", "5432/tcp=", "70000/tcp=all", "5432/tcp=all,5432/tcp=all"} {
		if _, err := ParseServes(bad); err == nil {
			t.Fatalf("%q was taken", bad)
		}
	}
	places, err := ParsePlaces(" 10.88.0.1:5432/tcp,10.88.0.3:53/udp ", "10.88.0.0/24", "10.88.0.2")
	if err != nil || !slices.Equal(places, []string{"10.88.0.1:5432/tcp", "10.88.0.3:53/udp"}) {
		t.Fatalf("places %v err %v", places, err)
	}
	for bad, says := range map[string]string{
		"vps-2:5432/tcp":     "is not a place such as",
		"10.88.0.2:5432/tcp": "is this server",
		"10.99.0.2:5432/tcp": "is outside the private network",
		"10.88.0.1:0/tcp":    "is not a place such as",
	} {
		if _, err := ParsePlaces(bad, "10.88.0.0/24", "10.88.0.2"); err == nil || !strings.Contains(err.Error(), says) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	var many []string
	for port := 1; port <= 33; port++ {
		many = append(many, "10.88.0.1:"+strconv.Itoa(port)+"/tcp")
	}
	if _, err := ParsePlaces(strings.Join(many, ","), "10.88.0.0/24", "10.88.0.2"); err == nil {
		t.Fatal("33 places were taken")
	}
}
