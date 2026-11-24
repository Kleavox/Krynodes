package mesh

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAProbeIsLimitedAndSaysWhetherItListened(t *testing.T) {
	m, _ := networkMesh(t)
	probeListen, probeOn = 50*time.Millisecond, netip.MustParseAddr("127.0.0.1")
	t.Cleanup(func() { probeListen, probeOn = 20*time.Second, netip.IPv6Unspecified() })
	peers := make([]string, 32)
	for index := range peers {
		peers[index] = "203.0.113." + string(rune('1'+index%9)) + ":51820"
	}
	if _, err := call(t, m, "probe", map[string]string{"port": "51900", "peers": strings.Join(peers, " ")}); err == nil || !strings.Contains(err.Error(), "1 to 31 peers") {
		t.Fatalf("32 peers %v", err)
	}
	for _, bad := range []map[string]string{
		{"port": "51900", "peers": "127.0.0.1:22"},
		{"port": "22", "peers": "127.0.0.1:51901"},
		{"port": "51900", "peers": "127.0.0.1:51901", "extra": "1"},
	} {
		if _, err := call(t, m, "probe", bad); err == nil {
			t.Fatalf("%v was taken", bad)
		}
	}
	message, err := call(t, m, "probe", map[string]string{"port": "51900", "peers": "127.0.0.1:51901"})
	var answer map[string]json.RawMessage
	if err != nil || json.Unmarshal([]byte(message), &answer) != nil || len(answer) != 2 || string(answer["listened"]) != "true" || string(answer["arrived"]) != "[]" {
		t.Fatalf("probe %s %v", message, err)
	}
}

func TestATestCountsBeforeAndAfterAndWalksLargeSizesDown(t *testing.T) {
	m, run := networkMesh(t)
	_, peer := joined(t, m)
	line := func(handshake, rx, tx string) string {
		return "cHJpdmF0ZQ==\tcHVibGlj\t51821\toff\n" + peer.Public + "\t(none)\t" + peerEndpoint + "\t10.88.0.1/32\t" + handshake + "\t" + rx + "\t" + tx + "\t25\n"
	}
	run.sequence = map[string][]string{"wg show kry0 dump": {line("1790000000", "100", "200"), line("1790000060", "400", "900")}}
	run.respond["systemctl is-active wg-quick@kry0.service"] = "active\n"
	run.respond["ping -n -c 5 -i 0.2 -W 1 -I kry0 10.88.0.1"] = "5 packets transmitted, 4 received, 20% packet loss, time 804ms\nrtt min/avg/max/mdev = 1.1/4.2/8.0/1.0 ms\n"
	run.respond["ping -n -c 2 -W 1 -M do -s 1352 -I kry0 10.88.0.1"] = "2 packets transmitted, 2 received, 0% packet loss\n"
	run.respond["ip -j route get 203.0.113.21"] = `[{"dst":"203.0.113.21","prefsrc":"203.0.113.30"}]`
	message, err := call(t, m, "test", map[string]string{"peer": peerNode, "address": "10.88.0.1", "mtu": "1420"})
	var found struct {
		Up, HasKey    bool
		Version       *int
		Clock         int64
		PublicAddress *string
		Firewall      struct {
			Lets bool
			Rule *bool
		}
		Handshakes struct {
			Sent, Received, Answered int
			Third                    *bool
		}
		Small struct {
			Sent, Lost int
			MS         *float64
		}
		Large struct {
			Passed *int
			Tried  []int
		}
	}
	if err != nil || json.Unmarshal([]byte(message), &found) != nil {
		t.Fatalf("%s (%v)", message, err)
	}
	if !found.Up || !found.HasKey || found.Version == nil || *found.Version != 1 || found.Clock != testNow.Unix() || found.PublicAddress == nil || *found.PublicAddress != "203.0.113.30" {
		t.Fatalf("found %+v", found)
	}
	if found.Firewall.Lets || found.Firewall.Rule == nil || *found.Firewall.Rule {
		t.Fatalf("firewall %+v", found.Firewall)
	}
	if found.Handshakes.Sent != 700 || found.Handshakes.Received != 300 || found.Handshakes.Answered != 1 || found.Handshakes.Third != nil {
		t.Fatalf("handshakes %+v", found.Handshakes)
	}
	if found.Small.Sent != 5 || found.Small.Lost != 1 || found.Small.MS == nil || *found.Small.MS != 4.2 {
		t.Fatalf("small %+v", found.Small)
	}
	if found.Large.Passed == nil || *found.Large.Passed != 1380 || !slices.Equal(found.Large.Tried, []int{1420, 1400, 1380}) {
		t.Fatalf("large %+v", found.Large)
	}
	if _, err := call(t, m, "test", map[string]string{"peer": peerNode, "address": "10.0.0.1", "mtu": "1420"}); err == nil {
		t.Fatal("a test outside the network was taken")
	}
}

func TestATestSeesTheUfwRuleKrynodesMade(t *testing.T) {
	m, run := networkMesh(t)
	joined(t, m)
	rootFile(t, m, "/etc/default/ufw", "DEFAULT_INPUT_POLICY=\"DROP\"\n")
	rootFile(t, m, "/etc/ufw/user.rules", "### tuple ### allow udp 51821 0.0.0.0/0 any 0.0.0.0/0 in comment=6b72796e6f6465732d6e6574776f726b\n")
	run.respond["wg show kry0 dump"] = ""
	message, err := call(t, m, "test", map[string]string{"peer": peerNode, "address": "10.88.0.1", "mtu": "1280"})
	var found struct {
		Firewall struct {
			Lets bool
			Rule *bool
		}
	}
	if err != nil || json.Unmarshal([]byte(message), &found) != nil || !found.Firewall.Lets || found.Firewall.Rule == nil || !*found.Firewall.Rule {
		t.Fatalf("%s %v", message, err)
	}
}

func TestAnInspectAnswerFitsOneMessage(t *testing.T) {
	m, run := networkMesh(t)
	message, err := call(t, m, "inspect", nil)
	var fields map[string]json.RawMessage
	if err != nil || json.Unmarshal([]byte(message), &fields) != nil {
		t.Fatalf("inspect %s %v", message, err)
	}
	for _, name := range []string{"kernel", "tools", "iptables", "used", "others", "port", "mtu", "public"} {
		if _, ok := fields[name]; !ok || len(fields) != 8 {
			t.Fatalf("inspect %s", message)
		}
	}
	var addresses []string
	for index := range 300 {
		addresses = append(addresses, `{"family":"inet","local":"172.20.`+strconv.Itoa(index/250)+`.`+strconv.Itoa(index%250+1)+`","prefixlen":32}`)
	}
	run.respond["ip -d -j addr show"] = `[{"ifname":"eth0","mtu":1500,"addr_info":[` + strings.Join(addresses, ",") + `]}]`
	message, err = call(t, m, "inspect", nil)
	var found struct {
		Used []string `json:"used"`
	}
	if err != nil || len(message) > maxMessage || json.Unmarshal([]byte(message), &found) != nil || len(found.Used) == 0 || len(found.Used) >= 200 {
		t.Fatalf("inspect %d bytes %v", len(message), err)
	}
	if again, _ := call(t, m, "inspect", nil); again != message || found.Used[0] != "172.20.0.1/32" {
		t.Fatal("the trim is not the same every time")
	}
	if _, err := call(t, m, "inspect", map[string]string{"x": "1"}); err == nil {
		t.Fatal("inspect took an argument")
	}
}
