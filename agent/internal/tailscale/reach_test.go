package tailscale

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const pivoxStatus = `{"BackendState":"Running","MagicDNSSuffix":"tail4d2a.ts.net","Self":{"ID":"nSelf1CNTRL","DNSName":"pivox.tail4d2a.ts.net.","TailscaleIPs":["100.101.7.20","fd7a:115c:a1e0::20"],"Tags":["tag:kry"]},"Peer":{"k1":{"DNSName":"io.tail4d2a.ts.net.","TailscaleIPs":["100.101.7.11","fd7a:115c:a1e0::11"]},"k2":{"DNSName":"laptop.tail4d2a.ts.net.","TailscaleIPs":["100.101.7.33"]}}}`

func filter(body string, err error) Local {
	return func(_ context.Context, path string) ([]byte, error) {
		if path != "/localapi/v0/debug-packet-filter-rules" {
			return nil, errors.New("unexpected " + path)
		}
		return []byte(body), err
	}
}

func TestEveryDeviceOnEveryPortIsOneEntry(t *testing.T) {
	reach, names := Reach([]byte(`[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}]`), []string{"100.101.7.20"}, nil)
	if want := []reporter.TailscaleReach{{From: []string{"*"}, Ports: []string{"*"}}}; !reflect.DeepEqual(reach, want) || len(names) != 0 {
		t.Fatalf("got %+v %v", reach, names)
	}
}

func TestEachSourceSetIsOneEntryWithItsPortsOnThisServer(t *testing.T) {
	rules := `[
		{"SrcIPs":["100.101.7.11"],"DstPorts":[{"IP":"100.101.7.20","Ports":{"First":53,"Last":53}}],"IPProto":[17]},
		{"SrcIPs":["100.101.7.33","100.101.7.34"],"DstPorts":[{"IP":"100.101.7.20/32","Ports":{"First":22,"Last":22}},{"IP":"fd7a:115c:a1e0::20/128","Ports":{"First":53,"Last":53}},{"IP":"100.101.7.99","Ports":{"First":80,"Last":80}}],"IPProto":[6]},
		{"SrcIPs":["100.101.7.34","100.101.7.33"],"DstPorts":[{"IP":"100.101.7.20","Ports":{"First":53,"Last":53}},{"IP":"100.101.7.20","Ports":{"First":8000,"Last":8100}}],"IPProto":[17]},
		{"SrcIPs":["100.101.7.11"],"DstPorts":[{"IP":"100.101.7.20","Ports":{"First":0,"Last":65535}}],"IPProto":[1]}
	]`
	peers := map[string]string{"100.101.7.11": "io", "100.101.7.33": "laptop"}
	reach, names := Reach([]byte(rules), []string{"100.101.7.20", "fd7a:115c:a1e0::20"}, peers)
	want := []reporter.TailscaleReach{
		{From: []string{"100.101.7.11"}, Ports: []string{"53/udp"}},
		{From: []string{"100.101.7.33", "100.101.7.34"}, Ports: []string{"22/tcp", "53", "8000-8100/udp"}},
	}
	if !reflect.DeepEqual(reach, want) {
		t.Fatalf("got %+v", reach)
	}
	if !maps.Equal(names, map[string]string{"100.101.7.11": "io", "100.101.7.33": "laptop"}) {
		t.Fatalf("names %v", names)
	}
	shuffled := `[
		{"SrcIPs":["100.101.7.11"],"DstPorts":[{"IP":"100.101.7.20","Ports":{"First":0,"Last":65535}}],"IPProto":[1]},
		{"SrcIPs":["100.101.7.33","100.101.7.34"],"DstPorts":[{"IP":"100.101.7.20","Ports":{"First":8000,"Last":8100}},{"IP":"100.101.7.20","Ports":{"First":53,"Last":53}}],"IPProto":[17]},
		{"SrcIPs":["100.101.7.34","100.101.7.33"],"DstPorts":[{"IP":"fd7a:115c:a1e0::20","Ports":{"First":53,"Last":53}},{"IP":"100.101.7.20","Ports":{"First":22,"Last":22}}],"IPProto":[6]},
		{"SrcIPs":["100.101.7.11"],"DstPorts":[{"IP":"100.101.7.20","Ports":{"First":53,"Last":53}}],"IPProto":[17]}
	]`
	if again, _ := Reach([]byte(shuffled), []string{"fd7a:115c:a1e0::20", "100.101.7.20"}, peers); !reflect.DeepEqual(again, want) {
		t.Fatalf("the order changed the report: %+v", again)
	}
}

func TestTheReportCarriesTheServersTagTailnetAndWhoMayReachIt(t *testing.T) {
	report := Report(context.Background(), answer(pivoxStatus, nil), filter(`[{"SrcIPs":["100.101.7.11"],"DstPorts":[{"IP":"100.101.7.20","Ports":{"First":22,"Last":22}}],"IPProto":[6]}]`, nil))
	if report.State != "running" || *report.ID != "nSelf1CNTRL" || *report.Tailnet != "tail4d2a.ts.net" || !reflect.DeepEqual(report.Tags, []string{"tag:kry"}) || report.Peers != 2 {
		t.Fatalf("got %+v", report)
	}
	if report.Reach == nil || !reflect.DeepEqual(*report.Reach, []reporter.TailscaleReach{{From: []string{"100.101.7.11"}, Ports: []string{"22/tcp"}}}) || !maps.Equal(report.Names, map[string]string{"100.101.7.11": "io"}) {
		t.Fatalf("reach %+v names %v", report.Reach, report.Names)
	}
}

func TestAFilterThatCannotBeReadLeavesTheRestOfTheReport(t *testing.T) {
	for _, local := range []Local{nil, filter("", errors.New("403 Forbidden"))} {
		report := Report(context.Background(), answer(pivoxStatus, nil), local)
		if report.State != "running" || report.Reach != nil || *report.ID != "nSelf1CNTRL" || report.Peers != 2 || report.Names == nil {
			t.Fatalf("got %+v", report)
		}
	}
	stopped := Report(context.Background(), answer("", errors.New("exit status 1")), filter("[]", nil))
	if stopped.State != "stopped" || stopped.Reach != nil || stopped.ID != nil || stopped.Tags == nil || stopped.Names == nil {
		t.Fatalf("got %+v", stopped)
	}
}

func TestInUseNowIsWhatComesInOverTailscaleToAListeningPort(t *testing.T) {
	listening := Listening("tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\nudp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\ntcp LISTEN 0 4096 [::]:53 [::]:*\ntcp LISTEN 0 4096 127.0.0.1:631 0.0.0.0:*\n")
	if !reflect.DeepEqual(listening, []string{"22/tcp", "53/tcp", "53/udp"}) {
		t.Fatalf("listening %v", listening)
	}
	established := "0 0 100.101.7.20:22 100.101.7.33:51515\n0 0 100.101.7.20:43210 100.101.7.11:443\n0 0 10.88.0.4:22 10.88.0.2:40000\n0 0 [fd7a:115c:a1e0::20]:22 [fd7a:115c:a1e0::33]:51516\n0 0 100.101.7.20:22 100.101.7.33:51517\n"
	conntrack := "ipv4     2 udp      17 25 src=100.101.7.11 dst=100.101.7.20 sport=40000 dport=53 src=100.101.7.20 dst=100.101.7.11 sport=53 dport=40000 [ASSURED] mark=0 use=2\n" +
		"ipv4     2 tcp      6 431999 ESTABLISHED src=100.101.7.33 dst=100.101.7.20 sport=51515 dport=22 src=100.101.7.20 dst=100.101.7.33 sport=22 dport=51515 [ASSURED] mark=0 use=2\n" +
		"ipv4     2 udp      17 25 src=100.101.7.20 dst=100.101.7.11 sport=40001 dport=53 src=100.101.7.11 dst=100.101.7.20 sport=53 dport=40001 mark=0 use=2\n"
	used := InUse(established, conntrack, []string{"100.101.7.20", "fd7a:115c:a1e0::20"}, listening)
	want := []reporter.TailscaleUse{
		{From: "100.101.7.33", Port: "22/tcp"},
		{From: "fd7a:115c:a1e0::33", Port: "22/tcp"},
		{From: "100.101.7.11", Port: "53/udp"},
	}
	if !reflect.DeepEqual(used, want) {
		t.Fatalf("got %+v", used)
	}
}
