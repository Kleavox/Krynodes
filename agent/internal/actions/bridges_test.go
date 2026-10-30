package actions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const (
	netList   = "docker network ls -q --no-trunc"
	addrList  = "ip -j addr show"
	routeList = "ip -j route show"
	addrJSON  = `[{"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]},{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.168.1.20","prefixlen":24},{"family":"inet6","local":"fe80::1","prefixlen":64}]},{"ifname":"docker0","addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16}]},{"ifname":"br-0a1b2c3d4e5f","addr_info":[{"family":"inet","local":"172.18.0.1","prefixlen":16}]}]`
	routeJSON = `[{"dst":"default","gateway":"192.168.1.1","dev":"eth0"},{"dst":"192.168.1.0/24","dev":"eth0"},{"dst":"10.200.0.0/16","gateway":"192.168.1.5","dev":"eth0"},{"dst":"172.17.0.0/16","dev":"docker0"},{"dst":"172.24.0.0/24","dev":"krc0a1b2c3d4e5f"}]`
)

func dockerNet(name, id, subnet string, labels map[string]string, containers map[string]any) map[string]any {
	config := []any{}
	if subnet != "" {
		config = append(config, map[string]any{"Subnet": subnet})
	}
	if labels == nil {
		labels = map[string]string{}
	}
	if containers == nil {
		containers = map[string]any{}
	}
	return map[string]any{"Name": name, "Id": id, "Driver": "bridge", "Labels": labels, "IPAM": map[string]any{"Config": config}, "Containers": containers}
}

func endpoint(name, address string) map[string]any {
	return map[string]any{"Name": name, "IPv4Address": address}
}

var serverNets = []map[string]any{
	dockerNet("bridge", "b0b0b0b0b0b0b0b0", "172.17.0.0/16", nil, nil),
	dockerNet("panel_default", "0a1b2c3d4e5f6a7b", "172.18.0.0/16", map[string]string{"com.docker.compose.network": "default", "com.docker.compose.project": "panel"}, nil),
	dockerNet("proxy", "c0c0c0c0c0c0c0c0", "172.19.0.0/16", nil, nil),
	{"Name": "host", "Id": "d0d0d0d0d0d0d0d0", "Driver": "host", "Labels": map[string]string{}, "IPAM": map[string]any{"Config": []any{}}, "Containers": map[string]any{}},
}

func onServer(t *testing.T, run *fakeRun, nets ...map[string]any) {
	t.Helper()
	if run.respond == nil {
		run.respond = map[string]string{}
	}
	ids := make([]string, 0, len(nets))
	for _, net := range nets {
		ids = append(ids, net["Id"].(string))
		run.respond["docker network inspect -f {{.Id}} "+net["Name"].(string)] = net["Id"].(string) + "\n"
	}
	encoded, err := json.Marshal(nets)
	if err != nil {
		t.Fatal(err)
	}
	run.respond[netList] = strings.Join(ids, "\n") + "\n"
	run.respond["docker network inspect "+strings.Join(ids, " ")] = string(encoded)
	run.respond[addrList] = addrJSON
	run.respond[routeList] = routeJSON
}

func bridgeExecutor(t *testing.T, filter string) (Executor, *fakeRun) {
	t.Helper()
	executor, run := stackExecutor(t)
	executor.Root = t.TempDir()
	path := filepath.Join(executor.Root, "proc", "sys", "net", "bridge")
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "bridge-nf-call-iptables"), []byte(filter+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	return executor, run
}

func bridgeRequest(t *testing.T, name, action string, args map[string]string) Request {
	t.Helper()
	return signedRequest(t, Command{ID: idA, Kind: "bridge", Name: name, Action: action, Args: args})
}

func expectedBridge(name string) string {
	sum := sha256.Sum256([]byte("net:" + name))
	return "krc" + hex.EncodeToString(sum[:])[:12]
}

func writeStack(t *testing.T, executor Executor, project string, meta stackMeta, compose string) string {
	t.Helper()
	dir := filepath.Join(executor.StateDir, "compose", project)
	if err := writeJSON(dir, "krynodes.json", meta, 0o640); err != nil {
		t.Fatal(err)
	}
	if compose != "" {
		if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestBridgeCreateMakesAContainedNetworkWithItsOwnBridge(t *testing.T) {
	executor, run := bridgeExecutor(t, "1")
	onServer(t, run, serverNets...)
	create := "docker network create --driver bridge --subnet 172.24.0.0/24 --internal -o com.docker.network.bridge.enable_icc=false -o com.docker.network.bridge.name=" + expectedBridge("apps-inner") + " --label com.krynodes.network=contained apps-inner"
	run.respond[create] = "9f2c00000000000000000000\n"
	result := runRequest(t, executor, bridgeRequest(t, "apps-inner", "create", map[string]string{"kind": "contained", "subnet": "172.24.0.0/24"}))
	if !result.OK || result.Output != "created apps-inner · 172.24.0.0/24" {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	if !slices.Contains(run.calls, create) {
		t.Fatalf("calls %q", run.calls)
	}
	want := bridgeRecord{ID: "9f2c00000000000000000000", Kind: "contained", Subnet: "172.24.0.0/24", Bridge: expectedBridge("apps-inner")}
	if got := executor.readBridges()["apps-inner"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("record %#v", got)
	}
}

func TestBridgeCreateMakesAFullAccessNetworkAsAPlainBridge(t *testing.T) {
	executor, run := bridgeExecutor(t, "0")
	onServer(t, run, serverNets...)
	create := "docker network create --driver bridge --subnet 172.23.0.0/16 --label com.krynodes.network=full default-env_public"
	run.respond[create] = "fe11000000000000000000\n"
	result := runRequest(t, executor, bridgeRequest(t, "default-env_public", "create", map[string]string{"kind": "full", "subnet": "172.23.0.0/16"}))
	if !result.OK || result.Output != "created default-env_public · 172.23.0.0/16" {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	if got := executor.readBridges()["default-env_public"]; got.Bridge != "br-fe1100000000" || got.Kind != "full" {
		t.Fatalf("record %#v", got)
	}
}

func TestBridgeCreateRefusesWhatTheServerCannotTake(t *testing.T) {
	cases := []struct {
		label, name, kind, subnet, refusal string
	}{
		{"taken name", "proxy", "contained", "172.24.0.0/24", "This server already has a network named proxy."},
		{"claimed name", "default-env_public", "full", "172.23.0.0/16", "The default-env stack makes its own public network with this name. Write external: true there, or pick another name."},
		{"docker network", "apps-inner", "contained", "172.18.5.0/24", "Overlaps panel_default (172.18.0.0/16) on this server."},
		{"private network", "apps-inner", "contained", "10.88.0.0/16", "Overlaps your private network (10.88.0.0/24)."},
		{"tailscale", "apps-inner", "contained", "100.100.0.0/16", "Overlaps Tailscale's addresses (100.64.0.0/10)."},
		{"own network", "apps-inner", "contained", "192.168.1.0/24", "Overlaps this server's own network (192.168.1.0/24 on eth0)."},
		{"route", "apps-inner", "contained", "10.200.4.0/24", "Overlaps this server's own network (10.200.0.0/16 on eth0)."},
		{"public range", "apps-inner", "contained", "8.8.0.0/16", "Use a private range: 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16."},
		{"prefix", "apps-inner", "contained", "172.24.0.0/30", "Use a prefix from /16 to /28."},
		{"wide prefix", "apps-inner", "contained", "10.0.0.0/15", "Use a prefix from /16 to /28."},
		{"not a range", "apps-inner", "contained", "172.24.0.0", "Write it as 172.24.0.0/24."},
		{"not aligned", "apps-inner", "contained", "172.24.0.9/24", "Write it as 172.24.0.0/24."},
		{"kind", "apps-inner", "open", "172.24.0.0/24", "A network is Contained or Full Access."},
		{"name", "-apps", "contained", "172.24.0.0/24", "invalid target"},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			executor, run := bridgeExecutor(t, "1")
			onServer(t, run, serverNets...)
			writeStack(t, executor, "default-env", stackMeta{Access: "full", Networks: map[string]string{"default": "default-env_default", "public": "default-env_public"}}, "")
			if err := writeJSON(executor.StateDir, "network.json", map[string]any{"document": map[string]any{"range": "10.88.0.0/24"}}, 0o640); err != nil {
				t.Fatal(err)
			}
			result := runRequest(t, executor, bridgeRequest(t, c.name, "create", map[string]string{"kind": c.kind, "subnet": c.subnet}))
			if result.OK || result.Output != "refused: "+c.refusal {
				t.Fatalf("result %#v", result)
			}
			if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "docker network create") }) {
				t.Fatalf("calls %q", run.calls)
			}
		})
	}
}

func TestAnUnsignedBridgeCreateIsRefused(t *testing.T) {
	executor, run := bridgeExecutor(t, "1")
	onServer(t, run, serverNets...)
	unsigned := bridgeRequest(t, "apps-inner", "create", map[string]string{"kind": "contained", "subnet": "172.24.0.0/24"})
	unsigned.Signed = nil
	result := runRequest(t, executor, unsigned)
	if result.OK || result.Output != "refused: the request is not signed" {
		t.Fatalf("result %#v", result)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "docker network create") }) {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestBridgeCreateUndoesAContainedNetworkTheKernelCannotFilter(t *testing.T) {
	executor, run := bridgeExecutor(t, "0")
	onServer(t, run, serverNets...)
	result := runRequest(t, executor, bridgeRequest(t, "apps-inner", "create", map[string]string{"kind": "contained", "subnet": "172.24.0.0/24"}))
	if result.OK || result.Output != "refused: This server's kernel does not filter traffic inside Docker bridges (br_netfilter), so a Contained network cannot be kept closed here." {
		t.Fatalf("result %#v", result)
	}
	if !slices.Contains(run.calls, "docker network rm apps-inner") {
		t.Fatalf("calls %q", run.calls)
	}
	if _, found := executor.readBridges()["apps-inner"]; found {
		t.Fatal("a removed network must not be recorded")
	}
}

func TestANetworkWithTheRightNameButAnotherIDIsOutsideKrynodes(t *testing.T) {
	executor, run := bridgeExecutor(t, "1")
	if err := executor.saveBridges(map[string]bridgeRecord{"apps-inner": {ID: "9f2c00000000000000000000", Kind: "contained", Subnet: "172.24.0.0/24", Bridge: expectedBridge("apps-inner")}}); err != nil {
		t.Fatal(err)
	}
	onServer(t, run, dockerNet("apps-inner", "badd00000000000000000000", "172.24.0.0/24", map[string]string{"com.krynodes.network": "contained"}, nil))
	if _, owned := executor.ownedBridge(context.Background(), "apps-inner"); owned {
		t.Fatal("another network with the same name is not Krynodes'")
	}
	report := executor.bridgesReport(context.Background())
	if report == nil || len(report.Networks) != 1 || report.Networks[0].Kind != "outside" {
		t.Fatalf("report %#v", report)
	}
	result := runRequest(t, executor, bridgeRequest(t, "apps-inner", "remove", nil))
	if result.OK || slices.Contains(run.calls, "docker network rm apps-inner") {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
}

func TestBridgeRemoveRefusesWhileStacksUseIt(t *testing.T) {
	executor, run := bridgeExecutor(t, "1")
	if err := executor.saveBridges(map[string]bridgeRecord{"apps-inner": {ID: "9f2c00000000000000000000", Kind: "contained", Subnet: "172.24.0.0/24", Bridge: expectedBridge("apps-inner"), Pins: map[string]string{"panel/web": "172.24.0.2"}}}); err != nil {
		t.Fatal(err)
	}
	writeStack(t, executor, "tracker", stackMeta{Access: "contained"}, "services:\n  web:\n    networks: [inner]\nnetworks:\n  inner:\n    name: apps-inner\n    external: true\n")
	writeStack(t, executor, "other", stackMeta{Access: "contained"}, "services:\n  web:\n    networks: [apps-inner-2]\n")
	onServer(t, run, dockerNet("apps-inner", "9f2c00000000000000000000", "172.24.0.0/24", map[string]string{"com.krynodes.network": "contained"}, map[string]any{"c1": endpoint("panel-web-1", "172.24.0.2/24")}))
	run.respond["docker ps -a --no-trunc --format "+labelsFormat] = "c1\tpanel\tweb\n"
	result := runRequest(t, executor, bridgeRequest(t, "apps-inner", "remove", nil))
	if result.OK || result.Output != "refused: panel and tracker still use it. Take it out of their compose files first." {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	if slices.Contains(run.calls, "docker network rm apps-inner") {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestBridgeRemoveDeletesAnUnusedNetworkAndItsPins(t *testing.T) {
	executor, run := bridgeExecutor(t, "1")
	if err := executor.saveBridges(map[string]bridgeRecord{
		"apps-inner": {ID: "9f2c00000000000000000000", Kind: "contained", Subnet: "172.24.0.0/24", Bridge: expectedBridge("apps-inner"), Pins: map[string]string{"panel/web": "172.24.0.2"}, Freed: []string{"172.24.0.3"}},
		"cache":      {ID: "cace00000000000000000000", Kind: "full", Subnet: "172.25.0.0/24", Bridge: "br-cace00000000"},
	}); err != nil {
		t.Fatal(err)
	}
	onServer(t, run, dockerNet("apps-inner", "9f2c00000000000000000000", "172.24.0.0/24", map[string]string{"com.krynodes.network": "contained"}, nil))
	result := runRequest(t, executor, bridgeRequest(t, "apps-inner", "remove", nil))
	if !result.OK || result.Output != "deleted apps-inner" || !slices.Contains(run.calls, "docker network rm apps-inner") {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	records := executor.readBridges()
	if _, found := records["apps-inner"]; found || records["cache"].ID == "" {
		t.Fatalf("records %#v", records)
	}
}

func TestPinsTakeTheLowestUnusedAddressThenTheOldestFreed(t *testing.T) {
	executor, _ := newExecutor(t)
	records := map[string]bridgeRecord{"apps-inner": {ID: "9f2c", Kind: "contained", Subnet: "172.24.0.0/28"}}
	take := func(key string) string {
		t.Helper()
		record := records["apps-inner"]
		address, err := pin("apps-inner", &record, key)
		if err != nil {
			t.Fatal(err)
		}
		records["apps-inner"] = record
		if err := executor.saveBridges(records); err != nil {
			t.Fatal(err)
		}
		return address
	}
	if a, b, again := take("panel/web"), take("adns/dns"), take("panel/web"); a != "172.24.0.2" || b != "172.24.0.3" || again != "172.24.0.2" {
		t.Fatalf("pins %s %s %s", a, b, again)
	}
	if err := executor.unpin("panel"); err != nil {
		t.Fatal(err)
	}
	records = executor.readBridges()
	if got := records["apps-inner"]; !slices.Equal(got.Freed, []string{"172.24.0.2"}) || got.Pins["panel/web"] != "" {
		t.Fatalf("record %#v", got)
	}
	if next := take("db/postgres"); next != "172.24.0.4" {
		t.Fatalf("a new service takes an address never used, got %s", next)
	}
	for index := 5; index <= 14; index++ {
		if next := take(fmt.Sprintf("app%d/web", index)); next != fmt.Sprintf("172.24.0.%d", index) {
			t.Fatalf("pin %d got %s", index, next)
		}
	}
	if next := take("late/web"); next != "172.24.0.2" {
		t.Fatalf("with the range full the oldest freed address is taken, got %s", next)
	}
	record := records["apps-inner"]
	if _, err := pin("apps-inner", &record, "last/web"); err == nil || err.Error() != "apps-inner has no free address left." {
		t.Fatalf("err %v", err)
	}
}

func TestBridgesReportListsNetworksMembersAndWhatIsTaken(t *testing.T) {
	executor, run := bridgeExecutor(t, "1")
	if err := executor.saveBridges(map[string]bridgeRecord{"apps-inner": {ID: "9f2c00000000000000000000", Kind: "contained", Subnet: "172.24.0.0/24", Bridge: "krc0a1b2c3d4e5f"}}); err != nil {
		t.Fatal(err)
	}
	writeStack(t, executor, "panel", stackMeta{Access: "contained", Offers: []string{"apps-inner/web=3001/tcp", "apps-inner/web=3002/udp", "other/web=80/tcp"}, Networks: map[string]string{"default": "panel_default"}}, "")
	writeStack(t, executor, "db", stackMeta{Access: "full", Offers: []string{"apps-inner/postgres=5432/tcp"}, Networks: map[string]string{"default": "db_default", "data": "db-data"}}, "")
	nets := append(slices.Clone(serverNets), dockerNet("apps-inner", "9f2c00000000000000000000", "172.24.0.0/24", map[string]string{"com.krynodes.network": "contained"}, map[string]any{
		"c2": endpoint("db-postgres-1", "172.24.0.3/24"),
		"c1": endpoint("panel-web-1", "172.24.0.2/24"),
		"c3": endpoint("loose", ""),
	}))
	onServer(t, run, nets...)
	run.respond["docker ps -a --no-trunc --format "+labelsFormat] = "c1\tpanel\tweb\nc2\tdb\tpostgres\nc3\t\t\n"
	report := executor.bridgesReport(context.Background())
	address := func(text string) *string { return &text }
	want := &reporter.Bridges{
		Networks: []reporter.BridgeNetwork{
			{Name: "apps-inner", Kind: "contained", Subnet: address("172.24.0.0/24"), Members: []reporter.BridgeMember{
				{Project: "db", Service: "postgres", Address: address("172.24.0.3"), Offers: []string{"5432/tcp"}, Guest: true},
				{Project: "loose", Service: "loose", Offers: []string{}},
				{Project: "panel", Service: "web", Address: address("172.24.0.2"), Offers: []string{"3001/tcp", "3002/udp"}},
			}},
			{Name: "proxy", Kind: "outside", Subnet: address("172.19.0.0/16"), Members: []reporter.BridgeMember{}},
		},
		Taken: []reporter.Taken{
			{Range: "172.24.0.0/24", By: "apps-inner"},
			{Range: "172.17.0.0/16", By: "bridge"},
			{Range: "172.18.0.0/16", By: "panel_default"},
			{Range: "172.19.0.0/16", By: "proxy"},
			{Range: "192.168.1.0/24", By: "eth0", Own: true},
			{Range: "10.200.0.0/16", By: "eth0", Own: true},
		},
		Claimed: []string{"db-data", "db_default", "panel_default"},
	}
	if !reflect.DeepEqual(report, want) {
		got, _ := json.Marshal(report)
		t.Fatalf("report %s", got)
	}
}

func TestBridgesReportIsNullWithoutDocker(t *testing.T) {
	executor, run := bridgeExecutor(t, "1")
	run.failing = map[string]string{netList: "Cannot connect to the Docker daemon"}
	if report := executor.bridgesReport(context.Background()); report != nil {
		t.Fatalf("report %#v", report)
	}
}

func TestTheInventoryHashFollowsAMembersOffers(t *testing.T) {
	executor, run := bridgeExecutor(t, "1")
	executor.Audit = true
	if err := executor.saveBridges(map[string]bridgeRecord{"apps-inner": {ID: "9f2c00000000000000000000", Kind: "contained", Subnet: "172.24.0.0/24", Bridge: "krc0a1b2c3d4e5f"}}); err != nil {
		t.Fatal(err)
	}
	onServer(t, run, dockerNet("apps-inner", "9f2c00000000000000000000", "172.24.0.0/24", nil, map[string]any{"c1": endpoint("panel-web-1", "172.24.0.2/24")}))
	run.respond["docker ps -a --no-trunc --format "+labelsFormat] = "c1\tpanel\tweb\n"
	hash := func(offers ...string) string {
		t.Helper()
		writeStack(t, executor, "panel", stackMeta{Access: "contained", Offers: offers}, "")
		if err := executor.Execute(context.Background()); err != nil {
			t.Fatal(err)
		}
		var inventory Inventory
		if err := readJSON(filepath.Join(executor.StateDir, "inventory.json"), &inventory); err != nil {
			t.Fatal(err)
		}
		if inventory.Bridges == nil {
			t.Fatal("the inventory must carry the networks")
		}
		return inventory.Hash
	}
	first, same, changed := hash("apps-inner/web=3001/tcp"), hash("apps-inner/web=3001/tcp"), hash("apps-inner/web=3002/tcp")
	if first != same || first == changed {
		t.Fatalf("hashes %s %s %s", first, same, changed)
	}
}

func TestAStackRecordsTheNetworksItMakesItself(t *testing.T) {
	executor, run := stackExecutor(t)
	networks := map[string]any{
		"default": map[string]any{"name": "panel_default"},
		"public":  map[string]any{"name": "panel_public"},
		"shared":  map[string]any{"name": "apps-inner", "external": true},
	}
	dir := panelReady(t, executor, run, panelService(panelDir(executor)), map[string]any{"networks": networks})
	request := composeRequest(t, idA, "panel", "create", func(c *Command) { c.Compose, c.Access = panelText, "full" })
	if result := runRequest(t, executor, request); !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	if meta := executor.metaOf(dir); !reflect.DeepEqual(meta.Networks, map[string]string{"default": "panel_default", "public": "panel_public"}) {
		t.Fatalf("meta %#v", meta)
	}
}

func TestTheRelaySendsTheNetworksAndTheirAbsence(t *testing.T) {
	for _, bridges := range []*reporter.Bridges{nil, {Networks: []reporter.BridgeNetwork{}, Taken: []reporter.Taken{}, Claimed: []string{"panel_default"}}} {
		relay, poster := newRelay(t)
		inventory, err := NewInventory(Parts{Docker: "ready", Bridges: bridges}, executorNow)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeJSON(relay.StateDir, "inventory.json", inventory, 0o640); err != nil {
			t.Fatal(err)
		}
		poster.hash = inventory.Hash
		if err := relay.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
		sent := poster.reports[0].Inventory
		if sent == nil || sent.Bridges == nil || !reflect.DeepEqual(sent.Bridges.Report, bridges) {
			t.Fatalf("sent %#v", sent)
		}
		encoded, err := json.Marshal(sent)
		if err != nil {
			t.Fatal(err)
		}
		if bridges == nil && !strings.Contains(string(encoded), `"bridges":null`) {
			t.Fatalf("encoded %s", encoded)
		}
	}
}
