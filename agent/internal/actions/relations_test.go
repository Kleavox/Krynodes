package actions

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/cloudflare"
)

const listmonkAliases = `docker inspect --format {{with index .NetworkSettings.Networks "listmonk_default"}}{{join .Aliases " "}}{{end}} listmonk-app-1`

func TestAStackReportsTheNamesOfItsServices(t *testing.T) {
	_, stacks := parseContainers("mon-panel-1\trunning\tmon\t/opt/mon\t/opt/mon/compose.yaml\t2026-09-25 11:37:02 +0700 WIB\t\tpanel\n" +
		"mon-db-1\trunning\tmon\t/opt/mon\t/opt/mon/compose.yaml\t2026-09-25 11:37:02 +0700 WIB\t\tdb\n" +
		"mon-db-2\trunning\tmon\t/opt/mon\t/opt/mon/compose.yaml\t2026-09-25 11:37:02 +0700 WIB\t\tdb\n")
	if len(stacks) != 1 || !reflect.DeepEqual(stacks[0].Services, []string{"db", "panel"}) {
		t.Fatalf("stacks %#v", stacks)
	}
	executor, _ := stackExecutor(t)
	entries := executor.stackEntries(Snapshot{Stacks: stacks})
	if len(entries) != 1 || !reflect.DeepEqual(entries[0].Services, []string{"db", "panel"}) {
		t.Fatalf("entries %#v", entries)
	}
}

func TestEveryServiceAnswersToItsRelationName(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := panelReady(t, executor, run, panelService(panelDir(executor)), nil)
	if result := createPanel(t, executor, "contained", nil); !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	web := krynodesConfig(t, dir)["services"].(map[string]any)["web"].(map[string]any)
	if aliases := asMap(asMap(web["networks"])["default"])["aliases"]; !reflect.DeepEqual(aliases, []any{"web.panel"}) {
		t.Fatalf("web %#v", web)
	}
}

func TestAFullAccessStackGetsItsRelationNamesInItsOwnFile(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := panelDir(executor)
	panelReady(t, executor, run, panelService(dir), map[string]any{"services": map[string]any{
		"web": panelService(dir),
		"dns": map[string]any{"image": "example/resolver", "network_mode": "host"},
	}})
	if result := createPanel(t, executor, "full", nil); !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	var override map[string]any
	if err := readJSON(filepath.Join(dir, hostsFile), &override); err != nil {
		t.Fatal(err)
	}
	services := override["services"].(map[string]any)
	web := asMap(services["web"])
	if aliases := asMap(asMap(web["networks"])["default"])["aliases"]; !reflect.DeepEqual(aliases, []any{"web.panel"}) {
		t.Fatalf("override %#v", override)
	}
	if _, found := services["dns"]; found {
		t.Fatalf("a service on the server's own network has no relation name: %#v", override)
	}
	if !slices.Contains(run.calls, composeCall(dir, "compose.yaml -f "+filepath.Join(dir, hostsFile), "up -d")) {
		t.Fatalf("calls %q", run.calls)
	}
}

func exposeListmonk(t *testing.T, executor Executor, run *fakeRun, piece []byte, aliases string) Result {
	t.Helper()
	run.respond["docker ps --filter label=com.docker.compose.project=listmonk --filter label=com.docker.compose.service=app --format {{.Names}}"] = "listmonk-app-1\n"
	run.respond["docker inspect --format {{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}} listmonk-app-1"] = "listmonk_default \n"
	run.respond[listmonkAliases] = aliases
	args := map[string]string{"service": "app", "port": "9000", "hostname": "listmonk-server-1.example.org", "mode": "everyone", "zone": "example.org"}
	return runRequest(t, executor, exposeRequest(t, executor, piece, "expose", args))
}

func TestAWebAddressRoutesToItsRelationName(t *testing.T) {
	executor, run, fake := cloudflareExecutor(t, listmonkStack())
	split := pieces(t, "cf-token", 2)
	storePiece(t, executor, split[0], "2")
	run.respond = map[string]string{}
	if result := exposeListmonk(t, executor, run, split[1], "app.listmonk app\n"); !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	for _, rules := range fake.Ingress {
		if rules[0].Service != "http://app.listmonk:9000" {
			t.Fatalf("rules %#v", rules)
		}
	}
	address := executor.addresses()["listmonk-server-1.example.org"]
	if address.Host != "app.listmonk" || address.Port != 9000 || address.Container != "listmonk-app-1" {
		t.Fatalf("address %#v", address)
	}
}

func TestOpeningTheVaultMovesOlderAddressesToTheirRelationNames(t *testing.T) {
	executor, run, fake := cloudflareExecutor(t, listmonkStack())
	split := pieces(t, "cf-token", 2)
	storePiece(t, executor, split[0], "2")
	run.respond = map[string]string{}
	if result := exposeListmonk(t, executor, run, split[1], "app\n"); !result.OK {
		t.Fatalf("expose %#v", result)
	}
	var tunnel string
	for id := range fake.Tunnels {
		tunnel = id
	}
	if rules := fake.Ingress[tunnel]; rules[0].Service != "http://listmonk-app-1:9000" {
		t.Fatalf("a container without its relation name keeps the container route: %#v", rules)
	}
	cf := &cloudflare.Client{Token: "cf-token", Base: executor.CloudflareBase, HTTP: executor.CloudflareHTTP}
	if err := cf.Route(context.Background(), "acc-1", tunnel, "panel.example.org", "http://panel-web-1:3001"); err != nil {
		t.Fatal(err)
	}
	addresses := executor.addresses()
	addresses["panel.example.org"] = webAddress{Project: "panel", Service: "web", Container: "panel-web-1", Network: "panel_default", Tunnel: tunnel, Account: "acc-1"}
	if err := writeJSON(executor.StateDir, "addresses.json", addresses, 0o640); err != nil {
		t.Fatal(err)
	}
	run.respond["docker ps --filter label=com.docker.compose.project=panel --filter label=com.docker.compose.service=web --format {{.Names}}"] = "panel\n"
	run.respond[`docker inspect --format {{with index .NetworkSettings.Networks "panel_default"}}{{join .Aliases " "}}{{end}} panel`] = "web.panel web panel-web-1\n"
	off := composeRequest(t, idB, "listmonk", "unexpose", func(c *Command) {
		c.Args = map[string]string{"hostname": "listmonk-server-1.example.org", "zone": "example.org"}
	})
	off.Attachment = sealedPiece(t, executor, splitSet, split[1])
	if result := runRequest(t, executor, off); !result.OK {
		t.Fatalf("unexpose %#v", result)
	}
	rules := fake.Ingress[tunnel]
	if !slices.ContainsFunc(rules, func(rule cloudflare.Rule) bool {
		return rule.Hostname == "panel.example.org" && rule.Service == "http://web.panel:3001"
	}) {
		t.Fatalf("rules %#v", rules)
	}
	if address := executor.addresses()["panel.example.org"]; address.Host != "web.panel" {
		t.Fatalf("address %#v", address)
	}
}

func TestARelationRoutedAddressNeedsNoOldNameAlias(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := namedPanel(t, executor, run, nil)
	addresses := map[string]webAddress{"panel.example.com": {Project: "panel", Service: "web", Container: "panel-web-1", Network: "panel_default", Host: "web.panel", Port: 3001}}
	if err := writeJSON(executor.StateDir, "addresses.json", addresses, 0o640); err != nil {
		t.Fatal(err)
	}
	if result := createPanel(t, executor, "contained", map[string]string{"names": "web=panel"}); !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	web := krynodesConfig(t, dir)["services"].(map[string]any)["web"].(map[string]any)
	if aliases := asMap(asMap(web["networks"])["default"])["aliases"]; !reflect.DeepEqual(aliases, []any{"web.panel"}) {
		t.Fatalf("aliases %#v", aliases)
	}
}

func TestANameAnotherStackOwnsIsRefused(t *testing.T) {
	monitoring := Stack{Project: "monitoring", Directory: "/opt/monitoring", Files: []string{"/opt/monitoring/compose.yaml"}, Running: 1, Total: 1, Containers: []string{"monitoring-panel-1"}, Services: []string{"panel"}}
	cases := map[string]string{
		"web=panel":              "panel is a service of monitoring",
		"web=monitoring-panel-1": "monitoring-panel-1 is a container of monitoring",
		"web=resolver":           "this server already runs a container named resolver",
		"web=db.monitoring":      "db.monitoring ends in .monitoring",
		"web=web.panel":          "web.panel ends in .panel",
	}
	for names, want := range cases {
		t.Run(names, func(t *testing.T) {
			executor, run := stackExecutor(t, monitoring)
			namedPanel(t, executor, run, nil)
			result := createPanel(t, executor, "contained", map[string]string{"names": names})
			if result.OK || !strings.Contains(result.Output, want) {
				t.Fatalf("result %#v", result)
			}
		})
	}
}

func TestASharedNetworkRefusesASecondServiceWithTheSameName(t *testing.T) {
	executor, run := bridgeExecutor(t, "1")
	sharedRecord(t, executor, "contained", map[string]string{"immich/web": "172.24.0.2"})
	sharedPanel(t, executor, run, nil)
	result := createPanel(t, executor, "contained", map[string]string{"offers": "apps-inner/web=3001/tcp"})
	if result.OK || !strings.Contains(result.Output, "apps-inner already has a service named web, from immich") {
		t.Fatalf("result %#v", result)
	}
	if pins := executor.readBridges()["apps-inner"].Pins; len(pins) != 1 {
		t.Fatalf("nothing is pinned: %#v", pins)
	}
}

func TestLeftoversBlockANewStackWithTheirName(t *testing.T) {
	t.Run("folder", func(t *testing.T) {
		executor, run := stackExecutor(t)
		dir := namedPanel(t, executor, run, nil)
		if err := writeWhole(dir, ".env", []byte("PASSWORD=old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		result := createPanel(t, executor, "contained", nil)
		if result.OK || !strings.Contains(result.Output, "files left from an earlier panel") {
			t.Fatalf("result %#v", result)
		}
		if env, _ := os.ReadFile(filepath.Join(dir, ".env")); string(env) != "PASSWORD=old\n" {
			t.Fatalf("the leftovers stay until deleted: %q", env)
		}
	})
	t.Run("volumes", func(t *testing.T) {
		executor, run := stackExecutor(t)
		namedPanel(t, executor, run, nil)
		run.respond["docker volume ls -q --filter label=com.docker.compose.project=panel"] = "panel_data\n"
		if result := createPanel(t, executor, "contained", nil); result.OK || !strings.Contains(result.Output, "files left from an earlier panel") {
			t.Fatalf("result %#v", result)
		}
	})
}

func TestAFailedNewStackLeavesNothingBehind(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := namedPanel(t, executor, run, nil)
	run.sequence = map[string][]string{"docker volume ls -q --filter label=com.docker.compose.project=panel": {"", "panel_data\n"}}
	run.failing = map[string]string{composeCall(dir, "compose.krynodes.json", "pull"): "pull access denied"}
	if result := createPanel(t, executor, "contained", nil); result.OK {
		t.Fatalf("result %#v", result)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("the folder goes")
	}
	if !slices.Contains(run.calls, "docker volume rm panel_data") {
		t.Fatalf("the volumes go: %q", run.calls)
	}
}

func TestDeletingLeftoversWipesTheFolderAndTheVolumes(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := panelDir(executor)
	if err := writeWhole(dir, ".env", []byte("PASSWORD=old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run.respond = map[string]string{"docker volume ls -q --filter label=com.docker.compose.project=panel": "panel_data\n"}
	if result := runRequest(t, executor, composeRequest(t, idA, "panel", "purge", nil)); !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) || !slices.Contains(run.calls, "docker volume rm panel_data") {
		t.Fatalf("calls %q", run.calls)
	}
	if result := runRequest(t, executor, composeRequest(t, idB, "shop", "purge", nil)); result.OK {
		t.Fatal("a name with nothing left is not on this server")
	}
}

func TestTheInventoryListsLeftovers(t *testing.T) {
	executor, run := stackExecutor(t)
	for _, name := range []string{"old", "panel", "gone"} {
		if err := writeWhole(filepath.Join(executor.StateDir, "compose", name), "compose.yaml", []byte("services: {}\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(executor.StateDir, "compose", "empty"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := executor.saveBin(stackBin{Stacks: map[string]removedStack{"gone": {Directory: filepath.Join(executor.StateDir, "compose", "gone")}}}); err != nil {
		t.Fatal(err)
	}
	run.respond = map[string]string{`docker volume ls --filter label=com.docker.compose.project --format {{.Label "com.docker.compose.project"}}`: "vol\npanel\ngone\nvol\n"}
	got := executor.leftovers(context.Background(), Snapshot{Stacks: []Stack{{Project: "panel"}}})
	if !reflect.DeepEqual(got, []string{"old", "vol"}) {
		t.Fatalf("leftovers %q", got)
	}
}
