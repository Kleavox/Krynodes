package actions

import (
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func namedKuma(t *testing.T, executor Executor, run *fakeRun, change func(map[string]any)) string {
	t.Helper()
	service := kumaService(kumaDir(executor))
	if change != nil {
		change(service)
	}
	dir := kumaReady(t, executor, run, service, map[string]any{"networks": map[string]any{
		"default": map[string]any{"name": "kuma_default"},
	}})
	run.respond[composeCall(dir, "compose.yaml -f "+filepath.Join(dir, hostsFile), psStates)] = "web\trunning\t\t0\n"
	return dir
}

func TestAContainedStackKeepsItsTitleAndNamesItsContainers(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := namedKuma(t, executor, run, nil)
	if result := createKuma(t, executor, "contained", map[string]string{"title": "Uptime Kuma", "names": "web=uptime-kuma"}); !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	web := krynodesConfig(t, dir)["services"].(map[string]any)["web"].(map[string]any)
	if web["container_name"] != "uptime-kuma" {
		t.Fatalf("web %#v", web)
	}
	meta := executor.metaOf(dir)
	if meta.Title != "Uptime Kuma" || !maps.Equal(meta.Names, map[string]string{"web": "uptime-kuma"}) {
		t.Fatalf("meta %#v", meta)
	}
}

func TestAFullAccessStackNamesItsContainersBesideItsOwnFile(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := namedKuma(t, executor, run, nil)
	if result := createKuma(t, executor, "full", map[string]string{"names": "web=uptime-kuma"}); !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	var override map[string]any
	if err := readJSON(filepath.Join(dir, hostsFile), &override); err != nil {
		t.Fatal(err)
	}
	if web := override["services"].(map[string]any)["web"].(map[string]any); web["container_name"] != "uptime-kuma" {
		t.Fatalf("override %#v", override)
	}
	if !slices.Contains(run.calls, composeCall(dir, "compose.yaml -f "+filepath.Join(dir, hostsFile), "up -d")) {
		t.Fatalf("the names must be used: %q", run.calls)
	}
}

func TestStackNamesAreCheckedBeforeAnythingRuns(t *testing.T) {
	cases := map[string]map[string]string{
		"title with a space at the end": {"title": "Uptime Kuma "},
		"title on two lines":            {"title": "Uptime\nKuma"},
		"title too long":                {"title": strings.Repeat("k", 65)},
		"empty title":                   {"title": ""},
		"container with a space":        {"names": "web=uptime kuma"},
		"container one letter":          {"names": "web=k"},
		"container used twice":          {"names": "web=kuma,db=kuma"},
		"service named twice":           {"names": "web=kuma,web=kuma-2"},
		"no container":                  {"names": "web"},
	}
	for label, args := range cases {
		t.Run(label, func(t *testing.T) {
			executor, run := stackExecutor(t)
			namedKuma(t, executor, run, nil)
			result := createKuma(t, executor, "contained", args)
			if result.OK || slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "up -d") }) {
				t.Fatalf("result %#v calls %q", result, run.calls)
			}
		})
	}
}

func TestNamesSkipServicesWithCopiesAndServicesThatAreGone(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := namedKuma(t, executor, run, func(service map[string]any) {
		service["deploy"] = map[string]any{"replicas": 2.0}
	})
	if result := createKuma(t, executor, "full", map[string]string{"names": "web=uptime-kuma,old=old-kuma"}); !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	var override map[string]any
	if err := readJSON(filepath.Join(dir, hostsFile), &override); err != nil {
		t.Fatal(err)
	}
	if web := asMap(asMap(override["services"])["web"]); web["container_name"] != nil {
		t.Fatalf("a service with copies keeps Docker's numbers: %#v", override)
	}
	if names := executor.metaOf(dir).Names; len(names) != 0 {
		t.Fatalf("names %#v", names)
	}
}

func TestARenamedServiceKeepsTheNameItsWebAddressUses(t *testing.T) {
	for _, access := range []string{"contained", "full"} {
		t.Run(access, func(t *testing.T) {
			executor, run := stackExecutor(t)
			dir := namedKuma(t, executor, run, nil)
			addresses := map[string]webAddress{
				"kuma.example.com":  {Project: "kuma", Service: "web", Container: "kuma-web-1", Network: "kuma_default"},
				"other.example.com": {Project: "other", Service: "web", Container: "other-web-1", Network: "other_default"},
			}
			if err := writeJSON(executor.StateDir, "addresses.json", addresses, 0o640); err != nil {
				t.Fatal(err)
			}
			if result := createKuma(t, executor, access, map[string]string{"names": "web=uptime-kuma"}); !result.OK {
				t.Fatalf("result %#v calls %q", result, run.calls)
			}
			var written map[string]any
			if access == "contained" {
				written = krynodesConfig(t, dir)
			} else if err := readJSON(filepath.Join(dir, hostsFile), &written); err != nil {
				t.Fatal(err)
			}
			web := written["services"].(map[string]any)["web"].(map[string]any)
			network := asMap(asMap(web["networks"])["default"])
			if !reflect.DeepEqual(network["aliases"], []any{"kuma-web-1", "web.kuma"}) {
				t.Fatalf("web %#v", web)
			}
		})
	}
}

func TestAServiceThatKeepsItsNameGetsNoOldNameAlias(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := namedKuma(t, executor, run, nil)
	addresses := map[string]webAddress{"kuma.example.com": {Project: "kuma", Service: "web", Container: "uptime-kuma", Network: "kuma_default"}}
	if err := writeJSON(executor.StateDir, "addresses.json", addresses, 0o640); err != nil {
		t.Fatal(err)
	}
	if result := createKuma(t, executor, "contained", map[string]string{"names": "web=uptime-kuma"}); !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	web := krynodesConfig(t, dir)["services"].(map[string]any)["web"].(map[string]any)
	if aliases := asMap(asMap(web["networks"])["default"])["aliases"]; !reflect.DeepEqual(aliases, []any{"web.kuma"}) {
		t.Fatalf("aliases %#v", aliases)
	}
}

func TestChangingWhatAStackReachesKeepsItsNames(t *testing.T) {
	executor, _ := stackExecutor(t)
	current := stackMeta{Access: "contained", Title: "Uptime Kuma", Names: map[string]string{"web": "uptime-kuma"}}
	meta, err := executor.choicesFrom(Command{Args: map[string]string{"hostPorts": "3001/tcp"}}, "contained", current)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Title != "Uptime Kuma" || !maps.Equal(meta.Names, current.Names) {
		t.Fatalf("meta %#v", meta)
	}
}

func TestTheInventoryCarriesAStacksTitleAndNames(t *testing.T) {
	executor, _ := stackExecutor(t)
	dir := kumaDir(executor)
	if err := writeJSON(dir, "krynodes.json", stackMeta{Access: "contained", Title: "Uptime Kuma", Names: map[string]string{"web": "uptime-kuma"}}, 0o640); err != nil {
		t.Fatal(err)
	}
	entries := executor.stackEntries(Snapshot{Stacks: []Stack{{Project: "kuma", Directory: dir, Containers: []string{"uptime-kuma"}}}})
	if len(entries) != 1 || entries[0].Title != "Uptime Kuma" || !maps.Equal(entries[0].Names, map[string]string{"web": "uptime-kuma"}) {
		t.Fatalf("entries %#v", entries)
	}
}
