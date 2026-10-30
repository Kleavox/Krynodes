package actions

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const selinuxDocker = `["name=selinux","name=seccomp,profile=builtin"]`

func securityOpts(service map[string]any) []string {
	options := []string{}
	for _, option := range asList(service["security_opt"]) {
		options = append(options, asText(option))
	}
	return options
}

func TestEveryStackGetsItsOwnLevelAndKeepsIt(t *testing.T) {
	executor, _ := newExecutor(t)
	first, err := executor.levelFor("panel")
	if err != nil {
		t.Fatal(err)
	}
	second, _ := executor.levelFor("notes")
	again, _ := executor.levelFor("panel")
	if !strings.HasPrefix(first, "s0:c") || first == second || again != first {
		t.Fatalf("first %q second %q again %q", first, second, again)
	}
	state, _ := readState[labelState](executor.StateDir, labelsFile)
	if state.Levels["panel"] != first || state.Levels["notes"] != second {
		t.Fatalf("state %+v", state)
	}
}

func TestAContainedStackGetsItsLevelAndFolderLabelWhenDockerConfines(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := panelReady(t, executor, run, panelService(panelDir(executor)), nil)
	run.respond[dockerSecurity] = selinuxDocker
	if result := runRequest(t, executor, createRequest(t, idA, "panel", panelText)); !result.OK {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	level, _ := executor.levelFor("panel")
	web := asMap(asMap(krynodesConfig(t, dir)["services"])["web"])
	if got := securityOpts(web); !slices.Equal(got, []string{"label=level:" + level}) {
		t.Fatalf("security_opt %q", got)
	}
	relabel := "chcon -R -t container_file_t -l " + level + " " + dir
	at := slices.Index(run.calls, relabel)
	up := slices.Index(run.calls, composeCall(dir, "compose.krynodes.json", "up -d"))
	if at < 0 || up < 0 || at > up {
		t.Fatalf("the folder is relabelled before the stack starts: %q", run.calls)
	}
}

func TestNoLabelsWhenDockerDoesNotConfine(t *testing.T) {
	executor, run := stackExecutor(t)
	dir := panelReady(t, executor, run, panelService(panelDir(executor)), nil)
	if result := runRequest(t, executor, createRequest(t, idA, "panel", panelText)); !result.OK {
		t.Fatalf("result %#v", result)
	}
	web := asMap(asMap(krynodesConfig(t, dir)["services"])["web"])
	if web["security_opt"] != nil || slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "chcon") }) {
		t.Fatalf("web %#v calls %q", web, run.calls)
	}
}

func TestAFullAccessStackTurnsLabelsOffOnlyWhereItNeedsTheServer(t *testing.T) {
	executor, _ := stackExecutor(t)
	dir := panelDir(executor)
	cases := map[string]map[string]any{
		"own folder":   {"volumes": []any{map[string]any{"type": "bind", "source": filepath.Join(dir, "data"), "target": "/data"}}},
		"server path":  {"volumes": []any{map[string]any{"type": "bind", "source": "/etc", "target": "/host-etc"}}},
		"docker":       {"volumes": []any{map[string]any{"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}}},
		"privileged":   {"privileged": true},
		"devices":      {"devices": []any{map[string]any{"source": "/dev/ttyUSB0", "target": "/dev/ttyUSB0"}}},
		"host pid":     {"pid": "host"},
		"host network": {"network_mode": "host"},
	}
	for name, service := range cases {
		needs := needsServer(dir, service)
		if (name == "own folder") == needs {
			t.Fatalf("%s: needs the server %v", name, needs)
		}
	}
	override := map[string]any{"services": map[string]any{}}
	config := map[string]any{"services": map[string]any{"web": cases["own folder"], "tools": cases["docker"]}}
	addLabels(override, config, dir, "s0:c1,c2", true)
	services := asMap(override["services"])
	if got := securityOpts(asMap(services["web"])); !slices.Equal(got, []string{"label=level:s0:c1,c2"}) {
		t.Fatalf("web %q", got)
	}
	if got := securityOpts(asMap(services["tools"])); !slices.Equal(got, []string{"label=disable"}) {
		t.Fatalf("tools %q", got)
	}
}
