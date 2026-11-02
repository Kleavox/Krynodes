package actions

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/confine"
	"github.com/Kleavox/krynodes/agent/internal/recipes"
)

func managedSELinux(t *testing.T, executor Executor, run *fakeRun) string {
	t.Helper()
	rootFile(t, executor, "/etc/os-release", rockyRelease)
	rootFile(t, executor, recipes.DockerDaemon, "{\"log-driver\": \"local\"}\n")
	state := recipeState{Applied: map[string]appliedRecipe{"confinement": {At: executorNow, Saved: map[string]string{"system": "selinux", "mode": "permissive", "config": "permissive"}}}}
	if err := writeJSON(executor.StateDir, "recipes.json", state, 0o640); err != nil {
		t.Fatal(err)
	}
	dir, _ := ownPanel(t, executor, "contained", panelText)
	if err := os.WriteFile(filepath.Join(dir, "compose.krynodes.json"), []byte(`{"name":"panel","services":{"web":{"image":"example/panel:1","security_opt":["no-new-privileges:true"]}}}`), 0o640); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestConfineContainersMarksFirstThenRestartsDockerAndRelabelsEveryStack(t *testing.T) {
	executor, run := securityExecutor(t)
	dir := managedSELinux(t, executor, run)
	marked := false
	run.effects = map[string]func(){}
	run.effects["systemctl restart docker"] = func() {
		_, err := os.Stat(filepath.Join(executor.StateDir, confinementMark))
		marked = err == nil
	}
	result := hostRun(t, executor, hostRequest(t, idA, "confinement", "containers", map[string]string{"on": "1"}))
	if !result.OK || !strings.Contains(result.Output, "panel") {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	if !marked {
		t.Fatal("the mark is written before Docker restarts")
	}
	if daemon := readRoot(t, executor, recipes.DockerDaemon); !strings.Contains(daemon, `"selinux-enabled": true`) || !strings.Contains(daemon, `"log-driver": "local"`) {
		t.Fatalf("daemon.json %q", daemon)
	}
	level, _ := executor.levelFor("panel")
	web := asMap(asMap(krynodesConfig(t, dir)["services"])["web"])
	if got := securityOpts(web); !slices.Equal(got, []string{"no-new-privileges:true", "label=level:" + level}) {
		t.Fatalf("security_opt %q", got)
	}
	restart := slices.Index(run.calls, "systemctl restart docker")
	relabel := slices.Index(run.calls, "chcon -R -t container_file_t -l "+level+" "+dir)
	up := slices.Index(run.calls, composeCall(dir, "compose.krynodes.json", "up -d"))
	if restart < 0 || relabel < restart || up < relabel {
		t.Fatalf("order: %q", run.calls)
	}

	run.calls = nil
	if result := hostRun(t, executor, hostRequest(t, idB, "confinement", "containers", map[string]string{"on": "0"})); !result.OK {
		t.Fatalf("undo %#v", result)
	}
	if daemon := readRoot(t, executor, recipes.DockerDaemon); daemon != "{\"log-driver\": \"local\"}\n" {
		t.Fatalf("daemon.json after undo %q", daemon)
	}
	web = asMap(asMap(krynodesConfig(t, dir)["services"])["web"])
	if got := securityOpts(web); !slices.Equal(got, []string{"no-new-privileges:true"}) {
		t.Fatalf("security_opt after undo %q", got)
	}
	if !slices.Contains(run.calls, "systemctl restart docker") || !slices.Contains(run.calls, composeCall(dir, "compose.krynodes.json", "up -d")) {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestConfineContainersKeepsItsMarkUntilTheLastStackIsBack(t *testing.T) {
	executor, run := securityExecutor(t)
	managedSELinux(t, executor, run)
	rootFile(t, executor, "/sys/fs/selinux/enforce", "1")
	rootFile(t, executor, confine.AuditLog, "")
	run.respond["systemctl is-active auditd"] = "active\n"
	run.respond[modulesCall] = "100 base pp\n"
	clock := executorNow
	executor.Now = func() time.Time { return clock }
	executor.watchDenials(context.Background())
	run.effects = map[string]func(){}
	run.effects["systemctl restart docker"] = func() { clock = clock.Add(90 * time.Second) }
	run.effects[composeCall(filepath.Join(executor.StateDir, "compose", "panel"), "compose.krynodes.json", "up -d")] = func() { clock = clock.Add(90 * time.Second) }
	if result := hostRun(t, executor, hostRequest(t, idA, "confinement", "containers", map[string]string{"on": "1"})); !result.OK {
		t.Fatalf("result %#v", result)
	}
	stamp := func(at time.Time) string {
		return strings.Replace(avcLine("container_t", "s0:c1,c2", "cat", "shadow"), fmt.Sprintf("audit(%d.", executorNow.Unix()), fmt.Sprintf("audit(%d.", at.Unix()), 1)
	}
	appendAudit(t, executor, stamp(executorNow.Add(30*time.Second)), stamp(clock))
	clock = clock.Add(30 * time.Second)
	executor.watchDenials(context.Background())
	if events := readEvents(t, executor); len(events) != 0 {
		t.Fatalf("denials while Krynodes restarted its stacks count: %+v", events)
	}
}

func TestConfineContainersNeedsSELinuxManagedByKrynodes(t *testing.T) {
	executor, run := securityExecutor(t)
	rootFile(t, executor, "/etc/os-release", rockyRelease)
	if result := hostRun(t, executor, hostRequest(t, idA, "confinement", "containers", map[string]string{"on": "1"})); result.OK {
		t.Fatalf("result %#v", result)
	}
	if slices.Contains(run.calls, "systemctl restart docker") {
		t.Fatal("Docker restarted anyway")
	}
}

func TestDockerInstalledWhileSELinuxIsManagedConfinesFromTheStart(t *testing.T) {
	executor, run := securityExecutor(t)
	managedSELinux(t, executor, run)
	args := executor.installArgs(map[string]string{})
	if args["selinux"] != "1" {
		t.Fatalf("args %v", args)
	}
	if err := writeJSON(executor.StateDir, "recipes.json", recipeState{Applied: map[string]appliedRecipe{}}, 0o640); err != nil {
		t.Fatal(err)
	}
	if args := executor.installArgs(map[string]string{}); args["selinux"] != "" {
		t.Fatalf("args %v", args)
	}
}

func TestChangeBooleanSetsItForGoodInsideTheMarkSoItsPolicyLoadNeverCounts(t *testing.T) {
	executor, run := selinuxWatch(t, true, "")
	clock := executorNow
	executor.Now = func() time.Time { return clock }
	run.respond["getsebool httpd_can_network_connect"] = "httpd_can_network_connect --> off\n"
	marked := false
	run.effects = map[string]func(){"setsebool -P httpd_can_network_connect on": func() {
		_, err := os.Stat(filepath.Join(executor.StateDir, confinementMark))
		marked = err == nil
		clock = clock.Add(3 * time.Minute)
	}}
	result := hostRun(t, executor, hostRequest(t, idA, "confinement", "boolean", map[string]string{"name": "httpd_can_network_connect", "on": "1"}))
	if !result.OK || result.Output != "httpd_can_network_connect is on now (was off)" {
		t.Fatalf("result %#v calls %q", result, run.calls)
	}
	if !marked {
		t.Fatal("the mark is written before setsebool")
	}
	appendAudit(t, executor, fmt.Sprintf(`type=MAC_POLICY_LOAD msg=audit(%d.000:2): lsm=selinux res=1`, clock.Unix()))
	clock = clock.Add(30 * time.Second)
	executor.watchDenials(context.Background())
	if events := readEvents(t, executor); len(events) != 0 {
		t.Fatalf("Krynodes' own boolean counts: %+v", events)
	}

	appendAudit(t, executor, fmt.Sprintf(`type=MAC_POLICY_LOAD msg=audit(%d.000:3): lsm=selinux res=1`, clock.Add(5*time.Minute).Unix()))
	clock = clock.Add(5*time.Minute + 30*time.Second)
	executor.watchDenials(context.Background())
	if strong := eventsOfKind(t, executor, "confinement"); len(strong) != 1 {
		t.Fatalf("a policy load after the mark still counts: %+v", strong)
	}
}

func TestChangeBooleanRefusesWhatItCannotSetAndSkipsWhatIsSet(t *testing.T) {
	executor, run := selinuxWatch(t, true, "")
	run.respond["getsebool httpd_can_network_connect"] = "httpd_can_network_connect --> on\n"
	run.failing = map[string]string{"getsebool nope": "getsebool:  Error getting active value for nope\n"}
	ask := func(id string, args map[string]string) Result {
		return hostRun(t, executor, hostRequest(t, id, "confinement", "boolean", args))
	}
	if result := ask(idA, map[string]string{"name": "httpd_can_network_connect", "on": "1"}); !result.OK || result.Output != "httpd_can_network_connect is already on" {
		t.Fatalf("already on %#v", result)
	}
	if result := ask(idB, map[string]string{"name": "nope", "on": "1"}); result.OK || !strings.Contains(result.Output, "SELinux has no boolean nope") {
		t.Fatalf("unknown %#v", result)
	}
	for index, args := range []map[string]string{
		{"name": "Bad;name", "on": "1"},
		{"name": "httpd_can_network_connect", "on": "yes"},
		{"name": "httpd_can_network_connect"},
	} {
		if result := ask(fmt.Sprintf("00000000-0000-4000-8000-%012d", index+1), args); result.OK {
			t.Fatalf("%v %#v", args, result)
		}
	}
	for _, call := range run.calls {
		if strings.HasPrefix(call, "setsebool") || strings.Contains(call, "Bad;name") {
			t.Fatalf("calls %q", run.calls)
		}
	}

	executor, run = apparmorWatch(t, "")
	if result := hostRun(t, executor, hostRequest(t, idA, "confinement", "boolean", map[string]string{"name": "httpd_can_network_connect", "on": "1"})); result.OK || !strings.Contains(result.Output, "SELinux managed by Krynodes") {
		t.Fatalf("apparmor %#v", result)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool {
		return strings.HasPrefix(call, "getsebool") || strings.HasPrefix(call, "setsebool")
	}) {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestChangeBooleanGoesToTheHostUnitSigned(t *testing.T) {
	executor, _ := selinuxWatch(t, true, "")
	writeRequest(t, executor.RequestDir, idA+".json", hostRequest(t, idA, "confinement", "boolean", map[string]string{"name": "httpd_can_network_connect", "on": "1"}))
	if err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "host", idA+".json")); err != nil {
		t.Fatal(err)
	}
}
