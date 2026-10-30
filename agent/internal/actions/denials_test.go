package actions

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/confine"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const (
	modulesCall = "semodule --list-modules=full"
	profilesAt  = "/sys/kernel/security/apparmor/profiles"
	containerA  = "4f1c2a9e8b7d6c5f4e3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e"
)

func manage(t *testing.T, executor Executor, system string) {
	t.Helper()
	state := recipeState{Applied: map[string]appliedRecipe{"confinement": {At: executorNow, Saved: map[string]string{"system": system, "mode": "enforcing"}}}}
	if err := writeJSON(executor.StateDir, "recipes.json", state, 0o640); err != nil {
		t.Fatal(err)
	}
}

func selinuxWatch(t *testing.T, managed bool, access string) (Executor, *fakeRun) {
	t.Helper()
	executor, run := securityExecutor(t)
	rootFile(t, executor, "/etc/os-release", rockyRelease)
	rootFile(t, executor, "/sys/fs/selinux/enforce", "1")
	rootFile(t, executor, confine.AuditLog, "")
	run.respond["systemctl is-active auditd"] = "active\n"
	run.respond[modulesCall] = "100 base pp\n"
	if managed {
		manage(t, executor, "selinux")
	}
	if access != "" {
		ownPanel(t, executor, access, panelText)
	}
	executor.watchDenials(context.Background())
	return executor, run
}

func apparmorWatch(t *testing.T, access string) (Executor, *fakeRun) {
	t.Helper()
	executor, run := securityExecutor(t)
	rootFile(t, executor, "/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n")
	rootFile(t, executor, "/sys/module/apparmor/parameters/enabled", "Y")
	rootFile(t, executor, profilesAt, "/usr/sbin/cupsd (enforce)\n/usr/bin/gone (enforce)\ndocker-default (enforce)\n")
	rootFile(t, executor, "/usr/sbin/cupsd", "")
	manage(t, executor, "apparmor")
	if access != "" {
		ownPanel(t, executor, access, panelText)
	}
	executor.watchDenials(context.Background())
	return executor, run
}

func appendAudit(t *testing.T, executor Executor, lines ...string) {
	t.Helper()
	file, err := os.OpenFile(executor.path(confine.AuditLog), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		t.Fatal(err)
	}
}

func avcLine(kind, level, program, name string) string {
	return fmt.Sprintf(`type=AVC msg=audit(%d.000:1): avc:  denied  { read } for  pid=1234 comm="%s" name="%s" scontext=system_u:system_r:%s:%s tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0`, executorNow.Unix(), program, name, kind, level)
}

func auditLine(kind, rest string) string {
	return fmt.Sprintf(`type=%s msg=audit(%d.000:2): %s`, kind, executorNow.Unix(), rest)
}

func kernelCall(rest string) string {
	return "journalctl -k -o short-unix --no-pager -q --show-cursor " + rest
}

func eventsOfKind(t *testing.T, executor Executor, kind string) []reporter.Event {
	t.Helper()
	found := []reporter.Event{}
	for _, event := range readEvents(t, executor) {
		if event.Kind == kind {
			found = append(found, event)
		}
	}
	return found
}

func TestADeniedContainedStackStopsWithConfinementAsTheReason(t *testing.T) {
	executor, _ := selinuxWatch(t, true, "contained")
	level, _ := executor.levelFor("panel")
	appendAudit(t, executor, avcLine("container_t", level, "cat", "shadow"))
	executor.watchDenials(context.Background())
	stacks := eventsOfKind(t, executor, "stack")
	if len(stacks) != 1 || stacks[0].Detail["stack"] != "panel" || stacks[0].Detail["why"] != "confinement" || stacks[0].Detail["stopped"] != "true" || stacks[0].Detail["wanted"] != "read shadow" || stacks[0].Detail["program"] != "cat" {
		t.Fatalf("stack events %+v", stacks)
	}
	if !executor.knocked("panel") {
		t.Fatal("the stack stays stopped after a restart")
	}
	if strong := eventsOfKind(t, executor, "confinement"); len(strong) != 0 {
		t.Fatalf("the server is still trusted: %+v", strong)
	}
	report := readDenials(executor.StateDir, executor.Now())
	if report == nil || report.Count != 1 || len(report.Lines) != 1 || report.Lines[0].Stack != "panel" || report.Lines[0].Wanted != "read shadow" {
		t.Fatalf("report %+v", report)
	}
}

func TestAFullAccessStackStopsRightAfterItStartsAndQuarantinesLater(t *testing.T) {
	for _, started := range []time.Duration{5 * time.Minute, 20 * time.Minute} {
		executor, run := selinuxWatch(t, true, "full")
		level, _ := executor.levelFor("panel")
		run.respond["docker ps -q --filter label=com.docker.compose.project=panel"] = "c1\n"
		run.respond["docker inspect --format {{.State.StartedAt}} c1"] = executorNow.Add(-started).Format(time.RFC3339Nano) + "\n"
		appendAudit(t, executor, avcLine("container_t", level, "cat", "shadow"))
		executor.watchDenials(context.Background())
		stopped, strong := eventsOfKind(t, executor, "stack"), eventsOfKind(t, executor, "confinement")
		fresh := started < 10*time.Minute
		if (len(stopped) == 1) != fresh || (len(strong) == 1) == fresh {
			t.Fatalf("started %v ago: stopped %+v strong %+v", started, stopped, strong)
		}
		if !fresh && (strong[0].Detail["strong"] != "1" || !strings.Contains(strong[0].Detail["what"], "panel")) {
			t.Fatalf("strong %+v", strong)
		}
	}
}

func TestManyDenialsOfOneStackAskDockerOnce(t *testing.T) {
	executor, run := selinuxWatch(t, true, "full")
	level, _ := executor.levelFor("panel")
	run.respond["docker ps -q --filter label=com.docker.compose.project=panel"] = "c1\n"
	run.respond["docker inspect --format {{.State.StartedAt}} c1"] = executorNow.Add(-time.Hour).Format(time.RFC3339Nano) + "\n"
	appendAudit(t, executor, avcLine("container_t", level, "cat", "shadow"), avcLine("container_t", level, "cat", "passwd"), avcLine("container_t", level, "sh", "hosts"))
	run.calls = nil
	executor.watchDenials(context.Background())
	asked := 0
	for _, call := range run.calls {
		if strings.HasPrefix(call, "docker ps") {
			asked++
		}
	}
	if asked != 1 {
		t.Fatalf("docker ps asked %d times: %q", asked, run.calls)
	}
}

func TestAContainerKrynodesDidNotStartQuarantines(t *testing.T) {
	executor, _ := selinuxWatch(t, true, "")
	appendAudit(t, executor, avcLine("container_t", "s0:c1,c2", "cat", "shadow"))
	executor.watchDenials(context.Background())
	strong := eventsOfKind(t, executor, "confinement")
	if len(strong) != 1 || strong[0].Detail["strong"] != "1" || !strings.Contains(strong[0].Detail["what"], "did not start") {
		t.Fatalf("events %+v", readEvents(t, executor))
	}
}

func TestAHostServiceDenialWarnsOnceAnHourUntilItWasMe(t *testing.T) {
	executor, _ := selinuxWatch(t, true, "")
	appendAudit(t, executor, avcLine("httpd_t", "s0", "nginx", "shadow"), avcLine("httpd_t", "s0", "nginx", "passwd"))
	executor.watchDenials(context.Background())
	warned := eventsOfKind(t, executor, "confinement")
	if len(warned) != 1 || warned[0].Detail["strong"] != "" || warned[0].Detail["item"] != "nginx httpd_t" || warned[0].Detail["program"] != "nginx" || warned[0].Detail["system"] != "selinux" {
		t.Fatalf("warned %+v", warned)
	}
	if result := executor.acceptConfinement(Request{ID: idA}, "nginx httpd_t"); !result.OK {
		t.Fatalf("accept %#v", result)
	}
	executor.Now = func() time.Time { return executorNow.Add(time.Hour) }
	appendAudit(t, executor, avcLine("httpd_t", "s0", "nginx", "shadow"))
	executor.watchDenials(context.Background())
	if warned := eventsOfKind(t, executor, "confinement"); len(warned) != 1 {
		t.Fatalf("It Was Me accepts the program and type for good: %+v", warned)
	}
}

func TestPackageManagerDenialsAreOnlyShownAndTwentyAreKept(t *testing.T) {
	executor, _ := selinuxWatch(t, true, "")
	lines := []string{}
	for index := range 24 {
		lines = append(lines, avcLine("rpm_script_t", "s0", "sh", "file-"+strconv.Itoa(index)))
	}
	appendAudit(t, executor, lines...)
	executor.watchDenials(context.Background())
	if events := readEvents(t, executor); len(events) != 0 {
		t.Fatalf("a package script's denials: %+v", events)
	}
	rootFile(t, executor, "/proc/77/comm", "dnf\n")
	appendAudit(t, executor, avcLine("container_t", "s0:c1,c2", "cat", "shadow"))
	executor.watchDenials(context.Background())
	if events := readEvents(t, executor); len(events) != 0 {
		t.Fatalf("events %+v", events)
	}
	report := readDenials(executor.StateDir, executor.Now())
	if report == nil || report.Count != 25 || len(report.Lines) != 20 || report.Lines[19].Wanted != "read shadow" {
		t.Fatalf("denials %+v", report)
	}
}

func TestKrynodesOwnChangeIsExcusedByTheMark(t *testing.T) {
	executor, _ := selinuxWatch(t, true, "")
	if err := executor.markConfinement("apply"); err != nil {
		t.Fatal(err)
	}
	rootFile(t, executor, "/sys/fs/selinux/enforce", "0")
	appendAudit(t, executor, avcLine("container_t", "s0:c1,c2", "cat", "shadow"), auditLine("MAC_STATUS", "enforcing=0 old_enforcing=1 lsm=selinux res=1"), auditLine("MAC_POLICY_LOAD", "lsm=selinux res=1"))
	executor.watchDenials(context.Background())
	if events := readEvents(t, executor); len(events) != 0 {
		t.Fatalf("events %+v", events)
	}
}

func TestSELinuxSetPermissiveOutsideKrynodesQuarantinesUnlessARestartIsDue(t *testing.T) {
	executor, _ := selinuxWatch(t, true, "")
	rootFile(t, executor, "/sys/fs/selinux/enforce", "0")
	executor.watchDenials(context.Background())
	strong := eventsOfKind(t, executor, "confinement")
	if len(strong) != 1 || strong[0].Detail["strong"] != "1" || !strings.Contains(strong[0].Detail["what"], "permissive") {
		t.Fatalf("events %+v", strong)
	}

	executor, _ = selinuxWatch(t, true, "")
	rootFile(t, executor, confine.Relabel, "")
	rootFile(t, executor, "/sys/fs/selinux/enforce", "0")
	executor.watchDenials(context.Background())
	if events := readEvents(t, executor); len(events) != 0 {
		t.Fatalf("the relabelling boot runs permissive: %+v", events)
	}
}

func TestDenialsFromBeforeKrynodesManagedAreOnlyShown(t *testing.T) {
	executor, _ := selinuxWatch(t, true, "")
	early := executorNow.Add(-time.Minute).Unix()
	at := fmt.Sprintf("audit(%d.", executorNow.Unix())
	appendAudit(t, executor, strings.Replace(avcLine("container_t", "s0:c1,c2", "cat", "shadow"), at, fmt.Sprintf("audit(%d.", early), 1), strings.Replace(auditLine("MAC_STATUS", "enforcing=0 old_enforcing=1 lsm=selinux res=1"), at, fmt.Sprintf("audit(%d.", early), 1))
	executor.watchDenials(context.Background())
	if events := readEvents(t, executor); len(events) != 0 {
		t.Fatalf("events %+v", events)
	}
	if report := readDenials(executor.StateDir, executor.Now()); report == nil || len(report.Lines) != 1 {
		t.Fatalf("report %+v", report)
	}
}

func TestAnUnmanagedServerCountsDenialsAndRaisesNothing(t *testing.T) {
	executor, run := selinuxWatch(t, false, "")
	rootFile(t, executor, "/sys/fs/selinux/enforce", "0")
	appendAudit(t, executor, avcLine("container_t", "s0:c1,c2", "cat", "shadow"), auditLine("MAC_POLICY_LOAD", "lsm=selinux res=1"))
	executor.watchDenials(context.Background())
	if events := readEvents(t, executor); len(events) != 0 {
		t.Fatalf("events %+v", events)
	}
	if report := readDenials(executor.StateDir, executor.Now()); report == nil || report.Count != 1 {
		t.Fatalf("report %+v", report)
	}
	for _, call := range run.calls {
		if strings.HasPrefix(call, "semodule") || strings.HasPrefix(call, "docker") {
			t.Fatalf("an unmanaged server is only read: %q", run.calls)
		}
	}
}

func TestAPolicyLoadOutsideAnUpdateOrANewLocalModuleQuarantines(t *testing.T) {
	executor, _ := selinuxWatch(t, true, "")
	appendAudit(t, executor, auditLine("MAC_POLICY_LOAD", "lsm=selinux res=1"))
	executor.watchDenials(context.Background())
	if strong := eventsOfKind(t, executor, "confinement"); len(strong) != 1 || !strings.Contains(strong[0].Detail["what"], "policy") {
		t.Fatalf("events %+v", strong)
	}

	executor, run := selinuxWatch(t, true, "")
	rootFile(t, executor, "/proc/77/comm", "dnf\n")
	appendAudit(t, executor, auditLine("MAC_POLICY_LOAD", "lsm=selinux res=1"))
	executor.watchDenials(context.Background())
	if events := readEvents(t, executor); len(events) != 0 {
		t.Fatalf("an update loads policy: %+v", events)
	}
	run.respond[modulesCall] = "100 base pp\n400 permissive_httpd_t cil\n"
	appendAudit(t, executor, auditLine("MAC_POLICY_LOAD", "lsm=selinux res=1"))
	executor.watchDenials(context.Background())
	if strong := eventsOfKind(t, executor, "confinement"); len(strong) != 1 || !strings.Contains(strong[0].Detail["what"], "permissive_httpd_t") {
		t.Fatalf("events %+v", strong)
	}
}

func TestAuditdStoppingQuarantinesAndDenialsComeFromTheKernelLog(t *testing.T) {
	executor, run := selinuxWatch(t, true, "")
	run.respond["systemctl is-active auditd"] = "inactive\n"
	executor.watchDenials(context.Background())
	if strong := eventsOfKind(t, executor, "confinement"); len(strong) != 1 || !strings.Contains(strong[0].Detail["what"], "audit") {
		t.Fatalf("events %+v", strong)
	}
	since := kernelCall("--since=@" + strconv.FormatInt(executorNow.Unix(), 10))
	run.respond[since] = "1700000000.000000 server-1 kernel: audit: type=1400 " + strings.TrimPrefix(avcLine("httpd_t", "s0", "nginx", "shadow"), "type=AVC msg=") + "\n-- cursor: s=abc\n"
	executor.watchDenials(context.Background())
	executor.watchDenials(context.Background())
	if warned := eventsOfKind(t, executor, "confinement"); len(warned) != 2 || warned[1].Detail["item"] != "nginx httpd_t" {
		t.Fatalf("events %+v calls %q", warned, run.calls)
	}
	if run.calls[len(run.calls)-1] != kernelCall("--after-cursor=s=abc") {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestADenialOfSnapRefreshingItselfIsOnlyShown(t *testing.T) {
	executor, run := apparmorWatch(t, "")
	line := fmt.Sprintf(`1700000000.000000 server-1 kernel: audit: type=1400 audit(%d.000:4): apparmor="DENIED" operation="mount" profile="snap-update-ns.lxd" name="/snap/lxd/" pid=55 comm="snap-update-ns" requested_mask="r" denied_mask="r"`, executorNow.Unix())
	run.respond[kernelCall("--since=@"+strconv.FormatInt(executorNow.Unix(), 10))] = line + "\n-- cursor: s=ghi\n"
	executor.watchDenials(context.Background())
	if events := readEvents(t, executor); len(events) != 0 {
		t.Fatalf("events %+v", events)
	}
	if report := readDenials(executor.StateDir, executor.Now()); report == nil || len(report.Lines) != 1 {
		t.Fatalf("report %+v", report)
	}
}

func TestAnAppArmorProfileLeavingEnforceQuarantines(t *testing.T) {
	executor, _ := apparmorWatch(t, "")
	rootFile(t, executor, profilesAt, "/usr/sbin/cupsd (complain)\ndocker-default (enforce)\n")
	executor.watchDenials(context.Background())
	strong := eventsOfKind(t, executor, "confinement")
	if len(strong) != 1 || !strings.Contains(strong[0].Detail["what"], "/usr/sbin/cupsd") {
		t.Fatalf("a profile whose program is gone may unload; cupsd may not leave enforce: %+v", strong)
	}
}

func TestAnAppArmorContainerDenialStopsItsStackAndAnUntraceableOneWarns(t *testing.T) {
	executor, run := apparmorWatch(t, "contained")
	rootFile(t, executor, "/proc/4321/cgroup", "0::/system.slice/docker-"+containerA+".scope\n")
	run.respond[`docker inspect --format {{index .Config.Labels "com.docker.compose.project"}} `+containerA] = "panel\n"
	denied := func(pid int) string {
		return fmt.Sprintf(`1700000000.000000 server-1 kernel: audit: type=1400 audit(%d.000:3): apparmor="DENIED" operation="open" profile="docker-default" name="/etc/shadow" pid=%d comm="cat" requested_mask="r" denied_mask="r"`, executorNow.Unix(), pid)
	}
	run.respond[kernelCall("--since=@"+strconv.FormatInt(executorNow.Unix(), 10))] = denied(4321) + "\n" + denied(999) + "\n-- cursor: s=def\n"
	executor.watchDenials(context.Background())
	stacks, warned := eventsOfKind(t, executor, "stack"), eventsOfKind(t, executor, "confinement")
	if len(stacks) != 1 || stacks[0].Detail["stack"] != "panel" || stacks[0].Detail["why"] != "confinement" {
		t.Fatalf("stacks %+v", stacks)
	}
	if len(warned) != 1 || warned[0].Detail["strong"] != "" || warned[0].Detail["item"] != "cat docker-default" {
		t.Fatalf("warned %+v", warned)
	}
}
