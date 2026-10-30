package actions

import (
	"context"
	"slices"
	"testing"
)

func TestUnconfinedContainersOutsideKrynodesAreListedButNotFullAccessStacks(t *testing.T) {
	executor, run := securityExecutor(t)
	ownPanel(t, executor, "full", panelText)
	labelled := "system_u:system_r:container_t:s0:c1,c2"
	run.respond["docker ps -q"] = "c1\nc2\nc3\nc4\nc5\n"
	run.respond["docker inspect --format "+riskyFormat+" c1 c2 c3 c4 c5"] = "/armor\tfalse\t\t\tunconfined\t" + labelled + "\t\n" +
		"/filters\tfalse\t\tshop\tdocker-default\t" + labelled + "\tseccomp=unconfined;\n" +
		"/label\tfalse\t\t\tdocker-default\t\tlabel=disable;\n" +
		"/panel-web-1\tfalse\t\tpanel\tunconfined\t\tseccomp=unconfined;\n" +
		"/plain\tfalse\t\t\tdocker-default\t" + labelled + "\t\n"
	run.respond[dockerSecurity] = selinuxDocker
	risky, unconfined := executor.riskyContainers(context.Background())
	if len(risky) != 0 || !slices.Equal(unconfined, []string{"armor (AppArmor)", "filters (seccomp)", "label (SELinux)"}) {
		t.Fatalf("risky %q unconfined %q", risky, unconfined)
	}

	run.respond[dockerSecurity] = `["name=apparmor","name=seccomp,profile=builtin"]`
	if _, unconfined := executor.riskyContainers(context.Background()); !slices.Equal(unconfined, []string{"armor (AppArmor)", "filters (seccomp)"}) {
		t.Fatalf("an empty label means nothing while Docker runs without SELinux: %q", unconfined)
	}
}
