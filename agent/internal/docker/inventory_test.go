package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const unitList = `nginx.service                 loaded    active   running A high performance web server
shadowsocks-libev.service     loaded    inactive dead    Shadowsocks-libev Default Server Service
● resolver.service             loaded    failed   failed  Resolver
ssh.service                   loaded    active   running OpenBSD Secure Shell server
cron.service                  loaded    active   running Regular background program processing daemon
systemd-journald.service      loaded    active   running Journal Service
getty@tty1.service            loaded    active   running Getty on tty1
old.service                   loaded    inactive dead    Something disabled
ghost.service                 not-found inactive dead    ghost.service
backup.service                loaded    activating start Nightly backup
flaky.service                 loaded    activating auto-restart Crashing
mount-data\x2dbackup.service  loaded    active   running Escaped name
docker.service                loaded    active   running Docker Application Container Engine
`

const enabledList = `nginx.service enabled enabled
shadowsocks-libev.service enabled enabled
keyboard-setup.service enabled enabled
`

const composeContainers = "web-app-1\trunning\tUp 2 hours (healthy)\tghcr.io/example/app:1.4.2\t127.0.0.1:8080->80/tcp, 80/tcp\tweb\t/opt/web\tapp\n" +
	"web-db-1\texited\tExited (0) 3 hours ago\tpostgres:16\t\tweb\t/opt/web\tdb\n" +
	"legacy-api-1\trunning\tUp 5 minutes\texample/api:latest\t\tlegacy\t/srv/legacy\tapi\n" +
	"tools\trestarting\tRestarting (1) 4 seconds ago\tbusybox\t\t\t\t\n" +
	"Shop-1\trunning\tUp 1 minute\tbusybox\t\tShop\t/opt/shop\tweb\n" +
	"split-a-1\trunning\tUp 1 minute\tbusybox\t\tsplit\t/opt/split\ta\n" +
	"split-b-1\trunning\tUp 1 minute\tbusybox\t\tsplit\t/opt/elsewhere\tb\n" +
	"bad/name\trunning\tUp 1 minute\tbusybox\t\t\t\t\n"

type fake struct {
	containers string
	docker     error
	units      string
	calls      []string
}

func (f *fake) run(_ context.Context, name string, args ...string) ([]byte, int, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	switch {
	case name == "docker" && f.docker != nil:
		return nil, -1, f.docker
	case name == "docker" && args[0] == "ps":
		return []byte(f.containers), 0, nil
	case name == "docker":
		return []byte("2.29.1\n"), 0, nil
	case args[0] == "list-units":
		return []byte(f.units), 0, nil
	default:
		return []byte(enabledList), 0, nil
	}
}

func text(value string) *string { return &value }

func TestCollectReadsStacksFromComposeLabels(t *testing.T) {
	f := &fake{containers: composeContainers}
	meta := Meta{
		Stack: func(project, directory string) StackMeta {
			if project != "web" || directory != "/opt/web" {
				return StackMeta{}
			}
			return StackMeta{Own: true, Access: text("contained"), Title: text("Web"), Network: []int{8080, 0, 70000}, Rollback: true}
		},
		Removed: func() []reporter.RemovedEntry {
			return []reporter.RemovedEntry{{Project: "old", RemovedAt: "2026-11-20T08:30:00Z"}, {Project: "Bad", RemovedAt: "2026-11-21T08:30:00Z"}, {Project: "newer", RemovedAt: "2026-11-22T08:30:00Z"}}
		},
	}
	inventory, err := collectInventory(context.Background(), f.run, meta)
	if err != nil {
		t.Fatal(err)
	}
	want := []reporter.StackEntry{
		{Project: "legacy", Directory: "/srv/legacy", Running: 1, Total: 1, Network: []int{}, Services: []reporter.StackService{{Service: "api", Container: "legacy-api-1"}}},
		{Project: "web", Title: text("Web"), Directory: "/opt/web", Own: true, Access: text("contained"), Running: 1, Total: 2, Rollback: true, Network: []int{8080},
			Services: []reporter.StackService{{Service: "app", Container: "web-app-1"}, {Service: "db", Container: "web-db-1"}}},
	}
	if !reflect.DeepEqual(inventory.Stacks, want) {
		t.Fatalf("stacks\n got %+v\nwant %+v", inventory.Stacks, want)
	}
	if inventory.Docker != "ready" || inventory.Compose == nil || *inventory.Compose != "2.29.1" {
		t.Fatalf("docker %q compose %v", inventory.Docker, inventory.Compose)
	}
	names := []string{}
	for _, container := range inventory.Containers {
		names = append(names, container.Name)
	}
	if strings.Join(names, " ") != "Shop-1 legacy-api-1 split-a-1 split-b-1 tools web-app-1 web-db-1" {
		t.Fatalf("containers %v", names)
	}
	app := inventory.Containers[5]
	if *app.Project != "web" || *app.Service != "app" || app.State != "running" || *app.Health != "healthy" || !reflect.DeepEqual(app.Ports, []string{"127.0.0.1:8080->80/tcp"}) {
		t.Fatalf("app %+v", app)
	}
	if shop := inventory.Containers[0]; shop.Project != nil || shop.Service != nil {
		t.Fatalf("a project the Worker refuses leaves the container loose: %+v", shop)
	}
	if tools := inventory.Containers[4]; tools.State != "restarting" || tools.Project != nil || tools.Ports == nil {
		t.Fatalf("tools %+v", tools)
	}
	if !reflect.DeepEqual(inventory.Removed, []reporter.RemovedEntry{{Project: "newer", RemovedAt: "2026-11-22T08:30:00Z"}, {Project: "old", RemovedAt: "2026-11-20T08:30:00Z"}}) {
		t.Fatalf("removed %+v", inventory.Removed)
	}
	if len(inventory.Hash) != 64 || inventory.Type != "inventory" {
		t.Fatalf("inventory %+v", inventory)
	}
}

func TestStacksWithoutMetaAreNotOwned(t *testing.T) {
	inventory, err := collectInventory(context.Background(), (&fake{containers: composeContainers}).run, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	for _, stack := range inventory.Stacks {
		if stack.Own || stack.Access != nil || stack.Title != nil || stack.Rollback || stack.Network == nil || len(stack.Network) != 0 {
			t.Fatalf("stack %+v", stack)
		}
	}
	if inventory.Removed == nil || len(inventory.Removed) != 0 {
		t.Fatalf("removed %+v", inventory.Removed)
	}
}

func collectInventory(ctx context.Context, run Runner, meta Meta) (reporter.Inventory, error) {
	inventory, _, err := collect(ctx, run, meta)
	return inventory, err
}

func TestATitleIsSentOnlyWhenTheWorkerWouldTakeIt(t *testing.T) {
	for title, kept := range map[string]bool{"Web": true, "Web shop": true, "\uFEFFWeb": false, "Web\uFEFF": false, " Web": false, "Web\u00a0": false, "We\tb": false, "": false} {
		stack := reporter.StackEntry{Network: []int{}}
		described(&stack, StackMeta{Title: &title})
		if (stack.Title != nil) != kept {
			t.Errorf("%q kept %v", title, stack.Title != nil)
		}
	}
}

func TestUnitsListOnlyNonSystemUnitsAndMarkProtected(t *testing.T) {
	inventory, err := collectInventory(context.Background(), (&fake{docker: &exec.Error{Name: "docker", Err: exec.ErrNotFound}, units: unitList}).run, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	want := []reporter.UnitEntry{
		{Name: "backup.service", State: "stopped"},
		{Name: "docker.service", State: "running", Protected: true},
		{Name: "flaky.service", State: "failed"},
		{Name: "nginx.service", State: "running"},
		{Name: "resolver.service", State: "failed"},
		{Name: "shadowsocks-libev.service", State: "stopped"},
		{Name: "ssh.service", State: "running", Protected: true},
	}
	if !reflect.DeepEqual(inventory.Units, want) {
		t.Fatalf("units\n got %+v\nwant %+v", inventory.Units, want)
	}
}

func TestNoDockerReportsMissing(t *testing.T) {
	f := &fake{docker: &exec.Error{Name: "docker", Err: exec.ErrNotFound}, units: unitList}
	inventory, err := collectInventory(context.Background(), f.run, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Docker != "missing" || inventory.Compose != nil {
		t.Fatalf("docker %q compose %v", inventory.Docker, inventory.Compose)
	}
	encoded, _ := json.Marshal(inventory)
	for _, list := range []string{`"stacks":[]`, `"containers":[]`, `"removed":[]`} {
		if !strings.Contains(string(encoded), list) {
			t.Fatalf("%s missing from %s", list, encoded)
		}
	}
	stopped, err := collectInventory(context.Background(), (&fake{docker: errors.New("Cannot connect to the Docker daemon"), units: unitList}).run, Meta{})
	if err != nil || stopped.Docker != "stopped" || stopped.Compose != nil || len(stopped.Units) != 7 {
		t.Fatalf("stopped %+v, err %v", stopped, err)
	}
}

func TestAnInventoryNeverCarriesANullList(t *testing.T) {
	inventory, err := collectInventory(context.Background(), (&fake{}).run, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(inventory)
	if strings.Contains(string(encoded), "null") {
		t.Fatalf("an empty machine must send empty lists: %s", encoded)
	}
}

func TestNamesTheWorkerWouldRefuseAreLeftOutAndListsAreCapped(t *testing.T) {
	var containers, units strings.Builder
	for index := range 300 {
		fmt.Fprintf(&containers, "c-%03d\trunning\tUp\tbusybox\t\tbig\t/opt/big\ts%03d\n", index, index)
		fmt.Fprintf(&units, "u%03d.service loaded active running U\n", index)
	}
	for index := range 70 {
		fmt.Fprintf(&containers, "p-%03d\trunning\tUp\tbusybox\t\tp%03d\t/opt/p%03d\tweb\n", index, index, index)
	}
	containers.WriteString("x\trunning\tUp\tbusybox\t\t\t\t\n")
	units.WriteString("a\\x2db.service loaded active running Escaped\n")
	inventory, err := collectInventory(context.Background(), (&fake{containers: containers.String(), units: units.String()}).run, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Containers) != 256 || len(inventory.Units) != 256 || len(inventory.Stacks) != 64 {
		t.Fatalf("containers %d units %d stacks %d", len(inventory.Containers), len(inventory.Units), len(inventory.Stacks))
	}
	for _, stack := range inventory.Stacks {
		if stack.Project == "big" && (stack.Total != 300 || len(stack.Services) != 64) {
			t.Fatalf("big %d %d", stack.Total, len(stack.Services))
		}
	}
	for _, container := range inventory.Containers {
		if container.Name == "x" {
			t.Fatal("a one-letter container name is refused by the Worker")
		}
	}
	for _, unit := range inventory.Units {
		if strings.Contains(unit.Name, `\`) {
			t.Fatalf("unit %q", unit.Name)
		}
	}
}

func TestASkippedNameIsLoggedOnce(t *testing.T) {
	skippedMu.Lock()
	skipped = map[string]bool{}
	skippedMu.Unlock()
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	f := &fake{containers: "once/only\trunning\tUp\tbusybox\t\t\t\t\n", units: "once\\x2donly.service loaded active running U\n"}
	for range 3 {
		if _, err := collectInventory(context.Background(), f.run, Meta{}); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Count(logged.String(), `"once/only"`) != 1 || strings.Count(logged.String(), `once\\x2donly.service`) != 1 {
		t.Fatalf("logged %q", logged.String())
	}
}

func TestTheHashIgnoresNothingButItself(t *testing.T) {
	f := &fake{containers: composeContainers, units: unitList}
	first, _ := collectInventory(context.Background(), f.run, Meta{})
	second, _ := collectInventory(context.Background(), f.run, Meta{})
	if first.Hash != second.Hash {
		t.Fatal("the same machine must hash the same")
	}
	f.containers = strings.Replace(composeContainers, "web-db-1\texited", "web-db-1\trunning", 1)
	changed, _ := collectInventory(context.Background(), f.run, Meta{})
	if changed.Hash == first.Hash {
		t.Fatal("a state change must change the hash")
	}
}

func TestCollectFailsWithoutSystemdButKeepsDocker(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		if name == "systemctl" {
			return nil, -1, errors.New("no systemctl")
		}
		return (&fake{containers: composeContainers}).run(context.Background(), name, args...)
	}
	inventory, err := collectInventory(context.Background(), run, Meta{})
	if err == nil || inventory.Docker != "ready" || len(inventory.Containers) != 7 {
		t.Fatalf("inventory %+v err %v", inventory, err)
	}
}

func TestProtectedMatchesTheSharedFixture(t *testing.T) {
	raw, err := os.ReadFile("../../../packages/protocol/src/fixtures/targets.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Protected [][2]string `json:"protected"`
		Allowed   [][2]string `json:"allowed"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Protected) == 0 {
		t.Fatal("the fixture lists no protected targets")
	}
	for _, target := range fixture.Protected {
		if !Protected(target[0], target[1]) {
			t.Errorf("%s %s must be protected", target[0], target[1])
		}
	}
	for _, target := range fixture.Allowed {
		if (target[0] == "unit" || target[0] == "container") && Protected(target[0], target[1]) {
			t.Errorf("%s %s must not be protected", target[0], target[1])
		}
	}
}

func TestAManagedStackWithNoContainersStaysListed(t *testing.T) {
	meta := Meta{
		Stack: func(project, directory string) StackMeta {
			if project != "idle" || directory != "/var/lib/krynodes/compose/idle" {
				return StackMeta{}
			}
			return StackMeta{Own: true, Access: text("full"), Title: text("Idle"), Network: []int{9000}, Rollback: true}
		},
		Managed: func() map[string]string {
			return map[string]string{"idle": "/var/lib/krynodes/compose/idle", "web": "/opt/web", "Bad": "/var/lib/krynodes/compose/Bad", "loose": "relative"}
		},
	}
	inventory, err := collectInventory(context.Background(), (&fake{containers: composeContainers}).run, meta)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, stack := range inventory.Stacks {
		names = append(names, stack.Project)
	}
	if strings.Join(names, " ") != "idle legacy web" {
		t.Fatalf("stacks %v", names)
	}
	want := reporter.StackEntry{Project: "idle", Title: text("Idle"), Directory: "/var/lib/krynodes/compose/idle", Own: true, Access: text("full"), Rollback: true, Network: []int{9000}, Services: []reporter.StackService{}}
	if !reflect.DeepEqual(inventory.Stacks[0], want) {
		t.Fatalf("idle\n got %+v\nwant %+v", inventory.Stacks[0], want)
	}
	if web := inventory.Stacks[2]; web.Total != 2 {
		t.Fatalf("a folder listed again a stack docker already shows: %+v", web)
	}
}

func TestManagedStacksKeepTheStackCap(t *testing.T) {
	folders := map[string]string{}
	for index := range 70 {
		name := fmt.Sprintf("s%02d", index)
		folders[name] = "/var/lib/krynodes/compose/" + name
	}
	inventory, err := collectInventory(context.Background(), (&fake{docker: errors.New("Cannot connect to the Docker daemon"), units: unitList}).run, Meta{Managed: func() map[string]string { return folders }})
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Stacks) != 64 || inventory.Stacks[0].Project != "s00" || inventory.Stacks[63].Project != "s63" || inventory.Stacks[0].Total != 0 {
		t.Fatalf("stacks %d %+v", len(inventory.Stacks), inventory.Stacks[0])
	}
}
