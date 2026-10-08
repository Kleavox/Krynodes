package actions

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

func inventoryOf(services []Service, now time.Time) (Inventory, error) {
	return NewInventory(Parts{Services: services}, now)
}

const unitList = `nginx.service                 loaded    active   running A high performance web server
shadowsocks-libev.service     loaded    inactive dead    Shadowsocks-libev Default Server Service
● adguard.service             loaded    failed   failed  AdGuard Home
ssh.service                   loaded    active   running OpenBSD Secure Shell server
cron.service                  loaded    active   running Regular background program processing daemon
old.service                   loaded    inactive dead    Something disabled
ghost.service                 not-found inactive dead    ghost.service
backup.service                loaded    activating start Nightly backup
`

const enabledList = `nginx.service enabled enabled
shadowsocks-libev.service enabled enabled
`

func TestUnitsBecomeServices(t *testing.T) {
	got := parseUnits(unitList, enabledList, nil)
	want := []Service{
		{Kind: "systemd", Name: "nginx.service", State: "running"},
		{Kind: "systemd", Name: "shadowsocks-libev.service", State: "stopped"},
		{Kind: "systemd", Name: "adguard.service", State: "failed"},
		{Kind: "systemd", Name: "cron.service", State: "running", System: true},
		{Kind: "systemd", Name: "backup.service", State: "starting"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("units\n got %#v\nwant %#v", got, want)
	}
}

func TestContainersBecomeServices(t *testing.T) {
	got, stacks := parseContainers("adguard\trunning\nweb,web/alias\texited\nbroken\tdead\nbad/name\trunning\nwarming\trestarting\n\n")
	if len(stacks) != 0 {
		t.Fatalf("containers without compose labels form no stack, got %#v", stacks)
	}
	want := []Service{
		{Kind: "docker", Name: "adguard", State: "running"},
		{Kind: "docker", Name: "web", State: "stopped"},
		{Kind: "docker", Name: "broken", State: "failed"},
		{Kind: "docker", Name: "warming", State: "starting"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("containers\n got %#v\nwant %#v", got, want)
	}
}

func TestTheHashIgnoresOrderButNotState(t *testing.T) {
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	a := []Service{{Kind: "docker", Name: "b", State: "running"}, {Kind: "systemd", Name: "a.service", State: "running"}}
	b := []Service{a[1], a[0]}
	first, _ := inventoryOf(a, now)
	second, _ := inventoryOf(b, now)
	if first.Hash != second.Hash || len(first.Hash) != 64 {
		t.Fatalf("hashes differ: %s %s", first.Hash, second.Hash)
	}
	if first.Services[0].Kind != "docker" || first.TakenAt != "2026-09-29T10:00:00Z" {
		t.Fatalf("unexpected inventory %#v", first)
	}
	changed, _ := inventoryOf([]Service{{Kind: "docker", Name: "b", State: "stopped"}, a[1]}, now)
	if changed.Hash == first.Hash {
		t.Fatal("a state change must change the hash")
	}
	empty, _ := inventoryOf(nil, now)
	if empty.Services == nil {
		t.Fatal("an empty inventory must encode as a list")
	}
}

func TestCollectSurvivesAMissingDocker(t *testing.T) {
	var calls []string
	run := func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		switch {
		case name == "docker":
			return nil, -1, errors.New("executable file not found")
		case args[0] == "list-units":
			return []byte(unitList), 0, nil
		default:
			return []byte(enabledList), 0, nil
		}
	}
	snapshot, err := Collect(context.Background(), run, nil)
	if err != nil || len(snapshot.Services) != 5 || snapshot.Compose || snapshot.Docker != "missing" {
		t.Fatalf("collect: %#v, err %v", snapshot, err)
	}
	if calls[2] != "docker ps -a --no-trunc --format "+containerFormat || len(calls) != 3 {
		t.Fatalf("unexpected docker calls %q", calls[2:])
	}
}

func TestCollectFailsWithoutSystemd(t *testing.T) {
	run := func(context.Context, string, ...string) ([]byte, int, error) {
		return nil, -1, errors.New("no systemctl")
	}
	if _, err := Collect(context.Background(), run, nil); err == nil {
		t.Fatal("expected an error")
	}
}

func TestCollectListsEveryUnitFileState(t *testing.T) {
	var calls []string
	run := func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, 0, nil
	}
	if _, err := Collect(context.Background(), run, nil); err != nil {
		t.Fatal(err)
	}
	if calls[1] != "systemctl list-unit-files --type=service --no-legend --plain --no-pager" {
		t.Fatalf("unexpected unit file call %q", calls[1])
	}
}

func TestUnitsStoppedThroughKrynodesStayListed(t *testing.T) {
	files := "nginx.service enabled enabled\nmanual.service static -\nopenvpn@.service disabled enabled\n"
	got := parseUnits(unitList, files, []string{"manual.service", "openvpn@server.service", "gone.service", "nginx.service", "ssh.service"})
	want := []Service{
		{Kind: "systemd", Name: "nginx.service", State: "running"},
		{Kind: "systemd", Name: "adguard.service", State: "failed"},
		{Kind: "systemd", Name: "cron.service", State: "running", System: true},
		{Kind: "systemd", Name: "backup.service", State: "starting"},
		{Kind: "systemd", Name: "manual.service", State: "stopped"},
		{Kind: "systemd", Name: "openvpn@server.service", State: "stopped"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("units\n got %#v\nwant %#v", got, want)
	}
}

func TestCollectGivesUpOnAHungDocker(t *testing.T) {
	previous := collectTimeout
	collectTimeout = 50 * time.Millisecond
	defer func() { collectTimeout = previous }()
	run := func(ctx context.Context, name string, args ...string) ([]byte, int, error) {
		if name == "docker" {
			<-ctx.Done()
			return nil, -1, ctx.Err()
		}
		if args[0] == "list-units" {
			return []byte(unitList), 0, nil
		}
		return []byte(enabledList), 0, nil
	}
	done := make(chan int, 1)
	go func() {
		snapshot, _ := Collect(context.Background(), run, nil)
		done <- len(snapshot.Services)
	}()
	select {
	case count := <-done:
		if count != 5 {
			t.Fatalf("expected the 5 units without containers, got %d", count)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Collect must not wait on a hung docker")
	}
}

func TestAnInventoryKeepsAtMost500ServicesPreferringYourOwn(t *testing.T) {
	var services []Service
	for index := range 400 {
		services = append(services, Service{Kind: "systemd", Name: fmt.Sprintf("s%03d.service", index), State: "running", System: true})
	}
	for index := range 200 {
		services = append(services, Service{Kind: "docker", Name: fmt.Sprintf("c%03d", index), State: "stopped"})
	}
	inventory, err := inventoryOf(services, executorNow)
	if err != nil {
		t.Fatal(err)
	}
	own := 0
	for _, service := range inventory.Services {
		if !service.System {
			own++
		}
	}
	if len(inventory.Services) != 500 || own != 200 {
		t.Fatalf("expected 500 services with all 200 of your own, got %d and %d", len(inventory.Services), own)
	}
}

func TestAnInventoryListsAtMost50RemovedStacksTheNewestFirst(t *testing.T) {
	var removed []reporter.RemovedStack
	for index := range 60 {
		removed = append(removed, reporter.RemovedStack{Project: fmt.Sprintf("s%02d", index), Directory: "/opt/s", RemovedAt: executorNow.Add(time.Duration(index) * time.Minute).Format(time.RFC3339)})
	}
	inventory, err := NewInventory(Parts{Removed: removed}, executorNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Removed) != 50 || inventory.Removed[0].Project != "s59" || inventory.Removed[49].Project != "s10" {
		t.Fatalf("removed %d, first %q, last %q", len(inventory.Removed), inventory.Removed[0].Project, inventory.Removed[len(inventory.Removed)-1].Project)
	}
}

const composeContainers = "listmonk_db\texited\tlistmonk\t/opt/listmonk\t/opt/listmonk/docker-compose.yaml\t2026-09-25 11:37:02 +0700 WIB\n" +
	"listmonk_app\trunning\tlistmonk\t/opt/listmonk\t/opt/listmonk/docker-compose.yml,/opt/listmonk/a-override.yml\t2026-09-25 11:56:10 +0700 +0700\n" +
	"adguard\trunning\t\t\t\t2026-09-20 08:00:00 +0700 WIB\n"

func TestAStackUsesTheNewestContainersComposeFilesInTheirOrder(t *testing.T) {
	services, stacks := parseContainers(composeContainers)
	if len(services) != 3 {
		t.Fatalf("services %#v", services)
	}
	want := []Stack{{
		Project: "listmonk", Directory: "/opt/listmonk",
		Files:   []string{"/opt/listmonk/docker-compose.yml", "/opt/listmonk/a-override.yml"},
		Running: 1, Total: 2,
	}}
	if !reflect.DeepEqual(stacks, want) {
		t.Fatalf("stacks\n got %#v\nwant %#v", stacks, want)
	}
}

func TestAStackWithARelativeDirectoryIsLeftOut(t *testing.T) {
	_, stacks := parseContainers("app\trunning\tshop\tshop\t/opt/shop/compose.yml\nweb\trunning\tsite\t/srv/site\tsite/compose.yml\n")
	if len(stacks) != 0 {
		t.Fatalf("relative paths must be left out, got %#v", stacks)
	}
}

func TestAnInvalidProjectIsLeftOut(t *testing.T) {
	_, stacks := parseContainers("app\trunning\tShop\t/opt/shop\t/opt/shop/compose.yml\nweb\trunning\t-x\t/opt/x\t/opt/x/compose.yml\n")
	if len(stacks) != 0 {
		t.Fatalf("invalid projects must be left out, got %#v", stacks)
	}
}

func TestDockerStateIsReportedEvenWithoutAStack(t *testing.T) {
	for _, item := range []struct {
		docker, compose bool
		want            string
	}{
		{true, true, "ready"},
		{true, false, "no-compose"},
		{false, false, "missing"},
	} {
		run := func(_ context.Context, name string, args ...string) ([]byte, int, error) {
			if name == "docker" && args[0] == "compose" {
				if item.compose {
					return []byte("Docker Compose version v2.29.1"), 0, nil
				}
				return nil, 1, errors.New("unknown command compose")
			}
			if name == "docker" {
				if item.docker {
					return []byte("adguard\trunning\t\t\t\t2026-09-30 10:00:00 +0000 UTC\n"), 0, nil
				}
				return nil, -1, errors.New("executable file not found")
			}
			return nil, 0, nil
		}
		snapshot, err := Collect(context.Background(), run, nil)
		if err != nil || snapshot.Docker != item.want || snapshot.Compose != item.compose {
			t.Fatalf("%s: %#v err %v", item.want, snapshot, err)
		}
	}
}

func TestComposeAvailabilityIsReported(t *testing.T) {
	for _, available := range []bool{true, false} {
		run := func(_ context.Context, name string, args ...string) ([]byte, int, error) {
			if name == "docker" && args[0] == "compose" {
				if available {
					return []byte("Docker Compose version v2.29.1"), 0, nil
				}
				return nil, 1, errors.New("unknown command compose")
			}
			if name == "docker" {
				return []byte(composeContainers), 0, nil
			}
			return nil, 0, nil
		}
		snapshot, err := Collect(context.Background(), run, nil)
		if err != nil || snapshot.Compose != available || len(snapshot.Stacks) != 1 {
			t.Fatalf("available %v: %#v err %v", available, snapshot, err)
		}
	}
}

func TestTheInventoryHashChangesWhenDockerChanges(t *testing.T) {
	first, _ := NewInventory(Parts{Docker: "missing"}, executorNow)
	second, _ := NewInventory(Parts{Docker: "ready"}, executorNow)
	if first.Hash == second.Hash || second.Docker != "ready" {
		t.Fatalf("docker must be part of the inventory: %#v %#v", first, second)
	}
}

func TestTheInventoryHashChangesWhenAStackIsRemoved(t *testing.T) {
	first, _ := NewInventory(Parts{Docker: "ready"}, executorNow)
	second, _ := NewInventory(Parts{Docker: "ready", Removed: []reporter.RemovedStack{{Project: "kuma", Directory: "/opt/kuma", RemovedAt: "2026-09-29T10:00:00Z"}}}, executorNow)
	if first.Hash == second.Hash || len(second.Removed) != 1 {
		t.Fatalf("removed stacks must be part of the inventory: %#v", second)
	}
}

func TestTheInventoryHashChangesWhenAStackChanges(t *testing.T) {
	stack := reporter.StackEntry{Project: "listmonk", Directory: "/opt/listmonk", Running: 5, Total: 5, Compose: true}
	first, _ := NewInventory(Parts{Stacks: []reporter.StackEntry{stack}}, executorNow)
	stack.Running = 4
	second, _ := NewInventory(Parts{Stacks: []reporter.StackEntry{stack}}, executorNow)
	if first.Hash == second.Hash {
		t.Fatal("a stack change must change the hash")
	}
}

func TestTheSealKeyIsPartOfTheInventory(t *testing.T) {
	first, _ := NewInventory(Parts{SealKey: "first"}, executorNow)
	second, _ := NewInventory(Parts{SealKey: "second"}, executorNow)
	if first.Hash == second.Hash || first.SealKey != "first" {
		t.Fatalf("the seal key must be reported: %#v", first)
	}
}
