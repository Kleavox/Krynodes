package network

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRun struct {
	calls   []string
	respond map[string]string
}

func (f *fakeRun) run(_ context.Context, name string, args ...string) ([]byte, int, error) {
	call := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.calls = append(f.calls, call)
	if answer, ok := f.respond[call]; ok {
		return []byte(answer), 0, nil
	}
	return nil, 1, errors.New("exit status 1")
}

const addresses = `[
 {"ifname":"lo","mtu":65536,"addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]},
 {"ifname":"eth0","mtu":1500,"addr_info":[{"family":"inet","local":"203.0.113.21","prefixlen":24},{"family":"inet6","local":"2001:db8::1","prefixlen":64}]},
 {"ifname":"wg0","mtu":1420,"linkinfo":{"info_kind":"wireguard"},"addr_info":[{"family":"inet","local":"10.0.0.1","prefixlen":24}]},
 {"ifname":"tailscale0","mtu":1280,"linkinfo":{"info_kind":"tun"},"addr_info":[{"family":"inet","local":"100.101.1.2","prefixlen":32}]},
 {"ifname":"docker0","mtu":1500,"linkinfo":{"info_kind":"bridge"},"addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16}]}
]`

func serverWithWg0(t *testing.T) (string, *fakeRun) {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"sys/module/wireguard", "usr/bin"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(root, "usr/bin/wg"), nil, 0o755)
	os.MkdirAll(filepath.Join(root, "proc/sys/kernel"), 0o755)
	os.WriteFile(filepath.Join(root, "proc/sys/kernel/osrelease"), []byte("6.1.0-27-amd64\n"), 0o644)
	return root, &fakeRun{respond: map[string]string{
		"ip -d -j addr show":          []string{addresses}[0],
		"ip -j route show default":    `[{"dst":"default","gateway":"203.0.113.1","dev":"eth0"}]`,
		"ip -j -6 route show default": `[]`,
		"docker network ls -q":        "a1\nb2\n",
		"docker network inspect --format {{range .IPAM.Config}}{{.Subnet}} {{end}} a1 b2": "172.17.0.0/16 \n10.88.0.0/24 fd00:1::/64 \n",
		"ss -lunH":                "UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\nUNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\nUNCONN 0 0 [::]:41641 [::]:*\n",
		"wg show all listen-port": "wg0\t51820\n",
	}}
}

func TestInspectLeavesAHandMadeWg0AloneAndSaysWhatItUses(t *testing.T) {
	root, run := serverWithWg0(t)
	found := Read(context.Background(), root, run.run)
	if !found.Kernel.OK || found.Kernel.Version == nil || *found.Kernel.Version != "6.1.0-27-amd64" || found.Kernel.Reason != nil || !found.Tools {
		t.Fatalf("kernel %+v tools %v", found.Kernel, found.Tools)
	}
	if strings.Join(found.Used, " ") != "203.0.113.21/24 10.0.0.1/24 100.101.1.2/32 172.17.0.1/16 172.17.0.0/16 10.88.0.0/24" {
		t.Fatalf("used %v", found.Used)
	}
	if len(found.Others) != 1 || found.Others[0].Name != "wg0" || *found.Others[0].Address != "10.0.0.1/24" || *found.Others[0].Port != 51820 {
		t.Fatalf("others %+v", found.Others)
	}
	if found.Port == nil || *found.Port != 51821 || found.MTU == nil || *found.MTU != 1500 {
		t.Fatalf("port %v mtu %v", found.Port, found.MTU)
	}
	for _, call := range run.calls {
		if strings.Contains(call, "wg0") {
			t.Fatalf("inspect named wg0: %s", call)
		}
	}
}

func TestAKernelWithoutWireGuardSaysWhy(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "proc/vz"), 0o755)
	found := Read(context.Background(), root, (&fakeRun{}).run)
	if found.Kernel.OK || found.Kernel.Reason == nil || *found.Kernel.Reason != "container" || found.Tools || found.Port == nil || *found.Port != 51820 || found.MTU != nil {
		t.Fatalf("found %+v", found)
	}
}

func TestARangeClashesWithAnythingItOverlaps(t *testing.T) {
	used := []string{"203.0.113.21/24", "10.0.0.1/24", "100.101.1.2/32", "172.17.0.0/16", "10.88.0.0/24"}
	if !Clashes("10.88.0.0/24", used) || !Clashes("10.88.5.0/24", []string{"10.88.0.0/16"}) {
		t.Fatal("an overlapping range is free")
	}
	if Clashes("10.88.1.0/24", used) || Clashes("10.88.1.0/24", []string{"not a range"}) {
		t.Fatal("a free range clashes")
	}
}

func TestThePortSkipsWhatIsTaken(t *testing.T) {
	if port, err := FreePort([]int{51820, 51821, 53}); err != nil || port != 51822 {
		t.Fatalf("port %d err %v", port, err)
	}
	all := []int{}
	for port := FirstPort; port <= LastPort; port++ {
		all = append(all, port)
	}
	if _, err := FreePort(all); err == nil {
		t.Fatal("a full range gave a port")
	}
}
