package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

type Runner func(ctx context.Context, name string, args ...string) ([]byte, int, error)

type Kernel struct {
	OK      bool    `json:"ok"`
	Version *string `json:"version"`
	Reason  *string `json:"reason"`
}

type Other struct {
	Name    string  `json:"name"`
	Address *string `json:"address"`
	Port    *int    `json:"port"`
}

type Inspect struct {
	Kernel Kernel   `json:"kernel"`
	Tools  bool     `json:"tools"`
	Used   []string `json:"used"`
	Others []Other  `json:"others"`
	Port   *int     `json:"port"`
	MTU    *int     `json:"mtu"`
	taken  []int
}

func (i Inspect) Free(port int) bool {
	return validPort(port) && !slices.Contains(i.taken, port)
}

type link struct {
	Name     string `json:"ifname"`
	MTU      int    `json:"mtu"`
	LinkInfo struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
	Addresses []struct {
		Family string `json:"family"`
		Local  string `json:"local"`
		Prefix int    `json:"prefixlen"`
	} `json:"addr_info"`
}

func exists(root, name string) bool {
	_, err := os.Stat(filepath.Join(root, filepath.FromSlash(name)))
	return err == nil
}

func Read(ctx context.Context, root string, run Runner) Inspect {
	found := Inspect{Kernel: kernel(ctx, root, run), Tools: exists(root, "/usr/bin/wg") || exists(root, "/usr/sbin/wg"), Used: []string{}, Others: []Other{}}
	var links []link
	if output, _, err := run(ctx, "ip", "-d", "-j", "addr", "show"); err == nil {
		json.Unmarshal(output, &links)
	}
	ports := map[string]int{}
	if found.Tools {
		if output, _, err := run(ctx, "wg", "show", "all", "listen-port"); err == nil {
			for _, line := range strings.Split(string(output), "\n") {
				if fields := strings.Fields(line); len(fields) == 2 {
					ports[fields[0]], _ = strconv.Atoi(fields[1])
				}
			}
		}
	}
	taken := udpPorts(ctx, run)
	for _, entry := range links {
		if entry.Name == "lo" || entry.Name == Interface {
			continue
		}
		var addresses []string
		for _, address := range entry.Addresses {
			if address.Family == "inet" {
				addresses = append(addresses, fmt.Sprintf("%s/%d", address.Local, address.Prefix))
			}
		}
		found.Used = append(found.Used, addresses...)
		if entry.LinkInfo.Kind != "wireguard" {
			continue
		}
		other := Other{Name: entry.Name}
		if len(addresses) > 0 {
			other.Address = &addresses[0]
		}
		if port, ok := ports[entry.Name]; ok {
			other.Port = &port
			taken = append(taken, port)
		}
		found.Others = append(found.Others, other)
	}
	found.Used = append(found.Used, dockerSubnets(ctx, run)...)
	found.taken = taken
	if port, ok := ports[Interface]; ok {
		found.Port = &port
	} else if port, err := FreePort(taken); err == nil {
		found.Port = &port
	}
	found.MTU = uplinkMTU(ctx, run, links)
	return found
}

func kernel(ctx context.Context, root string, run Runner) Kernel {
	var found Kernel
	if release, err := os.ReadFile(filepath.Join(root, "proc", "sys", "kernel", "osrelease")); err == nil {
		version := strings.TrimSpace(string(release))
		found.Version = &version
	}
	if exists(root, "/sys/module/wireguard") {
		found.OK = true
		return found
	}
	if _, _, err := run(ctx, "modprobe", "-n", "-q", "wireguard"); err == nil {
		found.OK = true
		return found
	}
	reason := "missing"
	virt, _, _ := run(ctx, "systemd-detect-virt", "--container")
	if exists(root, "/proc/vz") || exists(root, "/proc/user_beancounters") || (len(virt) > 0 && strings.TrimSpace(string(virt)) != "none") {
		reason = "container"
	}
	found.Reason = &reason
	return found
}

func dockerSubnets(ctx context.Context, run Runner) []string {
	ids, _, err := run(ctx, "docker", "network", "ls", "-q")
	if err != nil || len(strings.Fields(string(ids))) == 0 {
		return nil
	}
	output, _, err := run(ctx, "docker", append([]string{"network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}"}, strings.Fields(string(ids))...)...)
	if err != nil {
		return nil
	}
	var subnets []string
	for _, field := range strings.Fields(string(output)) {
		if prefix, err := netip.ParsePrefix(field); err == nil && prefix.Addr().Is4() {
			subnets = append(subnets, field)
		}
	}
	return subnets
}

func udpPorts(ctx context.Context, run Runner) []int {
	output, _, err := run(ctx, "ss", "-lunH")
	if err != nil {
		return nil
	}
	var ports []int
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		local := fields[3]
		if port, err := strconv.Atoi(local[strings.LastIndex(local, ":")+1:]); err == nil {
			ports = append(ports, port)
		}
	}
	return ports
}

func uplinkMTU(ctx context.Context, run Runner, links []link) *int {
	devices := map[string]bool{}
	for _, family := range [][]string{{"-j"}, {"-j", "-6"}} {
		output, _, err := run(ctx, "ip", append(family, "route", "show", "default")...)
		if err != nil {
			continue
		}
		var routes []struct {
			Device string `json:"dev"`
		}
		json.Unmarshal(output, &routes)
		for _, route := range routes {
			devices[route.Device] = true
		}
	}
	var smallest *int
	for _, entry := range links {
		if devices[entry.Name] && entry.MTU > 0 && (smallest == nil || entry.MTU < *smallest) {
			mtu := entry.MTU
			smallest = &mtu
		}
	}
	return smallest
}

func Clashes(network string, used []string) bool {
	wanted, err := netip.ParsePrefix(network)
	if err != nil {
		return true
	}
	for _, entry := range used {
		if prefix, err := netip.ParsePrefix(entry); err == nil && prefix.Overlaps(wanted) {
			return true
		}
	}
	return false
}

func FreePort(taken []int) (int, error) {
	busy := map[int]bool{}
	for _, port := range taken {
		busy[port] = true
	}
	for port := FirstPort; port <= LastPort; port++ {
		if !busy[port] {
			return port, nil
		}
	}
	return 0, errors.New("no UDP port is free between 51820 and 51919")
}
