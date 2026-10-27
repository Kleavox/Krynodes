package network

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func freeUDPPort(t *testing.T) int {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	return socket.LocalAddr().(*net.UDPAddr).Port
}

func TestAProbeHearsOnlyTheProbesOfItsPeers(t *testing.T) {
	first, second := freeUDPPort(t), freeUDPPort(t)
	peer := func(port int) []netip.AddrPort {
		return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))}
	}
	var wait sync.WaitGroup
	results := make([][]string, 2)
	listened := make([]bool, 2)
	for index, ports := range [][2]int{{first, second}, {second, first}} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index], listened[index] = Probe(context.Background(), peer(ports[0])[0], peer(ports[1]), 600*time.Millisecond)
		}()
	}
	time.Sleep(100 * time.Millisecond)
	stranger, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: first})
	if err == nil {
		stranger.Write([]byte(strings.Repeat("x", 32)))
		stranger.Close()
	}
	wait.Wait()
	for index := range results {
		if !listened[index] || strings.Join(results[index], ",") != "127.0.0.1" {
			t.Fatalf("probe %d heard %v (listened %v)", index, results[index], listened[index])
		}
	}
}

func TestAProbeOnATakenPortOnlySends(t *testing.T) {
	taken, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	heard, listened := Probe(context.Background(), taken.LocalAddr().(*net.UDPAddr).AddrPort(), nil, 50*time.Millisecond)
	if listened || len(heard) != 0 {
		t.Fatalf("heard %v listened %v", heard, listened)
	}
}

func TestProbeArgsAreLimited(t *testing.T) {
	peers := func(count, port int) string {
		list := make([]string, count)
		for index := range list {
			list[index] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(index + 1)}), uint16(port)).String()
		}
		return strings.Join(list, " ")
	}
	if port, list, err := ProbeArgs(map[string]string{"port": "51821", "peers": peers(16, 51820)}); err != nil || port != 51821 || len(list) != 16 {
		t.Fatalf("port %d peers %d err %v", port, len(list), err)
	}
	for name, args := range map[string]map[string]string{
		"17 peers":        {"port": "51820", "peers": peers(17, 51820)},
		"a peer on 53":    {"port": "51820", "peers": peers(1, 53)},
		"a port on 52000": {"port": "52000", "peers": peers(1, 51820)},
		"no peers":        {"port": "51820", "peers": ""},
		"a name":          {"port": "51820", "peers": "vps-1.example.com:51820"},
		"another field":   {"port": "51820", "peers": peers(1, 51820), "extra": "x"},
	} {
		if _, _, err := ProbeArgs(args); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestPrepareAndTestArgsAreLimited(t *testing.T) {
	if network, port, err := PrepareArgs(map[string]string{"range": "10.88.3.0/24", "port": "51821"}); err != nil || network != "10.88.3.0/24" || port != 51821 {
		t.Fatalf("%s %d %v", network, port, err)
	}
	for _, args := range []map[string]string{
		{"range": "10.0.0.0/24", "port": "51820"},
		{"range": "10.88.0.0/16", "port": "51820"},
		{"range": "10.88.0.5/24", "port": "51820"},
		{"range": "10.88.0.0/24", "port": "53"},
		{"range": "10.88.0.0/24"},
	} {
		if _, _, err := PrepareArgs(args); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
	if peer, address, mtu, err := LinkTestArgs(map[string]string{"peer": nodeA, "address": "10.88.0.1", "mtu": "1420"}); err != nil || peer != nodeA || address != "10.88.0.1" || mtu != 1420 {
		t.Fatalf("%s %s %d %v", peer, address, mtu, err)
	}
	for _, args := range []map[string]string{
		{"peer": nodeA, "address": "8.8.8.8", "mtu": "1420"},
		{"peer": nodeA, "address": "10.88.0.1", "mtu": "9000"},
		{"peer": "x; rm -rf /", "address": "10.88.0.1", "mtu": "1420"},
		{"peer": nodeA, "address": "10.88.0.1 -f", "mtu": "1420"},
	} {
		if _, _, _, err := LinkTestArgs(args); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
}
