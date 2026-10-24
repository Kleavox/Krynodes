package address

import (
	"net/netip"
	"reflect"
	"testing"
)

func addrs(texts ...string) []netip.Addr {
	parsed := make([]netip.Addr, 0, len(texts))
	for _, text := range texts {
		parsed = append(parsed, netip.MustParseAddr(text))
	}
	return parsed
}

func TestUsableKeepsWhatAServerCanBeReachedOn(t *testing.T) {
	links := []link{
		{name: "lo", up: true, loopback: true, addrs: addrs("127.0.0.1")},
		{name: "eth0", up: true, addrs: addrs("192.168.1.5", "fe80::1", "2001:db8::91c3", "ff02::1")},
		{name: "docker0", up: true, bridge: true, addrs: addrs("172.17.0.1")},
		{name: "vmbr0", up: true, bridge: true, addrs: addrs("51.79.0.10")},
		{name: "tailscale0", up: true, addrs: addrs("100.101.102.7")},
		{name: "wg1", addrs: addrs("10.9.0.1")},
	}
	want := []Interface{
		{Name: "eth0", Address: "192.168.1.5"},
		{Name: "eth0", Address: "2001:db8::91c3"},
		{Name: "vmbr0", Address: "51.79.0.10"},
		{Name: "tailscale0", Address: "100.101.102.7"},
	}
	if got := usable(links); !reflect.DeepEqual(got, want) {
		t.Fatalf("usable = %v", got)
	}
}
