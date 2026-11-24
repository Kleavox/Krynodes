package tray

import (
	"encoding/binary"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"github.com/Kleavox/krynodes/agent/windows/internal/pipe"
)

func on(value bool) *bool {
	return &value
}

func number(value int) *int {
	return &value
}

func titles(entries []entry, parent string) []string {
	var found []string
	for _, item := range entries {
		if item.Parent == parent && !item.Separator {
			found = append(found, item.Title)
		}
	}
	return found
}

func TestTheMenuFollowsTheApprovedOrder(t *testing.T) {
	status := pipe.Status{
		Joined: true, Connected: true, Name: "laptop-1", Address: "10.88.0.10", Exit: "s1", Dashboard: "https://kry.example.com", Fingerprint: "1A2B-3C4D-5E6F-7081",
		Exits: []pipe.Server{{Node: "s1", Name: "server-1", RTT: number(14)}, {Node: "s3", Name: "server-3"}},
		Servers: []pipe.Server{
			{Node: "s1", Name: "server-1", Address: "10.88.0.1", Online: on(true)},
			{Node: "s2", Name: "server-2", Address: "10.88.0.2", Via: "server-1", Online: on(false)},
			{Node: "s3", Name: "server-3", Address: "10.88.0.3"},
		},
	}
	entries := menu(status, true)
	if want := []string{"Connected", "This Laptop · laptop-1 · 10.88.0.10", "Exit Node · server-1", "Servers · 1 Reachable", "Fingerprint", "Open Dashboard", "Settings", "Quit"}; !slices.Equal(titles(entries, ""), want) {
		t.Fatalf("menu %q", titles(entries, ""))
	}
	if want := []string{"None", "server-1 · 14 ms", "server-3 · --", "Allow Local Network"}; !slices.Equal(titles(entries, "exit"), want) {
		t.Fatalf("exit node %q", titles(entries, "exit"))
	}
	if want := []string{"● server-1 · 10.88.0.1", "○ server-2 · 10.88.0.2 · via server-1", "– server-3 · 10.88.0.3", "Click a server to copy its address."}; !slices.Equal(titles(entries, "servers"), want) {
		t.Fatalf("servers %q", titles(entries, "servers"))
	}
	if want := []string{"Start with Windows", "Notify When a Server Goes Offline", "Update Agent"}; !slices.Equal(titles(entries, "settings"), want) {
		t.Fatalf("settings %q", titles(entries, "settings"))
	}
	for _, item := range entries {
		if strings.Contains(item.Title, "Send Stack") {
			t.Fatal("Send Stack to Server is Part E")
		}
		if item.Key == "connected" && (!item.Checked || item.Ask.Request != "disconnect") {
			t.Fatalf("connected %+v", item)
		}
		if item.Key == "exit:s3" && (item.Checked || *item.Ask.Server != "s3") {
			t.Fatalf("exit through server-3 %+v", item)
		}
	}
}

func TestALaptopWaitingForApprovalShowsItsFingerprint(t *testing.T) {
	entries := menu(pipe.Status{Connected: true, Fingerprint: "1A2B-3C4D-5E6F-7081"}, true)
	if want := []string{"Connected", "This laptop is not on the private network yet.", "Fingerprint", "Open Dashboard", "Settings", "Quit"}; !slices.Equal(titles(entries, ""), want) {
		t.Fatalf("menu %q", titles(entries, ""))
	}
	if !entries[0].Disabled || !entries[1].Disabled {
		t.Fatalf("header %+v", entries[:2])
	}
	index := slices.IndexFunc(entries, func(item entry) bool { return item.Key == "fingerprint" })
	if item := entries[index]; item.Disabled || item.Show != "This laptop's network fingerprint is 1A2B-3C4D-5E6F-7081. Approve it only if the dashboard shows the same one." || item.Copy != "" || item.Ask != nil {
		t.Fatalf("fingerprint %+v", item)
	}
	if item := menu(pipe.Status{}, true)[3]; item.Key != "fingerprint" || !item.Disabled {
		t.Fatalf("a laptop without keys %+v", item)
	}
}

func TestTheFirewallLineAndAMissingService(t *testing.T) {
	entries := menu(pipe.Status{Joined: true, Connected: true, FirewallOff: true}, true)
	if entries[1].Title != "Windows Firewall is off, so this laptop accepts connections from the network." || !entries[1].Disabled {
		t.Fatalf("header %+v", entries[1])
	}
	if want := []string{"The Krynodes service is not running.", "Quit"}; !slices.Equal(titles(menu(pipe.Status{}, false), ""), want) {
		t.Fatalf("menu %q", titles(menu(pipe.Status{}, false), ""))
	}
}

func TestTheIconIsTheHubK(t *testing.T) {
	data := icon(true)
	if len(data) != 22+40+side*side*4+side*side/8 || binary.LittleEndian.Uint16(data[2:]) != 1 || binary.LittleEndian.Uint32(data[18:]) != 22 {
		t.Fatalf("header % x", data[:22])
	}
	alpha := func(x, y int) byte { return data[62+((side-1-y)*side+x)*4+3] }
	if alpha(8, 16) != 255 || alpha(31, 31) != 0 || alpha(30, 16) != 0 {
		t.Fatalf("hub %d, corner %d, right edge %d", alpha(8, 16), alpha(31, 31), alpha(30, 16))
	}
}

func TestTheNotificationLayoutMatchesWindows(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("the offsets are for amd64")
	}
	var data notifyIconData
	if size, title, flags := unsafe.Sizeof(data), unsafe.Offsetof(data.InfoTitle), unsafe.Offsetof(data.InfoFlags); size != 976 || title != 820 || flags != 948 {
		t.Fatalf("size %d, InfoTitle at %d, InfoFlags at %d; want 976, 820, 948", size, title, flags)
	}
}

func TestOneBalloonShowsTheNewestNote(t *testing.T) {
	lines := []string{"server-1 went offline.", "server-2 went offline.", "server-3 went offline."}
	for count, want := range []string{"", "server-1 went offline.", "server-2 went offline.\nAnd 1 more.", "server-3 went offline.\nAnd 2 more."} {
		if got := shown(lines[:count]); got != want {
			t.Errorf("%d notes show %q, want %q", count, got, want)
		}
	}
}

func TestTheTrayRestartsOnlyForANewerService(t *testing.T) {
	for _, test := range []struct {
		service, own string
		want         bool
	}{
		{"0.7.25", "0.7.24", true},
		{"0.7.24", "0.7.24", false},
		{"0.7.23", "0.7.24", false},
		{"", "0.7.24", false},
		{"0.7.25.1", "0.7.24", false},
		{"0.7.25", "dev", false},
	} {
		if got := newer(test.service, test.own); got != test.want {
			t.Errorf("newer(%q, %q) = %v, want %v", test.service, test.own, got, test.want)
		}
	}
}
