package network

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

const journalFixture = `1793136240.100000 vps-2 kernel: kry-knock IN=kry0 OUT= MAC= SRC=10.88.0.1 DST=10.88.0.2 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=1 DF PROTO=TCP SPT=40001 DPT=5433 WINDOW=64240 RES=0x00 SYN URGP=0
1793136240.200000 vps-2 kernel: kry-reach IN=krc111111111111 OUT=kry0 MAC= SRC=172.30.0.2 DST=10.88.0.3 LEN=60 PROTO=UDP SPT=40002 DPT=6379 LEN=40
1793136240.300000 vps-2 kernel: usb 1-1: new device
`

func TestKnocksAreReadFromTheKernelJournal(t *testing.T) {
	knocks := ParseKnocks(journalFixture)
	want := []Knock{
		{At: time.Unix(1793136240, 100000000), In: "kry0", Src: "10.88.0.1", Target: "10.88.0.2:5433/tcp"},
		{At: time.Unix(1793136240, 200000000), Reach: true, In: "krc111111111111", Src: "172.30.0.2", Target: "10.88.0.3:6379/udp"},
	}
	if !slices.EqualFunc(knocks, want, func(a, b Knock) bool {
		return a.At.Equal(b.At) && a.Reach == b.Reach && a.In == b.In && a.Src == b.Src && a.Target == b.Target
	}) {
		t.Fatalf("knocks %+v", knocks)
	}
}

func knocking(at time.Time, src string, reach bool, in string, targets ...string) []Knock {
	var knocks []Knock
	for _, target := range targets {
		knocks = append(knocks, Knock{At: at, Reach: reach, In: in, Src: src, Target: target})
	}
	return knocks
}

func ports(from, count int) []string {
	var targets []string
	for port := from; port < from+count; port++ {
		targets = append(targets, fmt.Sprintf("10.88.0.2:%d/tcp", port))
	}
	return targets
}

func TestTenClosedPortsInOneMinuteAreAScan(t *testing.T) {
	now := time.Unix(1793136300, 0)
	knocks := knocking(now.Add(-10*time.Second), "10.88.0.1", false, "kry0", ports(5000, 9)...)
	knocks = append(knocks, knocking(now.Add(-2*time.Minute), "10.88.0.1", false, "kry0", ports(6000, 5)...)...)
	if seen := Scans(knocks, now, 10, nil, nil); len(seen.Sources) != 0 {
		t.Fatalf("nine in the minute %+v", seen)
	}
	knocks = append(knocks, knocking(now, "10.88.0.1", false, "kry0", "10.88.0.3:22/tcp")...)
	seen := Scans(knocks, now, 10, nil, nil)
	if len(seen.Sources) != 1 || seen.Sources[0].Who != "10.88.0.1" || seen.Sources[0].Count != 10 || len(seen.Sources[0].Sample) != 4 {
		t.Fatalf("ten %+v", seen)
	}
}

func TestAStackThatTriesPlacesItWasNotGivenIsNamedByItsBridge(t *testing.T) {
	now := time.Unix(1793136300, 0)
	var targets []string
	for host := 1; host <= 14; host++ {
		targets = append(targets, fmt.Sprintf("10.88.0.%d:6379/tcp", host))
	}
	seen := Scans(knocking(now, "172.30.0.2", true, "krc111111111111", targets...), now, 10, map[string]string{"krc111111111111": "app"}, nil)
	if len(seen.Stacks) != 1 || seen.Stacks[0].Who != "app" || seen.Stacks[0].Count != 14 || len(seen.Sources) != 0 {
		t.Fatalf("stack %+v", seen)
	}
	if seen := Scans(knocking(now, "172.30.0.2", true, "krc999999999999", targets...), now, 10, map[string]string{}, nil); len(seen.Stacks) != 0 {
		t.Fatalf("an unknown bridge %+v", seen)
	}
}

func TestOneWrongPortKnockedAgainAndAgainIsNotAScan(t *testing.T) {
	now := time.Unix(1793136300, 0)
	target := "10.88.0.2:5433/tcp"
	seen := Scans(knocking(now, "10.88.0.5", false, "kry0", strings.Split(strings.Repeat(target+",", 12), ",")[:12]...), now, 10, nil, nil)
	if len(seen.Sources) != 0 || len(seen.Wrong) != 1 || seen.Wrong[0] != (Wrong{From: "10.88.0.5", Target: target}) {
		t.Fatalf("wrong %+v", seen)
	}
}

func TestAStackOnASharedBridgeIsKnownByItsAddress(t *testing.T) {
	now := time.Unix(1793136300, 0)
	targets := make([]string, 10)
	for index := range targets {
		targets[index] = fmt.Sprintf("172.24.0.%d:%d", 3+index, 5432)
	}
	addresses := map[string]string{"172.24.0.2": "panel"}
	seen := Scans(knocking(now, "172.24.0.2", true, "krc0a1b2c3d4e5f", targets...), now, 10, map[string]string{"krc111111111111": "app"}, addresses)
	if len(seen.Stacks) != 1 || seen.Stacks[0].Who != "panel" || seen.Stacks[0].Count != 10 {
		t.Fatalf("seen %+v", seen)
	}
	if seen := Scans(knocking(now, "172.24.0.9", true, "krc0a1b2c3d4e5f", targets...), now, 10, nil, addresses); len(seen.Stacks) != 0 {
		t.Fatalf("an unknown address is nobody's: %+v", seen)
	}
}
