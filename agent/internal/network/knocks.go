package network

import (
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	KnockPrefix = "kry-knock "
	ReachPrefix = "kry-reach "
	KnockWindow = time.Minute
	wrongHits   = 3
	sampleSize  = 4
)

var logField = regexp.MustCompile(`\b(IN|SRC|DST|PROTO|DPT)=(\S*)`)

type Knock struct {
	At     time.Time
	Reach  bool
	In     string
	Src    string
	Target string
}

type Scan struct {
	Who    string
	Count  int
	Sample []string
}

type Wrong struct {
	From   string
	Target string
}

type Seen struct {
	Sources []Scan
	Stacks  []Scan
	Wrong   []Wrong
}

func stampOf(text string) (time.Time, bool) {
	whole, fraction, _ := strings.Cut(text, ".")
	seconds, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	fraction = (fraction + "000000000")[:9]
	nanos, err := strconv.ParseInt(fraction, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(seconds, nanos), true
}

func ParseKnocks(journal string) []Knock {
	var knocks []Knock
	for line := range strings.SplitSeq(journal, "\n") {
		stamp, rest, ok := strings.Cut(strings.TrimSpace(line), " ")
		reach := strings.Contains(rest, ReachPrefix)
		if !ok || (!reach && !strings.Contains(rest, KnockPrefix)) {
			continue
		}
		at, ok := stampOf(stamp)
		if !ok {
			continue
		}
		fields := map[string]string{}
		for _, match := range logField.FindAllStringSubmatch(rest, -1) {
			if _, seen := fields[match[1]]; !seen {
				fields[match[1]] = match[2]
			}
		}
		if fields["SRC"] == "" || fields["DST"] == "" || fields["DPT"] == "" {
			continue
		}
		target := fields["DST"] + ":" + fields["DPT"] + "/" + strings.ToLower(fields["PROTO"])
		knocks = append(knocks, Knock{At: at, Reach: reach, In: fields["IN"], Src: fields["SRC"], Target: target})
	}
	return knocks
}

func scanOf(who string, targets map[string]int) Scan {
	sorted := slices.Sorted(maps.Keys(targets))
	return Scan{Who: who, Count: len(sorted), Sample: sorted[:min(sampleSize, len(sorted))]}
}

func Scans(knocks []Knock, now time.Time, scan int, bridges map[string]string, addresses map[string]string) Seen {
	sources := map[string]map[string]int{}
	stacks := map[string]map[string]int{}
	add := func(into map[string]map[string]int, who, target string) {
		if into[who] == nil {
			into[who] = map[string]int{}
		}
		into[who][target]++
	}
	for _, knock := range knocks {
		if now.Sub(knock.At) > KnockWindow {
			continue
		}
		if !knock.Reach {
			add(sources, knock.Src, knock.Target)
		} else if project, ok := bridges[knock.In]; ok {
			add(stacks, project, knock.Target)
		} else if project, ok := addresses[knock.Src]; ok {
			add(stacks, project, knock.Target)
		}
	}
	var seen Seen
	for _, who := range slices.Sorted(maps.Keys(sources)) {
		targets := sources[who]
		if len(targets) >= scan {
			seen.Sources = append(seen.Sources, scanOf(who, targets))
			continue
		}
		for _, target := range slices.Sorted(maps.Keys(targets)) {
			if targets[target] >= wrongHits {
				seen.Wrong = append(seen.Wrong, Wrong{From: who, Target: target})
			}
		}
	}
	for _, project := range slices.Sorted(maps.Keys(stacks)) {
		if len(stacks[project]) >= scan {
			seen.Stacks = append(seen.Stacks, scanOf(project, stacks[project]))
		}
	}
	return seen
}
