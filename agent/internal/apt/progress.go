package apt

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

const maxStepLine = 200

type Step struct {
	Done  int    `json:"done"`
	Total int    `json:"total"`
	Line  string `json:"line"`
}

var (
	statusLine = regexp.MustCompile(`^pmstatus:[^:]+(?::[^:]+)?:([0-9.]+):(.+)$`)
	archTag    = regexp.MustCompile(`:[a-z0-9]+\b`)
	lockLine   = regexp.MustCompile(`held by process ([0-9]+)(?: \(([^)]+)\))?`)
	summary    = regexp.MustCompile(`^([0-9]+) upgraded, ([0-9]+) newly installed, (?:([0-9]+) reinstalled, )?([0-9]+) to remove`)
)

func ParseStatusFd(line string, total int) (Step, bool) {
	if strings.HasPrefix(line, "dlstatus:") && strings.Count(line, ":") >= 3 {
		return Step{Total: total, Line: "downloading"}, true
	}
	found := statusLine.FindStringSubmatch(line)
	if found == nil {
		return Step{}, false
	}
	percent, err := strconv.ParseFloat(found[1], 64)
	if err != nil {
		return Step{}, false
	}
	message, _, _ := strings.Cut(found[2], " (")
	message = archTag.ReplaceAllString(strings.TrimSpace(message), "")
	if message != "" {
		message = strings.ToLower(message[:1]) + message[1:]
	}
	if len(message) > maxStepLine {
		message = message[:maxStepLine]
	}
	done := min(max(int(math.Floor(percent*float64(total)/100+0.001)), 0), total)
	return Step{Done: done, Total: total, Line: message}, true
}

func LockHolder(line string) (string, bool) {
	if !strings.HasPrefix(line, "Waiting for cache lock") {
		return "", false
	}
	found := lockLine.FindStringSubmatch(line)
	switch {
	case found == nil:
		return "another program", true
	case found[2] == "unattended-upgr":
		return "unattended-upgrades", true
	case found[2] != "":
		return found[2], true
	}
	return "process " + found[1], true
}

func planned(line string) (int, bool) {
	found := summary.FindStringSubmatch(line)
	if found == nil {
		return 0, false
	}
	total := 0
	for _, count := range found[1:] {
		number, _ := strconv.Atoi(count)
		total += number
	}
	return total, true
}
