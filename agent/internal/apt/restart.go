package apt

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const maxRestartServices = 50

var release = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*(-[0-9]+(\.[0-9]+)*)?`)

func flavour(kernel string) string {
	return kernel[len(release.FindString(kernel)):]
}

func Kernels(packages []Package) []string {
	var kernels []string
	for _, pkg := range packages {
		for _, prefix := range []string{"linux-image-unsigned-", "linux-image-"} {
			if kernel, found := strings.CutPrefix(pkg.Name, prefix); found {
				if kernel != "" && digit(kernel[0]) && !slices.Contains(kernels, kernel) {
					kernels = append(kernels, kernel)
				}
				break
			}
		}
	}
	return kernels
}

func stamp(when time.Time) string {
	return when.UTC().Format(time.RFC3339Nano)
}

func Restart(root string, kernels []string) *reporter.RestartReport {
	report := &reporter.RestartReport{Services: OldLibraries(root)}
	running := ""
	if body, err := os.ReadFile(at(root, "/proc/sys/kernel/osrelease")); err == nil {
		running = strings.TrimSpace(string(body))
	}
	if running != "" {
		report.Running = &running
	}
	newest := ""
	for _, kernel := range kernels {
		if running != "" && flavour(kernel) != flavour(running) {
			continue
		}
		if newest == "" || compareParts(kernel, newest) > 0 {
			newest = kernel
		}
	}
	if newest != "" {
		report.Newest = &newest
	}
	newer := running != "" && newest != "" && compareParts(newest, running) > 0
	since := time.Time{}
	if info, err := os.Stat(at(root, "/run/reboot-required")); err == nil {
		report.File, since = true, info.ModTime()
	}
	if !newer && !report.File && len(report.Services) == 0 {
		return nil
	}
	if since.IsZero() && newer {
		if info, err := os.Stat(at(root, "/var/lib/dpkg/info/linux-image-"+newest+".list")); err == nil {
			since = info.ModTime()
		}
	}
	if since.IsZero() {
		since = time.Now()
		if info, err := os.Stat(at(root, "/var/lib/dpkg/status")); err == nil {
			since = info.ModTime()
		}
	}
	report.Since = stamp(since)
	return report
}

func unitOf(cgroup string) string {
	for line := range strings.SplitSeq(cgroup, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) != 3 || !strings.HasPrefix(parts[2], "/system.slice/") {
			continue
		}
		if unit := filepath.Base(parts[2]); strings.HasSuffix(unit, ".service") {
			return unit
		}
	}
	return ""
}

func oldLibrary(maps string) bool {
	body, err := os.ReadFile(maps)
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(string(body), "\n") {
		line, deleted := strings.CutSuffix(line, " (deleted)")
		if !deleted {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		library := strings.Join(fields[5:], " ")
		if (strings.HasPrefix(library, "/usr/lib/") || strings.HasPrefix(library, "/lib/")) && strings.Contains(library, ".so") {
			return true
		}
	}
	return false
}

func OldLibraries(root string) []string {
	entries, _ := os.ReadDir(at(root, "/proc"))
	var units []string
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil || len(units) >= maxRestartServices {
			continue
		}
		process := at(root, "/proc/"+entry.Name())
		cgroup, err := os.ReadFile(filepath.Join(process, "cgroup"))
		if err != nil {
			continue
		}
		unit := unitOf(string(cgroup))
		if unit == "" || slices.Contains(units, unit) || !oldLibrary(filepath.Join(process, "maps")) {
			continue
		}
		units = append(units, unit)
	}
	slices.Sort(units)
	if units == nil {
		units = []string{}
	}
	return units
}
