package apt

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

type Runner func(ctx context.Context, name string, args ...string) ([]byte, int, error)

type Group struct {
	Feature  string
	Packages []string
}

type Facts struct {
	System   string
	Codename string
	Distro   string
	Ours     []string
	Krynodes []Group
}

const (
	maxPackages = 5000
	maxUpdates  = 500
)

var noCache = []string{"-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache="}

func output(ctx context.Context, run Runner, name string, args ...string) (string, bool) {
	text, _, err := run(ctx, "env", append([]string{"LC_ALL=C", name}, args...)...)
	return string(text), err == nil
}

func simulate(ctx context.Context, run Runner, args ...string) (Simulation, bool) {
	text, ok := output(ctx, run, "apt-get", append(append([]string{"-s", "-o", "Debug::NoLocking=1"}, noCache...), args...)...)
	return ParseSimulation(text), ok
}

func Stamp(root string) string {
	var notes strings.Builder
	note := func(path string) {
		if info, err := os.Stat(path); err == nil {
			fmt.Fprintf(&notes, "%s %d %d\n", path, info.ModTime().UnixNano(), info.Size())
		}
	}
	for _, name := range []string{"/var/lib/dpkg/status", "/var/log/apt/history.log", sourcesList, "/var/lib/apt/periodic/update-success-stamp"} {
		note(at(root, name))
	}
	for _, name := range []string{sourcesDir, "/etc/apt/keyrings", "/var/lib/apt/lists"} {
		entries, _ := os.ReadDir(at(root, name))
		for _, entry := range entries {
			note(filepath.Join(at(root, name), entry.Name()))
		}
	}
	sum := sha256.Sum256([]byte(notes.String()))
	return hex.EncodeToString(sum[:])
}

func checkedAt(root string) *string {
	var newest time.Time
	entries, _ := os.ReadDir(at(root, "/var/lib/apt/lists"))
	for _, entry := range entries {
		if info, err := entry.Info(); err == nil && info.Mode().IsRegular() && entry.Name() != "lock" && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	if info, err := os.Stat(at(root, "/var/lib/apt/periodic/update-success-stamp")); err == nil && info.ModTime().After(newest) {
		newest = info.ModTime()
	}
	if newest.IsZero() {
		return nil
	}
	text := stamp(newest)
	return &text
}

func security(origins []Origin) bool {
	return slices.ContainsFunc(origins, func(origin Origin) bool { return strings.HasSuffix(origin.Suite, "-security") })
}

func text(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

type row struct {
	by      string
	feature string
	with    []string
}

func rows(installed map[string]Package, added map[string]Added, groups []Group) map[string]*row {
	found := map[string]*row{}
	for name, entry := range added {
		if _, present := installed[name]; present {
			found[name] = &row{by: entry.By, with: entry.With}
		}
	}
	for _, group := range groups {
		index := slices.IndexFunc(group.Packages, func(name string) bool { _, present := installed[name]; return present })
		if index < 0 {
			continue
		}
		head := group.Packages[index]
		entry := found[head]
		if entry == nil {
			entry = &row{}
			found[head] = entry
		}
		entry.by, entry.feature = "Krynodes", group.Feature
		for _, name := range group.Packages {
			if name != head {
				entry.with = append(entry.with, name)
				delete(found, name)
			}
		}
	}
	return found
}

func Build(ctx context.Context, root string, run Runner, facts Facts, now time.Time) (reporter.PackagesReport, []string, error) {
	raw, err := os.ReadFile(at(root, "/var/lib/dpkg/status"))
	if err != nil {
		return reporter.PackagesReport{}, nil, err
	}
	installed := map[string]Package{}
	var names []string
	for _, pkg := range ParseStatus(string(raw)) {
		if ValidName(pkg.Name) && pkg.Version != "" {
			installed[pkg.Name] = pkg
			names = append(names, pkg.Name)
		}
	}
	slices.Sort(names)
	sources := ReadSources(root, facts.Distro, facts.Ours)
	policyText, _ := output(ctx, run, "apt-cache", append(append(slices.Clone(noCache), "policy"), names...)...)
	policies := ParsePolicy(policyText)
	report := reporter.PackagesReport{
		Apt: true, System: facts.System, Codename: facts.Codename, ReadAt: stamp(now), CheckedAt: checkedAt(root),
		Installed: len(names), Packages: []reporter.PackageEntry{}, Updates: waiting(ctx, run, names, installed, policies, sources), Sources: sources,
	}
	if report.Sources == nil {
		report.Sources = []reporter.SourceEntry{}
	}
	by := rows(installed, ParseHistory(ReadHistory(root)...), facts.Krynodes)
	for _, name := range names {
		pkg, policy := installed[name], policies[name]
		origins := policy.From
		if len(origins) == 0 {
			origins = policy.To
		}
		entry := reporter.PackageEntry{Name: name, Version: pkg.Version, From: sourceName(sources, origins), Held: pkg.Held}
		if found := by[name]; found != nil {
			entry.By, entry.Feature = text(found.by), text(found.feature)
			var counted []string
			for _, other := range found.with {
				if _, present := installed[other]; present && other != name && !slices.Contains(counted, other) {
					counted = append(counted, other)
				}
			}
			entry.More = len(counted)
		}
		report.Packages = append(report.Packages, entry)
	}
	if len(report.Packages) > maxPackages {
		slices.SortStableFunc(report.Packages, func(a, b reporter.PackageEntry) int {
			return cmp.Compare(rank(a), rank(b))
		})
		report.Packages = report.Packages[:maxPackages]
	}
	return report, Kernels(ParseStatus(string(raw))), nil
}

func rank(entry reporter.PackageEntry) int {
	if entry.By != nil {
		return 0
	}
	return 1
}

func waiting(ctx context.Context, run Runner, names []string, installed map[string]Package, policies map[string]Policy, sources []reporter.SourceEntry) []reporter.UpdateEntry {
	plain, simulated := simulate(ctx, run, "upgrade")
	var kept []string
	for _, name := range plain.Kept {
		if !installed[name].Held && !slices.Contains(plain.Phased, name) {
			kept = append(kept, name)
		}
	}
	var more, dist Simulation
	if len(kept) > 0 {
		more, _ = simulate(ctx, run, "--with-new-pkgs", "upgrade")
		if slices.ContainsFunc(kept, func(name string) bool { _, along := more.Upgrades[name]; return !along }) {
			dist, _ = simulate(ctx, run, "dist-upgrade")
		}
	}
	updates := []reporter.UpdateEntry{}
	for _, name := range names {
		pkg, policy := installed[name], policies[name]
		if policy.Candidate == "" || policy.Candidate == "(none)" || Compare(policy.Candidate, pkg.Version) <= 0 || slices.Contains(plain.Phased, name) {
			continue
		}
		update := reporter.UpdateEntry{Name: name, From: pkg.Version, To: policy.Candidate, Source: sourceName(sources, policy.To), Security: security(policy.To), Held: pkg.Held}
		if _, plainly := plain.Upgrades[name]; simulated && !pkg.Held && !plainly {
			back := reporter.HeldBack{Adds: []string{}, Removes: []string{}}
			if _, along := more.Upgrades[name]; along {
				back.Adds = append(back.Adds, more.New...)
			} else if _, removing := dist.Upgrades[name]; removing {
				back.Removes = append(back.Removes, dist.Removes...)
			}
			update.Back = &back
		}
		updates = append(updates, update)
		if len(updates) == maxUpdates {
			break
		}
	}
	return updates
}
