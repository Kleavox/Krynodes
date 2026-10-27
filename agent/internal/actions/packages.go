package actions

import (
	"context"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/apt"
	"github.com/Kleavox/krynodes/agent/internal/recipes"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/tailscale"
)

const packagesTimeout = 2 * time.Minute

type packagesCache struct {
	Stamp   string                  `json:"stamp"`
	Report  reporter.PackagesReport `json:"report"`
	Kernels []string                `json:"kernels"`
}

type aptState struct {
	Installed []string `json:"installed"`
	Sources   []string `json:"sources"`
}

func (e Executor) krynodesPackages() ([]apt.Group, []string) {
	var groups []apt.Group
	var ours []string
	if _, err := os.Stat(filepath.Join(e.StateDir, "docker.json")); err == nil {
		groups = append(groups, apt.Group{Feature: "docker", Packages: recipes.DockerPackages})
		ours = append(ours, recipes.DockerList)
	}
	applied := e.readRecipes().Applied
	for _, name := range slices.Sorted(maps.Keys(applied)) {
		if installed := strings.Fields(applied[name].Saved["installed"]); len(installed) > 0 {
			groups = append(groups, apt.Group{Feature: name, Packages: installed})
		}
	}
	if e.readNetwork().Tools {
		groups = append(groups, apt.Group{Feature: "network", Packages: []string{networkTools}})
	}
	state, _ := readState[aptState](e.StateDir, "apt.json")
	for _, name := range state.Installed {
		groups = append(groups, apt.Group{Packages: []string{name}})
	}
	return groups, append(ours, state.Sources...)
}

func (e Executor) packages(ctx context.Context) *reporter.PackagesReport {
	platform := recipes.Detect(e.recipeEnv())
	if _, err := os.Stat(e.path("/usr/bin/apt-get")); platform.Family != recipes.Debian || err != nil {
		return &reporter.PackagesReport{System: platform.Name}
	}
	groups, ours := e.krynodesPackages()
	stamp := apt.Stamp(e.Root) + fmt.Sprint(groups, ours)
	cache, _ := readState[packagesCache](e.StateDir, "packages.json")
	if cache.Stamp != stamp {
		facts := apt.Facts{
			System:   strings.TrimSpace(strings.Replace(platform.Name, " GNU/Linux", "", 1) + " " + platform.Codename),
			Codename: platform.Codename, Distro: platform.ID, Ours: ours, Krynodes: groups,
		}
		reading, cancel := context.WithTimeout(ctx, packagesTimeout)
		report, kernels, err := apt.Build(reading, e.Root, apt.Runner(e.Run), facts, e.Now())
		cancel()
		switch {
		case err == nil:
			cache = packagesCache{Stamp: stamp, Report: report, Kernels: kernels}
			if err := writeJSON(e.StateDir, "packages.json", cache, 0o640); err != nil {
				log.Printf("keep packages: %v", err)
			}
		case !cache.Report.Apt:
			log.Printf("read packages: %v", err)
			return nil
		default:
			log.Printf("read packages: %v", err)
		}
	}
	report := cache.Report
	report.Security.On = e.automaticUpdates(ctx, recipes.Debian)
	report.Security.LastRan = nil
	if info, err := os.Stat(e.path("/var/lib/apt/periodic/unattended-upgrades-stamp")); err == nil {
		ran := info.ModTime().UTC().Format(time.RFC3339Nano)
		report.Security.LastRan = &ran
	}
	report.Restart = apt.Restart(e.Root, cache.Kernels)
	return &report
}

func (e Executor) tailnet(ctx context.Context) *reporter.TailscaleReport {
	if _, err := os.Stat(e.path(tailscale.Binary)); err != nil {
		return nil
	}
	report := tailscale.Report(ctx, tailscale.Runner(e.Run), e.TailscaleLocal)
	return &report
}
