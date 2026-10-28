package actions

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const bookworm = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\nID=debian\n"

func aptExecutor(t *testing.T) (Executor, *fakeRun) {
	t.Helper()
	executor, run := securityExecutor(t)
	rootFile(t, executor, "/etc/os-release", bookworm)
	rootFile(t, executor, "/usr/bin/apt-get", "")
	rootFile(t, executor, "/var/lib/dpkg/status", "Package: docker-ce\nStatus: install ok installed\nVersion: 5:27.3.1-1\n\nPackage: containerd.io\nStatus: install ok installed\nVersion: 1.7.22-1\n\nPackage: fail2ban\nStatus: install ok installed\nVersion: 1.0.2-2\n\nPackage: python3-systemd\nStatus: install ok installed\nVersion: 235-1\n\nPackage: nginx\nStatus: install ok installed\nVersion: 1.22.1-9\n")
	rootFile(t, executor, "/proc/sys/kernel/osrelease", "6.1.0-27-amd64\n")
	return executor, run
}

func policyCalls(run *fakeRun) int {
	count := 0
	for _, call := range run.calls {
		if strings.Contains(call, " policy ") {
			count++
		}
	}
	return count
}

func TestPackagesNameWhatKrynodesInstalledAndForWhat(t *testing.T) {
	executor, _ := aptExecutor(t)
	if err := writeJSON(executor.StateDir, "docker.json", dockerState{InstalledAt: executorNow}, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(executor.StateDir, "recipes.json", recipeState{Applied: map[string]appliedRecipe{"fail2ban": {At: executorNow, Saved: map[string]string{"installed": "fail2ban python3-systemd"}}}}, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(executor.StateDir, "apt.json", aptState{Installed: []string{"nginx"}}, 0o640); err != nil {
		t.Fatal(err)
	}
	report := executor.packages(context.Background())
	if report == nil || !report.Apt || report.System != "Debian 12 bookworm" || report.Codename != "bookworm" || report.Installed != 5 {
		t.Fatalf("got %+v", report)
	}
	described := map[string]string{}
	for _, entry := range report.Packages {
		by, feature := "--", "--"
		if entry.By != nil {
			by = *entry.By
		}
		if entry.Feature != nil {
			feature = *entry.Feature
		}
		described[entry.Name] = by + " " + feature
	}
	for name, want := range map[string]string{"docker-ce": "Krynodes docker", "containerd.io": "-- --", "fail2ban": "Krynodes fail2ban", "python3-systemd": "-- --", "nginx": "Krynodes --"} {
		if described[name] != want {
			t.Fatalf("%s: got %q, want %q", name, described[name], want)
		}
	}
	if report.Restart != nil {
		t.Fatalf("restart %+v", report.Restart)
	}
}

func TestPackagesAreReadAgainOnlyWhenAptChanged(t *testing.T) {
	executor, run := aptExecutor(t)
	executor.packages(context.Background())
	executor.packages(context.Background())
	if policyCalls(run) != 1 {
		t.Fatalf("read %d times: %v", policyCalls(run), run.calls)
	}
	later := time.Now().Add(time.Hour)
	os.Chtimes(executor.path("/var/lib/dpkg/status"), later, later)
	executor.packages(context.Background())
	if policyCalls(run) != 2 {
		t.Fatalf("a changed dpkg status was not read: %v", run.calls)
	}
}

func TestRestartNeededAndTheDailyUpdatesAreReadEveryRun(t *testing.T) {
	executor, run := aptExecutor(t)
	run.respond["dpkg-query -W -f ${Status} unattended-upgrades"] = "install ok installed"
	run.respond["apt-config shell UU APT::Periodic::Unattended-Upgrade"] = "UU='1'"
	rootFile(t, executor, "/etc/apt/apt.conf.d/52krynodes-auto-upgrades", "APT::Periodic::Unattended-Upgrade \"1\";\n")
	rootFile(t, executor, "/var/lib/apt/periodic/unattended-upgrades-stamp", "")
	ran := time.Date(2026, 9, 29, 6, 12, 0, 0, time.UTC)
	os.Chtimes(executor.path("/var/lib/apt/periodic/unattended-upgrades-stamp"), ran, ran)
	if report := executor.packages(context.Background()); !report.Security.On || report.Security.LastRan == nil || *report.Security.LastRan != "2026-09-29T06:12:00Z" || report.Restart != nil {
		t.Fatalf("got %+v", report)
	}
	rootFile(t, executor, "/run/reboot-required", "")
	if report := executor.packages(context.Background()); report.Restart == nil || !report.Restart.File {
		t.Fatalf("got %+v", report.Restart)
	}
}

func TestAServerWithoutAptReportsItsSystem(t *testing.T) {
	executor, run := securityExecutor(t)
	rootFile(t, executor, "/etc/os-release", "PRETTY_NAME=\"Fedora Linux 42 (Server Edition)\"\nNAME=\"Fedora Linux\"\nVERSION_ID=42\nID=fedora\n")
	report := executor.packages(context.Background())
	if report == nil || report.Apt || report.System != "Fedora Linux 42" || len(run.calls) != 0 {
		t.Fatalf("got %+v after %v", report, run.calls)
	}
}

func TestTailscaledIsReadOnlyWhereTailscaleIsInstalled(t *testing.T) {
	executor, run := securityExecutor(t)
	if report := executor.tailnet(context.Background()); report != nil || len(run.calls) != 0 {
		t.Fatalf("got %+v", report)
	}
	rootFile(t, executor, "/usr/bin/tailscale", "")
	run.respond["tailscale status --json"] = `{"BackendState":"NeedsLogin","Self":{}}`
	if report := executor.tailnet(context.Background()); report == nil || report.State != "needs-login" {
		t.Fatalf("got %+v", report)
	}
}

func TestThePackageListIsSentOnlyWhenItChanged(t *testing.T) {
	relay, poster := newRelay(t)
	packages := &reporter.PackagesReport{Apt: true, System: "Debian 12 bookworm", Packages: []reporter.PackageEntry{{Name: "nginx", Version: "1.22.1-9"}}}
	write := func(services []Service, report *reporter.PackagesReport) {
		inventory, err := NewInventory(Parts{Services: services, Packages: report, Tailscale: &reporter.TailscaleReport{State: "stopped", Addresses: []string{}}}, executorNow)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeJSON(relay.StateDir, "inventory.json", inventory, 0o640); err != nil {
			t.Fatal(err)
		}
		poster.hash = inventory.Hash
	}
	poll := func() *reporter.InventoryReport {
		if err := relay.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
		return poster.reports[len(poster.reports)-1].Inventory
	}
	write(nil, packages)
	if sent := poll(); sent.Packages == nil || sent.Tailscale == nil {
		t.Fatalf("first report %+v", sent)
	}
	write([]Service{{Kind: "docker", Name: "adguard", State: "running"}}, packages)
	if sent := poll(); sent.Packages != nil || sent.Tailscale == nil || sent.Services == nil {
		t.Fatalf("an unchanged package list was sent again: %+v", sent)
	}
	changed := *packages
	changed.Installed = 2
	write([]Service{{Kind: "docker", Name: "adguard", State: "running"}}, &changed)
	if sent := poll(); sent.Packages == nil || sent.Packages.Installed != 2 {
		t.Fatalf("a changed package list was not sent: %+v", sent)
	}
}

func TestTheInventoryHashFollowsThePackageList(t *testing.T) {
	first, err := NewInventory(Parts{Packages: &reporter.PackagesReport{Apt: true, Installed: 1}}, executorNow)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewInventory(Parts{Packages: &reporter.PackagesReport{Apt: true, Installed: 2}}, executorNow)
	if err != nil {
		t.Fatal(err)
	}
	if first.Hash == second.Hash || first.PackagesHash == "" || first.PackagesHash == second.PackagesHash {
		t.Fatalf("hashes %s %s, packages %s %s", first.Hash, second.Hash, first.PackagesHash, second.PackagesHash)
	}
}
