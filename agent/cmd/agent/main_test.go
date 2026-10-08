package main

import (
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCyclesStartTwoSecondsAfterEachIntervalOnTheClock(t *testing.T) {
	boundary := time.Unix(1_800_000_000, 0)
	for _, test := range []struct {
		now  time.Time
		want time.Duration
	}{
		{boundary.Add(time.Second), time.Second},
		{boundary.Add(10 * time.Second), 52 * time.Second},
		{boundary.Add(2 * time.Second), time.Minute},
		{boundary.Add(2*time.Second + 300*time.Millisecond), time.Minute - 300*time.Millisecond},
	} {
		if got := untilNextTick(test.now, time.Minute); got != test.want {
			t.Errorf("untilNextTick(boundary+%s) = %s, want %s", test.now.Sub(boundary), got, test.want)
		}
	}
	if got := untilNextTick(boundary.Add(4*time.Minute), 5*time.Minute); got != 62*time.Second {
		t.Errorf("five-minute interval waits %s, want 62s", got)
	}
}

func TestServiceUnitRunsAsKrynodes(t *testing.T) {
	unit := serviceUnit("/usr/local/bin/kry", defaultConfigPath)
	for _, want := range []string{
		"Description=Krynodes Agent",
		"User=kry\n",
		"Group=kry\n",
		"ExecStart=/usr/local/bin/kry run --config /etc/kry/config.json",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit is missing %q:\n%s", want, unit)
		}
	}
	if strings.Contains(strings.ToLower(unit), "kleavox") {
		t.Fatalf("unit still uses an old name:\n%s", unit)
	}
	if unitPath != "/etc/systemd/system/krynodes.service" {
		t.Fatalf("unit path is %s", unitPath)
	}
}

func TestAgentUnitCanWriteItsUpdateRequest(t *testing.T) {
	unit := serviceUnit("/usr/local/bin/kry", defaultConfigPath)
	if !strings.Contains(unit, "StateDirectory=kry\n") {
		t.Fatalf("agent unit has no state directory:\n%s", unit)
	}
}

func TestUpdaterUnitsRunSelfUpdateWhenAskedTo(t *testing.T) {
	updater := updaterUnit("/usr/local/bin/kry")
	for _, want := range []string{
		"Type=oneshot",
		"ExecStart=/usr/local/bin/kry self-update",
	} {
		if !strings.Contains(updater, want) {
			t.Fatalf("updater unit is missing %q:\n%s", want, updater)
		}
	}
	if strings.Contains(updater, "User=") {
		t.Fatalf("updater must run as root:\n%s", updater)
	}
	path := pathUnit()
	for _, want := range []string{
		"PathChanged=/var/lib/kry/update-request",
		"Unit=krynodes-update.service",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(path, want) {
			t.Fatalf("path unit is missing %q:\n%s", want, path)
		}
	}
}

func TestAnEnrolledServerIsNotEnrolledAgain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	before := []byte(`{"endpoint":"https://kry.example","node_id":"node-old","token":"tok","interval_seconds":60}`)
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"enroll", "--endpoint", "https://127.0.0.1:1", "--token", "fresh", "--config", path})
	if err == nil || !strings.Contains(err.Error(), "already enrolled as node-old") || !strings.Contains(err.Error(), "kry uninstall-service") {
		t.Fatalf("err %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatalf("the config must stay: %s", after)
	}
}

func TestAUnitIsWrittenWholeAndOnlyWhenItChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "krynodes.service")
	if err := writeUnit(path, "first\n"); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	old := before.ModTime().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if err := writeUnit(path, "first\n"); err != nil {
		t.Fatal(err)
	}
	if same, _ := os.Stat(path); !same.ModTime().Equal(old) {
		t.Fatal("an unchanged unit is left as it is")
	}
	if err := writeUnit(path, "second\n"); err != nil {
		t.Fatal(err)
	}
	if body, _ := os.ReadFile(path); string(body) != "second\n" {
		t.Fatalf("unit %q", body)
	}
	if leftovers, _ := filepath.Glob(path + "*.tmp"); len(leftovers) != 0 {
		t.Fatalf("left %v", leftovers)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o644 && runtime.GOOS != "windows" {
		t.Fatalf("mode %v", info.Mode())
	}
}

func TestTheExecutorUnitRunsAsRootInASandbox(t *testing.T) {
	unit := execUnit("/usr/local/bin/kry")
	for _, want := range []string{
		"StartLimitIntervalSec=0\n",
		"Type=oneshot\n",
		"Group=kry\n",
		"ExecStart=/usr/local/bin/kry exec\n",
		"NoNewPrivileges=true\n",
		"ProtectSystem=strict\n",
		"ReadWritePaths=/var/lib/kry-exec\n",
		"Environment=DOCKER_CONFIG=/var/lib/kry-exec/docker\n",
		"TimeoutStartSec=60min\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("executor unit is missing %q", want)
		}
	}
	if strings.Contains(unit, "User=") {
		t.Error("the executor must run as root")
	}
}

func TestTheExecutorCanReadStacksUnderHomeDirectories(t *testing.T) {
	unit := execUnit("/usr/local/bin/kry")
	if !strings.Contains(unit, "ProtectHome=read-only\n") || strings.Contains(unit, "ProtectHome=true") {
		t.Fatalf("compose files under /root or /home must stay readable:\n%s", unit)
	}
}

func TestTrustArgumentsMayStartWithADash(t *testing.T) {
	options, err := parseTrust([]string{"--initial", "--origin", "https://kry.kleavox.xyz", "--", "-abc.-7.KEY", "def.-257.KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.initial || options.origin != "https://kry.kleavox.xyz" || len(options.keys) != 2 || options.keys[0] != "-abc.-7.KEY" {
		t.Fatalf("options %+v", options)
	}
}

func TestTrustArgumentsCarryTheGrant(t *testing.T) {
	options, err := parseTrust([]string{"--initial", "--origin", "https://kry.kleavox.xyz", "--grant", "--", "-abc.-7.KEY"})
	if err != nil || !options.grant || len(options.keys) != 1 {
		t.Fatalf("options %+v err %v", options, err)
	}
	if _, err := parseTrust([]string{"--initial", "--passphrase", "SALT.600000.KEY"}); err == nil {
		t.Fatal("the passphrase flag is gone")
	}
}

func TestTheExecutorIsStartedByRequestsAndATimer(t *testing.T) {
	path := execPathUnit()
	for _, want := range []string{"PathChanged=/var/lib/kry/actions\n", "Unit=krynodes-exec.service\n", "WantedBy=multi-user.target\n"} {
		if !strings.Contains(path, want) {
			t.Errorf("path unit is missing %q", want)
		}
	}
	timer := execTimerUnit()
	for _, want := range []string{"OnBootSec=1min\n", "OnUnitActiveSec=5min\n", "Unit=krynodes-exec.service\n", "WantedBy=timers.target\n"} {
		if !strings.Contains(timer, want) {
			t.Errorf("timer unit is missing %q", want)
		}
	}
}

func TestUninstallStopsTheExecutorBeforeRemovingItsState(t *testing.T) {
	commands := uninstallCommands()
	if len(commands) != 3 || strings.Join(commands[1], " ") != "systemctl stop krynodes-exec.service krynodes-host.service" {
		t.Fatalf("unexpected commands %#v", commands)
	}
	if slices.Contains(commands[0], "krynodes.service") || strings.Join(commands[2], " ") != "systemctl disable --now krynodes.service" {
		t.Fatalf("the agent itself stops last, after it reported: %#v", commands)
	}
	all := strings.Join(append(append(slices.Clone(commands[0]), commands[1]...), commands[2]...), " ")
	for _, unit := range enabledUnits() {
		if !strings.Contains(all, unit) {
			t.Fatalf("%s stays enabled: %#v", unit, commands)
		}
	}
}

func TestTheContainmentUnitRunsBeforeDocker(t *testing.T) {
	unit := guardUnit("/usr/local/bin/kry")
	for _, want := range []string{"Before=docker.service\n", "Type=oneshot\n", "ExecStart=/usr/local/bin/kry guard\n", "WantedBy=multi-user.target\n"} {
		if !strings.Contains(unit, want) {
			t.Errorf("guard unit is missing %q", want)
		}
	}
	if !slices.Contains(enabledUnits(), "krynodes-guard.service") || !slices.Contains(leftovers("/usr/local/bin/kry"), guardPath) {
		t.Fatalf("enabled %v leftovers %v", enabledUnits(), leftovers("/usr/local/bin/kry"))
	}
}

func TestUninstallWaitsForEveryResultToBeReported(t *testing.T) {
	requests, state := t.TempDir(), t.TempDir()
	const id = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a01"
	if unreported(requests, state) {
		t.Fatal("nothing waits")
	}
	if err := os.WriteFile(filepath.Join(requests, id+".json"), []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	if unreported(requests, state) {
		t.Fatal("a request without a result never gets one once the executor stopped")
	}
	if err := os.MkdirAll(filepath.Join(state, "results"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "results", id+".json"), []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	if !unreported(requests, state) {
		t.Fatal("a result the dashboard has not heard of waits")
	}
}

func TestUninstallWaitsForHostWorkBeforeStoppingIt(t *testing.T) {
	answers := []string{"inactive\nactivating\n", "active\ninactive\n", "inactive\ninactive\n"}
	waited := time.Duration(0)
	sleep := func(d time.Duration) { waited += d }
	next := func() string {
		answer := answers[0]
		answers = answers[1:]
		return answer
	}
	if !waitFor(func() bool { return unitsBusy(next()) }, sleep, time.Minute, "waiting") || waited != 4*time.Second || len(answers) != 0 {
		t.Fatalf("waited %s, answers left %q", waited, answers)
	}
	waited = 0
	if waitFor(func() bool { return unitsBusy("activating\n") }, sleep, 10*time.Second, "waiting") || waited != 10*time.Second {
		t.Fatalf("gives up after the limit: waited %s", waited)
	}
	if !strings.Contains(strings.Join(uninstallCommands()[0], " "), "krynodes-host.path") {
		t.Fatal("new host work is stopped before the wait")
	}
	if !slices.Equal(busyUnits, []string{"krynodes-exec.service", "krynodes-host.service", "krynodes-update.service"}) {
		t.Fatalf("waits for %v", busyUnits)
	}
}

func TestUninstallLeavesNothingOfKrynodesBehind(t *testing.T) {
	paths := leftovers("/usr/local/bin/kry")
	for _, want := range []string{unitPath, updaterPath, watcherPath, execPath, execWatcherPath, execTimerPath, hostPath, hostWatcherPath, "/var/lib/kry", "/etc/kry", "/usr/local/bin/kry"} {
		if !slices.Contains(paths, want) {
			t.Errorf("uninstall leaves %s behind", want)
		}
	}
	if err := run([]string{"uninstall-service", "--everything"}); err == nil || !strings.Contains(err.Error(), "--delete-apps") {
		t.Fatalf("an unknown flag must name the one there is: %v", err)
	}
	if err := run([]string{"uninstall-service", "--delete-apps"}); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("--delete-apps is accepted and still needs root: %v", err)
	}
}

func TestSetupChecksItsFlagsBeforeAnythingElse(t *testing.T) {
	for args, want := range map[string]string{
		"--everything":                   "flag provided but not defined",
		"":                               "choose --recommended, --docker or both",
		"--recommended --reboot-hour 24": "--reboot-hour is 0 to 23",
		"--docker extra":                 `unexpected argument "extra"`,
		"--recommended --docker":         "root",
	} {
		err := run(append([]string{"setup"}, strings.Fields(args)...))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", args, err)
		}
	}
	if got := setupCommandLine(true, true, 20); got != "kry setup --recommended --docker --reboot-hour 20" {
		t.Fatalf("command %q", got)
	}
	if got := setupCommandLine(false, true, 20); got != "kry setup --docker" {
		t.Fatalf("command %q", got)
	}
}

func TestUpdatesNeedTLS13(t *testing.T) {
	transport := updateClient().Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("release downloads must need TLS 1.3")
	}
}

func TestTheHostUnitRunsOnlyTheFixedRecipesWhenAsked(t *testing.T) {
	unit := hostUnit("/usr/local/bin/kry")
	for _, want := range []string{"Type=oneshot\n", "ExecStart=/usr/local/bin/kry host-apply\n", "TimeoutStartSec=120min\n", "Environment=DOCKER_CONFIG=/var/lib/kry-exec/docker\n", "PrivateTmp=true\n"} {
		if !strings.Contains(unit, want) {
			t.Errorf("host unit is missing %q", want)
		}
	}
	if strings.Contains(unit, "User=") || strings.Contains(unit, "ProtectSystem") {
		t.Errorf("recipes change system files as root:\n%s", unit)
	}
	path := hostPathUnit()
	for _, want := range []string{"DirectoryNotEmpty=/var/lib/kry-exec/host\n", "Unit=krynodes-host.service\n", "WantedBy=multi-user.target\n"} {
		if !strings.Contains(path, want) {
			t.Errorf("host path unit is missing %q", want)
		}
	}
	if !slices.Contains(enabledUnits(), "krynodes-host.path") || !slices.Contains(uninstallCommands()[0], "krynodes-host.path") {
		t.Fatalf("enabled %v uninstall %v", enabledUnits(), uninstallCommands())
	}
}

func TestHostApplyIsACommand(t *testing.T) {
	if err := run([]string{"host-apply"}); err == nil || strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("host-apply must exist and need root on Linux: %v", err)
	}
}
