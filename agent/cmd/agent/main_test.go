package main

import (
	"crypto/tls"
	"net/http"
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
		"TimeoutStartSec=30min\n",
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
	if len(commands) < 2 || strings.Join(commands[1], " ") != "systemctl stop krynodes-exec.service" {
		t.Fatalf("unexpected commands %#v", commands)
	}
}

func TestUpdatesNeedTLS13(t *testing.T) {
	transport := updateClient().Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("release downloads must need TLS 1.3")
	}
}
