package apt

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

type event struct {
	line    string
	advance time.Duration
}

type machine struct {
	t       *testing.T
	root    string
	now     time.Time
	calls   []string
	steps   []Step
	audit   string
	stream  func(command string) ([]event, error)
	replies func(command string) string
}

func (m *machine) run(_ context.Context, name string, args ...string) ([]byte, int, error) {
	command := strings.Join(append([]string{name}, args...), " ")
	m.calls = append(m.calls, command)
	if command == "dpkg --audit" {
		return []byte(m.audit), 0, nil
	}
	if m.replies != nil {
		return []byte(m.replies(command)), 0, nil
	}
	return nil, 0, nil
}

func (m *machine) streamed(_ context.Context, each func(string), name string, args ...string) error {
	command := strings.Join(append([]string{name}, args...), " ")
	m.calls = append(m.calls, command)
	var events []event
	var err error
	if m.stream != nil {
		events, err = m.stream(command)
	}
	for _, happened := range events {
		m.now = m.now.Add(happened.advance)
		each(happened.line)
	}
	return err
}

func (m *machine) job() Job {
	return Job{Root: m.root, Run: m.run, Stream: m.streamed, Now: func() time.Time { return m.now }, Step: func(step Step) { m.steps = append(m.steps, step) }}
}

func (m *machine) installed(names ...string) {
	var lines []string
	for _, name := range names {
		lines = append(lines, "Package: "+name+"\nStatus: install ok installed\nVersion: 1.0\n")
	}
	put(m.t, m.root, "/var/lib/dpkg/status", strings.Join(lines, "\n"))
}

func newMachine(t *testing.T) *machine {
	m := &machine{t: t, root: t.TempDir(), now: time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)}
	m.installed("base-files", "curl")
	put(t, m.root, "/proc/sys/kernel/osrelease", "6.1.0-27-amd64\n")
	return m
}

func called(calls []string, part string) []string {
	var found []string
	for _, call := range calls {
		if strings.Contains(call, part) {
			found = append(found, call)
		}
	}
	return found
}

func TestStatusLinesBecomeSteps(t *testing.T) {
	for line, want := range map[string]Step{
		"pmstatus:docker-ce:42.8571:Unpacking docker-ce (amd64)":      {Done: 6, Total: 14, Line: "unpacking docker-ce"},
		"pmstatus:libc6:amd64:50:Unpacking libc6:amd64 (2.36-9)":      {Done: 7, Total: 14, Line: "unpacking libc6"},
		"pmstatus:dpkg-exec:0:Running dpkg":                           {Done: 0, Total: 14, Line: "running dpkg"},
		"pmstatus:docker-ce:100:Installed docker-ce (amd64)":          {Done: 14, Total: 14, Line: "installed docker-ce"},
		"dlstatus:3:20.5:Retrieving file 3 of 14":                     {Done: 0, Total: 14, Line: "downloading"},
		"pmstatus:7zip:12.5:Preparing to configure 7zip (amd64)":      {Done: 1, Total: 14, Line: "preparing to configure 7zip"},
		"pmstatus:man-db:96:Running post-installation trigger man-db": {Done: 13, Total: 14, Line: "running post-installation trigger man-db"},
	} {
		got, ok := ParseStatusFd(line, 14)
		if !ok || got != want {
			t.Fatalf("%s: got %+v %v", line, got, ok)
		}
	}
	for _, line := range []string{"Setting up nginx (1.22.1-9) ...", "pmstatus:broken", "pmerror:x:12:failed"} {
		if _, ok := ParseStatusFd(line, 14); ok {
			t.Fatalf("%s read as a step", line)
		}
	}
	if holder, ok := LockHolder("Waiting for cache lock: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 812 (unattended-upgr)... 12s"); !ok || holder != "unattended-upgrades" {
		t.Fatalf("holder %q %v", holder, ok)
	}
}

func TestAFailedInstallTakesBackOnlyWhatItAdded(t *testing.T) {
	for _, undoFails := range []bool{false, true} {
		m := newMachine(t)
		m.replies = func(command string) string {
			if strings.Contains(command, "-s ") && strings.Contains(command, " install nginx") {
				return "Inst nginx-common (1.22.1-9 Debian:12/stable [all])\nInst nginx (1.22.1-9 Debian:12/stable [amd64])\n"
			}
			return ""
		}
		m.stream = func(command string) ([]event, error) {
			switch {
			case strings.HasSuffix(command, " install nginx"):
				m.installed("base-files", "curl", "nginx", "nginx-common")
				return []event{{line: "dpkg: error processing package nginx (--configure):"}, {line: "E: Sub-process /usr/bin/dpkg returned an error code (1)"}}, errors.New("exit status 100")
			case strings.HasSuffix(command, " remove nginx nginx-common"):
				if undoFails {
					return nil, errors.New("exit status 100")
				}
				m.installed("base-files", "curl")
			}
			return nil, nil
		}
		outcome, err := m.job().Install(context.Background(), "nginx")
		if err == nil || !strings.Contains(outcome.Failed, "dpkg returned an error code") {
			t.Fatalf("got %+v %v", outcome, err)
		}
		if !slices.Equal(outcome.Tail, []string{"dpkg: error processing package nginx (--configure):", "E: Sub-process /usr/bin/dpkg returned an error code (1)"}) {
			t.Fatalf("tail %q", outcome.Tail)
		}
		if !slices.Equal(outcome.Added, []string{"nginx", "nginx-common"}) || len(called(m.calls, " remove ")) != 1 {
			t.Fatalf("added %v, calls %v", outcome.Added, m.calls)
		}
		if undoFails != (len(outcome.Left) == 2) {
			t.Fatalf("undo fails %v, left %v", undoFails, outcome.Left)
		}
	}
}

func TestAJobWaitsForTheLockAndSaysForWhom(t *testing.T) {
	m := newMachine(t)
	m.stream = func(command string) ([]event, error) {
		return []event{
			{line: "Waiting for cache lock: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 812 (unattended-upgr)... 1s"},
			{line: "Waiting for cache lock: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 812 (unattended-upgr)... 20s", advance: 20 * time.Second},
			{line: "pmstatus:openssl:50:Unpacking openssl (amd64)", advance: 21 * time.Second},
		}, nil
	}
	outcome, err := m.job().Upgrade(context.Background())
	if err != nil || outcome.Waited != 41 || outcome.Holder != "unattended-upgrades" {
		t.Fatalf("got %+v %v", outcome, err)
	}
	if len(m.steps) == 0 || m.steps[0].Line != "waiting for unattended-upgrades" {
		t.Fatalf("steps %+v", m.steps)
	}
	upgrade := called(m.calls, "apt-get")
	if len(upgrade) != 1 || !strings.Contains(upgrade[0], "DEBIAN_FRONTEND=noninteractive") || !strings.Contains(upgrade[0], "--with-new-pkgs upgrade") || !strings.Contains(upgrade[0], "APT::Status-Fd=1") || !strings.Contains(upgrade[0], "--force-confold") || !strings.Contains(upgrade[0], "DPkg::Lock::Timeout=300") {
		t.Fatalf("upgrade ran as %v", upgrade)
	}
	if len(called(m.calls, "dist-upgrade")) != 0 || len(called(m.calls, "full-upgrade")) != 0 {
		t.Fatal("an upgrade may never remove packages")
	}
}

func TestAptIsRepairedOnlyWhenDpkgSaysSo(t *testing.T) {
	m := newMachine(t)
	if outcome, _ := m.job().Upgrade(context.Background()); outcome.Repaired || len(called(m.calls, "--configure -a")) != 0 {
		t.Fatalf("repaired without a finding: %v", m.calls)
	}
	m.calls = nil
	m.audit = "The following packages are only half configured, probably due to problems\nconfiguring them the first time.\n nginx\n"
	outcome, _ := m.job().Upgrade(context.Background())
	repair := called(m.calls, "--configure -a")
	if !outcome.Repaired || len(repair) != 1 || slices.Index(m.calls, repair[0]) > slices.Index(m.calls, called(m.calls, "upgrade")[0]) {
		t.Fatalf("got %+v after %v", outcome, m.calls)
	}
}

func TestKeptConfigFilesAreNamed(t *testing.T) {
	m := newMachine(t)
	m.stream = func(string) ([]event, error) {
		return []event{
			{line: "Configuration file '/etc/ssh/sshd_config'"},
			{line: " ==> Modified (by you or by a script) since installation."},
			{line: " ==> Package distributor has shipped an updated version."},
			{line: " ==> Keeping old config file as default."},
		}, nil
	}
	outcome, err := m.job().Upgrade(context.Background())
	if err != nil || !slices.Equal(outcome.Kept, []string{"/etc/ssh/sshd_config"}) {
		t.Fatalf("got %+v %v", outcome, err)
	}
}

func TestAnUpgradeSaysEachVersionItMoved(t *testing.T) {
	m := newMachine(t)
	m.stream = func(string) ([]event, error) {
		put(t, m.root, "/var/lib/dpkg/status", "Package: base-files\nStatus: install ok installed\nVersion: 1.0\n\nPackage: curl\nStatus: install ok installed\nVersion: 7.88.1-10+deb12u8\n")
		return nil, nil
	}
	outcome, err := m.job().Upgrade(context.Background())
	if err != nil || !slices.Equal(outcome.Moved, []Move{{Name: "curl", From: "1.0", To: "7.88.1-10+deb12u8"}}) {
		t.Fatalf("got %+v %v", outcome, err)
	}
}

func TestSomePackagesAreNeverRemoved(t *testing.T) {
	m := newMachine(t)
	put(t, m.root, "/var/lib/dpkg/status", "Package: base-files\nEssential: yes\nStatus: install ok installed\nVersion: 12\n\nPackage: systemd\nProtected: yes\nStatus: install ok installed\nVersion: 252\n\nPackage: htop\nStatus: install ok installed\nVersion: 3\n")
	job := m.job()
	job.Features = map[string]string{"docker-ce": "docker", "containerd.io": "docker"}
	for _, removes := range [][]string{{"openssh-server"}, {"linux-image-6.1.0-27-amd64"}, {"linux-image-unsigned-6.1.0-27-amd64"}, {"base-files"}, {"systemd"}, {"containerd.io"}, {"htop", "openssh-server"}} {
		if err := job.Removable(removes); err == nil {
			t.Fatalf("%v may not be removed", removes)
		}
	}
	if err := job.Removable([]string{"htop", "linux-image-6.1.0-26-amd64"}); err != nil {
		t.Fatal(err)
	}
}

func TestARemovalTriedFirstIsRefusedWhenItTakesSomethingProtected(t *testing.T) {
	m := newMachine(t)
	m.installed("base-files", "curl", "openssh-server", "openssh-client", "htop")
	m.replies = func(command string) string {
		if strings.Contains(command, "-s ") && strings.HasSuffix(command, " remove openssh-client") {
			return "Remv openssh-server [1:9.2p1-2]\nRemv openssh-client [1:9.2p1-2]\n"
		}
		return ""
	}
	if _, err := m.job().Remove(context.Background(), "openssh-client", false); err == nil || !strings.Contains(err.Error(), "openssh-server") {
		t.Fatalf("got %v", err)
	}
	if len(called(m.calls, "DEBIAN_FRONTEND")) != 0 {
		t.Fatalf("removed anyway: %v", m.calls)
	}
	m.stream = func(command string) ([]event, error) {
		if strings.HasSuffix(command, " purge htop") {
			m.installed("base-files", "curl", "openssh-server", "openssh-client")
		}
		return nil, nil
	}
	outcome, err := m.job().Remove(context.Background(), "htop", true)
	if err != nil || !slices.Equal(outcome.Removed, []string{"htop"}) {
		t.Fatalf("got %+v %v", outcome, err)
	}
}
