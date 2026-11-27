package platform

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type fakeRun struct {
	calls   []string
	respond map[string]string
	failing map[string]bool
	effects map[string]func()
	slept   time.Duration
}

func (f *fakeRun) run(_ context.Context, name string, args ...string) ([]byte, int, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if effect := f.effects[call]; effect != nil {
		effect()
	}
	if f.failing[call] {
		if answer := f.respond[call]; answer != "" {
			return []byte(answer), 100, errors.New("exit status 100")
		}
		return []byte("failed"), 1, errors.New("exit status 1")
	}
	return []byte(f.respond[call]), 0, nil
}

func (f *fakeRun) count(call string) int {
	n := 0
	for _, made := range f.calls {
		if made == call {
			n++
		}
	}
	return n
}

func (f *fakeRun) failTimes(call string, times int) {
	f.failing[call] = true
	f.effects[call] = func() {
		if f.count(call) > times {
			delete(f.failing, call)
		}
	}
}

var releases = map[string]string{
	"debian 12": "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\nID=debian\n",
	"debian 13": "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\nID=debian\n",
	"ubuntu":    "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\nUBUNTU_CODENAME=noble\n",
	"mint":      "PRETTY_NAME=\"Linux Mint 22\"\nNAME=\"Linux Mint\"\nVERSION_ID=\"22\"\nVERSION_CODENAME=wilma\nID=linuxmint\nID_LIKE=\"ubuntu debian\"\nUBUNTU_CODENAME=noble\n",
	"rocky":     "PRETTY_NAME=\"Rocky Linux 9.4 (Blue Onyx)\"\nNAME=\"Rocky Linux\"\nVERSION_ID=\"9.4\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n",
	"almalinux": "PRETTY_NAME=\"AlmaLinux 10.0 (Purple Lion)\"\nNAME=\"AlmaLinux\"\nVERSION_ID=\"10.0\"\nID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\n",
	"oracle":    "PRETTY_NAME=\"Oracle Linux Server 9.5\"\nNAME=\"Oracle Linux Server\"\nVERSION_ID=\"9.5\"\nID=\"ol\"\nID_LIKE=\"fedora\"\n",
	"centos":    "PRETTY_NAME=\"CentOS Stream 9\"\nNAME=\"CentOS Stream\"\nVERSION_ID=\"9\"\nID=\"centos\"\nID_LIKE=\"rhel fedora\"\n",
	"centos 7":  "PRETTY_NAME=\"CentOS Linux 7 (Core)\"\nNAME=\"CentOS Linux\"\nVERSION_ID=\"7\"\nID=\"centos\"\nID_LIKE=\"rhel fedora\"\n",
	"rhel":      "PRETTY_NAME=\"Red Hat Enterprise Linux 9.6 (Plow)\"\nNAME=\"Red Hat Enterprise Linux\"\nVERSION_ID=\"9.6\"\nID=\"rhel\"\nID_LIKE=\"fedora\"\n",
	"fedora":    "PRETTY_NAME=\"Fedora Linux 42 (Server Edition)\"\nNAME=\"Fedora Linux\"\nVERSION_ID=42\nID=fedora\n",
	"opensuse":  "NAME=\"openSUSE Leap\"\nVERSION_ID=\"15.6\"\nID=\"opensuse-leap\"\nID_LIKE=\"suse opensuse\"\nPRETTY_NAME=\"openSUSE Leap 15.6\"\n",
	"sles":      "NAME=\"SLES\"\nVERSION_ID=\"15.6\"\nID=\"sles\"\nID_LIKE=\"suse\"\nPRETTY_NAME=\"SUSE Linux Enterprise Server 15 SP6\"\n",
	"arch":      "NAME=\"Arch Linux\"\nPRETTY_NAME=\"Arch Linux\"\nID=arch\n",
	"manjaro":   "NAME=\"Manjaro Linux\"\nPRETTY_NAME=\"Manjaro Linux\"\nID=manjaro\nID_LIKE=arch\n",
	"alpine":    "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME=\"Alpine Linux v3.20\"\n",
	"unknown":   "NAME=\"Something\"\nID=something\n",
}

func onRelease(t *testing.T, key string) (Env, *fakeRun) {
	t.Helper()
	run := &fakeRun{respond: map[string]string{}, failing: map[string]bool{}, effects: map[string]func(){}}
	env := Env{Root: t.TempDir(), Run: run.run, sleep: func(d time.Duration) { run.slept += d }}
	write(t, env, "/etc/os-release", releases[key])
	if !strings.HasSuffix(key, " 7") {
		write(t, env, "/usr/bin/dnf", "")
	}
	return env, run
}

func write(t *testing.T, env Env, name, body string) {
	t.Helper()
	full := filepath.Join(env.Root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectKnowsTheFamiliesAndTheirPackageManager(t *testing.T) {
	for key, want := range map[string]Platform{
		"debian 12": {ID: "debian", Version: "12", Codename: "bookworm", Name: "Debian GNU/Linux 12", Family: Debian, Base: "debian", Manager: "apt"},
		"ubuntu":    {ID: "ubuntu", Version: "24.04", Codename: "noble", Name: "Ubuntu 24.04", Family: Debian, Base: "ubuntu", Manager: "apt"},
		"mint":      {ID: "linuxmint", Version: "22", Codename: "noble", Name: "Linux Mint 22", Family: Debian, Base: "ubuntu", Manager: "apt"},
		"rocky":     {ID: "rocky", Version: "9", Name: "Rocky Linux 9.4", Family: RHEL, Base: "centos", Manager: "dnf"},
		"almalinux": {ID: "almalinux", Version: "10", Name: "AlmaLinux 10.0", Family: RHEL, Base: "centos", Manager: "dnf"},
		"oracle":    {ID: "ol", Version: "9", Name: "Oracle Linux Server 9.5", Family: RHEL, Base: "centos", Manager: "dnf"},
		"centos":    {ID: "centos", Version: "9", Name: "CentOS Stream 9", Family: RHEL, Base: "centos", Manager: "dnf"},
		"centos 7":  {ID: "centos", Version: "7", Name: "CentOS Linux 7", Family: RHEL, Base: "centos", Manager: "yum"},
		"rhel":      {ID: "rhel", Version: "9", Name: "Red Hat Enterprise Linux 9.6", Family: RHEL, Base: "rhel", Manager: "dnf"},
		"fedora":    {ID: "fedora", Version: "42", Name: "Fedora Linux 42", Manager: "dnf"},
		"opensuse":  {ID: "opensuse-leap", Version: "15.6", Name: "openSUSE Leap 15.6", Manager: "zypper"},
		"sles":      {ID: "sles", Version: "15.6", Name: "SLES 15.6", Manager: "zypper"},
		"arch":      {ID: "arch", Name: "Arch Linux", Manager: "pacman"},
		"manjaro":   {ID: "manjaro", Name: "Manjaro Linux", Manager: "pacman"},
		"alpine":    {ID: "alpine", Version: "3.20.3", Name: "Alpine Linux 3.20.3", Manager: "apk"},
		"unknown":   {ID: "something", Name: "Something"},
	} {
		env, _ := onRelease(t, key)
		got := Detect(env)
		got.Pretty = ""
		if got != want {
			t.Errorf("%s: got %+v want %+v", key, got, want)
		}
	}
	env, _ := onRelease(t, "debian 13")
	if got := Detect(env); got.Pretty != "Debian GNU/Linux 13 (trixie)" {
		t.Fatalf("pretty name: %+v", got)
	}
}

func TestOnlyMissingPackagesAreInstalledAndReported(t *testing.T) {
	ctx := context.Background()
	env, run := onRelease(t, "debian 13")
	run.failing["dpkg-query -W -f ${Status} wireguard-tools"] = true
	run.respond["dpkg-query -W -f ${Status} iptables"] = "install ok installed"
	installed, err := Install(ctx, env, "wireguard-tools", "iptables")
	if err != nil || !slices.Equal(installed, []string{"wireguard-tools"}) {
		t.Fatalf("installed %q err %v", installed, err)
	}
	want := []string{
		"dpkg-query -W -f ${Status} wireguard-tools",
		"dpkg-query -W -f ${Status} iptables",
		aptUpdate,
		"env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -q wireguard-tools",
	}
	if !slices.Equal(run.calls, want) {
		t.Fatalf("calls %q", run.calls)
	}
	env, run = onRelease(t, "debian 13")
	run.respond["dpkg-query -W -f ${Status} iptables"] = "install ok installed"
	if installed, err := Install(ctx, env, "iptables"); err != nil || installed != nil || len(run.calls) != 1 {
		t.Fatalf("installed %q err %v calls %q", installed, err, run.calls)
	}
}

func TestEachPackageManagerInstallsAndPurgesItsOwnWay(t *testing.T) {
	ctx := context.Background()
	for key, want := range map[string][3]string{
		"rocky":    {"rpm -q wireguard-tools", "dnf install -y -q wireguard-tools", "dnf remove -y -q wireguard-tools"},
		"centos 7": {"rpm -q wireguard-tools", "yum install -y -q wireguard-tools", "yum remove -y -q wireguard-tools"},
		"opensuse": {"rpm -q wireguard-tools", "zypper --non-interactive install wireguard-tools", "zypper --non-interactive remove wireguard-tools"},
		"arch":     {"pacman -Q wireguard-tools", "pacman -S --noconfirm --needed wireguard-tools", "pacman -Rns --noconfirm wireguard-tools"},
		"alpine":   {"apk info -e wireguard-tools", "apk add -q wireguard-tools", "apk del -q wireguard-tools"},
		"ubuntu":   {"dpkg-query -W -f ${Status} wireguard-tools", "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -q wireguard-tools", "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 purge -y -q wireguard-tools"},
	} {
		env, run := onRelease(t, key)
		run.failing[want[0]] = true
		installed, err := Install(ctx, env, "wireguard-tools")
		if err != nil || !slices.Equal(installed, []string{"wireguard-tools"}) || !slices.Contains(run.calls, want[1]) {
			t.Fatalf("%s: installed %q err %v calls %q", key, installed, err, run.calls)
		}
		if err := Purge(ctx, env, "wireguard-tools"); err != nil || run.calls[len(run.calls)-1] != want[2] {
			t.Fatalf("%s: purge %v calls %q", key, err, run.calls)
		}
		if key != "ubuntu" && slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "apt-get") }) {
			t.Fatalf("%s: apt on another family: %q", key, run.calls)
		}
	}
}

func TestAFailedInstallSaysWhatFailed(t *testing.T) {
	env, run := onRelease(t, "rocky")
	run.failing["rpm -q wireguard-tools"] = true
	run.failing["dnf install -y -q wireguard-tools"] = true
	if installed, err := Install(context.Background(), env, "wireguard-tools"); err == nil || installed != nil || !strings.Contains(err.Error(), "dnf install -y -q wireguard-tools failed: failed") {
		t.Fatalf("installed %q err %v", installed, err)
	}
}

func TestAnInstallThatFailsPartwayReportsWhatItInstalled(t *testing.T) {
	env, run := onRelease(t, "rocky")
	install := "dnf install -y -q wireguard-tools iptables-nft"
	run.failing["rpm -q wireguard-tools"] = true
	run.failing["rpm -q iptables-nft"] = true
	run.failing[install] = true
	run.effects[install] = func() { delete(run.failing, "rpm -q wireguard-tools") }
	installed, err := Install(context.Background(), env, "wireguard-tools", "iptables-nft")
	if err == nil || !slices.Equal(installed, []string{"wireguard-tools"}) {
		t.Fatalf("installed %q err %v", installed, err)
	}
	if run.count("rpm -q iptables-nft") != 2 || run.count("rpm -q wireguard-tools") != 2 {
		t.Fatalf("calls %q", run.calls)
	}
	env, run = onRelease(t, "debian 12")
	run.failing[aptUpdate] = true
	if installed, err := Install(context.Background(), env, "wireguard-tools"); err == nil || installed != nil {
		t.Fatalf("a failed update reports %q err %v", installed, err)
	}
}

func TestAServerWithoutAKnownPackageManagerIsRefused(t *testing.T) {
	env, run := onRelease(t, "unknown")
	if _, err := Install(context.Background(), env, "wireguard-tools"); !errors.Is(err, ErrUnsupported) || len(run.calls) != 0 {
		t.Fatalf("err %v calls %q", err, run.calls)
	}
	if err := Purge(context.Background(), env, "wireguard-tools"); !errors.Is(err, ErrUnsupported) || len(run.calls) != 0 {
		t.Fatalf("err %v calls %q", err, run.calls)
	}
}

const (
	aptUpdate = "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 update -q"
	listsHeld = "Reading package lists...\nE: Could not get lock /var/lib/apt/lists/lock. It is held by process 4242 (apt-get)\nE: Unable to lock directory /var/lib/apt/lists/"
	missing   = "dpkg-query -W -f ${Status} wireguard-tools"
)

func TestPackageListsAnotherAptHoldsAreWaitedFor(t *testing.T) {
	env, run := onRelease(t, "debian 12")
	run.failing[missing] = true
	run.respond[aptUpdate] = listsHeld
	run.failTimes(aptUpdate, 2)
	if _, err := Install(context.Background(), env, "wireguard-tools"); err != nil {
		t.Fatal(err)
	}
	if run.count(aptUpdate) != 3 || run.slept != 10*time.Second || !slices.Contains(run.calls, "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -q wireguard-tools") {
		t.Fatalf("slept %v calls %q", run.slept, run.calls)
	}
}

func TestPackageListsAreWaitedForTenMinutesAndNothingElseIsWaitedFor(t *testing.T) {
	env, run := onRelease(t, "debian 12")
	run.failing[missing] = true
	run.respond[aptUpdate] = listsHeld
	run.failing[aptUpdate] = true
	_, err := Install(context.Background(), env, "wireguard-tools")
	if err == nil || !strings.Contains(err.Error(), "/var/lib/apt/lists/lock") || run.slept != 10*time.Minute || run.count(aptUpdate) != 121 {
		t.Fatalf("err %v slept %v updates %d", err, run.slept, run.count(aptUpdate))
	}
	env, run = onRelease(t, "debian 12")
	run.failing[missing] = true
	run.failing[aptUpdate] = true
	if _, err := Install(context.Background(), env, "wireguard-tools"); err == nil || run.slept != 0 || run.count(aptUpdate) != 1 {
		t.Fatalf("err %v slept %v calls %q", err, run.slept, run.calls)
	}
}

func TestAnInstalledPackageIsAloneOnlyWhenNothingElseWouldGoWithIt(t *testing.T) {
	ctx := context.Background()
	apt := "apt-get -s purge iptables"
	dnf := "env LC_ALL=C dnf remove --assumeno iptables-nft"
	for name, test := range map[string]struct {
		release, call, pkg, answer string
		fail                       bool
		want                       bool
	}{
		"apt only the package":              {"debian 12", apt, "iptables", "Reading package lists...\nPurg iptables [1.8.9-2]\n", false, true},
		"apt removed and purged":            {"ubuntu", apt, "iptables", "Remv iptables [1.8.10-3]\nPurg iptables [1.8.10-3]\n", false, true},
		"apt another package goes":          {"debian 12", apt, "iptables", "Remv kubelet [1.30.0]\nRemv docker-ce [5:27.0]\nPurg iptables [1.8.9-2]\n", false, false},
		"apt another one first":             {"debian 12", apt, "iptables", "Purg iptables [1.8.9-2]\nPurg ufw [0.36]\n", false, false},
		"apt a name that only starts alike": {"debian 12", apt, "iptables", "Purg iptables-persistent [1.0]\n", false, false},
		"apt the simulation says nothing":   {"debian 12", apt, "iptables", "", false, false},
		"apt the simulation fails":          {"debian 12", apt, "iptables", "E: Unable to locate package iptables", true, false},
		"dnf only the package":              {"rocky", dnf, "iptables-nft", "Removing:\n iptables-nft x86_64 1.8.10 @baseos 80 k\nRemoving unused dependencies:\n iptables-libs x86_64 1.8.10 @baseos 70 k\nOperation aborted.\n", false, true},
		"dnf dependent packages":            {"rocky", dnf, "iptables-nft", "Removing:\n iptables-nft x86_64 1.8.10 @baseos 80 k\nRemoving dependent packages:\n docker-ce x86_64 27.0 @docker 100 M\nOperation aborted.\n", false, false},
		"dnf nothing matches":               {"rocky", dnf, "iptables-nft", "No match for argument: iptables-nft\nNo packages marked for removal.\n", false, false},
		"yum dependencies":                  {"centos 7", "env LC_ALL=C yum remove --assumeno iptables-nft", "iptables-nft", "Removing:\n iptables-nft x86_64 1.8.10 @base 80 k\nRemoving for dependencies:\n kubelet x86_64 1.30 @k8s 90 M\n", false, false},
		"pacman cannot say":                 {"arch", "pacman -Rns --print iptables", "iptables", "iptables\n", false, false},
	} {
		env, run := onRelease(t, test.release)
		run.respond[test.call] = test.answer
		if test.fail {
			run.failing[test.call] = true
		}
		if got := Alone(ctx, env, test.pkg); got != test.want {
			t.Fatalf("%s: %v, calls %q", name, got, run.calls)
		}
	}
}

func TestTheDockerDropInRunsTheGuardFirst(t *testing.T) {
	if DockerGuardDropInPath != "/etc/systemd/system/docker.service.d/krynodes-guard.conf" {
		t.Fatalf("path %q", DockerGuardDropInPath)
	}
	if got := DockerGuardDropIn("/usr/local/bin/kry"); got != "[Service]\nExecStartPre=/usr/local/bin/kry guard\n" {
		t.Fatalf("a guard that cannot be skipped: %q", got)
	}
}

func TestDockerWaitsForTheGuardOnlyOnceTheDropInIsLoaded(t *testing.T) {
	env, run := onRelease(t, "debian 13")
	env.Executable = "/usr/local/bin/kry"
	if err := env.GuardDocker(context.Background()); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(env.Root, filepath.FromSlash(DockerGuardDropInPath)))
	if err != nil || string(body) != "[Service]\nExecStartPre=/usr/local/bin/kry guard\n" {
		t.Fatalf("drop-in %q %v", body, err)
	}
	if !slices.Equal(run.calls, []string{"systemctl daemon-reload"}) {
		t.Fatalf("calls %q", run.calls)
	}

	for _, executable := range []string{"", "kry", "./kry"} {
		bare, bareRun := onRelease(t, "debian 13")
		bare.Executable = executable
		if err := bare.GuardDocker(context.Background()); err == nil {
			t.Errorf("%q: a drop-in that names no absolute path would keep Docker down", executable)
		}
		if _, err := os.Stat(filepath.Join(bare.Root, filepath.FromSlash(DockerGuardDropInPath))); err == nil || len(bareRun.calls) > 0 {
			t.Errorf("%q: nothing is written or reloaded: %q", executable, bareRun.calls)
		}
	}

	broken, brokenRun := onRelease(t, "debian 13")
	broken.Executable = "/usr/local/bin/kry"
	brokenRun.failing["systemctl daemon-reload"] = true
	if err := broken.GuardDocker(context.Background()); err == nil || !strings.Contains(err.Error(), "daemon-reload") {
		t.Fatalf("a reload that failed is said: %v", err)
	}
}

const (
	loadState    = "systemctl show -p LoadState docker.service"
	execStartPre = "systemctl show -p ExecStartPre docker.service"
	dropInPaths  = "systemctl show -p DropInPaths docker.service"
	needsReload  = "systemctl show -p NeedDaemonReload docker.service"
	guardRuns    = "ExecStartPre={ path=/usr/local/bin/kry ; argv[]=/usr/local/bin/kry guard ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n"
)

func TestTheLoopGuardsDockerOnlyWhereItsServiceIsLoaded(t *testing.T) {
	for name, test := range map[string]struct {
		answer  string
		fail    bool
		written bool
	}{
		"loaded":                 {"LoadState=loaded\n", false, true},
		"not found":              {"LoadState=not-found\n", false, false},
		"systemd did not answer": {"", true, false},
	} {
		env, run := onRelease(t, "debian 13")
		env.Executable = "/usr/local/bin/kry"
		run.respond[loadState] = test.answer
		run.failing[loadState] = test.fail
		run.respond[execStartPre] = guardRuns
		err := env.GuardInstalledDocker(context.Background())
		switch {
		case test.written && err != nil:
			t.Fatalf("%s: %v", name, err)
		case name == "not found" && !errors.Is(err, ErrNoDockerUnit):
			t.Fatalf("%s: %v", name, err)
		case test.fail && (err == nil || errors.Is(err, ErrNoDockerUnit) || !strings.Contains(err.Error(), "does not say whether Docker has a unit")):
			t.Fatalf("%s: a question systemd cannot answer is not 'no docker.service': %v", name, err)
		}
		_, statErr := os.Stat(filepath.Join(env.Root, filepath.FromSlash(DockerGuardDropInPath)))
		if (statErr == nil) != test.written || (run.count("systemctl daemon-reload") == 1) != test.written {
			t.Fatalf("%s: written %v, calls %q", name, statErr == nil, run.calls)
		}
	}
}

func TestUnguardDockerTakesTheDropInAwayAndReloads(t *testing.T) {
	env, run := onRelease(t, "debian 13")
	env.Executable = "/usr/local/bin/kry"
	other := filepath.Join(env.Root, "etc", "systemd", "system", "docker.service.d", "other.conf")
	write(t, env, "/etc/systemd/system/docker.service.d/other.conf", "[Service]\n")
	if err := env.GuardDocker(context.Background()); err != nil {
		t.Fatal(err)
	}
	run.calls = nil
	if err := env.UnguardDocker(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(env.Root, filepath.FromSlash(DockerGuardDropInPath))); err == nil {
		t.Fatal("Docker would still wait for a binary that is going away")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("another drop-in of the owner's stays: %v", err)
	}
	if !slices.Equal(run.calls, []string{"systemctl daemon-reload"}) {
		t.Fatalf("calls %q", run.calls)
	}

	os.Remove(other)
	run.calls = nil
	if err := env.UnguardDocker(context.Background()); err != nil || len(run.calls) > 0 {
		t.Fatalf("nothing to take away: %v %q", err, run.calls)
	}
}

func TestTheDropInIsKeptWithoutReloadingSystemdAgain(t *testing.T) {
	env, run := onRelease(t, "debian 13")
	env.Executable = "/usr/local/bin/kry"
	run.respond[loadState] = "LoadState=loaded\n"
	run.respond[execStartPre] = guardRuns
	path := filepath.Join(env.Root, filepath.FromSlash(DockerGuardDropInPath))
	if err := env.GuardInstalledDocker(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(run.calls, []string{loadState, "systemctl daemon-reload", execStartPre}) {
		t.Fatalf("calls %q", run.calls)
	}

	run.calls = nil
	if err := env.GuardInstalledDocker(context.Background()); err != nil || !slices.Equal(run.calls, []string{loadState, execStartPre}) {
		t.Fatalf("a drop-in that is right is only checked, never written or reloaded: %v %q", err, run.calls)
	}

	write(t, env, DockerGuardDropInPath, "[Service]\nExecStartPre=/old/kry guard\n")
	if err := env.GuardInstalledDocker(context.Background()); err != nil {
		t.Fatal(err)
	}
	if body, _ := os.ReadFile(path); string(body) != DockerGuardDropIn("/usr/local/bin/kry") || run.count("systemctl daemon-reload") != 1 {
		t.Fatalf("a drop-in that differs is written again: %q %q", body, run.calls)
	}

	os.Remove(path)
	run.calls = nil
	run.failing["systemctl daemon-reload"] = true
	if err := env.GuardInstalledDocker(context.Background()); err == nil {
		t.Fatal("a reload that failed is said")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a drop-in that systemd did not load is not left to look finished")
	}
	delete(run.failing, "systemctl daemon-reload")
	if err := env.GuardInstalledDocker(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the next pass tries again: %v", err)
	}
}

func TestAnOverridingDropInIsNamedWhenSystemdDoesNotRunTheGuard(t *testing.T) {
	env, run := onRelease(t, "debian 13")
	env.Executable = "/usr/local/bin/kry"
	run.respond[loadState] = "LoadState=loaded\n"
	run.respond[execStartPre] = "ExecStartPre=\n"
	run.respond[dropInPaths] = "DropInPaths=/etc/systemd/system/docker.service.d/krynodes-guard.conf /etc/systemd/system/docker.service.d/override.conf\n"
	err := env.GuardInstalledDocker(context.Background())
	if err == nil || !strings.Contains(err.Error(), "/etc/systemd/system/docker.service.d/override.conf") || strings.Contains(err.Error(), "krynodes-guard.conf,") {
		t.Fatalf("the drop-in that resets ExecStartPre is named: %v", err)
	}

	run.respond[dropInPaths] = "DropInPaths=/etc/systemd/system/docker.service.d/krynodes-guard.conf\n"
	if err := env.GuardInstalledDocker(context.Background()); err == nil || !strings.Contains(err.Error(), "does not run /usr/local/bin/kry guard") {
		t.Fatalf("with nothing to name it still says that the guard does not run: %v", err)
	}

	run.respond[execStartPre] = "ExecStartPre={ path=/usr/local/bin/kry ; argv[]=/usr/local/bin/kry guard-other ; ignore_errors=no }\n"
	if err := env.GuardInstalledDocker(context.Background()); err == nil {
		t.Fatal("another command is not the guard")
	}

	run.respond[execStartPre] = "ExecStartPre={ path=/bin/true ; argv[]=/bin/true ; ignore_errors=no } ; { path=/usr/local/bin/kry ; argv[]=/usr/local/bin/kry guard ; ignore_errors=no }\n"
	if err := env.GuardInstalledDocker(context.Background()); err != nil {
		t.Fatalf("the guard among other commands is enough: %v", err)
	}

	run.failing[execStartPre] = true
	if err := env.GuardInstalledDocker(context.Background()); err == nil || !strings.Contains(err.Error(), "does not say what runs before Docker") {
		t.Fatalf("a question systemd cannot answer is said: %v", err)
	}
}

func TestAGuardThatSystemdMayIgnoreIsNotTheGuard(t *testing.T) {
	env, run := onRelease(t, "debian 13")
	env.Executable = "/usr/local/bin/kry"
	run.respond[loadState] = "LoadState=loaded\n"
	run.respond[dropInPaths] = "DropInPaths=/etc/systemd/system/docker.service.d/krynodes-guard.conf /etc/systemd/system/docker.service.d/override.conf\n"
	run.respond[execStartPre] = "ExecStartPre={ path=/usr/local/bin/kry ; argv[]=/usr/local/bin/kry guard ; ignore_errors=yes ; start_time=[n/a] }\n"
	err := env.GuardInstalledDocker(context.Background())
	if err == nil || !strings.Contains(err.Error(), "override.conf") {
		t.Fatalf("ExecStartPre=- lets Docker start when the guard fails, and the override is named: %v", err)
	}

	run.respond[execStartPre] = "ExecStartPre={ path=/usr/local/bin/kry ; argv[]=/usr/local/bin/kry guard ; ignore_errors=yes }\n{ path=/bin/true ; argv[]=/bin/true ; ignore_errors=no }\n"
	if err := env.GuardInstalledDocker(context.Background()); err == nil {
		t.Fatal("ignore_errors=no belonging to another entry does not count")
	}

	run.respond[execStartPre] = "ExecStartPre={ path=/bin/true ; argv[]=/bin/true ; ignore_errors=yes } ; { path=/usr/local/bin/kry ; argv[]=/usr/local/bin/kry guard ; ignore_errors=no }\n"
	if err := env.GuardInstalledDocker(context.Background()); err != nil {
		t.Fatalf("the guard entry with ignore_errors=no is enough: %v", err)
	}
}

func TestADropInThatSystemdHasNotLoadedIsReloadedOnce(t *testing.T) {
	env, run := onRelease(t, "debian 13")
	env.Executable = "/usr/local/bin/kry"
	write(t, env, DockerGuardDropInPath, DockerGuardDropIn("/usr/local/bin/kry"))
	run.respond[loadState] = "LoadState=loaded\n"
	run.respond[execStartPre] = "ExecStartPre=\n"
	run.respond[dropInPaths] = "DropInPaths=\n"
	run.respond[needsReload] = "NeedDaemonReload=yes\n"
	run.effects["systemctl daemon-reload"] = func() { run.respond[execStartPre] = guardRuns }
	if err := env.GuardInstalledDocker(context.Background()); err != nil {
		t.Fatalf("a file that is right and a reload that fixes it: %v", err)
	}
	if run.count("systemctl daemon-reload") != 1 {
		t.Fatalf("one reload: %q", run.calls)
	}

	run.calls = nil
	if err := env.GuardInstalledDocker(context.Background()); err != nil || run.count("systemctl daemon-reload") != 0 {
		t.Fatalf("once loaded it is only checked: %v %q", err, run.calls)
	}

	run.respond[execStartPre] = "ExecStartPre=\n"
	delete(run.effects, "systemctl daemon-reload")
	run.calls = nil
	err := env.GuardInstalledDocker(context.Background())
	if err == nil || !strings.Contains(err.Error(), "does not run /usr/local/bin/kry guard") || run.count("systemctl daemon-reload") != 1 {
		t.Fatalf("a reload that does not help is tried once and then said: %v %q", err, run.calls)
	}

	run.failing["systemctl daemon-reload"] = true
	run.calls = nil
	if err := env.GuardInstalledDocker(context.Background()); err == nil || !strings.Contains(err.Error(), "daemon-reload") {
		t.Fatalf("a reload that failed is said: %v", err)
	}
	delete(run.failing, "systemctl daemon-reload")

	run.respond[needsReload] = "NeedDaemonReload=no\n"
	for pass := range 3 {
		run.calls = nil
		if err := env.GuardInstalledDocker(context.Background()); err == nil || !strings.Contains(err.Error(), "does not run /usr/local/bin/kry guard") || run.count("systemctl daemon-reload") != 0 {
			t.Fatalf("pass %d: systemd says no reload is needed, so none is run and the error stays: %v %q", pass, err, run.calls)
		}
	}

	run.failing[needsReload] = true
	if err := env.GuardInstalledDocker(context.Background()); err == nil || !strings.Contains(err.Error(), "does not say whether it must reload") || run.count("systemctl daemon-reload") != 0 {
		t.Fatalf("a question systemd cannot answer is said and nothing is reloaded: %v", err)
	}
	delete(run.failing, needsReload)
	run.respond[needsReload] = "NeedDaemonReload=yes\n"

	delete(run.failing, "systemctl daemon-reload")
	run.respond[dropInPaths] = "DropInPaths=/etc/systemd/system/docker.service.d/krynodes-guard.conf /etc/systemd/system/docker.service.d/override.conf\n"
	run.calls = nil
	if err := env.GuardInstalledDocker(context.Background()); err == nil || !strings.Contains(err.Error(), "override.conf") || run.count("systemctl daemon-reload") != 0 {
		t.Fatalf("an override is named and no reload is tried for it: %v %q", err, run.calls)
	}
}

func TestTheDropInIsWrittenOnlyOnceTheGuardHolds(t *testing.T) {
	env, run := onRelease(t, "debian 13")
	env.Executable = "/usr/local/bin/kry"
	path := filepath.Join(env.Root, filepath.FromSlash(DockerGuardDropInPath))
	proved := 0
	env.Prove = func(context.Context) error {
		proved++
		if _, err := os.Stat(path); err == nil {
			t.Error("the drop-in was there before the guard held")
		}
		return errors.New("the guard of Contained stacks: iptables: Permission denied")
	}
	if err := env.GuardDocker(context.Background()); err == nil || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("a guard that fails is the error: %v", err)
	}
	if _, err := os.Stat(path); err == nil || proved != 1 || run.count("systemctl daemon-reload") > 0 {
		t.Fatalf("nothing is written or reloaded: proved %d, calls %q", proved, run.calls)
	}
	env.Prove = func(context.Context) error { proved++; return nil }
	if err := env.GuardDocker(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil || proved != 2 || run.count("systemctl daemon-reload") != 1 {
		t.Fatalf("a guard that holds lets the drop-in go in: %v, proved %d, calls %q", err, proved, run.calls)
	}
}
