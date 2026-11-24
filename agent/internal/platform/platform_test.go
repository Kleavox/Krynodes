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
