package recipes

import (
	"context"
	"slices"
	"strings"
	"testing"
)

var releases = map[string]string{
	"debian 12":  "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\nID=debian\n",
	"debian 13":  "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\nID=debian\n",
	"debian 14":  "PRETTY_NAME=\"Debian GNU/Linux 14 (forky)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"14\"\nVERSION_CODENAME=forky\nID=debian\n",
	"debian sid": "PRETTY_NAME=\"Debian GNU/Linux trixie/sid\"\nNAME=\"Debian GNU/Linux\"\nID=debian\n",
	"ubuntu":     "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\nUBUNTU_CODENAME=noble\n",
	"ubuntu new": "PRETTY_NAME=\"Ubuntu 26.10\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"26.10\"\nVERSION_CODENAME=stonking\nID=ubuntu\nID_LIKE=debian\n",
	"mint":       "PRETTY_NAME=\"Linux Mint 22\"\nNAME=\"Linux Mint\"\nVERSION_ID=\"22\"\nVERSION_CODENAME=wilma\nID=linuxmint\nID_LIKE=\"ubuntu debian\"\nUBUNTU_CODENAME=noble\n",
	"rocky":      "PRETTY_NAME=\"Rocky Linux 9.4 (Blue Onyx)\"\nNAME=\"Rocky Linux\"\nVERSION_ID=\"9.4\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n",
	"rocky new":  "PRETTY_NAME=\"Rocky Linux 11.0\"\nNAME=\"Rocky Linux\"\nVERSION_ID=\"11.0\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n",
	"almalinux":  "PRETTY_NAME=\"AlmaLinux 10.0 (Purple Lion)\"\nNAME=\"AlmaLinux\"\nVERSION_ID=\"10.0\"\nID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\n",
	"oracle":     "PRETTY_NAME=\"Oracle Linux Server 9.5\"\nNAME=\"Oracle Linux Server\"\nVERSION_ID=\"9.5\"\nID=\"ol\"\nID_LIKE=\"fedora\"\n",
	"centos":     "PRETTY_NAME=\"CentOS Stream 9\"\nNAME=\"CentOS Stream\"\nVERSION_ID=\"9\"\nID=\"centos\"\nID_LIKE=\"rhel fedora\"\n",
	"rhel":       "PRETTY_NAME=\"Red Hat Enterprise Linux 9.6 (Plow)\"\nNAME=\"Red Hat Enterprise Linux\"\nVERSION_ID=\"9.6\"\nID=\"rhel\"\nID_LIKE=\"fedora\"\n",
	"fedora":     "PRETTY_NAME=\"Fedora Linux 42 (Server Edition)\"\nNAME=\"Fedora Linux\"\nVERSION_ID=42\nID=fedora\n",
	"alpine":     "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME=\"Alpine Linux v3.20\"\n",
}

func onRelease(t *testing.T, key string) (Env, *fakeRun) {
	t.Helper()
	env, run := newEnv(t)
	write(t, env, "/etc/os-release", releases[key])
	return env, run
}

func TestDetectKnowsTheFamilies(t *testing.T) {
	for key, want := range map[string]Platform{
		"debian 12": {ID: "debian", Version: "12", Codename: "bookworm", Name: "Debian GNU/Linux 12", Family: Debian, Base: "debian"},
		"ubuntu":    {ID: "ubuntu", Version: "24.04", Codename: "noble", Name: "Ubuntu 24.04", Family: Debian, Base: "ubuntu"},
		"mint":      {ID: "linuxmint", Version: "22", Codename: "noble", Name: "Linux Mint 22", Family: Debian, Base: "ubuntu"},
		"rocky":     {ID: "rocky", Version: "9", Name: "Rocky Linux 9.4", Family: RHEL, Base: "centos"},
		"almalinux": {ID: "almalinux", Version: "10", Name: "AlmaLinux 10.0", Family: RHEL, Base: "centos"},
		"oracle":    {ID: "ol", Version: "9", Name: "Oracle Linux Server 9.5", Family: RHEL, Base: "centos"},
		"centos":    {ID: "centos", Version: "9", Name: "CentOS Stream 9", Family: RHEL, Base: "centos"},
		"rhel":      {ID: "rhel", Version: "9", Name: "Red Hat Enterprise Linux 9.6", Family: RHEL, Base: "rhel"},
		"fedora":    {ID: "fedora", Version: "42", Name: "Fedora Linux 42"},
		"alpine":    {ID: "alpine", Version: "3.20.3", Name: "Alpine Linux 3.20.3"},
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

func TestPackagesFollowTheFamily(t *testing.T) {
	ctx := context.Background()
	env, run := onRelease(t, "debian 13")
	run.failing["dpkg-query -W -f ${Status} curl"] = true
	run.respond["dpkg-query -W -f ${Status} gnupg"] = "install ok installed"
	fresh, err := env.install(ctx, "curl", "gnupg")
	if err != nil || fresh != "curl" {
		t.Fatalf("fresh %q err %v", fresh, err)
	}
	if err := env.purge(ctx, "curl"); err != nil {
		t.Fatal(err)
	}
	for _, call := range []string{
		"env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 update -q",
		"env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -q curl gnupg",
		"env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 purge -y -q curl",
	} {
		if !slices.Contains(run.calls, call) {
			t.Fatalf("missing %q in %q", call, run.calls)
		}
	}
	env, run = onRelease(t, "rocky")
	run.failing["rpm -q curl"] = true
	fresh, err = env.install(ctx, "curl", "tar")
	if err != nil || fresh != "curl" || !env.has(ctx, "tar") || env.has(ctx, "curl") {
		t.Fatalf("fresh %q err %v", fresh, err)
	}
	if err := env.purge(ctx, "curl"); err != nil {
		t.Fatal(err)
	}
	for _, call := range []string{"dnf install -y -q curl tar", "dnf remove -y -q curl"} {
		if !slices.Contains(run.calls, call) {
			t.Fatalf("missing %q in %q", call, run.calls)
		}
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, "apt-get") }) {
		t.Fatalf("no apt on RHEL: %q", run.calls)
	}
}

func TestApplyRunsOnAnyVersionOfAFamilyAndRefusesFedora(t *testing.T) {
	ctx := context.Background()
	env, run := onRelease(t, "rocky new")
	if _, err := Apply(ctx, env, "fail2ban", nil); err != nil {
		t.Fatal(err)
	}
	before := len(run.calls)
	if err := Undo(ctx, env, "fail2ban", nil); err != nil || len(run.calls) == before {
		t.Fatalf("undo %v", err)
	}
	for _, key := range []string{"fedora", "alpine"} {
		env, run = onRelease(t, key)
		if _, err := Apply(ctx, env, "fail2ban", nil); err != ErrUnsupported || len(run.calls) != 0 {
			t.Fatalf("%s: err %v calls %q", key, err, run.calls)
		}
	}
}
