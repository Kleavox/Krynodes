package recipes

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
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
	"fedora old": "PRETTY_NAME=\"Fedora Linux 40 (Server Edition)\"\nNAME=\"Fedora Linux\"\nVERSION_ID=40\nID=fedora\n",
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
		"debian 12": {ID: "debian", Version: "12", Codename: "bookworm", Name: "Debian GNU/Linux 12", Family: Debian, Base: "debian", Verified: true, Checked: "11 to 13"},
		"ubuntu":    {ID: "ubuntu", Version: "24.04", Codename: "noble", Name: "Ubuntu 24.04", Family: Debian, Base: "ubuntu", Verified: true, Checked: "22.04 to 26.04"},
		"mint":      {ID: "linuxmint", Version: "22", Codename: "noble", Name: "Linux Mint 22", Family: Debian, Base: "ubuntu"},
		"rocky":     {ID: "rocky", Version: "9", Name: "Rocky Linux 9.4", Family: RHEL, Base: "centos", Verified: true, Checked: "8 to 10"},
		"almalinux": {ID: "almalinux", Version: "10", Name: "AlmaLinux 10.0", Family: RHEL, Base: "centos", Verified: true, Checked: "8 to 10"},
		"oracle":    {ID: "ol", Version: "9", Name: "Oracle Linux Server 9.5", Family: RHEL, Base: "centos", Verified: true, Checked: "8 to 10"},
		"centos":    {ID: "centos", Version: "9", Name: "CentOS Stream 9", Family: RHEL, Base: "centos", Verified: true, Checked: "9 to 10"},
		"rhel":      {ID: "rhel", Version: "9", Name: "Red Hat Enterprise Linux 9.6", Family: RHEL, Base: "rhel", Verified: true, Checked: "8 to 10"},
		"fedora":    {ID: "fedora", Version: "42", Name: "Fedora Linux 42", Family: RHEL, Base: "fedora", Verified: true, Checked: "41 to 44"},
		"alpine":    {ID: "alpine", Version: "3.20.3", Name: "Alpine Linux 3.20.3"},
	} {
		env, _ := onRelease(t, key)
		got := Detect(env)
		got.Pretty, got.EndOfLife = "", time.Time{}
		if got != want {
			t.Errorf("%s: got %+v want %+v", key, got, want)
		}
	}
	env, _ := onRelease(t, "debian 13")
	if got := Detect(env); got.Pretty != "Debian GNU/Linux 13 (trixie)" || !got.EndOfLife.Equal(time.Date(2030, 6, 30, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("pretty name and end of life: %+v", got)
	}
}

func TestNewerOlderAndUncheckedVersionsAreUnverified(t *testing.T) {
	for key, want := range map[string]string{
		"debian 14":  "Debian GNU/Linux 14 is newer than the versions Krynodes has checked (11 to 13).",
		"rocky new":  "Rocky Linux 11 is newer than the versions Krynodes has checked (8 to 10).",
		"ubuntu new": "Ubuntu 26.10 is newer than the versions Krynodes has checked (22.04 to 26.04).",
		"fedora old": "Fedora Linux 40 is older than the versions Krynodes has checked (41 to 44).",
		"mint":       "Krynodes has not checked Linux Mint 22.",
		"debian sid": "Krynodes has not checked Debian GNU/Linux.",
		"rocky":      "",
		"alpine":     "",
	} {
		env, _ := onRelease(t, key)
		if got := Detect(env).Unverified(); got != want {
			t.Errorf("%s: got %q want %q", key, got, want)
		}
	}
}

func TestEndOfLifeTableMatchesTheSpec(t *testing.T) {
	for key, want := range map[string]string{
		"debian 11": "2026-08-31", "debian 12": "2028-06-30", "debian 13": "2030-06-30", "debian 10": "2024-06-30",
		"ubuntu 22.04": "2027-06-01", "ubuntu 24.04": "2029-05-31", "ubuntu 24.10": "2025-07-10", "ubuntu 25.04": "2026-01-17",
		"ubuntu 25.10": "2026-07-01", "ubuntu 26.04": "2031-05-29", "ubuntu 20.04": "2025-05-31",
		"rhel 8": "2029-05-31", "rhel 9": "2032-05-31", "rhel 10": "2035-05-31",
		"rocky 8": "2029-05-31", "rocky 9": "2032-05-31", "rocky 10": "2035-05-31",
		"almalinux 8": "2029-05-31", "almalinux 9": "2032-05-31", "almalinux 10": "2035-05-31",
		"ol 8": "2029-07-31", "ol 9": "2032-06-30", "ol 10": "2035-06-30",
		"centos 9": "2027-05-31", "centos 10": "2030-05-31",
		"fedora 41": "2025-12-15", "fedora 42": "2026-05-27", "fedora 43": "2026-12-09", "fedora 44": "2027-06-02",
	} {
		id, version, _ := strings.Cut(key, " ")
		got, ok := EndOfLifeFor(id, version)
		if !ok || got.Format(time.DateOnly) != want {
			t.Errorf("%s: got %v %v want %s", key, got, ok, want)
		}
	}
	if _, ok := EndOfLifeFor("alpine", "3.20"); ok {
		t.Fatal("an unknown system has no end date")
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

func TestApplyWaitsOnAnUnverifiedVersionButUndoDoesNot(t *testing.T) {
	ctx := context.Background()
	env, run := onRelease(t, "rocky new")
	_, err := Apply(ctx, env, "fail2ban", nil)
	if err == nil || err.Error() != "Rocky Linux 11 is newer than the versions Krynodes has checked (8 to 10). Confirm to run it anyway." || len(run.calls) != 0 {
		t.Fatalf("err %v calls %q", err, run.calls)
	}
	if _, err := Apply(ctx, env, "fail2ban", map[string]string{"anyway": "yes"}); err != nil {
		t.Fatal(err)
	}
	before := len(run.calls)
	if err := Undo(ctx, env, "fail2ban", nil); err != nil || len(run.calls) == before {
		t.Fatalf("undo %v", err)
	}
	env, run = onRelease(t, "alpine")
	if _, err := Apply(ctx, env, "fail2ban", map[string]string{"anyway": "yes"}); err == nil || err.Error() != "Protections and Docker setup support Debian, Ubuntu and RHEL-family servers" || len(run.calls) != 0 {
		t.Fatalf("err %v calls %q", err, run.calls)
	}
}
