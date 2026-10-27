package apt

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const testKey = "mDMEZyAAABYJKwYBBAHaRw8BAQdAMFV6n8TpDjNYfaLH7BE2W4Clyu8UOV6DqM3yFzxhhqu0LktyeW5vZGVzIFRlc3QgKFBhY2thZ2UgcmVwb3NpdG9yeSBzaWduaW5nIGtleSk="

const testFingerprint = "21DAE8A9E6167221BD7A7023D8F3939D95389CC8"

func keyBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(testKey)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func armored(raw []byte) string {
	text := base64.StdEncoding.EncodeToString(raw)
	var lines []string
	for len(text) > 64 {
		lines, text = append(lines, text[:64]), text[64:]
	}
	lines = append(lines, text)
	return "-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: test\n\n" + strings.Join(lines, "\n") + "\n-----END PGP PUBLIC KEY BLOCK-----\n"
}

func put(t *testing.T, root, name, body string) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const status = `Package: libc6
Status: install ok installed
Priority: optional
Architecture: amd64
Version: 2.36-9+deb12u8
Description: GNU C Library
 Contains the standard libraries.

Package: base-files
Essential: yes
Status: install ok installed
Version: 12.4+deb12u8

Package: nodejs
Status: hold ok installed
Version: 20.18.0-1nodesource1

Package: systemd
Status: install ok installed
Protected: yes
Version: 252.30-1~deb12u2

Package: oldthing
Status: deinstall ok config-files
Version: 1.0

Package: libc6
Architecture: i386
Status: install ok installed
Version: 2.36-9+deb12u8
`

func TestDpkgStatusSaysWhatIsInstalledAndHow(t *testing.T) {
	got := ParseStatus(status)
	want := []Package{
		{Name: "libc6", Version: "2.36-9+deb12u8"},
		{Name: "base-files", Version: "12.4+deb12u8", Essential: true},
		{Name: "nodejs", Version: "20.18.0-1nodesource1", Held: true},
		{Name: "systemd", Version: "252.30-1~deb12u2", Protected: true},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v", got)
	}
}

const olderHistory = `
Start-Date: 2025-11-01  10:00:00
Commandline: apt-get install nginx
Install: nginx:amd64 (1.22.1-9), nginx-common:amd64 (1.22.1-9, automatic)
End-Date: 2025-11-01  10:00:20
`

const history = `
Start-Date: 2026-03-01  10:00:00
Commandline: apt-get -o DPkg::Lock::Timeout=300 install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
Install: docker-ce:amd64 (5:27.3.1-1~debian.12~bookworm), pigz:amd64 (2.6-1, automatic), docker-ce-cli:amd64 (5:27.3.1-1~debian.12~bookworm), containerd.io:amd64 (1.7.22-1), docker-buildx-plugin:amd64 (0.17.1-1~debian.12~bookworm), docker-compose-plugin:amd64 (2.29.7-1~debian.12~bookworm), docker-ce-rootless-extras:amd64 (5:27.3.1-1~debian.12~bookworm, automatic)
End-Date: 2026-03-01  10:01:00

Start-Date: 2026-03-02  09:00:00
Commandline: apt install htop
Requested-By: seld (1000)
Install: htop:amd64 (3.2.2-2), libnl-genl-3-200:amd64 (3.7.0-0.2+b1, automatic)
End-Date: 2026-03-02  09:00:05

Start-Date: 2026-03-03  06:12:00
Commandline: /usr/bin/unattended-upgrade
Install: linux-image-6.1.0-27-amd64:amd64 (6.1.0-27)
Upgrade: openssl:amd64 (3.0.14-1~deb12u1, 3.0.14-1~deb12u2)
End-Date: 2026-03-03  06:13:00

Start-Date: 2026-03-04  09:00:00
Commandline: apt-get remove htop
Requested-By: seld (1000)
Remove: htop:amd64 (3.2.2-2)
End-Date: 2026-03-04  09:00:02

Start-Date: 2026-03-05  09:00:00
Commandline: apt-get install -y htop curl
Requested-By: seld (1000)
Install: htop:amd64 (3.2.2-2), curl:amd64 (7.88.1-10+deb12u8)
End-Date: 2026-03-05  09:00:09
`

func TestAptHistorySaysWhoAddedWhat(t *testing.T) {
	got := ParseHistory(olderHistory, history)
	want := map[string]Added{
		"nginx":                 {By: "root", With: []string{"nginx-common"}},
		"docker-ce":             {By: "root", With: []string{"pigz", "docker-ce-rootless-extras"}},
		"docker-ce-cli":         {By: "root"},
		"containerd.io":         {By: "root"},
		"docker-buildx-plugin":  {By: "root"},
		"docker-compose-plugin": {By: "root"},
		"htop":                  {By: "seld"},
		"curl":                  {By: "seld"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for name, entry := range want {
		if got[name].By != entry.By || !slices.Equal(got[name].With, entry.With) {
			t.Fatalf("%s: got %+v, want %+v", name, got[name], entry)
		}
	}
}

func TestHistoryIsReadOldestFirstIncludingRotatedLogs(t *testing.T) {
	root := t.TempDir()
	var packed bytes.Buffer
	writer := gzip.NewWriter(&packed)
	writer.Write([]byte(olderHistory))
	writer.Close()
	put(t, root, "/var/log/apt/history.log.2.gz", packed.String())
	put(t, root, "/var/log/apt/history.log.1", "\nStart-Date: 2026-01-01  10:00:00\nCommandline: apt-get remove nginx\nRemove: nginx:amd64 (1.22.1-9)\nEnd-Date: 2026-01-01  10:00:01\n")
	put(t, root, "/var/log/apt/history.log", history)
	got := ParseHistory(ReadHistory(root)...)
	if _, found := got["nginx"]; found {
		t.Fatalf("nginx was removed after it was installed: %+v", got["nginx"])
	}
	if got["htop"].By != "seld" {
		t.Fatalf("got %+v", got)
	}
}

func sourcesRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	put(t, root, "/etc/apt/sources.list", `deb http://deb.debian.org/debian bookworm main contrib
deb http://deb.debian.org/debian bookworm-updates main
# deb http://deb.debian.org/debian bookworm-backports main
deb http://security.debian.org/debian-security bookworm-security main
deb-src http://security.debian.org/debian-security bookworm-security main
`)
	put(t, root, "/etc/apt/sources.list.d/docker.list", "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable\n")
	put(t, root, "/etc/apt/keyrings/docker.asc", armored(keyBytes(t)))
	put(t, root, "/etc/apt/sources.list.d/tailscale.sources", "Types: deb\nURIs: https://pkgs.tailscale.com/stable/debian\nSuites: bookworm\nComponents: main\nSigned-By: /etc/apt/keyrings/krynodes-tailscale.gpg\n")
	put(t, root, "/etc/apt/keyrings/krynodes-tailscale.gpg", string(keyBytes(t)))
	put(t, root, "/etc/apt/sources.list.d/off.sources", "Types: deb\nURIs: https://off.example.com/apt\nSuites: stable\nComponents: main\nEnabled: no\n")
	inline := strings.ReplaceAll(strings.TrimSuffix(armored(keyBytes(t)), "\n"), "\n\n", "\n.\n")
	put(t, root, "/etc/apt/sources.list.d/archive_uri-https_repo_example_com-stable.sources", "Types: deb deb-src\nURIs: https://repo.example.com/apt\nSuites: stable\nComponents: main\nSigned-By:\n "+strings.ReplaceAll(inline, "\n", "\n ")+"\n")
	put(t, root, "/etc/apt/sources.list.d/nodesource.list", "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main\n")
	return root
}

func TestSourcesAreReadFromBothFormatsWithTheirKeys(t *testing.T) {
	root := sourcesRoot(t)
	short := "D8F3 939D 9538 9CC8"
	got := ReadSources(root, "debian", []string{"/etc/apt/sources.list.d/tailscale.sources"})
	want := []reporter.SourceEntry{
		{Name: "debian", Host: "deb.debian.org", Suites: []string{"bookworm", "bookworm-updates"}, File: "/etc/apt/sources.list", System: true},
		{Name: "debian-security", Host: "security.debian.org", Suites: []string{"bookworm-security"}, File: "/etc/apt/sources.list", System: true},
		{Name: "archive-uri-https-repo-example-com-stable", Host: "repo.example.com", Suites: []string{"stable"}, Key: &short, File: "/etc/apt/sources.list.d/archive_uri-https_repo_example_com-stable.sources"},
		{Name: "docker", Host: "download.docker.com", Suites: []string{"bookworm"}, Key: &short, File: "/etc/apt/sources.list.d/docker.list"},
		{Name: "nodesource", Host: "deb.nodesource.com", Suites: []string{"nodistro"}, File: "/etc/apt/sources.list.d/nodesource.list"},
		{Name: "tailscale", Host: "pkgs.tailscale.com", Suites: []string{"bookworm"}, Key: &short, Krynodes: true, File: "/etc/apt/sources.list.d/tailscale.sources"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for index := range want {
		a, b := got[index], want[index]
		if a.Name != b.Name || a.Host != b.Host || !slices.Equal(a.Suites, b.Suites) || a.File != b.File || a.System != b.System || a.Krynodes != b.Krynodes || (a.Key == nil) != (b.Key == nil) || (a.Key != nil && *a.Key != *b.Key) {
			t.Fatalf("%d: got %+v key %v, want %+v", index, a, a.Key, b)
		}
	}
}

func TestDebianTwelvesOwnSourcesFileIsTheSystems(t *testing.T) {
	root := t.TempDir()
	put(t, root, "/etc/apt/sources.list.d/debian.sources", "Types: deb\nURIs: http://deb.debian.org/debian\nSuites: bookworm bookworm-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: http://deb.debian.org/debian-security\nSuites: bookworm-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n")
	got := ReadSources(root, "debian", nil)
	if len(got) != 2 || got[0].Name != "debian" || got[1].Name != "debian-security" || !got[0].System || !got[1].System || got[1].Host != "deb.debian.org" {
		t.Fatalf("got %+v", got)
	}
}

func TestAKeysFingerprintIsReadFromItsPacket(t *testing.T) {
	raw := keyBytes(t)
	newFormat := append([]byte{0xC6, raw[1]}, raw[2:]...)
	for name, data := range map[string][]byte{"binary": raw, "new packet format": newFormat, "armored": []byte(armored(raw))} {
		keys, err := ReadKeys(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(keys) != 1 || keys[0].Fingerprint != testFingerprint || keys[0].User != "Krynodes Test (Package repository signing key)" {
			t.Fatalf("%s: got %+v", name, keys)
		}
	}
	if Short(testFingerprint) != "D8F3 939D 9538 9CC8" {
		t.Fatalf("short %q", Short(testFingerprint))
	}
	if _, err := ReadKeys([]byte("not a key")); err == nil {
		t.Fatal("text that is not a key was read as one")
	}
}

const plainUpgrade = `Reading package lists... Done
Building dependency tree... Done
Calculating upgrade... Done
The following packages have been kept back:
  docker-ce nodejs
  tzdata
The following packages will be upgraded:
  openssl tailscale
The following upgrades have been deferred due to phasing:
  python3-update-manager
2 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.
Inst openssl [3.0.14-1~deb12u2] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])
Inst tailscale [1.76.1] (1.78.1 Tailscale:bookworm [amd64])
Conf openssl (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])
Conf tailscale (1.78.1 Tailscale:bookworm [amd64])
`

const withNew = `The following NEW packages will be installed:
  docker-ce-rootless-extras
The following packages have been kept back:
  nodejs tzdata
Inst docker-ce-rootless-extras (5:27.4.0-1~debian.12~bookworm Docker CE:bookworm [amd64])
Inst docker-ce [5:27.3.1-1~debian.12~bookworm] (5:27.4.0-1~debian.12~bookworm Docker CE:bookworm [amd64])
Inst openssl [3.0.14-1~deb12u2] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])
Inst tailscale [1.76.1] (1.78.1 Tailscale:bookworm [amd64])
`

const distUpgrade = `The following packages will be REMOVED:
  oldlib
Remv oldlib [1.0]
Inst tzdata [2024a-0+deb12u1] (2024b-0+deb12u1 Debian:12.8/stable [all])
Inst docker-ce-rootless-extras (5:27.4.0-1~debian.12~bookworm Docker CE:bookworm [amd64])
`

func TestADryRunSaysWhatItWouldDo(t *testing.T) {
	plain := ParseSimulation(plainUpgrade)
	if plain.Upgrades["openssl"] != "3.0.15-1~deb12u1" || plain.Upgrades["tailscale"] != "1.78.1" || len(plain.Upgrades) != 2 {
		t.Fatalf("upgrades %+v", plain.Upgrades)
	}
	if !slices.Equal(plain.Kept, []string{"docker-ce", "nodejs", "tzdata"}) || !slices.Equal(plain.Phased, []string{"python3-update-manager"}) {
		t.Fatalf("kept %v phased %v", plain.Kept, plain.Phased)
	}
	more := ParseSimulation(withNew)
	if !slices.Equal(more.New, []string{"docker-ce-rootless-extras"}) || more.Upgrades["docker-ce"] == "" {
		t.Fatalf("got %+v", more)
	}
	dist := ParseSimulation(distUpgrade)
	if !slices.Equal(dist.Removes, []string{"oldlib"}) || dist.Upgrades["tzdata"] == "" {
		t.Fatalf("got %+v", dist)
	}
}

func policyOf(name, installed, candidate, from, to string) string {
	lines := []string{name + ":", "  Installed: " + installed, "  Candidate: " + candidate, "  Version table:"}
	if candidate != installed {
		lines = append(lines, "     "+candidate+" 500")
		if to != "" {
			lines = append(lines, "        500 "+to+" amd64 Packages")
		}
	}
	lines = append(lines, " *** "+installed+" 500")
	if from != "" {
		lines = append(lines, "        500 "+from+" amd64 Packages")
	}
	lines = append(lines, "        100 /var/lib/dpkg/status")
	return strings.Join(lines, "\n") + "\n"
}

func TestPolicySaysWhereEachVersionComesFrom(t *testing.T) {
	text := policyOf("openssl", "3.0.14-1~deb12u2", "3.0.15-1~deb12u1", "http://deb.debian.org/debian bookworm/main", "http://security.debian.org/debian-security bookworm-security/main") +
		policyOf("nodejs", "20.18.0-1nodesource1", "20.19.1-1nodesource1", "", "https://deb.nodesource.com/node_20.x nodistro/main") +
		policyOf("localpkg", "1.0", "1.0", "", "")
	got := ParsePolicy(text)
	openssl := got["openssl"]
	if openssl.Installed != "3.0.14-1~deb12u2" || openssl.Candidate != "3.0.15-1~deb12u1" || !slices.Equal(openssl.From, []Origin{{"deb.debian.org", "bookworm"}}) || !slices.Equal(openssl.To, []Origin{{"security.debian.org", "bookworm-security"}}) {
		t.Fatalf("openssl %+v", openssl)
	}
	if len(got["nodejs"].From) != 0 || !slices.Equal(got["nodejs"].To, []Origin{{"deb.nodesource.com", "nodistro"}}) {
		t.Fatalf("nodejs %+v", got["nodejs"])
	}
	if local := got["localpkg"]; local.Installed != "1.0" || len(local.From) != 0 || len(local.To) != 0 {
		t.Fatalf("localpkg %+v", local)
	}
}

func TestVersionsCompareTheWayDpkgDoes(t *testing.T) {
	for _, pair := range [][2]string{
		{"3.0.15-1~deb12u1", "3.0.14-1~deb12u2"},
		{"1:1.0", "2.0"},
		{"1.0", "1.0~rc1"},
		{"5:27.4.0-1~debian.12~bookworm", "5:27.3.1-1~debian.12~bookworm"},
		{"2.36-9+deb12u10", "2.36-9+deb12u8"},
		{"1.0a", "1.0"},
		{"1.0-2", "1.0-1"},
	} {
		if Compare(pair[0], pair[1]) <= 0 || Compare(pair[1], pair[0]) >= 0 {
			t.Fatalf("%s should be newer than %s", pair[0], pair[1])
		}
	}
	if Compare("1.0-1", "1.0-1") != 0 || Compare("0:1.0", "1.0") != 0 {
		t.Fatal("equal versions differ")
	}
}

func TestANewerKernelOfTheSameFlavourNeedsARestart(t *testing.T) {
	root := t.TempDir()
	put(t, root, "/proc/sys/kernel/osrelease", "6.1.0-26-amd64\n")
	dpkgList := put(t, root, "/var/lib/dpkg/info/linux-image-6.1.0-27-amd64.list", "")
	installed := time.Date(2026, 10, 25, 21, 41, 0, 0, time.UTC)
	os.Chtimes(dpkgList, installed, installed)
	kernels := Kernels([]Package{{Name: "linux-image-6.1.0-26-amd64"}, {Name: "linux-image-6.1.0-27-amd64"}, {Name: "linux-image-amd64"}, {Name: "linux-image-6.1.0-28-cloud-amd64"}})
	restart := Restart(root, kernels)
	if restart == nil || *restart.Running != "6.1.0-26-amd64" || *restart.Newest != "6.1.0-27-amd64" || restart.File || restart.Since != "2026-10-25T21:41:00Z" {
		t.Fatalf("got %+v", restart)
	}
	put(t, root, "/proc/sys/kernel/osrelease", "6.1.0-27-amd64\n")
	if restart := Restart(root, kernels); restart != nil {
		t.Fatalf("the newest kernel runs, yet %+v", restart)
	}
	flag := put(t, root, "/run/reboot-required", "*** System restart required ***\n")
	asked := time.Date(2026, 10, 26, 6, 12, 0, 0, time.UTC)
	os.Chtimes(flag, asked, asked)
	if restart := Restart(root, kernels); restart == nil || !restart.File || restart.Since != "2026-10-26T06:12:00Z" {
		t.Fatalf("got %+v", restart)
	}
}

func TestARaspberryPiKernelIsComparedWithItsOwnFlavour(t *testing.T) {
	root := t.TempDir()
	put(t, root, "/proc/sys/kernel/osrelease", "6.6.51+rpt-rpi-v8\n")
	kernels := Kernels([]Package{{Name: "linux-image-6.6.51+rpt-rpi-v8"}, {Name: "linux-image-6.6.51+rpt-rpi-2712"}})
	if restart := Restart(root, kernels); restart != nil {
		t.Fatalf("got %+v", restart)
	}
}

func TestServicesStillOnDeletedLibrariesAreNamed(t *testing.T) {
	root := t.TempDir()
	put(t, root, "/proc/sys/kernel/osrelease", "6.1.0-27-amd64\n")
	put(t, root, "/proc/412/cgroup", "0::/system.slice/ssh.service\n")
	put(t, root, "/proc/412/maps", "7f00-7f10 r-xp 00000000 08:01 123 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n")
	put(t, root, "/proc/413/cgroup", "0::/system.slice/cron.service\n")
	put(t, root, "/proc/413/maps", "7f00-7f10 r-xp 00000000 08:01 124 /usr/lib/x86_64-linux-gnu/libc.so.6\n7f20-7f30 rw-s 00000000 00:01 9 /memfd:x (deleted)\n")
	put(t, root, "/proc/414/cgroup", "0::/system.slice/docker-0123.scope\n")
	put(t, root, "/proc/414/maps", "7f00-7f10 r-xp 00000000 08:01 125 /usr/lib/libz.so.1 (deleted)\n")
	put(t, root, "/proc/415/cgroup", "12:name=systemd:/system.slice/nginx.service\n")
	put(t, root, "/proc/415/maps", "7f00-7f10 r-xp 00000000 08:01 126 /lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2 (deleted)\n")
	restart := Restart(root, nil)
	if restart == nil || !slices.Equal(restart.Services, []string{"nginx.service", "ssh.service"}) || restart.Newest != nil {
		t.Fatalf("got %+v", restart)
	}
}

type commands struct {
	calls []string
	reply func(command string) string
}

func (c *commands) run(_ context.Context, name string, args ...string) ([]byte, int, error) {
	command := strings.Join(append([]string{name}, args...), " ")
	c.calls = append(c.calls, command)
	return []byte(c.reply(command)), 0, nil
}

func buildRoot(t *testing.T) string {
	t.Helper()
	root := sourcesRoot(t)
	var lines []string
	for _, pkg := range []string{"base-files 12.4+deb12u8", "openssl 3.0.14-1~deb12u2", "tailscale 1.76.1", "docker-ce 5:27.3.1-1~debian.12~bookworm", "docker-ce-cli 5:27.3.1-1~debian.12~bookworm", "containerd.io 1.7.22-1", "docker-buildx-plugin 0.17.1-1~debian.12~bookworm", "docker-compose-plugin 2.29.7-1~debian.12~bookworm", "pigz 2.6-1", "tzdata 2024a-0+deb12u1", "oldlib 1.0", "htop 3.2.2-2", "curl 7.88.1-10+deb12u8", "nginx 1.22.1-9", "nginx-common 1.22.1-9"} {
		name, version, _ := strings.Cut(pkg, " ")
		lines = append(lines, fmt.Sprintf("Package: %s\nStatus: install ok installed\nVersion: %s\n", name, version))
	}
	lines = append(lines, "Package: nodejs\nStatus: hold ok installed\nVersion: 20.18.0-1nodesource1\n")
	put(t, root, "/var/lib/dpkg/status", strings.Join(lines, "\n"))
	put(t, root, "/var/log/apt/history.log", olderHistory+history)
	list := put(t, root, "/var/lib/apt/lists/deb.debian.org_debian_dists_bookworm_InRelease", "")
	checked := time.Date(2026, 10, 26, 8, 57, 0, 0, time.UTC)
	os.Chtimes(list, checked, checked)
	return root
}

func aptReplies(command string) string {
	switch {
	case strings.Contains(command, " policy "):
		debian := "http://deb.debian.org/debian bookworm/main"
		return policyOf("openssl", "3.0.14-1~deb12u2", "3.0.15-1~deb12u1", debian, "http://security.debian.org/debian-security bookworm-security/main") +
			policyOf("tailscale", "1.76.1", "1.78.1", "https://pkgs.tailscale.com/stable/debian bookworm/main", "https://pkgs.tailscale.com/stable/debian bookworm/main") +
			policyOf("docker-ce", "5:27.3.1-1~debian.12~bookworm", "5:27.4.0-1~debian.12~bookworm", "https://download.docker.com/linux/debian bookworm/stable", "https://download.docker.com/linux/debian bookworm/stable") +
			policyOf("tzdata", "2024a-0+deb12u1", "2024b-0+deb12u1", debian, debian) +
			policyOf("nodejs", "20.18.0-1nodesource1", "20.19.1-1nodesource1", "", "https://deb.nodesource.com/node_20.x nodistro/main") +
			policyOf("htop", "3.2.2-2", "3.2.2-2", debian, "") +
			policyOf("nginx", "1.22.1-9", "1.22.1-9", "", "")
	case strings.Contains(command, "--with-new-pkgs"):
		return withNew
	case strings.Contains(command, "dist-upgrade"):
		return distUpgrade
	case strings.Contains(command, "upgrade"):
		return plainUpgrade
	}
	return ""
}

func TestTheReportSaysWhatIsAddedWaitingAndHeld(t *testing.T) {
	root := buildRoot(t)
	run := &commands{reply: aptReplies}
	now := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	facts := Facts{
		System: "Debian 12 bookworm", Codename: "bookworm", Distro: "debian",
		Ours:     []string{"/etc/apt/sources.list.d/docker.list"},
		Krynodes: []Group{{Feature: "docker", Packages: []string{"docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"}}},
	}
	report, kernels, err := Build(context.Background(), root, run.run, facts, now)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Apt || report.System != "Debian 12 bookworm" || report.Installed != 16 || report.ReadAt != "2026-10-26T09:00:00Z" || report.CheckedAt == nil || *report.CheckedAt != "2026-10-26T08:57:00Z" || kernels != nil {
		t.Fatalf("report %+v", report)
	}
	rows := map[string]reporter.PackageEntry{}
	for _, entry := range report.Packages {
		rows[entry.Name] = entry
	}
	text := func(value *string) string {
		if value == nil {
			return "--"
		}
		return *value
	}
	for name, want := range map[string]string{
		"docker-ce":     "Krynodes docker 5 docker",
		"docker-ce-cli": "-- -- 0 --",
		"htop":          "seld -- 0 debian",
		"curl":          "seld -- 0 --",
		"nginx":         "root -- 1 --",
		"nginx-common":  "-- -- 0 --",
		"nodejs":        "-- -- 0 nodesource",
		"openssl":       "-- -- 0 debian",
		"tailscale":     "-- -- 0 tailscale",
	} {
		row := rows[name]
		if got := fmt.Sprintf("%s %s %d %s", text(row.By), text(row.Feature), row.More, text(row.From)); got != want {
			t.Fatalf("%s: got %q, want %q", name, got, want)
		}
	}
	if !rows["nodejs"].Held || rows["htop"].Held {
		t.Fatal("holds are wrong")
	}
	updates := map[string]reporter.UpdateEntry{}
	var names []string
	for _, update := range report.Updates {
		updates[update.Name] = update
		names = append(names, update.Name)
	}
	if !slices.Equal(names, []string{"docker-ce", "nodejs", "openssl", "tailscale", "tzdata"}) {
		t.Fatalf("updates %v", names)
	}
	if u := updates["openssl"]; !u.Security || text(u.Source) != "debian-security" || u.Back != nil || u.To != "3.0.15-1~deb12u1" || u.From != "3.0.14-1~deb12u2" {
		t.Fatalf("openssl %+v", u)
	}
	if u := updates["tailscale"]; u.Security || text(u.Source) != "tailscale" || u.Back != nil {
		t.Fatalf("tailscale %+v", u)
	}
	if u := updates["docker-ce"]; u.Back == nil || !slices.Equal(u.Back.Adds, []string{"docker-ce-rootless-extras"}) || len(u.Back.Removes) != 0 || u.Back.Removes == nil {
		t.Fatalf("docker-ce %+v", u.Back)
	}
	if u := updates["tzdata"]; u.Back == nil || len(u.Back.Adds) != 0 || !slices.Equal(u.Back.Removes, []string{"oldlib"}) {
		t.Fatalf("tzdata %+v", u.Back)
	}
	if u := updates["nodejs"]; !u.Held || u.Back != nil || u.To != "20.19.1-1nodesource1" || text(u.Source) != "nodesource" {
		t.Fatalf("nodejs %+v", u)
	}
	for _, call := range run.calls {
		if strings.Contains(call, "apt-get") && (!strings.Contains(call, " -s ") || !strings.Contains(call, "Debug::NoLocking=1")) {
			t.Fatalf("a read changed something: %s", call)
		}
	}
}

func TestTheStampMovesOnlyWhenAptsFilesDo(t *testing.T) {
	root := buildRoot(t)
	first := Stamp(root)
	if Stamp(root) != first {
		t.Fatal("the stamp moved by itself")
	}
	later := time.Now().Add(time.Hour)
	os.Chtimes(filepath.Join(root, "etc", "apt", "sources.list.d", "docker.list"), later, later)
	if Stamp(root) == first {
		t.Fatal("a changed source left the stamp alone")
	}
}
