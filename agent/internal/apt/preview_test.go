package apt

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

func unpacked(t *testing.T, m *machine, files map[string]string) {
	previous := m.replies
	m.replies = func(command string) string {
		fields := strings.Fields(command)
		switch {
		case len(fields) > 3 && fields[0] == "env" && fields[1] == "-C" && slices.Contains(fields, "download"):
			for _, wanted := range fields[slices.Index(fields, "download")+1:] {
				name, _, _ := strings.Cut(wanted, "=")
				put(t, fields[2], "/"+name+".deb", "")
			}
		case len(fields) == 4 && fields[0] == "dpkg-deb" && fields[1] == "-x":
			stem := strings.TrimSuffix(filepath.Base(fields[2]), ".deb")
			for path, body := range files {
				if owner, inside, _ := strings.Cut(path, ":"); owner == stem {
					put(t, fields[3], inside, body)
				}
			}
		}
		return previous(command)
	}
}

func TestTheDryRunOfAnInstallSaysWhatItBrings(t *testing.T) {
	m := newMachine(t)
	m.replies = func(command string) string {
		switch {
		case strings.Contains(command, "apt-get -s ") && strings.HasSuffix(command, " install web"):
			return "Inst web-common (2.1-1 Debian:12.7/stable [all])\nInst curl [7.88.1-10] (7.88.1-10+deb12u8 Debian-Security:12/stable-security [amd64])\nInst web (2.1-1 Debian:12.7/stable [amd64])\nRemv apache2 [2.4.62-1~deb12u1]\nConf web-common (2.1-1 Debian:12.7/stable [all])\n"
		case strings.Contains(command, "apt-cache show --no-all-versions"):
			return "Package: curl\nVersion: 7.88.1-10+deb12u8\nInstalled-Size: 500\nSize: 315000\n\nPackage: web\nVersion: 2.1-1\nInstalled-Size: 1200\nSize: 600000\n\nPackage: web-common\nVersion: 2.1-1\nInstalled-Size: 300\nSize: 100000\n"
		}
		return ""
	}
	unpacked(t, m, map[string]string{
		"web:/lib/systemd/system/web.service":         "[Unit]\nDescription=Web\n[Service]\nExecStart=/usr/sbin/web\n[Install]\nWantedBy=multi-user.target\n",
		"web:/lib/systemd/system/web-debug.service":   "[Service]\nExecStart=/usr/sbin/web -d\n",
		"web:/lib/systemd/system/web-admin.socket":    "[Socket]\nListenStream=0.0.0.0:9090\nListenStream=[::]:9090\nListenDatagram=5353\n[Install]\nWantedBy=sockets.target\n",
		"web:/usr/lib/systemd/system/web@.service":    "[Service]\nExecStart=/usr/sbin/web %i\n[Install]\nWantedBy=multi-user.target\n",
		"web-common:/usr/share/doc/web-common/README": "x",
		"curl:/usr/lib/systemd/system/never.service":  "[Install]\nWantedBy=multi-user.target\n",
	})
	preview := m.job().PreviewInstall(context.Background(), "web", t.TempDir())
	if preview.What != "install" || preview.Refused != nil {
		t.Fatalf("got %+v", preview)
	}
	if !slices.Equal(preview.Installs, []Change{{Name: "web", Version: "2.1-1"}, {Name: "web-common", Version: "2.1-1"}}) || !slices.Equal(preview.Upgrades, []Change{{Name: "curl", Version: "7.88.1-10+deb12u8"}}) || !slices.Equal(preview.Removes, []string{"apache2"}) {
		t.Fatalf("changes %+v", preview)
	}
	if preview.Download == nil || *preview.Download != 1015000 || preview.Disk == nil || *preview.Disk != 1500*1024 {
		t.Fatalf("sizes %v %v", preview.Download, preview.Disk)
	}
	want := []Unit{{Unit: "web-admin.socket", Ports: []Port{{Port: 9090, Protocol: "tcp"}, {Port: 5353, Protocol: "udp"}}}, {Unit: "web.service"}}
	if preview.Unread || !slices.EqualFunc(preview.Services, want, func(a, b Unit) bool { return a.Unit == b.Unit && slices.Equal(a.Ports, b.Ports) }) {
		t.Fatalf("services %+v", preview.Services)
	}
	if want[1].Ports != nil || preview.Services[1].Ports != nil {
		t.Fatal("a service without a socket has ports nobody knows yet")
	}
}

func TestAnInstallTooLargeToOpenSaysServicesShowLater(t *testing.T) {
	m := newMachine(t)
	m.replies = func(command string) string {
		switch {
		case strings.Contains(command, "apt-get -s "):
			return "Inst big (1 Debian:12/stable [amd64])\n"
		case strings.Contains(command, "apt-cache show"):
			return "Package: big\nVersion: 1\nInstalled-Size: 200000\nSize: 60000000\n"
		}
		return ""
	}
	preview := m.job().PreviewInstall(context.Background(), "big", t.TempDir())
	if !preview.Unread || preview.Services == nil || len(preview.Services) != 0 || len(called(m.calls, " download ")) != 0 {
		t.Fatalf("got %+v after %v", preview, m.calls)
	}
}

func TestAnInstallThatWouldRemoveSomethingProtectedIsRefusedBeforehand(t *testing.T) {
	m := newMachine(t)
	m.replies = func(command string) string {
		if strings.Contains(command, "apt-get -s ") {
			return "Inst dropbear (2022.83-1 Debian:12/stable [amd64])\nRemv openssh-server [1:9.2p1-2]\n"
		}
		return ""
	}
	preview := m.job().PreviewInstall(context.Background(), "dropbear", t.TempDir())
	if preview.Refused == nil || !strings.Contains(*preview.Refused, "openssh-server") {
		t.Fatalf("got %+v", preview)
	}
}

func TestTheDryRunOfARemovalNamesWhatStops(t *testing.T) {
	m := newMachine(t)
	m.installed("base-files", "curl", "tailscale", "openssh-server", "openssh-client")
	put(t, m.root, "/var/lib/dpkg/info/tailscale.list", "/.\n/lib/systemd/system/tailscaled.service\n/usr/sbin/tailscaled\n")
	put(t, m.root, "/var/lib/dpkg/info/openssh-client.list", "/usr/bin/ssh\n")
	m.replies = func(command string) string {
		switch {
		case strings.Contains(command, "apt-get -s ") && strings.HasSuffix(command, " purge tailscale"):
			return "Purg tailscale [1.76.6]\n"
		case strings.Contains(command, "apt-get -s ") && strings.HasSuffix(command, " remove openssh-client"):
			return "Remv openssh-server [1:9.2p1-2]\nRemv openssh-client [1:9.2p1-2]\n"
		case command == "systemctl is-active tailscaled.service":
			return "active\n"
		}
		return ""
	}
	preview := m.job().PreviewRemove(context.Background(), "tailscale", true)
	if preview.What != "purge" || preview.Refused != nil || !slices.Equal(preview.Removes, []string{"tailscale"}) || !slices.Equal(preview.Stops, []string{"tailscaled.service"}) {
		t.Fatalf("got %+v", preview)
	}
	refused := m.job().PreviewRemove(context.Background(), "openssh-client", false)
	if refused.Refused == nil || !strings.Contains(*refused.Refused, "openssh-server") {
		t.Fatalf("got %+v", refused)
	}
}

func TestTheDryRunOfAnUpgradeNamesWhatRestarts(t *testing.T) {
	m := newMachine(t)
	put(t, m.root, "/var/lib/dpkg/info/docker-ce.list", "/lib/systemd/system/docker.service\n/lib/systemd/system/docker.socket\n")
	put(t, m.root, "/var/lib/dpkg/info/libssl3:amd64.list", "/usr/lib/x86_64-linux-gnu/libssl.so.3\n")
	m.replies = func(command string) string {
		switch {
		case strings.Contains(command, "apt-get -s ") && strings.HasSuffix(command, " --with-new-pkgs upgrade"):
			return "Inst docker-ce [5:27.3.1-1~debian.12~bookworm] (5:27.4.0-1~debian.12~bookworm Docker CE:bookworm [amd64])\nInst docker-ce-rootless-extras (5:27.4.0-1~debian.12~bookworm Docker CE:bookworm [amd64])\nInst libssl3:amd64 [3.0.14-1~deb12u2] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])\n"
		case command == "systemctl is-active docker.service docker.socket":
			return "active\ninactive\n"
		}
		return ""
	}
	preview := m.job().PreviewUpgrade(context.Background())
	if preview.What != "upgrade" || !slices.Equal(preview.Upgrades, []Change{{Name: "docker-ce", Version: "5:27.4.0-1~debian.12~bookworm"}, {Name: "libssl3", Version: "3.0.15-1~deb12u1"}}) {
		t.Fatalf("upgrades %+v", preview.Upgrades)
	}
	if !slices.Equal(preview.Adds, []Change{{Name: "docker-ce-rootless-extras", Version: "5:27.4.0-1~debian.12~bookworm"}}) || !slices.Equal(preview.Restarts, []string{"docker.service"}) {
		t.Fatalf("got %+v", preview)
	}
}

func TestFindingAPackageListsExactNamesFirst(t *testing.T) {
	m := newMachine(t)
	m.installed("base-files", "nginx-common")
	sources := []reporter.SourceEntry{{Name: "debian", Host: "deb.debian.org", Suites: []string{"bookworm"}}}
	m.replies = func(command string) string {
		switch {
		case strings.Contains(command, "apt-cache") && strings.HasSuffix(command, " search nginx"):
			return "libnginx-mod-http-geoip - GeoIP HTTP module for Nginx\npython3-certbot-nginx - Nginx plugin for Certbot\nnginx-common - small, powerful, scalable web/proxy server - common files\nnginx - small, powerful, scalable web/proxy server\n"
		case strings.Contains(command, "apt-cache") && strings.Contains(command, " policy "):
			var text strings.Builder
			for _, name := range []string{"nginx", "nginx-common", "libnginx-mod-http-geoip", "python3-certbot-nginx"} {
				text.WriteString(policyOf(name, "(none)", "1.22.1-9", "", "http://deb.debian.org/debian bookworm/main"))
			}
			return text.String()
		}
		return ""
	}
	matches, err := m.job().Find(context.Background(), "Nginx", sources)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, match := range matches {
		names = append(names, match.Name)
	}
	if !slices.Equal(names, []string{"nginx", "nginx-common", "libnginx-mod-http-geoip", "python3-certbot-nginx"}) {
		t.Fatalf("order %v", names)
	}
	first := matches[0]
	if first.Version != "1.22.1-9" || first.Summary != "small, powerful, scalable web/proxy server" || first.From == nil || *first.From != "debian" || first.Installed != nil || matches[1].Installed == nil {
		t.Fatalf("got %+v", matches[:2])
	}
	for _, bad := range []string{"", "-o Debug::pkgProblemResolver=1", "a;b", strings.Repeat("x", 65)} {
		if _, err := m.job().Find(context.Background(), bad, sources); err == nil {
			t.Fatalf("%q searched", bad)
		}
	}
}

func repoMachine(t *testing.T) (*machine, map[string][]byte, Job) {
	m := newMachine(t)
	served := map[string][]byte{}
	job := m.job()
	job.Get = func(_ context.Context, address string) ([]byte, error) {
		m.calls = append(m.calls, "get "+address)
		if body, ok := served[address]; ok {
			return body, nil
		}
		return nil, os.ErrNotExist
	}
	return m, served, job
}

var tailscaleRepo = Repo{Name: "tailscale", URI: "https://pkgs.tailscale.com/stable/debian", Suites: []string{"bookworm"}, Components: []string{"main"}, Key: "https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg"}

func TestARepositoryWhoseKeyDiffersIsRefusedAndNothingIsWritten(t *testing.T) {
	m, served, job := repoMachine(t)
	served[tailscaleRepo.Key] = keyBytes(t)
	repo := tailscaleRepo
	repo.Fingerprint = "2596A99EAAB33821893C0A79458CA832957F5868"
	if _, err := job.AddRepo(context.Background(), repo); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("got %v", err)
	}
	insecure := tailscaleRepo
	insecure.Key, insecure.Fingerprint = "http://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg", "21DAE8A9E6167221BD7A7023D8F3939D95389CC8"
	if _, err := job.AddRepo(context.Background(), insecure); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(at(m.root, "/etc/apt")); !os.IsNotExist(err) {
		t.Fatalf("something was written: %v", err)
	}
	if len(called(m.calls, "apt-get")) != 0 {
		t.Fatalf("apt ran: %v", m.calls)
	}
}

func TestARepositoryIsAddedWithItsOwnKeyOnly(t *testing.T) {
	m, served, job := repoMachine(t)
	served[tailscaleRepo.Key] = keyBytes(t)
	repo := tailscaleRepo
	repo.Fingerprint = "21dae8a9e6167221bd7a7023d8f3939d95389cc8"
	file, err := job.AddRepo(context.Background(), repo)
	if err != nil || file != "/etc/apt/sources.list.d/tailscale.sources" {
		t.Fatalf("got %q %v", file, err)
	}
	body, _ := os.ReadFile(at(m.root, file))
	if string(body) != "Types: deb\nURIs: https://pkgs.tailscale.com/stable/debian\nSuites: bookworm\nComponents: main\nSigned-By: /etc/apt/keyrings/krynodes-tailscale.gpg\n" {
		t.Fatalf("sources file:\n%s", body)
	}
	if key, _ := os.ReadFile(at(m.root, "/etc/apt/keyrings/krynodes-tailscale.gpg")); !slices.Equal(key, keyBytes(t)) {
		t.Fatal("the key was not written as fetched")
	}
	update := called(m.calls, "update")
	if len(update) != 1 || !strings.Contains(update[0], "Dir::Etc::sourcelist=/etc/apt/sources.list.d/tailscale.sources") || !strings.Contains(update[0], "Dir::Etc::sourceparts=-") {
		t.Fatalf("update ran as %v", update)
	}
	if _, err := job.AddRepo(context.Background(), repo); err == nil {
		t.Fatal("a repository was added twice")
	}
}

func TestARepositoryThatDoesNotAnswerIsTakenBack(t *testing.T) {
	m, served, job := repoMachine(t)
	served[tailscaleRepo.Key] = []byte(armored(keyBytes(t)))
	job.Run = func(ctx context.Context, name string, args ...string) ([]byte, int, error) {
		m.calls = append(m.calls, name+" "+strings.Join(args, " "))
		if slices.Contains(args, "update") {
			return []byte("E: The repository 'https://pkgs.tailscale.com/stable/debian bookworm Release' does not have a Release file.\n"), 100, os.ErrInvalid
		}
		return nil, 0, nil
	}
	repo := tailscaleRepo
	repo.Fingerprint = "21DAE8A9E6167221BD7A7023D8F3939D95389CC8"
	if _, err := job.AddRepo(context.Background(), repo); err == nil || !strings.Contains(err.Error(), "does not have a Release file") {
		t.Fatalf("got %v", err)
	}
	for _, path := range []string{"/etc/apt/sources.list.d/tailscale.sources", "/etc/apt/keyrings/krynodes-tailscale.asc"} {
		if _, err := os.Stat(at(m.root, path)); !os.IsNotExist(err) {
			t.Fatalf("%s left behind", path)
		}
	}
}

func TestDroppingARepositoryLeavesTheSystemsSourcesAndOtherKeys(t *testing.T) {
	m, _, job := repoMachine(t)
	put(t, m.root, "/etc/apt/sources.list", "deb http://deb.debian.org/debian bookworm main\n")
	put(t, m.root, "/etc/apt/sources.list.d/debian.sources", "Types: deb\nURIs: http://deb.debian.org/debian\nSuites: bookworm\n")
	put(t, m.root, "/etc/apt/sources.list.d/tailscale.sources", "Types: deb\nURIs: https://pkgs.tailscale.com/stable/debian\nSuites: bookworm\nComponents: main\nSigned-By: /etc/apt/keyrings/krynodes-tailscale.gpg\n")
	put(t, m.root, "/etc/apt/keyrings/krynodes-tailscale.gpg", "key")
	put(t, m.root, "/etc/apt/sources.list.d/nodesource.list", "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main\n")
	put(t, m.root, "/usr/share/keyrings/nodesource.gpg", "key")
	for _, name := range []string{"debian", "bookworm", "../tailscale"} {
		if err := job.DropRepo(context.Background(), name, "debian"); err == nil {
			t.Fatalf("%s dropped", name)
		}
	}
	if err := job.DropRepo(context.Background(), "tailscale", "debian"); err != nil {
		t.Fatal(err)
	}
	if err := job.DropRepo(context.Background(), "nodesource", "debian"); err != nil {
		t.Fatal(err)
	}
	for path, kept := range map[string]bool{"/etc/apt/sources.list.d/tailscale.sources": false, "/etc/apt/keyrings/krynodes-tailscale.gpg": false, "/etc/apt/sources.list.d/nodesource.list": false, "/usr/share/keyrings/nodesource.gpg": true, "/etc/apt/sources.list.d/debian.sources": true} {
		if _, err := os.Stat(at(m.root, path)); (err == nil) != kept {
			t.Fatalf("%s kept %v", path, err == nil)
		}
	}
}

func TestTheRepositoryIsReadBeforeItIsAdded(t *testing.T) {
	_, served, job := repoMachine(t)
	served["https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list"] = []byte("# Tailscale packages for debian bookworm\ndeb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/debian bookworm main\n")
	served[tailscaleRepo.Key] = keyBytes(t)
	served["https://pkgs.tailscale.com/stable/debian/dists/bookworm/InRelease"] = []byte("Origin: Tailscale\n")
	served["https://pkgs.tailscale.com/stable/debian/dists/bookworm/main/binary-amd64/Packages"] = []byte("Package: tailscale\nVersion: 1.76.6\n\nPackage: tailscale\nVersion: 1.76.1\n\nPackage: tailscale-archive-keyring\nVersion: 1.35.181\n")
	job.Run = func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		if name == "dpkg" && slices.Equal(args, []string{"--print-architecture"}) {
			return []byte("amd64\n"), 0, nil
		}
		return nil, 0, nil
	}
	preview := job.PreviewRepo(context.Background(), Repo{Name: "tailscale", List: "https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list", Key: tailscaleRepo.Key})
	if preview.Refused != nil || preview.URI != tailscaleRepo.URI || !slices.Equal(preview.Suites, []string{"bookworm"}) || !slices.Equal(preview.Components, []string{"main"}) {
		t.Fatalf("got %+v", preview)
	}
	if preview.Key == nil || preview.Key.Fingerprint != "21DAE8A9E6167221BD7A7023D8F3939D95389CC8" || preview.Key.User != "Krynodes Test (Package repository signing key)" {
		t.Fatalf("key %+v", preview.Key)
	}
	if !preview.Answers || !slices.Equal(preview.Packages, []string{"tailscale", "tailscale-archive-keyring"}) || preview.Count != 2 || preview.File != "/etc/apt/sources.list.d/tailscale.sources" {
		t.Fatalf("got %+v", preview)
	}
	plain := job.PreviewRepo(context.Background(), Repo{Name: "tailscale", URI: tailscaleRepo.URI, Suites: []string{"bookworm"}, Components: []string{"main"}, Key: "http://pkgs.tailscale.com/key.gpg"})
	if plain.Refused == nil || !strings.Contains(*plain.Refused, "HTTPS") {
		t.Fatalf("got %+v", plain)
	}
}
