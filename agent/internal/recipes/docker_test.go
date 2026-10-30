package recipes

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

const dockerLine = "docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"

func withFetch(env Env) (Env, *[]string) {
	fetched := &[]string{}
	env.Fetch = func(_ context.Context, url string) ([]byte, error) {
		*fetched = append(*fetched, url)
		switch {
		case strings.HasSuffix(url, "/gpg"):
			return []byte("KEY"), nil
		case strings.HasSuffix(url, "/Release"):
			return []byte("Origin: Docker\nArchitectures: amd64 arm64 armhf ppc64el s390x\n"), nil
		case strings.HasSuffix(url, "/repomd.xml"):
			return []byte("<repomd/>"), nil
		}
		return []byte("[docker-ce-stable]\nbaseurl=https://download.docker.com\n"), nil
	}
	return env, fetched
}

func freshServer(run *fakeRun) {
	run.failing["docker --version"] = true
	run.failing["rpm -q podman"] = true
	run.respond["docker version --format {{.Client.Version}}"] = "28.4.0\n"
	run.respond["uname -m"] = "x86_64\n"
}

func notPublished(env Env, suffix string) (Env, *[]string) {
	env, fetched := withFetch(env)
	inner := env.Fetch
	env.Fetch = func(ctx context.Context, url string) ([]byte, error) {
		if strings.HasSuffix(url, suffix) {
			*fetched = append(*fetched, url)
			return nil, httpAnswer{URL: url, Status: "404 Not Found", Code: 404}
		}
		return inner(ctx, url)
	}
	return env, fetched
}

func nothingWritten(t *testing.T, env Env, run *fakeRun) {
	t.Helper()
	for _, path := range []string{"/etc/apt/keyrings/docker.asc", "/etc/apt/sources.list.d/docker.list", "/etc/yum.repos.d/docker-ce.repo"} {
		if exists(env, path) {
			t.Fatalf("%s was written", path)
		}
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.Contains(call, " install ") }) {
		t.Fatalf("calls %q", run.calls)
	}
}

func TestDockerWaitsForDockerToPublishTheRelease(t *testing.T) {
	env, run := onRelease(t, "ubuntu new")
	env, _ = notPublished(env, "/Release")
	freshServer(run)
	run.respond["dpkg --print-architecture"] = "amd64\n"
	_, err := InstallDocker(context.Background(), env, nil)
	if err == nil || err.Error() != "Docker has not published packages for Ubuntu 26.10 (stonking) yet." {
		t.Fatalf("err %v", err)
	}
	nothingWritten(t, env, run)
}

func TestDockerNeedsPackagesForTheArchitecture(t *testing.T) {
	env, run := onRelease(t, "debian 13")
	env, _ = withFetch(env)
	freshServer(run)
	run.respond["dpkg --print-architecture"] = "riscv64\n"
	_, err := InstallDocker(context.Background(), env, nil)
	if err == nil || err.Error() != "Docker publishes no riscv64 packages for Debian GNU/Linux 13." {
		t.Fatalf("err %v", err)
	}
	nothingWritten(t, env, run)
}

func TestDockerNeedsACodename(t *testing.T) {
	env, run := onRelease(t, "debian sid")
	env, fetched := withFetch(env)
	freshServer(run)
	run.respond["dpkg --print-architecture"] = "amd64\n"
	_, err := InstallDocker(context.Background(), env, nil)
	if err == nil || err.Error() != "This server names no codename, so Docker's repository cannot be chosen." || len(*fetched) != 0 {
		t.Fatalf("err %v fetched %q", err, *fetched)
	}
}

func TestDockerOnRHELWaitsForTheRelease(t *testing.T) {
	env, run := onRelease(t, "rocky new")
	env, _ = notPublished(env, "/repomd.xml")
	freshServer(run)
	_, err := InstallDocker(context.Background(), env, nil)
	if err == nil || err.Error() != "Docker has not published packages for Rocky Linux 11.0 (x86_64) yet." {
		t.Fatalf("err %v", err)
	}
	nothingWritten(t, env, run)
}

func TestDockerOnDebianUsesDockersRepository(t *testing.T) {
	for key, want := range map[string]string{
		"debian 13": "deb [arch=arm64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable\n",
		"ubuntu":    "deb [arch=arm64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable\n",
		"mint":      "deb [arch=arm64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable\n",
	} {
		env, run := onRelease(t, key)
		env, fetched := withFetch(env)
		freshServer(run)
		run.respond["dpkg --print-architecture"] = "arm64\n"
		result, err := InstallDocker(context.Background(), env, nil)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if result != (DockerResult{Message: "Docker 28.4.0 with Compose", Installed: true}) {
			t.Fatalf("%s: %+v", key, result)
		}
		base, codename := "debian", "trixie"
		if key != "debian 13" {
			base, codename = "ubuntu", "noble"
		}
		if !slices.Equal(*fetched, []string{"https://download.docker.com/linux/" + base + "/dists/" + codename + "/Release", "https://download.docker.com/linux/" + base + "/gpg"}) || read(env, "/etc/apt/keyrings/docker.asc") != "KEY" {
			t.Fatalf("%s: fetched %q", key, *fetched)
		}
		if got := read(env, "/etc/apt/sources.list.d/docker.list"); got != want {
			t.Fatalf("%s: list %q", key, got)
		}
		mustCall(t, run, "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -q "+dockerLine, "systemctl enable --now docker")
	}
}

func TestAFreshDockerKeepsItsLogsSmall(t *testing.T) {
	for _, owned := range []string{"", "{\"data-root\": \"/srv/docker\"}\n"} {
		env, run := onRelease(t, "debian 13")
		env, _ = withFetch(env)
		freshServer(run)
		run.respond["dpkg --print-architecture"] = "amd64\n"
		want := "{\"log-driver\": \"local\"}\n"
		if owned != "" {
			write(t, env, "/etc/docker/daemon.json", owned)
			want = owned
		}
		if _, err := InstallDocker(context.Background(), env, nil); err != nil {
			t.Fatal(err)
		}
		if got := read(env, "/etc/docker/daemon.json"); got != want {
			t.Fatalf("daemon.json %q, want %q", got, want)
		}
	}
}

func TestDockerLeavesARepositoryTheOwnerAddedAlone(t *testing.T) {
	env, run := onRelease(t, "debian 13")
	env, fetched := withFetch(env)
	freshServer(run)
	write(t, env, "/etc/apt/sources.list.d/docker.sources", "URIs: https://download.docker.com/linux/debian\n")
	if _, err := InstallDocker(context.Background(), env, nil); err != nil {
		t.Fatal(err)
	}
	if len(*fetched) != 0 || exists(env, "/etc/apt/sources.list.d/docker.list") {
		t.Fatalf("fetched %q", *fetched)
	}
	mustCall(t, run, "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -q "+dockerLine)
}

func TestDockerOnRHELUsesDockersRepoFile(t *testing.T) {
	for key, base := range map[string]string{"rocky": "centos", "almalinux": "centos", "oracle": "centos", "centos": "centos", "rhel": "rhel"} {
		env, run := onRelease(t, key)
		env, fetched := withFetch(env)
		freshServer(run)
		if _, err := InstallDocker(context.Background(), env, nil); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		major := strings.Split(Detect(env).Version, ".")[0]
		if !slices.Equal(*fetched, []string{"https://download.docker.com/linux/" + base + "/" + major + "/x86_64/stable/repodata/repomd.xml", "https://download.docker.com/linux/" + base + "/docker-ce.repo"}) || !strings.Contains(read(env, "/etc/yum.repos.d/docker-ce.repo"), "[docker-ce-stable]") {
			t.Fatalf("%s: fetched %q", key, *fetched)
		}
		mustCall(t, run, "dnf install -y -q "+dockerLine, "systemctl enable --now docker")
	}
}

func TestDockerIsRefusedNextToPodman(t *testing.T) {
	env, run := onRelease(t, "rocky")
	env, fetched := withFetch(env)
	freshServer(run)
	delete(run.failing, "rpm -q podman")
	run.failing["rpm -q docker-ce"] = true
	_, err := InstallDocker(context.Background(), env, nil)
	if err == nil || err.Error() != "Podman is installed; remove it or install Docker by hand." || len(*fetched) != 0 {
		t.Fatalf("err %v fetched %q", err, *fetched)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "dnf install") }) {
		t.Fatalf("nothing installed: %q", run.calls)
	}
}

func TestDockerWithoutComposeGetsOnlyThePlugin(t *testing.T) {
	env, run := onRelease(t, "debian 13")
	env, _ = withFetch(env)
	run.failing["docker compose version"] = true
	run.respond["dpkg --print-architecture"] = "amd64\n"
	run.respond["docker version --format {{.Client.Version}}"] = "26.1.5\n"
	result, err := InstallDocker(context.Background(), env, nil)
	if err != nil || result != (DockerResult{Message: "Docker 26.1.5 with Compose"}) {
		t.Fatalf("result %+v err %v", result, err)
	}
	mustCall(t, run, "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -q docker-compose-plugin")
	if slices.Contains(run.calls, "systemctl enable --now docker") || exists(env, "/etc/docker/daemon.json") {
		t.Fatalf("the running Docker is left as it is: %q", run.calls)
	}
}

func TestDockerAlreadyThereIsLeftAlone(t *testing.T) {
	env, run := onRelease(t, "rocky")
	env, fetched := withFetch(env)
	result, err := InstallDocker(context.Background(), env, nil)
	if err != nil || result != (DockerResult{Message: "Docker is already installed"}) || len(*fetched) != 0 {
		t.Fatalf("result %+v err %v", result, err)
	}
	if slices.ContainsFunc(run.calls, func(call string) bool { return strings.HasPrefix(call, "dnf install") }) {
		t.Fatalf("nothing installed: %q", run.calls)
	}
}

func TestDockerReportsADownloadFailure(t *testing.T) {
	env, run := onRelease(t, "rocky")
	freshServer(run)
	env.Fetch = func(context.Context, string) ([]byte, error) { return nil, errors.New("no route to host") }
	if _, err := InstallDocker(context.Background(), env, nil); err == nil || !strings.Contains(err.Error(), "no route to host") {
		t.Fatalf("err %v", err)
	}
}

func TestTheSELinuxKeyMergesIntoDaemonJSONAndComesOutAgain(t *testing.T) {
	env, _ := onRelease(t, "rocky")
	original := "{\n  \"log-driver\": \"local\",\n  \"data-root\": \"/srv/docker\"\n}\n"
	write(t, env, DockerDaemon, original)
	previous, existed, err := MergeDaemon(env, "selinux-enabled", true)
	if err != nil || previous != original || !existed {
		t.Fatalf("previous %q existed %v err %v", previous, existed, err)
	}
	merged := read(env, DockerDaemon)
	for _, key := range []string{`"log-driver": "local"`, `"data-root": "/srv/docker"`, `"selinux-enabled": true`} {
		if !strings.Contains(merged, key) {
			t.Fatalf("missing %s in %s", key, merged)
		}
	}
	if err := RestoreDaemon(env, previous, existed); err != nil || read(env, DockerDaemon) != original {
		t.Fatalf("restored %q err %v", read(env, DockerDaemon), err)
	}

	env, _ = onRelease(t, "rocky")
	previous, existed, err = MergeDaemon(env, "selinux-enabled", true)
	if err != nil || existed || !strings.Contains(read(env, DockerDaemon), `"selinux-enabled": true`) {
		t.Fatalf("new file %q err %v", read(env, DockerDaemon), err)
	}
	if err := RestoreDaemon(env, previous, existed); err != nil || exists(env, DockerDaemon) {
		t.Fatalf("a file Krynodes wrote is removed again: %v", err)
	}
}

func TestDockerInstalledUnderManagedSELinuxConfinesFromTheStart(t *testing.T) {
	env, run := onRelease(t, "rocky")
	env, _ = withFetch(env)
	freshServer(run)
	if _, err := InstallDocker(context.Background(), env, map[string]string{"selinux": "1"}); err != nil {
		t.Fatal(err)
	}
	daemon := read(env, DockerDaemon)
	if !strings.Contains(daemon, `"selinux-enabled": true`) || !strings.Contains(daemon, `"log-driver": "local"`) {
		t.Fatalf("daemon.json %q", daemon)
	}
}
