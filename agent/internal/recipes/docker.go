package recipes

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type Fetcher func(ctx context.Context, url string) ([]byte, error)

type DockerResult struct {
	Message   string
	Installed bool
}

const (
	dockerKey    = "/etc/apt/keyrings/docker.asc"
	DockerList   = "/etc/apt/sources.list.d/docker.list"
	dockerRepo   = "/etc/yum.repos.d/docker-ce.repo"
	DockerDaemon = "/etc/docker/daemon.json"
	DockerLogs   = "{\"log-driver\": \"local\"}\n"
)

var DockerPackages = []string{"docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"}

var fetchClient = &http.Client{
	Timeout:   2 * time.Minute,
	Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}},
	CheckRedirect: func(next *http.Request, via []*http.Request) error {
		if next.URL.Scheme != "https" {
			return errors.New("the download was redirected away from HTTPS")
		}
		if len(via) >= 10 {
			return errors.New("the download was redirected too many times")
		}
		return nil
	},
}

type httpAnswer struct {
	URL, Status string
	Code        int
}

func (a httpAnswer) Error() string { return a.URL + " answered " + a.Status }

func (e Env) Get(ctx context.Context, url string) ([]byte, error) {
	return e.fetch(ctx, url)
}

func (e Env) fetch(ctx context.Context, url string) ([]byte, error) {
	if e.Fetch != nil {
		return e.Fetch(ctx, url)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := fetchClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, httpAnswer{URL: url, Status: response.Status, Code: response.StatusCode}
	}
	return io.ReadAll(io.LimitReader(response.Body, 1<<20))
}

func (e Env) mentions(directory, text string) bool {
	entries, _ := os.ReadDir(e.path(directory))
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(e.path(directory), entry.Name()))
		if err == nil && strings.Contains(string(body), text) {
			return true
		}
	}
	return false
}

func InstallDocker(ctx context.Context, env Env, args map[string]string) (DockerResult, error) {
	if err := Hold(env); err != nil {
		return DockerResult{}, err
	}
	platform := Detect(env)
	_, missing := env.output(ctx, "docker", "--version")
	_, noCompose := env.output(ctx, "docker", "compose", "version")
	if missing == nil && noCompose == nil {
		return DockerResult{Message: "Docker is already installed"}, nil
	}
	if platform.Family == RHEL && env.has(ctx, "podman") && !env.has(ctx, "docker-ce") {
		return DockerResult{}, errors.New("Podman is installed; remove it or install Docker by hand.")
	}
	if err := dockerRepository(ctx, env, platform); err != nil {
		return DockerResult{}, err
	}
	packages := DockerPackages
	if missing == nil {
		packages = []string{"docker-compose-plugin"}
	} else if _, err := os.Stat(env.path(DockerDaemon)); errors.Is(err, os.ErrNotExist) {
		if err := env.write(DockerDaemon, DockerLogs, 0o644); err != nil {
			return DockerResult{}, err
		}
	}
	if _, err := env.install(ctx, packages...); err != nil {
		return DockerResult{}, err
	}
	if missing != nil {
		if err := env.run(ctx, "systemctl", "enable", "--now", "docker"); err != nil {
			return DockerResult{}, err
		}
	}
	version, _ := env.output(ctx, "docker", "version", "--format", "{{.Client.Version}}")
	message := "Docker with Compose"
	if version = strings.TrimSpace(version); version != "" {
		message = "Docker " + version + " with Compose"
	}
	return DockerResult{Message: message, Installed: missing != nil}, nil
}

func dockerRepository(ctx context.Context, env Env, platform Platform) error {
	if platform.Family == RHEL {
		if env.mentions("/etc/yum.repos.d", "download.docker.com") {
			return nil
		}
		machine, err := env.output(ctx, "uname", "-m")
		if machine = strings.TrimSpace(machine); err != nil || machine == "" {
			return errors.New("uname does not say this server's architecture")
		}
		if _, err := env.fetch(ctx, "https://download.docker.com/linux/"+platform.Base+"/"+platform.Version+"/"+machine+"/stable/repodata/repomd.xml"); err != nil {
			return published(platform, machine, err)
		}
		body, err := env.fetch(ctx, "https://download.docker.com/linux/"+platform.Base+"/docker-ce.repo")
		if err != nil {
			return fmt.Errorf("Docker's repository: %w", err)
		}
		return env.write(dockerRepo, string(body), 0o644)
	}
	if env.mentions("/etc/apt/sources.list.d", "download.docker.com") {
		return nil
	}
	if platform.Codename == "" {
		return errors.New("This server names no codename, so Docker's repository cannot be chosen.")
	}
	arch, err := env.output(ctx, "dpkg", "--print-architecture")
	if arch = strings.TrimSpace(arch); err != nil || arch == "" {
		return errors.New("dpkg does not say this server's architecture")
	}
	release, err := env.fetch(ctx, "https://download.docker.com/linux/"+platform.Base+"/dists/"+platform.Codename+"/Release")
	if err != nil {
		return published(platform, platform.Codename, err)
	}
	if !archListed(release, arch) {
		return fmt.Errorf("Docker publishes no %s packages for %s.", arch, platform.Name)
	}
	key, err := env.fetch(ctx, "https://download.docker.com/linux/"+platform.Base+"/gpg")
	if err != nil {
		return fmt.Errorf("Docker's signing key: %w", err)
	}
	if err := env.write(dockerKey, string(key), 0o644); err != nil {
		return err
	}
	line := fmt.Sprintf("deb [arch=%s signed-by=%s] https://download.docker.com/linux/%s %s stable\n", arch, dockerKey, platform.Base, platform.Codename)
	return env.write(DockerList, line, 0o644)
}

func published(platform Platform, which string, err error) error {
	var answer httpAnswer
	if errors.As(err, &answer) && answer.Code == http.StatusNotFound {
		return fmt.Errorf("Docker has not published packages for %s (%s) yet.", platform.Name, which)
	}
	return fmt.Errorf("Docker's repository: %w", err)
}

func archListed(release []byte, arch string) bool {
	for line := range strings.SplitSeq(string(release), "\n") {
		if fields, found := strings.CutPrefix(line, "Architectures:"); found {
			return slices.Contains(strings.Fields(fields), arch)
		}
	}
	return false
}
