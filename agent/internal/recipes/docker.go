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
	"strings"
	"time"
)

type Fetcher func(ctx context.Context, url string) ([]byte, error)

type DockerResult struct {
	Message   string
	Installed bool
}

const (
	dockerKey  = "/etc/apt/keyrings/docker.asc"
	dockerList = "/etc/apt/sources.list.d/docker.list"
	dockerRepo = "/etc/yum.repos.d/docker-ce.repo"
)

var dockerPackages = []string{"docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"}

var fetchClient = &http.Client{
	Timeout:   2 * time.Minute,
	Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}},
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
		return nil, fmt.Errorf("%s answered %s", url, response.Status)
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
	if err := Hold(env, args); err != nil {
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
	packages := dockerPackages
	if missing == nil {
		packages = []string{"docker-compose-plugin"}
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
		body, err := env.fetch(ctx, "https://download.docker.com/linux/"+platform.Base+"/docker-ce.repo")
		if err != nil {
			return fmt.Errorf("Docker's repository: %w", err)
		}
		return env.write(dockerRepo, string(body), 0o644)
	}
	if env.mentions("/etc/apt/sources.list.d", "download.docker.com") {
		return nil
	}
	key, err := env.fetch(ctx, "https://download.docker.com/linux/"+platform.Base+"/gpg")
	if err != nil {
		return fmt.Errorf("Docker's signing key: %w", err)
	}
	if err := env.write(dockerKey, string(key), 0o644); err != nil {
		return err
	}
	arch, err := env.output(ctx, "dpkg", "--print-architecture")
	if err != nil || strings.TrimSpace(arch) == "" {
		return errors.New("dpkg does not say this server's architecture")
	}
	line := fmt.Sprintf("deb [arch=%s signed-by=%s] https://download.docker.com/linux/%s %s stable\n", strings.TrimSpace(arch), dockerKey, platform.Base, platform.Codename)
	return env.write(dockerList, line, 0o644)
}
