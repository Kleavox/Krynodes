package platform

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

	"github.com/Kleavox/krynodes/agent/internal/safefile"
)

const DockerGuardDropInPath = "/etc/systemd/system/docker.service.d/krynodes-guard.conf"

const (
	dockerKey    = "/etc/apt/keyrings/docker.asc"
	dockerList   = "/etc/apt/sources.list.d/docker.list"
	dockerRepo   = "/etc/yum.repos.d/docker-ce.repo"
	dockerDaemon = "/etc/docker/daemon.json"
	dockerLogs   = "{\"log-driver\": \"local\"}\n"
	maxDownload  = 1 << 20
)

var ErrNoDockerUnit = errors.New("this server's Docker has no docker.service")

var errNoExecutable = errors.New("the agent does not know where it is installed, so Docker cannot be made to wait for the guard of Contained stacks")

var dockerPackages = []string{"docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"}

var download = &http.Client{
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

type answered struct {
	url, status string
	code        int
}

func (a answered) Error() string { return a.url + " answered " + a.status }

func (e Env) fetch(ctx context.Context, url string) ([]byte, error) {
	if e.Fetch != nil {
		return e.Fetch(ctx, url)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := download.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, answered{url: url, status: response.Status, code: response.StatusCode}
	}
	return io.ReadAll(io.LimitReader(response.Body, maxDownload))
}

func (e Env) output(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	output, _, err := e.Run(ctx, name, args...)
	return strings.TrimSpace(string(output)), err
}

func (e Env) write(name string, body []byte) error {
	path := e.path(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return safefile.Write(path, body, 0o644)
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

func InstallDocker(ctx context.Context, env Env) (string, bool, error) {
	_, missing := env.output(ctx, "docker", "--version")
	_, noCompose := env.output(ctx, "docker", "compose", "version")
	if missing == nil && noCompose == nil {
		return "", false, nil
	}
	if !strings.HasPrefix(env.Executable, "/") {
		return "", false, errNoExecutable
	}
	platform := Detect(env)
	if platform.Family != Debian && platform.Family != RHEL {
		return "", false, errors.New("Install Docker knows Debian, Ubuntu and the RHEL family; install Docker by hand on this server")
	}
	if platform.Family == RHEL && env.has(ctx, platform.Manager, "podman") && !env.has(ctx, platform.Manager, "docker-ce") {
		return "", false, errors.New("Podman is installed; remove it or install Docker by hand")
	}
	if err := dockerRepository(ctx, env, platform); err != nil {
		return "", false, err
	}
	packages := dockerPackages
	if missing == nil {
		packages = []string{"docker-compose-plugin"}
	} else if _, err := os.Stat(env.path(dockerDaemon)); errors.Is(err, os.ErrNotExist) {
		if err := env.write(dockerDaemon, []byte(dockerLogs)); err != nil {
			return "", false, err
		}
	}
	if _, err := Install(ctx, env, packages...); err != nil {
		return "", false, err
	}
	if missing != nil {
		if err := env.run(ctx, "systemctl", "enable", "--now", "docker"); err != nil {
			return "", false, err
		}
	}
	if err := env.GuardDocker(ctx); err != nil {
		return "", false, fmt.Errorf("Docker is installed, but its guard drop-in was not written: %w", err)
	}
	version, _ := env.output(ctx, "docker", "version", "--format", "{{.Client.Version}}")
	return version, true, nil
}

func DockerGuardDropIn(executable string) string {
	return "[Service]\nExecStartPre=" + executable + " guard\n"
}

func (e Env) GuardDocker(ctx context.Context) error {
	if !strings.HasPrefix(e.Executable, "/") {
		return errNoExecutable
	}
	if e.Prove != nil {
		if err := e.Prove(ctx); err != nil {
			return err
		}
	}
	if err := e.write(DockerGuardDropInPath, []byte(DockerGuardDropIn(e.Executable))); err != nil {
		return err
	}
	if err := e.run(ctx, "systemctl", "daemon-reload"); err != nil {
		os.Remove(e.path(DockerGuardDropInPath))
		return err
	}
	return nil
}

func (e Env) dockerUnit(ctx context.Context) (bool, error) {
	state, err := e.output(ctx, "systemctl", "show", "-p", "LoadState", "docker.service")
	return state == "LoadState=loaded", err
}

func (e Env) DockerLoaded(ctx context.Context) bool {
	loaded, err := e.dockerUnit(ctx)
	return err == nil && loaded
}

func (e Env) GuardInstalledDocker(ctx context.Context) error {
	loaded, err := e.dockerUnit(ctx)
	if err != nil {
		return fmt.Errorf("systemd does not say whether Docker has a unit: %w", err)
	}
	if !loaded {
		return ErrNoDockerUnit
	}
	if body, err := os.ReadFile(e.path(DockerGuardDropInPath)); err != nil || string(body) != DockerGuardDropIn(e.Executable) {
		if err := e.GuardDocker(ctx); err != nil {
			return err
		}
	}
	return e.dockerRunsGuard(ctx)
}

func (e Env) runsGuard(ctx context.Context) (bool, error) {
	shown, err := e.output(ctx, "systemctl", "show", "-p", "ExecStartPre", "docker.service")
	if err != nil {
		return false, fmt.Errorf("systemd does not say what runs before Docker: %w", err)
	}
	for entry := range strings.SplitSeq(shown, "}") {
		if strings.Contains(entry, "argv[]="+e.Executable+" guard ;") && strings.Contains(entry, "ignore_errors=no") {
			return true, nil
		}
	}
	return false, nil
}

func (e Env) dockerRunsGuard(ctx context.Context) error {
	runs, err := e.runsGuard(ctx)
	if runs || err != nil {
		return err
	}
	ours := filepath.Base(DockerGuardDropInPath)
	listed, _ := e.output(ctx, "systemctl", "show", "-p", "DropInPaths", "docker.service")
	var others []string
	for _, path := range strings.Fields(strings.TrimPrefix(listed, "DropInPaths=")) {
		if filepath.Base(path) > ours {
			others = append(others, path)
		}
	}
	if len(others) > 0 {
		return fmt.Errorf("systemd does not run %s guard before Docker: %s comes after the guard's drop-in and can reset ExecStartPre", e.Executable, strings.Join(others, ", "))
	}
	needed, err := e.output(ctx, "systemctl", "show", "-p", "NeedDaemonReload", "docker.service")
	if err != nil {
		return fmt.Errorf("systemd does not say whether it must reload: %w", err)
	}
	if needed == "NeedDaemonReload=yes" {
		if err := e.run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		if runs, err = e.runsGuard(ctx); runs || err != nil {
			return err
		}
	}
	return fmt.Errorf("systemd does not run %s guard before Docker with ignore_errors=no, though %s is in place", e.Executable, DockerGuardDropInPath)
}

func (e Env) UnguardDocker(ctx context.Context) error {
	path := e.path(DockerGuardDropInPath)
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	os.Remove(filepath.Dir(path))
	return e.run(ctx, "systemctl", "daemon-reload")
}

func dockerRepository(ctx context.Context, env Env, platform Platform) error {
	if platform.Family == RHEL {
		if env.mentions("/etc/yum.repos.d", "download.docker.com") {
			return nil
		}
		machine, err := env.output(ctx, "uname", "-m")
		if err != nil || machine == "" {
			return errors.New("uname does not say this server's architecture")
		}
		if _, err := env.fetch(ctx, "https://download.docker.com/linux/"+platform.Base+"/"+platform.Version+"/"+machine+"/stable/repodata/repomd.xml"); err != nil {
			return unpublished(platform, machine, err)
		}
		body, err := env.fetch(ctx, "https://download.docker.com/linux/"+platform.Base+"/docker-ce.repo")
		if err != nil {
			return fmt.Errorf("Docker's repository: %w", err)
		}
		return env.write(dockerRepo, body)
	}
	if env.mentions("/etc/apt/sources.list.d", "download.docker.com") {
		return nil
	}
	if platform.Codename == "" {
		return errors.New("This server names no codename, so Docker's repository cannot be chosen.")
	}
	arch, err := env.output(ctx, "dpkg", "--print-architecture")
	if err != nil || arch == "" {
		return errors.New("dpkg does not say this server's architecture")
	}
	release, err := env.fetch(ctx, "https://download.docker.com/linux/"+platform.Base+"/dists/"+platform.Codename+"/Release")
	if err != nil {
		return unpublished(platform, platform.Codename, err)
	}
	if !archListed(release, arch) {
		return fmt.Errorf("Docker publishes no %s packages for %s.", arch, platform.Name)
	}
	key, err := env.fetch(ctx, "https://download.docker.com/linux/"+platform.Base+"/gpg")
	if err != nil {
		return fmt.Errorf("Docker's signing key: %w", err)
	}
	if err := env.write(dockerKey, key); err != nil {
		return err
	}
	line := fmt.Sprintf("deb [arch=%s signed-by=%s] https://download.docker.com/linux/%s %s stable\n", arch, dockerKey, platform.Base, platform.Codename)
	return env.write(dockerList, []byte(line))
}

func unpublished(platform Platform, which string, err error) error {
	if refused, ok := errors.AsType[answered](err); ok && refused.code == http.StatusNotFound {
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
