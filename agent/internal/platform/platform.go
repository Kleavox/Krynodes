package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type Runner func(ctx context.Context, name string, args ...string) ([]byte, int, error)

type Env struct {
	Root  string
	Run   Runner
	sleep func(time.Duration)
}

type Family string

const (
	Debian Family = "debian"
	RHEL   Family = "rhel"
)

const (
	stepTimeout = 15 * time.Minute
	lockWait    = 10 * time.Minute
	lockRetry   = 5 * time.Second
	listsLock   = "/var/lib/apt/lists/lock"
)

var ErrUnsupported = errors.New("this server has none of apt, dnf, yum, zypper, pacman or apk")

type Platform struct {
	ID       string
	Version  string
	Codename string
	Name     string
	Pretty   string
	Base     string
	Family   Family
	Manager  string
}

func (e Env) path(name string) string {
	return filepath.Join(e.Root, filepath.FromSlash(name))
}

func Detect(env Env) Platform {
	values := map[string]string{}
	body, _ := os.ReadFile(env.path("/etc/os-release"))
	for line := range strings.SplitSeq(string(body), "\n") {
		if key, value, found := strings.Cut(strings.TrimSpace(line), "="); found {
			values[key] = strings.Trim(value, `"'`)
		}
	}
	id := strings.ToLower(values["ID"])
	like := strings.Fields(strings.ToLower(values["ID_LIKE"]))
	is := func(names ...string) bool {
		return slices.Contains(names, id) || slices.ContainsFunc(like, func(name string) bool { return slices.Contains(names, name) })
	}
	name := values["NAME"]
	if name == "" && id != "" {
		name = strings.ToUpper(id[:1]) + id[1:]
	}
	platform := Platform{ID: id, Version: values["VERSION_ID"], Pretty: values["PRETTY_NAME"], Name: strings.TrimSpace(name + " " + values["VERSION_ID"])}
	switch {
	case is("debian", "ubuntu"):
		platform.Family, platform.Base = Debian, "debian"
		platform.Codename = values["UBUNTU_CODENAME"]
		if id == "ubuntu" || platform.Codename != "" {
			platform.Base = "ubuntu"
		}
		if platform.Codename == "" {
			platform.Codename = values["VERSION_CODENAME"]
		}
	case is("rhel", "rocky", "almalinux", "centos", "ol"):
		platform.Family, platform.Base = RHEL, "centos"
		if id == "rhel" {
			platform.Base = "rhel"
		}
		platform.Version, _, _ = strings.Cut(platform.Version, ".")
	}
	switch {
	case platform.Family == Debian:
		platform.Manager = "apt"
	case platform.Family == RHEL || is("fedora"):
		platform.Manager = "yum"
		if _, err := os.Stat(env.path("/usr/bin/dnf")); err == nil {
			platform.Manager = "dnf"
		}
	case is("suse", "opensuse", "sles"):
		platform.Manager = "zypper"
	case is("arch"):
		platform.Manager = "pacman"
	case is("alpine"):
		platform.Manager = "apk"
	}
	return platform
}

func (e Env) run(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	output, _, err := e.Run(ctx, name, args...)
	if err != nil {
		text := strings.TrimSpace(string(output))
		if len(text) > 400 {
			text = text[len(text)-400:]
		}
		return fmt.Errorf("%s %s failed: %s", name, strings.Join(args, " "), text)
	}
	return nil
}

func (e Env) apt(ctx context.Context, args ...string) error {
	command := append([]string{"DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", fmt.Sprintf("DPkg::Lock::Timeout=%d", int(lockWait.Seconds()))}, args...)
	for waited := time.Duration(0); ; waited += lockRetry {
		err := e.run(ctx, "env", command...)
		if err == nil || waited >= lockWait || !strings.Contains(err.Error(), listsLock) {
			return err
		}
		if e.sleep == nil {
			time.Sleep(lockRetry)
		} else {
			e.sleep(lockRetry)
		}
	}
}

func (e Env) has(ctx context.Context, manager, pkg string) bool {
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	var query []string
	switch manager {
	case "apt":
		output, _, err := e.Run(ctx, "dpkg-query", "-W", "-f", "${Status}", pkg)
		return err == nil && strings.Contains(string(output), "install ok installed")
	case "pacman":
		query = []string{"pacman", "-Q", pkg}
	case "apk":
		query = []string{"apk", "info", "-e", pkg}
	default:
		query = []string{"rpm", "-q", pkg}
	}
	_, _, err := e.Run(ctx, query[0], query[1:]...)
	return err == nil
}

func Install(ctx context.Context, env Env, packages ...string) ([]string, error) {
	manager := Detect(env).Manager
	if manager == "" {
		return nil, ErrUnsupported
	}
	var fresh []string
	for _, name := range packages {
		if !env.has(ctx, manager, name) {
			fresh = append(fresh, name)
		}
	}
	if fresh == nil {
		return nil, nil
	}
	var err error
	switch manager {
	case "apt":
		if err = env.apt(ctx, "update", "-q"); err == nil {
			err = env.apt(ctx, append([]string{"install", "-y", "-q"}, fresh...)...)
		}
	case "dnf", "yum":
		err = env.run(ctx, manager, append([]string{"install", "-y", "-q"}, fresh...)...)
	case "zypper":
		err = env.run(ctx, manager, append([]string{"--non-interactive", "install"}, fresh...)...)
	case "pacman":
		err = env.run(ctx, manager, append([]string{"-S", "--noconfirm", "--needed"}, fresh...)...)
	case "apk":
		err = env.run(ctx, manager, append([]string{"add", "-q"}, fresh...)...)
	}
	if err != nil {
		var installed []string
		for _, name := range fresh {
			if env.has(ctx, manager, name) {
				installed = append(installed, name)
			}
		}
		return installed, err
	}
	return fresh, nil
}

func Purge(ctx context.Context, env Env, packages ...string) error {
	switch manager := Detect(env).Manager; manager {
	case "apt":
		return env.apt(ctx, append([]string{"purge", "-y", "-q"}, packages...)...)
	case "dnf", "yum":
		return env.run(ctx, manager, append([]string{"remove", "-y", "-q"}, packages...)...)
	case "zypper":
		return env.run(ctx, manager, append([]string{"--non-interactive", "remove"}, packages...)...)
	case "pacman":
		return env.run(ctx, manager, append([]string{"-Rns", "--noconfirm"}, packages...)...)
	case "apk":
		return env.run(ctx, manager, append([]string{"del", "-q"}, packages...)...)
	}
	return ErrUnsupported
}
