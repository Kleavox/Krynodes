package recipes

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

type Family string

const (
	Debian Family = "debian"
	RHEL   Family = "rhel"
)

const (
	lockWait  = 10 * time.Minute
	lockRetry = 5 * time.Second
	listsLock = "/var/lib/apt/lists/lock"
)

var ErrUnsupported = errors.New("Protections and Docker setup support Debian, Ubuntu and RHEL-family servers")

type Platform struct {
	ID       string
	Version  string
	Codename string
	Name     string
	Pretty   string
	Base     string
	Family   Family
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
	return platform
}

func (e Env) apt(ctx context.Context, args ...string) error {
	command := append([]string{"DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", fmt.Sprintf("DPkg::Lock::Timeout=%d", int(lockWait.Seconds()))}, args...)
	for waited := time.Duration(0); ; waited += lockRetry {
		err := e.run(ctx, "env", command...)
		if err == nil || waited >= lockWait || !strings.Contains(err.Error(), listsLock) {
			return err
		}
		e.pause(lockRetry)
	}
}

func (e Env) pause(d time.Duration) {
	if e.Sleep == nil {
		time.Sleep(d)
		return
	}
	e.Sleep(d)
}

func (e Env) has(ctx context.Context, pkg string) bool {
	if Detect(e).Family == RHEL {
		_, err := e.output(ctx, "rpm", "-q", pkg)
		return err == nil
	}
	status, err := e.output(ctx, "dpkg-query", "-W", "-f", "${Status}", pkg)
	return err == nil && strings.Contains(status, "install ok installed")
}

func (e Env) install(ctx context.Context, packages ...string) (string, error) {
	var fresh []string
	for _, name := range packages {
		if !e.has(ctx, name) {
			fresh = append(fresh, name)
		}
	}
	if Detect(e).Family == RHEL {
		return strings.Join(fresh, " "), e.run(ctx, "dnf", append([]string{"install", "-y", "-q"}, packages...)...)
	}
	if err := e.apt(ctx, "update", "-q"); err != nil {
		return "", err
	}
	return strings.Join(fresh, " "), e.apt(ctx, append([]string{"install", "-y", "-q"}, packages...)...)
}

func Install(ctx context.Context, env Env, packages ...string) (string, error) {
	return env.install(ctx, packages...)
}

func Purge(ctx context.Context, env Env, packages ...string) error {
	return env.purge(ctx, packages...)
}

func Upgrade(ctx context.Context, env Env) error {
	if Detect(env).Family == RHEL {
		return env.run(ctx, "dnf", "upgrade", "-y", "-q")
	}
	if err := env.apt(ctx, "update", "-q"); err != nil {
		return err
	}
	return env.apt(ctx, "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "--with-new-pkgs", "upgrade", "-y", "-q")
}

func (e Env) purge(ctx context.Context, packages ...string) error {
	if Detect(e).Family == RHEL {
		return e.run(ctx, "dnf", append([]string{"remove", "-y", "-q"}, packages...)...)
	}
	return e.apt(ctx, append([]string{"purge", "-y", "-q"}, packages...)...)
}
