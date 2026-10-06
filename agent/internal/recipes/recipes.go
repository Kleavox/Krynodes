package recipes

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

type Runner func(ctx context.Context, name string, args ...string) ([]byte, int, error)

type Env struct {
	Root  string
	Run   Runner
	Fetch Fetcher
}

const (
	autoUpgrades = "/etc/apt/apt.conf.d/52krynodes-auto-upgrades"
	sshDropIn    = "/etc/ssh/sshd_config.d/10-krynodes.conf"
	jail         = "/etc/fail2ban/jail.d/krynodes.local"
	stubDropIn   = "/etc/systemd/resolved.conf.d/krynodes-no-stub.conf"
	resolvConf   = "/etc/resolv.conf"
	fullResolver = "/run/systemd/resolve/resolv.conf"
	stepTimeout  = 15 * time.Minute
)

var (
	portRule    = regexp.MustCompile(`^\d{1,5}/(tcp|udp)$`)
	keyLine     = regexp.MustCompile(`^(ssh-|ecdsa-|sk-)`)
	includeConf = regexp.MustCompile(`(?im)^\s*include\s+\S*sshd_config\.d`)
)

func (e Env) path(name string) string {
	return filepath.Join(e.Root, filepath.FromSlash(name))
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

func (e Env) output(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	output, _, err := e.Run(ctx, name, args...)
	return string(output), err
}

func (e Env) write(name, body string, mode os.FileMode) error {
	full := e.path(name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(full, []byte(body), mode); err != nil {
		return err
	}
	return os.Chmod(full, mode)
}

func (e Env) remove(name string) error {
	if err := os.Remove(e.path(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func installed(fresh string) map[string]string {
	if fresh == "" {
		return nil
	}
	return map[string]string{"installed": fresh}
}

func lines(path string) []string {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(string(body), "\n")
}

func KeyedUsers(env Env) []string {
	admins := map[string]bool{}
	for _, line := range lines(env.path("/etc/group")) {
		fields := strings.Split(line, ":")
		if len(fields) == 4 && (fields[0] == "sudo" || fields[0] == "wheel") {
			for member := range strings.SplitSeq(fields[3], ",") {
				admins[strings.TrimSpace(member)] = true
			}
		}
	}
	var users []string
	for _, line := range lines(env.path("/etc/passwd")) {
		fields := strings.Split(line, ":")
		if len(fields) != 7 || strings.HasSuffix(fields[6], "nologin") || strings.HasSuffix(fields[6], "false") {
			continue
		}
		if fields[2] != "0" && !admins[fields[0]] {
			continue
		}
		if slices.ContainsFunc(lines(env.path(filepath.ToSlash(filepath.Join(fields[5], ".ssh", "authorized_keys")))), func(key string) bool {
			return keyLine.MatchString(strings.TrimSpace(key))
		}) {
			users = append(users, fields[0])
		}
	}
	slices.Sort(users)
	return users
}

func sshPorts(ctx context.Context, env Env) []string {
	output, err := env.output(ctx, "sshd", "-T")
	ports := []string{}
	if err == nil {
		for line := range strings.SplitSeq(output, "\n") {
			if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "port" && !slices.Contains(ports, fields[1]+"/tcp") {
				ports = append(ports, fields[1]+"/tcp")
			}
		}
	}
	if len(ports) == 0 {
		ports = append(ports, "22/tcp")
	}
	return ports
}

func reloadSSH(ctx context.Context, env Env) error {
	if Detect(env).Family == RHEL {
		return env.run(ctx, "systemctl", "reload", "sshd")
	}
	if err := env.run(ctx, "systemctl", "reload", "ssh"); err != nil {
		return env.run(ctx, "systemctl", "reload", "sshd")
	}
	return nil
}

func Hold(env Env, args map[string]string) error {
	platform := Detect(env)
	if platform.Family == "" {
		return ErrUnsupported
	}
	if sentence := platform.Unverified(); sentence != "" && args["anyway"] != "yes" {
		return errors.New(sentence + " Confirm to run it anyway.")
	}
	return nil
}

func Apply(ctx context.Context, env Env, id string, args map[string]string) (map[string]string, error) {
	if err := Hold(env, args); err != nil {
		return nil, err
	}
	switch id {
	case "security-updates":
		if Detect(env).Family == RHEL {
			return rhelUpdates(ctx, env)
		}
		fresh, err := env.install(ctx, "unattended-upgrades")
		if err != nil {
			return nil, err
		}
		return installed(fresh), env.write(autoUpgrades, "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n", 0o644)
	case "ssh-keys-only":
		if len(KeyedUsers(env)) == 0 {
			return nil, errors.New("no SSH key is set up for root or a sudo user; add one before turning passwords off")
		}
		config, _ := os.ReadFile(env.path("/etc/ssh/sshd_config"))
		if !includeConf.Match(config) {
			return nil, errors.New("this server's SSH does not read /etc/ssh/sshd_config.d; change it by hand")
		}
		if err := env.write(sshDropIn, "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n", 0o644); err != nil {
			return nil, err
		}
		if err := env.run(ctx, "sshd", "-t"); err != nil {
			env.remove(sshDropIn)
			return nil, err
		}
		return nil, reloadSSH(ctx, env)
	case "fail2ban":
		var fresh string
		var err error
		if Detect(env).Family == RHEL {
			fresh, err = rhelFail2ban(ctx, env)
		} else {
			fresh, err = env.install(ctx, "fail2ban", "python3-systemd")
		}
		if err != nil {
			return nil, err
		}
		if err := env.write(jail, "[sshd]\nenabled = true\nbackend = systemd\n", 0o644); err != nil {
			return nil, err
		}
		if err := env.run(ctx, "systemctl", "enable", "--now", "fail2ban"); err != nil {
			return nil, err
		}
		return installed(fresh), env.run(ctx, "systemctl", "restart", "fail2ban")
	case "firewall":
		return firewall(ctx, env, args["ports"])
	case "free-port-53":
		return freePort53(ctx, env)
	}
	return nil, fmt.Errorf("unknown recipe %q", id)
}

func firewall(ctx context.Context, env Env, chosen string) (map[string]string, error) {
	var extra []string
	for port := range strings.SplitSeq(chosen, ",") {
		if port = strings.TrimSpace(port); port == "" {
			continue
		}
		if !portRule.MatchString(port) {
			return nil, fmt.Errorf("%q is not a port like 80/tcp", port)
		}
		extra = append(extra, port)
	}
	if Detect(env).Family == RHEL {
		return firewalld(ctx, env, extra)
	}
	saved := map[string]string{}
	if _, err := env.output(ctx, "ufw", "version"); err != nil {
		fresh, err := env.install(ctx, "ufw")
		if err != nil {
			return nil, err
		}
		if fresh != "" {
			saved["installed"] = fresh
		}
	}
	status, _ := env.output(ctx, "ufw", "status")
	active := strings.Contains(status, "Status: active")
	rules := sshPorts(ctx, env)
	for _, port := range extra {
		if !slices.Contains(rules, port) {
			rules = append(rules, port)
		}
	}
	for _, rule := range rules {
		if err := env.run(ctx, "ufw", "allow", rule, "comment", "krynodes"); err != nil {
			return nil, err
		}
	}
	if !active {
		for _, step := range [][]string{{"default", "deny", "incoming"}, {"default", "allow", "outgoing"}, {"--force", "enable"}} {
			if err := env.run(ctx, "ufw", step...); err != nil {
				return nil, err
			}
		}
	}
	saved["wasActive"] = fmt.Sprint(active)
	saved["rules"] = strings.Join(rules, ",")
	return saved, nil
}

func freePort53(ctx context.Context, env Env) (map[string]string, error) {
	if err := env.run(ctx, "systemctl", "is-active", "--quiet", "systemd-resolved"); err != nil {
		return nil, errors.New("port 53 is not held by systemd-resolved on this server")
	}
	saved := map[string]string{}
	if link, err := os.Readlink(env.path(resolvConf)); err == nil {
		saved["link"] = link
	} else if body, err := os.ReadFile(env.path(resolvConf)); err == nil {
		saved["file"] = string(body)
	}
	if err := env.write(stubDropIn, "[Resolve]\nDNSStubListener=no\n", 0o644); err != nil {
		return nil, err
	}
	if err := env.remove(resolvConf); err != nil {
		return nil, err
	}
	if err := os.Symlink(fullResolver, env.path(resolvConf)); err != nil {
		return nil, err
	}
	return saved, env.run(ctx, "systemctl", "restart", "systemd-resolved")
}

func Undo(ctx context.Context, env Env, id string, saved map[string]string) error {
	if err := undo(ctx, env, id, saved); err != nil {
		return err
	}
	if packages := strings.Fields(saved["installed"]); len(packages) > 0 {
		return env.purge(ctx, packages...)
	}
	return nil
}

func undo(ctx context.Context, env Env, id string, saved map[string]string) error {
	switch id {
	case "security-updates":
		if Detect(env).Family == RHEL {
			return undoRHELUpdates(ctx, env)
		}
		return env.remove(autoUpgrades)
	case "ssh-keys-only":
		if err := env.remove(sshDropIn); err != nil {
			return err
		}
		if err := env.run(ctx, "sshd", "-t"); err != nil {
			return err
		}
		return reloadSSH(ctx, env)
	case "fail2ban":
		if err := env.remove(jail); err != nil {
			return err
		}
		return env.run(ctx, "systemctl", "disable", "--now", "fail2ban")
	case "firewall":
		if Detect(env).Family == RHEL {
			return undoFirewalld(ctx, env, saved)
		}
		for rule := range strings.SplitSeq(saved["rules"], ",") {
			if rule != "" {
				if err := env.run(ctx, "ufw", "--force", "delete", "allow", rule); err != nil {
					return err
				}
			}
		}
		if saved["wasActive"] != "true" {
			return env.run(ctx, "ufw", "--force", "disable")
		}
		return nil
	case "free-port-53":
		if err := env.remove(stubDropIn); err != nil {
			return err
		}
		if err := env.remove(resolvConf); err != nil {
			return err
		}
		switch {
		case saved["link"] != "":
			if err := os.Symlink(saved["link"], env.path(resolvConf)); err != nil {
				return err
			}
		case saved["file"] != "":
			if err := env.write(resolvConf, saved["file"], 0o644); err != nil {
				return err
			}
		}
		return env.run(ctx, "systemctl", "restart", "systemd-resolved")
	}
	return fmt.Errorf("unknown recipe %q", id)
}
