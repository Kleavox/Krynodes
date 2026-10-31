package recipes

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/confine"
)

const (
	semanageTool = "policycoreutils-python-utils"
	grubAppArmor = "/etc/default/grub.d/krynodes-apparmor.cfg"
)

func confineOn(ctx context.Context, env Env) (map[string]string, error) {
	state := confine.Read(env.Root, string(Detect(env).Family))
	switch state.System {
	case confine.SELinux:
		return selinuxOn(ctx, env, state)
	case confine.AppArmor:
		return apparmorOn(ctx, env, state)
	}
	return nil, errors.New("this server has neither SELinux nor AppArmor")
}

func confineOff(ctx context.Context, env Env, saved map[string]string) error {
	switch saved["system"] {
	case confine.SELinux:
		if saved["mode"] == confine.Enforcing {
			return nil
		}
		running := confine.Read(env.Root, string(RHEL)).Mode != confine.Disabled
		if saved["restart"] == "1" && !running {
			if err := env.remove(confine.Relabel); err != nil {
				return err
			}
			return setSELinux(env, saved["config"])
		}
		if running {
			if err := env.run(ctx, "setenforce", "0"); err != nil {
				return err
			}
		}
		if saved["mode"] == confine.Disabled {
			return setSELinux(env, confine.Permissive)
		}
		return setSELinux(env, saved["config"])
	case confine.AppArmor:
		for profile := range strings.SplitSeq(saved["complain"], "\n") {
			if profile != "" {
				if err := env.run(ctx, "aa-complain", profile); err != nil {
					return err
				}
			}
		}
		if saved["restart"] == "1" {
			if err := env.remove(grubAppArmor); err != nil {
				return err
			}
			return env.run(ctx, "update-grub")
		}
	}
	return nil
}

func setSELinux(env Env, value string) error {
	full := env.path(confine.SELinuxConfig)
	mode := os.FileMode(0o644)
	if info, err := os.Stat(full); err == nil {
		mode = info.Mode().Perm()
	}
	body, _ := os.ReadFile(full)
	lines := strings.SplitAfter(string(body), "\n")
	found := false
	for index, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "SELINUX=") {
			found = true
			lines[index] = ""
			if value != "" {
				lines[index] = "SELINUX=" + value + "\n"
			}
		}
	}
	if !found && value != "" {
		lines = append(lines, "SELINUX="+value+"\n")
	}
	return env.write(confine.SELinuxConfig, strings.Join(lines, ""), mode)
}

func loginHomes(ctx context.Context, env Env) []string {
	homes := []string{}
	for _, account := range keyLogins(ctx, env, shellUsers(env)) {
		home := strings.TrimRight(env.real(account.home), "/")
		if home != "" && home != "/root" && home != "/home" && !strings.HasPrefix(home, "/home/") && !slices.Contains(homes, home) {
			homes = append(homes, home)
		}
	}
	return homes
}

func selinuxOn(ctx context.Context, env Env, state confine.State) (map[string]string, error) {
	saved := map[string]string{"system": confine.SELinux, "mode": state.Mode, "config": state.Config}
	if state.Mode == confine.Enforcing {
		return saved, nil
	}
	ports := []string{}
	for _, port := range sshPorts(ctx, env) {
		if port != "22/tcp" {
			ports = append(ports, strings.TrimSuffix(port, "/tcp"))
		}
	}
	homes := loginHomes(ctx, env)
	need := []string{}
	for _, port := range ports {
		need = append(need, "SSH on port "+port)
	}
	for _, home := range homes {
		need = append(need, "key logins into "+home)
	}
	fresh := ""
	if len(need) > 0 {
		var err error
		if fresh, err = env.install(ctx, semanageTool); err != nil {
			return nil, fmt.Errorf("SELinux would block %s, and semanage could not be installed to allow it: %w", strings.Join(need, " and "), err)
		}
	}
	back := func(err error) error {
		if packages := strings.Fields(fresh); len(packages) > 0 {
			if undo := env.purge(ctx, packages...); undo != nil {
				return fmt.Errorf("%w; removing %s again also failed: %v", err, fresh, undo)
			}
		}
		return err
	}
	either := func(first, second []string) error {
		if err := env.run(ctx, first[0], first[1:]...); err != nil {
			return env.run(ctx, second[0], second[1:]...)
		}
		return nil
	}
	for _, port := range ports {
		if err := either([]string{"semanage", "port", "-a", "-t", "ssh_port_t", "-p", "tcp", port}, []string{"semanage", "port", "-m", "-t", "ssh_port_t", "-p", "tcp", port}); err != nil {
			return nil, back(fmt.Errorf("SELinux would block SSH on port %s: %w", port, err))
		}
	}
	for _, home := range homes {
		if err := either([]string{"semanage", "fcontext", "-a", "-e", "/home", home}, []string{"semanage", "fcontext", "-m", "-e", "/home", home}); err != nil {
			return nil, back(fmt.Errorf("SELinux would block key logins into %s: %w", home, err))
		}
		if err := env.run(ctx, "restorecon", "-R", home); err != nil {
			return nil, back(fmt.Errorf("SELinux would block key logins into %s: %w", home, err))
		}
	}
	if state.Mode == confine.Permissive {
		if err := env.run(ctx, "setenforce", "1"); err != nil {
			return nil, back(err)
		}
		if err := setSELinux(env, confine.Enforcing); err != nil {
			env.run(ctx, "setenforce", "0")
			return nil, back(err)
		}
	} else {
		if err := setSELinux(env, confine.Enforcing); err != nil {
			return nil, back(err)
		}
		if err := env.write(confine.Relabel, "", 0o644); err != nil {
			setSELinux(env, state.Config)
			return nil, back(err)
		}
		saved["restart"] = "1"
	}
	if fresh != "" {
		saved["installed"] = fresh
	}
	return saved, nil
}

func complainProfiles(env Env) []string {
	body, _ := os.ReadFile(env.path("/sys/kernel/security/apparmor/profiles"))
	profiles := []string{}
	for line := range strings.SplitSeq(string(body), "\n") {
		if name, ok := strings.CutSuffix(strings.TrimSpace(line), " (complain)"); ok {
			profiles = append(profiles, name)
		}
	}
	return profiles
}

func apparmorOn(ctx context.Context, env Env, state confine.State) (map[string]string, error) {
	saved := map[string]string{"system": confine.AppArmor, "mode": state.Mode}
	complain := complainProfiles(env)
	if state.Mode == confine.On && len(complain) == 0 {
		return saved, nil
	}
	tools := []string{"apparmor-utils"}
	if state.Mode != confine.On {
		tools = []string{"apparmor", "apparmor-utils"}
	}
	fresh, err := env.install(ctx, tools...)
	if err != nil {
		return nil, err
	}
	fresh = strings.Join(slices.DeleteFunc(strings.Fields(fresh), func(name string) bool { return name == "apparmor" }), " ")
	back := func(err error) error {
		if packages := strings.Fields(fresh); len(packages) > 0 {
			env.purge(ctx, packages...)
		}
		return err
	}
	if state.Mode == confine.KernelOff {
		if err := env.write(grubAppArmor, "GRUB_CMDLINE_LINUX=\"$GRUB_CMDLINE_LINUX apparmor=1 security=apparmor\"\n", 0o644); err != nil {
			return nil, back(err)
		}
		if err := env.run(ctx, "update-grub"); err != nil {
			env.remove(grubAppArmor)
			return nil, back(err)
		}
		saved["restart"] = "1"
	}
	if state.Mode != confine.On {
		if err := env.run(ctx, "systemctl", "enable", "--now", "apparmor"); err != nil {
			return nil, back(err)
		}
	}
	enforced := []string{}
	for _, profile := range complain {
		if err := env.run(ctx, "aa-enforce", profile); err != nil {
			for _, done := range enforced {
				env.run(ctx, "aa-complain", done)
			}
			return nil, back(fmt.Errorf("AppArmor could not enforce %s: %w", profile, err))
		}
		enforced = append(enforced, profile)
	}
	if len(enforced) > 0 {
		saved["complain"] = strings.Join(enforced, "\n")
	}
	if fresh != "" {
		saved["installed"] = fresh
	}
	return saved, nil
}
