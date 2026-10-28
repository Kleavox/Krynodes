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

const (
	updatesService = "/etc/systemd/system/krynodes-security-updates.service"
	updatesTimer   = "/etc/systemd/system/krynodes-security-updates.timer"
	updatesUnit    = "krynodes-security-updates.timer"
	rebootFile     = "/var/run/reboot-required"
)

var errNoMarker = errors.New("Nothing on this server marks when a restart is needed. Turn on Security updates first.")

func rhelUpdates(ctx context.Context, env Env) (map[string]string, error) {
	notices, err := env.output(ctx, "dnf", "-q", "updateinfo", "list", "--security", "--all")
	if err != nil {
		return nil, fmt.Errorf("dnf could not read the security notices: %w", err)
	}
	if strings.TrimSpace(notices) == "" {
		return nil, fmt.Errorf("%s's repositories publish no security notices, so dnf cannot pick out security updates.", Detect(env).Name)
	}
	if !env.has(ctx, "dnf-plugins-core") {
		if _, err := env.install(ctx, "dnf-plugins-core"); err != nil {
			return nil, err
		}
	}
	files := []struct{ path, body string }{
		{updatesService, "[Unit]\nDescription=Krynodes security updates\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/dnf -y upgrade --security\n"},
		{updatesTimer, "[Unit]\nDescription=Krynodes security updates\n\n[Timer]\nOnCalendar=daily\nRandomizedDelaySec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"},
	}
	back := func(err error) (map[string]string, error) {
		env.remove(updatesTimer)
		env.remove(updatesService)
		return nil, err
	}
	for _, file := range files {
		if err := env.write(file.path, file.body, 0o644); err != nil {
			return back(err)
		}
	}
	if err := env.run(ctx, "systemctl", "daemon-reload"); err != nil {
		return back(err)
	}
	if err := env.run(ctx, "systemctl", "enable", "--now", updatesUnit); err != nil {
		return back(err)
	}
	return nil, nil
}

func undoRHELUpdates(ctx context.Context, env Env) error {
	if err := env.run(ctx, "systemctl", "disable", "--now", updatesUnit); err != nil {
		return err
	}
	for _, path := range []string{updatesTimer, updatesService} {
		if err := env.remove(path); err != nil {
			return err
		}
	}
	return env.run(ctx, "systemctl", "daemon-reload")
}

func rhelFail2ban(ctx context.Context, env Env) (string, error) {
	platform := Detect(env)
	var fresh []string
	switch platform.ID {
	case "rhel":
		if !env.has(ctx, "epel-release") {
			if err := env.run(ctx, "dnf", "install", "-y", "-q", "https://dl.fedoraproject.org/pub/epel/epel-release-latest-"+platform.Version+".noarch.rpm"); err != nil {
				return "", err
			}
			fresh = append(fresh, "epel-release")
		}
	default:
		epel := "epel-release"
		if platform.ID == "ol" {
			epel = "oracle-epel-release-el" + platform.Version
		}
		added, err := env.install(ctx, epel)
		if err != nil {
			return "", err
		}
		if added != "" {
			fresh = append(fresh, added)
		}
	}
	added, err := env.install(ctx, "fail2ban", "fail2ban-systemd")
	if added != "" {
		fresh = append(fresh, added)
	}
	return strings.Join(fresh, " "), err
}

func RestartMarked(ctx context.Context, env Env) error {
	if Detect(env).Family == RHEL {
		answer, _ := env.output(ctx, "dnf", "needs-restarting", "-r")
		if strings.Contains(answer, "Reboot is required") || strings.Contains(answer, "Reboot should not be necessary") {
			return nil
		}
		return errNoMarker
	}
	for _, marker := range []string{"/usr/share/update-notifier/notify-reboot-required", "/etc/kernel/postinst.d/unattended-upgrades"} {
		if _, err := os.Stat(env.path(marker)); err == nil {
			return nil
		}
	}
	return errNoMarker
}

func RebootNeeded(ctx context.Context, env Env) (bool, time.Time) {
	if Detect(env).Family == RHEL {
		output, _ := env.output(ctx, "dnf", "needs-restarting", "-r")
		return strings.Contains(output, "Reboot is required"), time.Time{}
	}
	info, err := os.Stat(env.path(rebootFile))
	if err != nil {
		return false, time.Time{}
	}
	return true, info.ModTime()
}

func firewalld(ctx context.Context, env Env, extra []string) (map[string]string, error) {
	saved := map[string]string{}
	if !env.has(ctx, "firewalld") {
		fresh, err := env.install(ctx, "firewalld")
		if err != nil {
			return nil, err
		}
		if fresh != "" {
			saved["installed"] = fresh
		}
	}
	state, _ := env.output(ctx, "firewall-cmd", "--state")
	running := strings.TrimSpace(state) == "running"
	ssh := sshPorts(ctx, env)
	ports := slices.Clone(ssh)
	for _, port := range extra {
		if !slices.Contains(ports, port) {
			ports = append(ports, port)
		}
	}
	port := func(verb, port string) (string, []string) {
		if running {
			return "firewall-cmd", []string{"--permanent", "--" + verb + "-port=" + port}
		}
		return "firewall-offline-cmd", []string{"--" + verb + "-port=" + port}
	}
	var added []string
	for _, wanted := range ports {
		if tool, args := port("query", wanted); env.run(ctx, tool, args...) == nil {
			continue
		}
		tool, args := port("add", wanted)
		if err := env.run(ctx, tool, args...); err != nil {
			return nil, fmt.Errorf("%s could not open %s: %w", tool, wanted, err)
		}
		added = append(added, wanted)
	}
	if running {
		if err := env.run(ctx, "firewall-cmd", "--reload"); err != nil {
			return nil, err
		}
	} else if err := env.run(ctx, "systemctl", "enable", "--now", "firewalld"); err != nil {
		return nil, err
	}
	saved["ports"] = strings.Join(added, ",")
	saved["wasRunning"] = fmt.Sprint(running)
	if !running && slices.ContainsFunc(ssh, func(port string) bool { return env.run(ctx, "firewall-cmd", "--query-port="+port) != nil }) {
		return nil, firewallBack(undoFirewalld(ctx, env, saved))
	}
	return saved, nil
}

func undoFirewalld(ctx context.Context, env Env, saved map[string]string) error {
	for port := range strings.SplitSeq(saved["ports"], ",") {
		if port != "" {
			if err := env.run(ctx, "firewall-cmd", "--permanent", "--remove-port="+port); err != nil {
				return err
			}
		}
	}
	if err := env.run(ctx, "firewall-cmd", "--reload"); err != nil {
		return err
	}
	if saved["wasRunning"] != "true" {
		return env.run(ctx, "systemctl", "disable", "--now", "firewalld")
	}
	return nil
}
