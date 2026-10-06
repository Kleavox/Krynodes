package recipes

import (
	"context"
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

func rhelUpdates(ctx context.Context, env Env) (map[string]string, error) {
	files := []struct{ path, body string }{
		{updatesService, "[Unit]\nDescription=Krynodes security updates\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/dnf -y upgrade --security\n"},
		{updatesTimer, "[Unit]\nDescription=Krynodes security updates\n\n[Timer]\nOnCalendar=daily\nRandomizedDelaySec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"},
	}
	for _, file := range files {
		if err := env.write(file.path, file.body, 0o644); err != nil {
			return nil, err
		}
	}
	if err := env.run(ctx, "systemctl", "daemon-reload"); err != nil {
		return nil, err
	}
	return nil, env.run(ctx, "systemctl", "enable", "--now", updatesUnit)
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
	case "fedora":
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
	if !running {
		if err := env.run(ctx, "systemctl", "enable", "--now", "firewalld"); err != nil {
			return nil, err
		}
	}
	ports := sshPorts(ctx, env)
	for _, port := range extra {
		if !slices.Contains(ports, port) {
			ports = append(ports, port)
		}
	}
	var added []string
	for _, port := range ports {
		if _, err := env.output(ctx, "firewall-cmd", "--permanent", "--query-port="+port); err == nil {
			continue
		}
		if err := env.run(ctx, "firewall-cmd", "--permanent", "--add-port="+port); err != nil {
			return nil, err
		}
		added = append(added, port)
	}
	if err := env.run(ctx, "firewall-cmd", "--reload"); err != nil {
		return nil, err
	}
	saved["ports"] = strings.Join(added, ",")
	saved["wasRunning"] = fmt.Sprint(running)
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
