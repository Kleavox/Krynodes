package actions

import (
	"regexp"
	"slices"
	"strings"
)

var targetName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._-]{0,127}$`)

var projectName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

var Recipes = []string{"security-updates", "reboot-window", "ssh-keys-only", "fail2ban", "firewall", "free-port-53"}

const TunnelContainer = "krynodes-tunnel"

var protectedUnits = compile(
	`^ssh\.service$`, `^sshd\.service$`,
	`^krynodes\.service$`, `^krynodes-.+\.service$`,
	`^docker\.service$`, `^containerd\.service$`,
	`^systemd-.+\.service$`, `^dbus\.service$`, `^dbus-broker\.service$`,
	`^networking\.service$`, `^NetworkManager\.service$`,
	`^cloudflared\.service$`, `^cloudflared-.+\.service$`,
	`^getty@.*\.service$`, `^serial-getty@.*\.service$`, `^user@.*\.service$`,
	`^snap\.docker\..+\.service$`,
	`^ufw\.service$`, `^firewalld\.service$`, `^nftables\.service$`,
	`^netfilter-persistent\.service$`, `^iptables\.service$`, `^ip6tables\.service$`,
)

var systemUnits = compile(
	`^cron\.service$`, `^rsyslog\.service$`, `^polkit\.service$`, `^udisks2\.service$`,
	`^snapd.*\.service$`, `^cloud-.+\.service$`, `^unattended-upgrades\.service$`,
	`^apparmor\.service$`, `^ufw\.service$`, `^multipathd\.service$`, `^irqbalance\.service$`,
	`^ModemManager\.service$`, `^accounts-daemon\.service$`, `^packagekit\.service$`,
	`^fwupd\.service$`, `^qemu-guest-agent\.service$`, `^chrony\.service$`, `^ntp\.service$`,
	`^atd\.service$`, `^lvm2-.+\.service$`, `^rpcbind\.service$`,
)

func compile(patterns ...string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, len(patterns))
	for index, pattern := range patterns {
		compiled[index] = regexp.MustCompile(pattern)
	}
	return compiled
}

func matchesAny(patterns []*regexp.Regexp, name string) bool {
	for _, pattern := range patterns {
		if pattern.MatchString(name) {
			return true
		}
	}
	return false
}

func ValidTarget(kind, name string) bool {
	switch kind {
	case "compose":
		return projectName.MatchString(name)
	case "trust":
		return name == "devices"
	case "host":
		return name == "server" || name == "docker" || slices.Contains(Recipes, name)
	case "vault":
		return name == "cloudflare"
	}
	if !targetName.MatchString(name) {
		return false
	}
	switch kind {
	case "systemd":
		return strings.HasSuffix(name, ".service")
	case "docker":
		return true
	}
	return false
}

func Protected(kind, name string) bool {
	if kind == "docker" {
		return name == TunnelContainer
	}
	return kind == "systemd" && matchesAny(protectedUnits, name)
}

func systemUnit(name string) bool {
	return matchesAny(systemUnits, name)
}
