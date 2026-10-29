package actions

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Kleavox/krynodes/agent/internal/recipes"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

var (
	applyUpdates = regexp.MustCompile(`(?m)^\s*apply_updates\s*=\s*(yes|true|1)\s*$`)
	ufwEnabled   = regexp.MustCompile(`(?m)^\s*ENABLED\s*=\s*"?yes"?\s*$`)
)

const (
	checkEvery  = 6 * time.Hour
	staleReboot = 7 * 24 * time.Hour
)

type securityState struct {
	CheckedAt time.Time           `json:"checkedAt"`
	Findings  []reporter.Finding  `json:"findings"`
	Listeners []reporter.Listener `json:"listeners,omitempty"`
}

const maxListeners = 100

func (e Executor) path(name string) string {
	return filepath.Join(e.Root, filepath.FromSlash(name))
}

func (e Executor) output(ctx context.Context, name string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()
	output, _, err := e.Run(ctx, name, args...)
	return string(output), err == nil
}

func (e Executor) security(ctx context.Context, force bool) *reporter.SecurityReport {
	state, _ := readState[securityState](e.StateDir, "security.json")
	if force || state.CheckedAt.IsZero() || e.Now().Sub(state.CheckedAt) >= checkEvery {
		found, listeners := e.findings(ctx)
		state = securityState{CheckedAt: e.Now(), Findings: found, Listeners: listeners}
		if err := writeJSON(e.StateDir, "security.json", state, 0o640); err != nil {
			return nil
		}
	}
	findings := slices.Clone(state.Findings)
	if findings == nil {
		findings = []reporter.Finding{}
	}
	report := &reporter.SecurityReport{CheckedAt: state.CheckedAt.UTC().Format(time.RFC3339Nano), Recipes: e.appliedRecipes(), Platform: platformReport(recipes.Detect(e.recipeEnv()))}
	if _, err := os.Stat(filepath.Join(e.StateDir, "lockdown.json")); err == nil {
		report.Lockdown = true
		findings = append(findings, reporter.Finding{ID: "lockdown", Severity: "warning", Detail: "This server is locked down"})
	}
	if window, _ := readState[rebootWindow](e.StateDir, "reboot.json"); window.Hour != nil {
		report.RebootHour = window.Hour
	}
	report.Findings = findings
	report.Listeners = state.Listeners
	return report
}

func (e Executor) findings(ctx context.Context) ([]reporter.Finding, []reporter.Listener) {
	found := []reporter.Finding{}
	add := func(id, severity, detail string) {
		if len(detail) > 300 {
			detail = detail[:297] + "..."
		}
		found = append(found, reporter.Finding{ID: id, Severity: severity, Detail: detail})
	}
	settings, sshd := e.sshSettings(ctx)
	if sshd {
		passwords := settings["passwordauthentication"] == "yes" || settings["kbdinteractiveauthentication"] == "yes"
		if passwords {
			add("ssh-password", "serious", "SSH accepts passwords")
		}
		if passwords && settings["permitrootlogin"] == "yes" {
			add("ssh-root", "serious", "Root can log in over SSH with a password")
		}
		if settings["permitrootlogin"] != "no" {
			add("root-login", "note", "Root can log in over SSH.")
		}
	}
	if users := recipes.SSHLogins(ctx, e.recipeEnv()); len(users) == 0 {
		add("ssh-no-keys", "warning", "No SSH key lets root or a sudo user log in")
	} else {
		add("ssh-keys", "note", "SSH keys for "+strings.Join(users, ", "))
	}
	platform := recipes.Detect(e.recipeEnv())
	if !e.automaticUpdates(ctx, platform.Family) {
		add("updates-off", "warning", "Security updates are not installed automatically")
	}
	if waiting := e.securityUpdates(ctx, platform.Family); waiting == 1 {
		add("updates-pending", "warning", "1 security update is waiting")
	} else if waiting > 1 {
		add("updates-pending", "warning", fmt.Sprintf("%d security updates are waiting", waiting))
	}
	if needed, since := recipes.RebootNeeded(ctx, e.recipeEnv()); needed {
		switch {
		case since.IsZero():
			add("reboot-pending", "note", "A restart is waiting")
		case e.Now().Sub(since) >= staleReboot:
			add("reboot-pending", "warning", "A restart has been waiting since "+since.UTC().Format("2 Jan"))
		default:
			add("reboot-pending", "note", "A restart has been waiting since "+since.UTC().Format("2 Jan"))
		}
	}
	if risky := e.riskyContainers(ctx); len(risky) > 0 {
		add("risky-container", "serious", "Containers with full control of the server: "+strings.Join(risky, ", "))
	}
	listeners, stub := e.publicListeners(ctx, settings)
	firewall := e.firewallOf(ctx, platform.Family)
	listeners = e.throughFirewall(ctx, firewall, listeners)
	listeners = append(listeners, e.publicContainers(ctx)...)
	if public := listenerEntries(listeners); len(public) > 0 {
		add("public-ports", "warning", "Listening on public addresses outside Krynodes: "+strings.Join(public, ", "))
	}
	if len(listeners) > maxListeners {
		listeners = listeners[:maxListeners]
	}
	if !firewall.active {
		add("firewall-off", "note", "No firewall is active ("+firewall.tool+")")
	}
	if _, ok := e.output(ctx, "systemctl", "is-active", "--quiet", "fail2ban"); !ok {
		add("fail2ban-off", "note", "Repeated SSH login failures are not blocked")
	}
	if stub {
		add("dns-stub", "note", "systemd-resolved holds port 53 on this server")
	}
	if synced, _ := e.output(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value"); strings.TrimSpace(synced) == "no" {
		add("clock-unsynced", "warning", "The clock is not synchronized with a time server; signed actions can be refused")
	}
	return found, listeners
}

func (e Executor) sshSettings(ctx context.Context) (map[string]string, bool) {
	output, ok := e.output(ctx, "sshd", "-T")
	if !ok {
		return nil, false
	}
	settings := map[string]string{}
	ports := []string{}
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(strings.ToLower(line))
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "port" {
			ports = append(ports, fields[1])
		} else if _, seen := settings[fields[0]]; !seen {
			settings[fields[0]] = fields[1]
		}
	}
	settings["ports"] = strings.Join(ports, ",")
	return settings, true
}

func (e Executor) recipeEnv() recipes.Env {
	return recipes.Env{Root: e.Root, Run: recipes.Runner(e.Run), Fetch: e.Fetch}
}

func (e Executor) automaticUpdates(ctx context.Context, family recipes.Family) bool {
	if family == recipes.RHEL {
		for _, timer := range []string{"krynodes-security-updates.timer", "dnf-automatic-install.timer"} {
			if _, ok := e.output(ctx, "systemctl", "is-enabled", "--quiet", timer); ok {
				return true
			}
		}
		_, classic := e.output(ctx, "systemctl", "is-enabled", "--quiet", "dnf-automatic.timer")
		_, five := e.output(ctx, "systemctl", "is-enabled", "--quiet", "dnf5-automatic.timer")
		config, _ := os.ReadFile(e.path("/etc/dnf/automatic.conf"))
		return (classic || five) && applyUpdates.Match(config)
	}
	status, ok := e.output(ctx, "dpkg-query", "-W", "-f", "${Status}", "unattended-upgrades")
	return ok && strings.Contains(status, "install ok installed") && recipes.UnattendedOn(ctx, e.recipeEnv()) == nil
}

func (e Executor) securityUpdates(ctx context.Context, family recipes.Family) int {
	if family == recipes.RHEL {
		output, ok := e.output(ctx, "dnf", "-q", "updateinfo", "list", "--security", "--cacheonly")
		if !ok {
			return 0
		}
		count := 0
		for line := range strings.SplitSeq(output, "\n") {
			if strings.TrimSpace(line) != "" {
				count++
			}
		}
		return count
	}
	output, ok := e.output(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=1", "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=", "upgrade")
	if !ok {
		return 0
	}
	count := 0
	for line := range strings.SplitSeq(output, "\n") {
		if strings.HasPrefix(line, "Inst ") && strings.Contains(strings.ToLower(line), "security") {
			count++
		}
	}
	return count
}

func platformReport(platform recipes.Platform) *reporter.Platform {
	report := &reporter.Platform{Name: clip(platform.Name, 120), ID: clip(platform.ID, 40), Version: clip(platform.Version, 40)}
	if platform.Family != "" {
		family := string(platform.Family)
		report.Family = &family
	}
	return report
}

func clip(text string, limit int) string {
	for len(text) > limit {
		_, size := utf8.DecodeLastRuneInString(text)
		text = text[:len(text)-size]
	}
	return text
}

func (e Executor) fullAccess(project string) bool {
	return project != "" && ValidTarget("compose", project) && e.accessOf(filepath.Join(e.StateDir, "compose", project)) == "full"
}

func (e Executor) riskyContainers(ctx context.Context) []string {
	ids, ok := e.output(ctx, "docker", "ps", "-q")
	if !ok || strings.TrimSpace(ids) == "" {
		return nil
	}
	output, ok := e.output(ctx, "docker", append([]string{"inspect", "--format", "{{.Name}}\t{{.HostConfig.Privileged}}\t{{range .Mounts}}{{.Source}};{{end}}\t{{index .Config.Labels \"com.docker.compose.project\"}}"}, strings.Fields(ids)...)...)
	if !ok {
		return nil
	}
	var risky []string
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(fields) < 4 || e.fullAccess(fields[3]) {
			continue
		}
		mounts := strings.Split(fields[2], ";")
		if fields[1] == "true" || slices.Contains(mounts, "/var/run/docker.sock") || slices.Contains(mounts, "/run/docker.sock") {
			risky = append(risky, strings.TrimPrefix(fields[0], "/"))
		}
	}
	return risky
}

func listenerEntries(listeners []reporter.Listener) []string {
	var entries []string
	for _, listener := range listeners {
		entry := strconv.Itoa(listener.Port) + "/" + listener.Protocol
		if listener.Process != "" {
			entry += " (" + listener.Process + ")"
		}
		if !slices.Contains(entries, entry) {
			entries = append(entries, entry)
		}
	}
	return entries
}

func addListener(listeners []reporter.Listener, listener reporter.Listener) []reporter.Listener {
	if slices.Contains(listeners, listener) {
		return listeners
	}
	return append(listeners, listener)
}

func (e Executor) publicListeners(ctx context.Context, settings map[string]string) ([]reporter.Listener, bool) {
	output, ok := e.output(ctx, "ss", "-H", "-tulnp")
	if !ok {
		return nil, false
	}
	ssh := strings.Split(settings["ports"], ",")
	if settings["ports"] == "" {
		ssh = []string{"22"}
	}
	document, own := e.ownAddress()
	wireguard := 0
	for _, entry := range document.Members {
		if entry.Address == own {
			wireguard = entry.Port
		}
	}
	probe, _ := readState[probeMark](e.StateDir, probeFile)
	public := []reporter.Listener{}
	stub := false
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		local := fields[4]
		colon := strings.LastIndex(local, ":")
		if colon < 0 {
			continue
		}
		host, port := strings.Trim(local[:colon], "[]"), local[colon+1:]
		if percent := strings.Index(host, "%"); percent >= 0 {
			host = host[:percent]
		}
		if (host == "127.0.0.53" || host == "127.0.0.54") && port == "53" {
			stub = true
		}
		process, pid := "", ""
		if len(fields) > 6 {
			if start := strings.Index(fields[6], `(("`); start >= 0 {
				process, _, _ = strings.Cut(fields[6][start+3:], `"`)
			}
			if _, rest, ok := strings.Cut(fields[6], "pid="); ok {
				pid, _, _ = strings.Cut(rest, ",")
			}
		}
		if strings.HasPrefix(host, "127.") || host == "::1" || process == "docker-proxy" || (fields[0] == "tcp" && slices.Contains(ssh, port)) {
			continue
		}
		number, err := strconv.Atoi(port)
		if err != nil || (fields[0] != "tcp" && fields[0] != "udp") {
			continue
		}
		if fields[0] == "udp" && number == probe.Port && pid == strconv.Itoa(probe.PID) && e.Now().Before(probe.Until) {
			continue
		}
		if fields[0] == "udp" && process == "" && wireguard != 0 && number == wireguard {
			host, process = own, "WireGuard"
		}
		public = addListener(public, reporter.Listener{Address: host, Port: number, Protocol: fields[0], Process: process})
	}
	return public, stub
}

func (e Executor) publicContainers(ctx context.Context) []reporter.Listener {
	output, ok := e.output(ctx, "docker", "ps", "--format", "{{.Names}}\t{{.Ports}}\t{{.Label \"com.docker.compose.project\"}}")
	if !ok {
		return nil
	}
	var public []reporter.Listener
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(fields) < 3 || fields[0] == TunnelContainer {
			continue
		}
		for _, bound := range publicBindings(fields[1]) {
			bound.Process = fields[0]
			public = addListener(public, bound)
		}
	}
	return public
}
