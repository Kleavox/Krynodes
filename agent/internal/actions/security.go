package actions

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/recipes"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

var applyUpdates = regexp.MustCompile(`(?m)^\s*apply_updates\s*=\s*(yes|true|1)\s*$`)

const (
	checkEvery  = 6 * time.Hour
	staleReboot = 7 * 24 * time.Hour
	eolWarning  = 90 * 24 * time.Hour
)

type securityState struct {
	CheckedAt time.Time          `json:"checkedAt"`
	Findings  []reporter.Finding `json:"findings"`
}

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
		state = securityState{CheckedAt: e.Now(), Findings: e.findings(ctx)}
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
	return report
}

func (e Executor) findings(ctx context.Context) []reporter.Finding {
	found := []reporter.Finding{}
	add := func(id, severity, detail string) {
		if len(detail) > 300 {
			detail = detail[:297] + "..."
		}
		found = append(found, reporter.Finding{ID: id, Severity: severity, Detail: detail})
	}
	settings, sshd := e.sshSettings(ctx)
	if sshd {
		if settings["passwordauthentication"] == "yes" || settings["kbdinteractiveauthentication"] == "yes" {
			add("ssh-password", "serious", "SSH accepts passwords")
		}
		if settings["permitrootlogin"] == "yes" {
			add("ssh-root", "serious", "Root can log in over SSH with a password")
		}
	}
	if users := recipes.KeyedUsers(recipes.Env{Root: e.Root}); len(users) == 0 {
		add("ssh-no-keys", "warning", "No SSH key is set up for root or a sudo user")
	} else {
		add("ssh-keys", "note", "SSH keys for "+strings.Join(users, ", "))
	}
	platform := recipes.Detect(e.recipeEnv())
	if date := platform.EndOfLife; !date.IsZero() {
		switch {
		case e.Now().After(date):
			add("os-eol", "serious", fmt.Sprintf("%s no longer gets security updates (since %s)", platform.Name, date.Format("2 Jan 2006")))
		case date.Sub(e.Now()) <= eolWarning:
			add("os-eol", "warning", fmt.Sprintf("%s stops getting security updates on %s", platform.Name, date.Format("2 Jan 2006")))
		}
	}
	if sentence := platform.Unverified(); sentence != "" {
		add("os-unverified", "note", sentence)
	}
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
	public, stub := e.publicListeners(ctx, settings)
	public = append(public, e.publicContainers(ctx)...)
	if len(public) > 0 {
		add("public-ports", "warning", "Listening on public addresses outside Krynodes: "+strings.Join(public, ", "))
	}
	ufw, _ := e.output(ctx, "ufw", "status")
	firewall := strings.Contains(ufw, "Status: active")
	tool := "ufw"
	if platform.Family == recipes.RHEL {
		state, _ := e.output(ctx, "firewall-cmd", "--state")
		firewall = firewall || strings.TrimSpace(state) == "running"
		tool = "firewalld"
	}
	if !firewall {
		add("firewall-off", "note", "No firewall is active ("+tool+")")
	}
	if _, ok := e.output(ctx, "systemctl", "is-active", "--quiet", "fail2ban"); !ok {
		add("fail2ban-off", "note", "Repeated SSH login failures are not blocked")
	}
	if stub {
		add("dns-stub", "note", "systemd-resolved holds port 53 on this server")
	}
	return found
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
	if !ok || !strings.Contains(status, "install ok installed") {
		return false
	}
	entries, err := os.ReadDir(e.path("/etc/apt/apt.conf.d"))
	if err != nil {
		return false
	}
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(e.path("/etc/apt/apt.conf.d"), entry.Name()))
		if err == nil && strings.Contains(string(body), `APT::Periodic::Unattended-Upgrade "1"`) {
			return true
		}
	}
	return false
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
	report := &reporter.Platform{Name: platform.Name, Verified: platform.Verified, Checked: platform.Checked}
	if platform.Family != "" {
		family := string(platform.Family)
		report.Family = &family
	}
	return report
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

func (e Executor) publicListeners(ctx context.Context, settings map[string]string) ([]string, bool) {
	output, ok := e.output(ctx, "ss", "-H", "-tulnp")
	if !ok {
		return nil, false
	}
	ssh := strings.Split(settings["ports"], ",")
	if settings["ports"] == "" {
		ssh = []string{"22"}
	}
	var public []string
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
		process := ""
		if len(fields) > 6 {
			if start := strings.Index(fields[6], `(("`); start >= 0 {
				process, _, _ = strings.Cut(fields[6][start+3:], `"`)
			}
		}
		if strings.HasPrefix(host, "127.") || host == "::1" || process == "docker-proxy" || (fields[0] == "tcp" && slices.Contains(ssh, port)) {
			continue
		}
		entry := port + "/" + fields[0]
		if process != "" {
			entry += " (" + process + ")"
		}
		if !slices.Contains(public, entry) {
			public = append(public, entry)
		}
	}
	return public, stub
}

func (e Executor) publicContainers(ctx context.Context) []string {
	output, ok := e.output(ctx, "docker", "ps", "--format", "{{.Names}}\t{{.Ports}}\t{{.Label \"com.docker.compose.project\"}}")
	if !ok {
		return nil
	}
	var public []string
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(fields) < 3 || fields[0] == TunnelContainer || e.fullAccess(fields[2]) {
			continue
		}
		for _, port := range publicPorts(fields[1]) {
			public = append(public, port+" ("+fields[0]+")")
		}
	}
	return public
}
