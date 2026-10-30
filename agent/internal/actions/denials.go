package actions

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/confine"
	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/recipes"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const (
	denialsFile    = "denials.json"
	acceptedFile   = "confinement-accepted.json"
	denialLines    = 20
	freshStart     = 10 * time.Minute
	packageWindow  = 2 * time.Minute
	bootSettle     = 2 * time.Minute
	journalCursor  = "-- cursor: "
	stopVerdict    = "stop"
	strongVerdict  = "strong"
	warningVerdict = "warning"
)

var (
	packageTools   = []string{"rpm", "dnf", "yum", "dnf-automatic", "apt", "apt-get", "aptitude", "dpkg", "unattended-upgr"}
	packageTypes   = []string{"rpm_t", "rpm_script_t", "dpkg_t", "dpkg_script_t", "apt_t"}
	snapTools      = []string{"snap", "snapd", "snap-confine", "snap-update-ns", "snap-exec", "snap-seccomp"}
	packageFiles   = []string{"/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages", "/var/lib/dpkg/status"}
	containerTypes = []string{"container_t", "container_init_t", "svirt_lxc_net_t"}
	containerID    = regexp.MustCompile(`[0-9a-f]{64}`)
)

type denialState struct {
	Cursor   confine.Cursor        `json:"cursor"`
	Journal  string                `json:"journal,omitempty"`
	Since    int64                 `json:"since,omitempty"`
	Readable bool                  `json:"readable"`
	Hours    map[string]int        `json:"hours"`
	Lines    []reporter.DenialLine `json:"lines"`
	Managed  bool                  `json:"managed"`
	Auditd   bool                  `json:"auditd"`
	Modules  []string              `json:"modules"`
	Profiles []string              `json:"profiles"`
}

type acceptedPrograms struct {
	Items []string `json:"items"`
}

func (s denialState) count(now time.Time) int {
	total := 0
	for hour, count := range s.Hours {
		if at, err := strconv.ParseInt(hour, 10, 64); err == nil && now.Unix()/3600-at < 24 {
			total += count
		}
	}
	return total
}

func readDenials(stateDir string, now time.Time) *reporter.Denials {
	state, err := readState[denialState](stateDir, denialsFile)
	if err != nil || !state.Readable {
		return nil
	}
	return &reporter.Denials{Count: state.count(now), Lines: append([]reporter.DenialLine{}, state.Lines...)}
}

func (e Executor) bootTime() time.Time {
	body, _ := os.ReadFile(e.path("/proc/stat"))
	for line := range strings.SplitSeq(string(body), "\n") {
		if value, ok := strings.CutPrefix(line, "btime "); ok {
			if seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
				return time.Unix(seconds, 0)
			}
		}
	}
	return time.Time{}
}

func (e Executor) packagesBusy(now time.Time) bool {
	for _, file := range packageFiles {
		if info, err := os.Stat(e.path(file)); err == nil && now.Sub(info.ModTime()) < packageWindow {
			return true
		}
	}
	entries, _ := os.ReadDir(e.path("/proc"))
	return slices.ContainsFunc(entries, func(entry os.DirEntry) bool {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			return false
		}
		comm, _ := os.ReadFile(filepath.Join(e.path("/proc"), entry.Name(), "comm"))
		return slices.Contains(packageTools, strings.TrimSpace(string(comm)))
	})
}

func (e Executor) newDenials(ctx context.Context, state *denialState, auditd bool, now time.Time) (string, bool) {
	if auditd {
		text, err := confine.ReadNew(e.Root, &state.Cursor)
		return text, err == nil
	}
	if state.Journal == "" && state.Since == 0 {
		state.Since = now.Unix()
		return "", true
	}
	args := []string{"-k", "-o", "short-unix", "--no-pager", "-q", "--show-cursor"}
	if state.Journal != "" {
		args = append(args, "--after-cursor="+state.Journal)
	} else {
		args = append(args, "--since=@"+strconv.FormatInt(state.Since, 10))
	}
	output, ok := e.output(ctx, "journalctl", args...)
	if at := strings.LastIndex(output, journalCursor); at >= 0 {
		state.Journal = strings.TrimSpace(output[at+len(journalCursor):])
		output = output[:at]
	}
	return output, ok
}

func (e Executor) localModules(ctx context.Context) []string {
	output, _ := e.output(ctx, "semodule", "--list-modules=full")
	modules := []string{}
	for line := range strings.SplitSeq(output, "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "400" {
			modules = append(modules, fields[1])
		}
	}
	slices.Sort(modules)
	return modules
}

func enforcedPaths(profiles map[string]string) []string {
	paths := []string{}
	for name, mode := range profiles {
		if mode == "enforce" && strings.HasPrefix(name, "/") {
			paths = append(paths, name)
		}
	}
	slices.Sort(paths)
	return paths
}

func (e Executor) containerOfPid(pid int) string {
	body, err := os.ReadFile(e.path("/proc/" + strconv.Itoa(pid) + "/cgroup"))
	if err != nil || pid <= 0 {
		return ""
	}
	return containerID.FindString(string(body))
}

func (e Executor) startedWithin(ctx context.Context, project string, window time.Duration) bool {
	ids, _ := e.output(ctx, "docker", "ps", "-q", "--filter", "label=com.docker.compose.project="+project)
	if len(strings.Fields(ids)) == 0 {
		return false
	}
	started, _ := e.output(ctx, "docker", append([]string{"inspect", "--format", "{{.State.StartedAt}}"}, strings.Fields(ids)...)...)
	return slices.ContainsFunc(strings.Fields(started), func(value string) bool {
		at, err := time.Parse(time.RFC3339Nano, value)
		return err == nil && e.Now().Sub(at) < window
	})
}

func (e Executor) verdict(ctx context.Context, denial confine.Denial, levels map[string]string, memo map[string][2]string) (string, string) {
	key, id := "", ""
	switch {
	case denial.System == confine.SELinux && slices.Contains(containerTypes, denial.Type):
		key = "level " + denial.Level
	case denial.System == confine.AppArmor && strings.HasPrefix(denial.Type, "docker-"):
		if id = e.containerOfPid(denial.Pid); id == "" {
			return "", warningVerdict
		}
		key = "container " + id
	default:
		return "", warningVerdict
	}
	if seen, ok := memo[key]; ok {
		return seen[0], seen[1]
	}
	project := levels[denial.Level]
	if id != "" {
		label, _ := e.output(ctx, "docker", "inspect", "--format", `{{index .Config.Labels "com.docker.compose.project"}}`, id)
		project = strings.TrimSpace(label)
	}
	verdict, access := strongVerdict, ""
	if project != "" && ValidTarget("compose", project) {
		access = e.accessOf(filepath.Join(e.StateDir, "compose", project))
	}
	switch access {
	case "contained":
		verdict = stopVerdict
	case "full":
		if e.startedWithin(ctx, project, freshStart) {
			verdict = stopVerdict
		}
	default:
		project = ""
	}
	memo[key] = [2]string{project, verdict}
	return project, verdict
}

func (e Executor) confinementStop(ctx context.Context, project string, denial confine.Denial, hour string) {
	if e.knocked(project) {
		return
	}
	stopped := e.stopKnocking(ctx, network.Scan{Who: project, Count: 1, Sample: []string{denial.Wanted}}) == nil
	e.event("stack", "stack:"+shortHash(project, "confinement")+":"+hour, map[string]string{"stack": project, "count": "1", "tried": denial.Wanted, "stopped": strconv.FormatBool(stopped), "why": "confinement", "program": denial.Program, "wanted": denial.Wanted})
}

func (e Executor) watchDenials(ctx context.Context) {
	found := confine.Read(e.Root, string(recipes.Detect(e.recipeEnv()).Family))
	if found.System == "" {
		return
	}
	state, err := readState[denialState](e.StateDir, denialsFile)
	if err != nil {
		return
	}
	now := e.Now()
	hour := strconv.FormatInt(now.Unix()/3600, 10)
	applied, managed := e.readRecipes().Applied["confinement"]
	managed = managed && applied.Saved["system"] == found.System
	mark, _ := readState[confinementMarkRecord](e.StateDir, confinementMark)
	marked := now.Before(mark.Until)
	busy := e.packagesBusy(now)
	boot := e.bootTime()
	raise := func(key, what string) {
		e.event("confinement", "confinement:"+shortHash(key)+":"+hour, map[string]string{"strong": "1", "what": what})
	}
	excused := func(at time.Time) bool {
		return at.Before(applied.At) || !at.Before(mark.From) && at.Before(mark.Until)
	}
	settled := func(at time.Time) bool { return !at.Before(boot.Add(bootSettle)) && !excused(at) }

	active, _ := e.output(ctx, "systemctl", "is-active", "auditd")
	auditd := !slices.Contains([]string{"", "inactive", "failed", "unknown"}, strings.TrimSpace(active))
	if managed && found.System == confine.SELinux && state.Auditd && !auditd && !marked && !busy {
		if running, _ := e.output(ctx, "systemctl", "is-system-running"); strings.TrimSpace(running) != "stopping" {
			raise("auditd", "The audit service stopped while Krynodes manages SELinux")
		}
	}
	state.Auditd = auditd
	text, readable := e.newDenials(ctx, &state, auditd, now)
	state.Readable = readable

	baseline := managed && (!state.Managed || marked)
	if !managed {
		state.Modules, state.Profiles = nil, nil
	} else if baseline && found.System == confine.SELinux {
		state.Modules = e.localModules(ctx)
	}
	state.Managed = managed
	restart := found.Restart || (applied.Saved["restart"] == "1" && found.Mode == confine.KernelOff)
	if managed && !marked && !restart {
		switch {
		case found.System == confine.SELinux && found.Mode != confine.Enforcing:
			raise("mode", "SELinux was set to "+found.Mode+" outside Krynodes")
		case found.System == confine.AppArmor && found.Mode != confine.On:
			raise("mode", "AppArmor was turned off outside Krynodes")
		}
	}
	if managed && found.System == confine.AppArmor {
		profiles := confine.Profiles(e.Root)
		for _, name := range state.Profiles {
			mode, loaded := profiles[name]
			switch {
			case baseline || busy:
			case loaded && mode != "enforce":
				raise(name, "AppArmor profile "+name+" was moved to "+mode)
			case !loaded && regularFile(e.path(name)):
				raise(name, "AppArmor profile "+name+" was unloaded while its program is still installed")
			}
		}
		state.Profiles = enforcedPaths(profiles)
	}

	levels := map[string]string{}
	if labels, _ := readState[labelState](e.StateDir, labelsFile); managed {
		for project, level := range labels.Levels {
			levels[level] = project
		}
	}
	accepted, _ := readState[acceptedPrograms](e.StateDir, acceptedFile)
	if state.Hours == nil {
		state.Hours = map[string]int{}
	}
	policy := false
	memo := map[string][2]string{}
	for _, denial := range confine.Parse(text) {
		switch denial.Kind {
		case confine.Status:
			if managed && denial.Enforcing == "0" && settled(denial.At) {
				raise("mode", "SELinux was set to permissive outside Krynodes")
			}
		case confine.Policy:
			if managed && settled(denial.At) {
				policy = true
				if !busy {
					raise("policy", "A new SELinux policy was loaded outside a package update")
				}
			}
		case confine.Denied:
			state.Hours[strconv.FormatInt(denial.At.Unix()/3600, 10)]++
			project, verdict := "", ""
			if managed && !busy && !excused(denial.At) && !denial.At.Before(boot) && !slices.Contains(packageTools, denial.Program) && !slices.Contains(snapTools, denial.Program) && !slices.Contains(packageTypes, denial.Type) {
				project, verdict = e.verdict(ctx, denial, levels, memo)
			}
			state.Lines = append(state.Lines, reporter.DenialLine{At: denial.At.UTC().Format(time.RFC3339), Program: denial.Program, Wanted: denial.Wanted, Stack: project})
			switch item := denial.Program + " " + denial.Type; verdict {
			case stopVerdict:
				e.confinementStop(ctx, project, denial, hour)
			case strongVerdict:
				what := "A container Krynodes did not start was denied " + denial.Wanted + " (" + denial.Program + ")"
				if project != "" {
					what = "Full access stack " + project + " was denied " + denial.Wanted + " (" + denial.Program + ")"
				}
				raise(project+" "+item, what)
			case warningVerdict:
				if !slices.Contains(accepted.Items, item) {
					e.event("confinement", "confinement:"+shortHash(item)+":"+hour, map[string]string{"system": denial.System, "program": denial.Program, "type": denial.Type, "wanted": denial.Wanted, "item": item})
				}
			}
		}
	}
	if policy {
		modules := e.localModules(ctx)
		if added := slices.DeleteFunc(slices.Clone(modules), func(name string) bool { return slices.Contains(state.Modules, name) }); len(added) > 0 && !marked {
			raise("module "+strings.Join(added, " "), "A local SELinux module or permissive type was added: "+strings.Join(added, ", "))
		}
		state.Modules = modules
	}
	for hour := range maps.Clone(state.Hours) {
		if at, err := strconv.ParseInt(hour, 10, 64); err != nil || now.Unix()/3600-at >= 24 {
			delete(state.Hours, hour)
		}
	}
	state.Lines = slices.DeleteFunc(state.Lines, func(line reporter.DenialLine) bool {
		at, err := time.Parse(time.RFC3339, line.At)
		return err != nil || now.Sub(at) > 24*time.Hour
	})
	if len(state.Lines) > denialLines {
		state.Lines = state.Lines[len(state.Lines)-denialLines:]
	}
	writeJSON(e.StateDir, denialsFile, state, 0o640)
}

func (e Executor) acceptConfinement(request Request, item string) Result {
	accepted, err := readState[acceptedPrograms](e.StateDir, acceptedFile)
	if err != nil {
		return e.failed(request, err, "")
	}
	if len(strings.Fields(item)) != 2 {
		return e.refuse(request.ID, errors.New("a denied program is accepted as its name and type"))
	}
	if slices.Contains(accepted.Items, item) {
		return Result{ID: request.ID, OK: true, Output: "already accepted", FinishedAt: e.stamp()}
	}
	accepted.Items = append(accepted.Items, item)
	if err := writeJSON(e.StateDir, acceptedFile, accepted, 0o640); err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: "accepted: it no longer warns", FinishedAt: e.stamp()}
}
