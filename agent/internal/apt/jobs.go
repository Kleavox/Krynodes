package apt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

type Stream func(ctx context.Context, each func(string), name string, args ...string) error

type Job struct {
	Root     string
	Run      Runner
	Stream   Stream
	Now      func() time.Time
	Step     func(Step)
	Features map[string]string
	Get      func(ctx context.Context, url string) ([]byte, error)
}

type Move struct {
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`
}

type Outcome struct {
	Upgraded  []string            `json:"upgraded"`
	Moved     []Move              `json:"moved"`
	Added     []string            `json:"added"`
	Removed   []string            `json:"removed"`
	Took      int                 `json:"took"`
	Waited    int                 `json:"waited"`
	Holder    string              `json:"holder,omitempty"`
	Repaired  bool                `json:"repaired"`
	Kept      []string            `json:"kept"`
	Left      []string            `json:"left,omitempty"`
	Failed    string              `json:"failed,omitempty"`
	Tail      []string            `json:"tail,omitempty"`
	Restarted []string            `json:"restarted,omitempty"`
	Stacks    []StackState        `json:"stacks,omitempty"`
	Old       []string            `json:"old,omitempty"`
	Listeners []reporter.Listener `json:"listeners,omitempty"`
}

type StackState struct {
	Project string `json:"project"`
	Running int    `json:"running"`
	Total   int    `json:"total"`
}

var quiet = []string{
	"DEBIAN_FRONTEND=noninteractive", "LC_ALL=C", "apt-get", "-y", "-q",
	"-o", "DPkg::Lock::Timeout=300", "-o", "APT::Status-Fd=1",
	"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold",
}

func present(root string) map[string]string {
	raw, _ := os.ReadFile(at(root, "/var/lib/dpkg/status"))
	found := map[string]string{}
	for _, stanza := range stanzas(string(raw)) {
		state := strings.Fields(stanza["status"])
		if len(state) == 3 && state[2] != "not-installed" && state[2] != "config-files" && stanza["package"] != "" {
			found[stanza["package"]] = stanza["version"]
		}
	}
	return found
}

func Version(root, name string) string {
	return present(root)[name]
}

func (j Job) Removable(removes []string) error {
	raw, _ := os.ReadFile(at(j.Root, "/var/lib/dpkg/status"))
	marked := map[string]Package{}
	for _, pkg := range ParseStatus(string(raw)) {
		marked[pkg.Name] = pkg
	}
	running := ""
	if body, err := os.ReadFile(at(j.Root, "/proc/sys/kernel/osrelease")); err == nil {
		running = strings.TrimSpace(string(body))
	}
	for _, name := range removes {
		switch {
		case name == "openssh-server":
			return errors.New("openssh-server is never removed; it is how you reach this server")
		case running != "" && (name == "linux-image-"+running || name == "linux-image-unsigned-"+running):
			return fmt.Errorf("%s is the kernel this server runs", name)
		case marked[name].Essential:
			return fmt.Errorf("%s is essential to the system", name)
		case marked[name].Protected:
			return fmt.Errorf("%s is protected by the system", name)
		case j.Features[name] != "":
			return fmt.Errorf("%s came with %s; turn that off to remove it", name, j.Features[name])
		}
	}
	return nil
}

func (j Job) repair(ctx context.Context, outcome *Outcome) error {
	audit, _, err := j.Run(ctx, "dpkg", "--audit")
	if err == nil && strings.TrimSpace(string(audit)) == "" {
		return nil
	}
	if text, _, err := j.Run(ctx, "env", "DEBIAN_FRONTEND=noninteractive", "dpkg", "--force-confdef", "--force-confold", "--configure", "-a"); err != nil {
		return fmt.Errorf("apt was cut off before and repairing it failed: %s", last(string(text), err))
	}
	outcome.Repaired = true
	return nil
}

func last(text string, err error) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	for _, line := range slices.Backward(lines) {
		if found, ok := strings.CutPrefix(strings.TrimSpace(line), "E: "); ok {
			return found
		}
	}
	if lines[len(lines)-1] != "" {
		return strings.TrimSpace(lines[len(lines)-1])
	}
	return err.Error()
}

func (j Job) apt(ctx context.Context, outcome *Outcome, args ...string) error {
	total := 0
	var waitedFrom time.Time
	var output []string
	conffile := ""
	err := j.Stream(ctx, func(line string) {
		if holder, waiting := LockHolder(line); waiting {
			if waitedFrom.IsZero() {
				waitedFrom = j.Now()
				outcome.Holder = holder
				j.Step(Step{Total: total, Line: "waiting for " + holder})
			}
			return
		}
		if !waitedFrom.IsZero() {
			outcome.Waited += int(j.Now().Sub(waitedFrom).Round(time.Second) / time.Second)
			waitedFrom = time.Time{}
		}
		if count, ok := planned(line); ok {
			total = count
		}
		if step, ok := ParseStatusFd(line, total); ok {
			j.Step(step)
			return
		}
		if path, ok := strings.CutPrefix(line, "Configuration file '"); ok {
			conffile = strings.TrimSuffix(path, "'")
		} else if strings.TrimSpace(line) == "==> Keeping old config file as default." && conffile != "" && !slices.Contains(outcome.Kept, conffile) {
			outcome.Kept = append(outcome.Kept, conffile)
		}
		output = append(output, line)
		if len(output) > 50 {
			output = output[1:]
		}
	}, "env", append(slices.Clone(quiet), args...)...)
	if !waitedFrom.IsZero() {
		outcome.Waited += int(j.Now().Sub(waitedFrom).Round(time.Second) / time.Second)
	}
	if err != nil {
		outcome.Failed = last(strings.Join(output, "\n"), err)
		outcome.Tail = output
	}
	return err
}

func diff(outcome *Outcome, before, after map[string]string) {
	for name, version := range after {
		was, had := before[name]
		switch {
		case !had:
			outcome.Added = append(outcome.Added, name)
		case was != version:
			outcome.Upgraded = append(outcome.Upgraded, name)
			outcome.Moved = append(outcome.Moved, Move{Name: name, From: was, To: version})
		}
	}
	for name := range before {
		if _, kept := after[name]; !kept {
			outcome.Removed = append(outcome.Removed, name)
		}
	}
	slices.Sort(outcome.Added)
	slices.Sort(outcome.Upgraded)
	slices.SortFunc(outcome.Moved, func(a, b Move) int { return strings.Compare(a.Name, b.Name) })
	slices.Sort(outcome.Removed)
}

func (j Job) change(ctx context.Context, check func() error, args ...string) (Outcome, error) {
	started := j.Now()
	outcome := Outcome{Upgraded: []string{}, Moved: []Move{}, Added: []string{}, Removed: []string{}, Kept: []string{}}
	done := func(err error) (Outcome, error) {
		outcome.Took = int(j.Now().Sub(started).Round(time.Second) / time.Second)
		return outcome, err
	}
	if err := j.repair(ctx, &outcome); err != nil {
		outcome.Failed = err.Error()
		return done(err)
	}
	if check != nil {
		if err := check(); err != nil {
			return done(err)
		}
	}
	before := present(j.Root)
	err := j.apt(ctx, &outcome, args...)
	after := present(j.Root)
	diff(&outcome, before, after)
	if err != nil && args[0] == "install" && len(outcome.Added) > 0 {
		added := slices.Clone(outcome.Added)
		var ignored Outcome
		j.apt(ctx, &ignored, append([]string{"remove"}, added...)...)
		now := present(j.Root)
		outcome.Left = slices.DeleteFunc(added, func(name string) bool { _, still := now[name]; return !still })
	}
	return done(err)
}

func (j Job) tried(ctx context.Context, args ...string) Simulation {
	simulation, _ := simulate(ctx, j.Run, args...)
	return simulation
}

func (j Job) Install(ctx context.Context, name string) (Outcome, error) {
	return j.change(ctx, func() error { return j.Removable(j.tried(ctx, "install", name).Removes) }, "install", name)
}

func (j Job) Upgrade(ctx context.Context) (Outcome, error) {
	return j.change(ctx, nil, "--with-new-pkgs", "upgrade")
}

func (j Job) Remove(ctx context.Context, name string, purge bool) (Outcome, error) {
	verb := "remove"
	if purge {
		verb = "purge"
	}
	return j.change(ctx, func() error {
		return j.Removable(append([]string{name}, j.tried(ctx, verb, name).Removes...))
	}, verb, name)
}
