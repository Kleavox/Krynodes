package actions

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

const knockedDir = "knocked"

type knockedStack struct {
	At      time.Time         `json:"at"`
	Count   int               `json:"count"`
	Tried   []string          `json:"tried"`
	Restart map[string]string `json:"restart"`
}

func (e Executor) knocked(project string) bool {
	_, err := os.Stat(filepath.Join(e.StateDir, knockedDir, project+".json"))
	return err == nil
}

func (e Executor) watchKnocks(ctx context.Context) {
	record := e.readNetwork()
	if !record.Joined || record.Document == nil {
		return
	}
	settings := network.Effective(*record.Document, record.Tightened)
	now := e.Now()
	journal, _ := e.output(ctx, "journalctl", "-k", "--since=@"+strconv.FormatInt(now.Add(-network.KnockWindow).Unix(), 10), "-o", "short-unix", "--no-pager", "-q")
	bridges := map[string]string{}
	for _, stack := range e.diskRules(nil) {
		for _, bridge := range stack.Bridges {
			bridges[bridge] = stack.Project
		}
	}
	seen := network.Scans(network.ParseKnocks(journal), now, settings.Scan, bridges)
	minute, hour := strconv.FormatInt(now.Unix()/60, 10), strconv.FormatInt(now.Unix()/3600, 10)
	dropped := false
	for _, scan := range seen.Sources {
		if slices.Contains(record.Dropped, scan.Who) {
			continue
		}
		record.Dropped, dropped = append(record.Dropped, scan.Who), true
		e.event("knock", "knock:"+scan.Who+":"+minute, map[string]string{"from": scan.Who, "count": strconv.Itoa(scan.Count), "sample": strings.Join(scan.Sample, " ")})
	}
	if dropped && e.saveNetwork(record) == nil {
		e.syncRules(ctx)
	}
	for _, scan := range seen.Stacks {
		if e.knocked(scan.Who) {
			continue
		}
		stopped := settings.Stop && e.stopKnocking(ctx, scan) == nil
		e.event("stack", "stack:"+scan.Who+":"+hour, map[string]string{"stack": scan.Who, "count": strconv.Itoa(scan.Count), "tried": strings.Join(scan.Sample, " "), "stopped": strconv.FormatBool(stopped)})
	}
	for _, wrong := range seen.Wrong {
		e.event("wrong-port", "wrong-port:"+wrong.From+":"+wrong.Target+":"+hour, map[string]string{"from": wrong.From, "target": wrong.Target})
	}
}

func (e Executor) stopKnocking(ctx context.Context, scan network.Scan) error {
	ids, _ := e.output(ctx, "docker", "ps", "-a", "--filter", "label=com.docker.compose.project="+scan.Who, "--format", "{{.ID}}")
	mark := knockedStack{At: e.Now(), Count: scan.Count, Tried: scan.Sample, Restart: map[string]string{}}
	for _, id := range strings.Fields(ids) {
		policy, _ := e.output(ctx, "docker", "inspect", "--format", "{{.HostConfig.RestartPolicy.Name}}", id)
		mark.Restart[id] = strings.TrimSpace(policy)
	}
	if err := writeJSON(filepath.Join(e.StateDir, knockedDir), scan.Who+".json", mark, 0o640); err != nil {
		return err
	}
	if _, err := e.docker(ctx, upTimeout, "stop", "compose", "--project-name", scan.Who, "stop"); err != nil {
		return err
	}
	for _, id := range slices.Sorted(maps.Keys(mark.Restart)) {
		e.docker(ctx, collectTimeout, "restart policy", "update", "--restart", "no", id)
	}
	return nil
}

func (e Executor) unknock(ctx context.Context, project string) {
	mark, err := readState[knockedStack](filepath.Join(e.StateDir, knockedDir), project+".json")
	if err != nil {
		return
	}
	for id, policy := range mark.Restart {
		if policy != "" && policy != "no" {
			e.docker(ctx, collectTimeout, "restart policy", "update", "--restart", policy, id)
		}
	}
	os.Remove(filepath.Join(e.StateDir, knockedDir, project+".json"))
}
