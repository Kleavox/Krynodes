package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"slices"
	"strings"
)

const labelsFile = "labels.json"

type labelState struct {
	Levels map[string]string `json:"levels"`
}

func (e Executor) levelFor(project string) (string, error) {
	state, _ := readState[labelState](e.StateDir, labelsFile)
	if state.Levels == nil {
		state.Levels = map[string]string{}
	}
	if level, ok := state.Levels[project]; ok {
		return level, nil
	}
	used := map[string]bool{}
	for _, level := range state.Levels {
		used[level] = true
	}
	hash := fnv.New32a()
	hash.Write([]byte(project))
	seed := int(hash.Sum32() % (1024 * 1024))
	for step := range 1024 * 1024 {
		first, second := (seed+step)%1024, (seed/1024+step*7)%1024
		if first == second {
			continue
		}
		level := fmt.Sprintf("s0:c%d,c%d", min(first, second), max(first, second))
		if !used[level] {
			state.Levels[project] = level
			return level, writeJSON(e.StateDir, labelsFile, state, 0o640)
		}
	}
	return "", fmt.Errorf("no SELinux level is left for %s", project)
}

func (e Executor) dockerOptions(ctx context.Context) ([]string, bool) {
	output, ok := e.output(ctx, "docker", "info", "--format", "{{json .SecurityOptions}}")
	lines := strings.Fields(output)
	var options []string
	if !ok || len(lines) == 0 || json.Unmarshal([]byte(lines[len(lines)-1]), &options) != nil {
		return nil, false
	}
	return options, true
}

func (e Executor) dockerSELinux(ctx context.Context) bool {
	options, _ := e.dockerOptions(ctx)
	return slices.ContainsFunc(options, func(option string) bool { return strings.HasPrefix(option, "name=selinux") })
}

func needsServer(directory string, service map[string]any) bool {
	if service["privileged"] == true || len(asList(service["devices"])) > 0 || asText(service["pid"]) == "host" || asText(service["network_mode"]) == "host" {
		return true
	}
	return slices.ContainsFunc(asList(service["volumes"]), func(raw any) bool {
		volume := asMap(raw)
		return asText(volume["type"]) == "bind" && !confined(directory, asText(volume["source"]))
	})
}

func addLabels(target, config map[string]any, directory, level string, full bool) {
	into := asMap(target["services"])
	services := asMap(config["services"])
	for _, name := range sortedKeys(services) {
		option := "label=level:" + level
		if full && needsServer(directory, asMap(services[name])) {
			option = "label=disable"
		}
		entry := asMap(into[name])
		if entry == nil {
			entry = map[string]any{}
			into[name] = entry
		}
		entry["security_opt"] = append(asList(entry["security_opt"]), option)
	}
}

func (e Executor) relabelFolder(ctx context.Context, directory, level string) error {
	if output, _, err := e.Run(ctx, "chcon", "-R", "-t", "container_file_t", "-l", level, directory); err != nil {
		return fmt.Errorf("label %s for its containers: %s", directory, strings.TrimSpace(string(output)))
	}
	return nil
}
