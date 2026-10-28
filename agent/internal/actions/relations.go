package actions

import (
	"context"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/cloudflare"
)

func relation(service, project string) string {
	return service + "." + project
}

func networkKeys(service map[string]any) []string {
	switch joined := service["networks"].(type) {
	case map[string]any:
		return sortedKeys(joined)
	case []any:
		keys := make([]string, 0, len(joined))
		for _, key := range joined {
			keys = append(keys, asText(key))
		}
		return keys
	}
	return []string{"default"}
}

func addAlias(target, base map[string]any, service, key, alias string) map[string]any {
	services := asMap(target["services"])
	if services == nil {
		services = map[string]any{}
		target["services"] = services
	}
	entry := asMap(services[service])
	if entry == nil {
		entry = map[string]any{}
		services[service] = entry
	}
	settings := serviceNetwork(entry, key)
	aliases := asList(settings["aliases"])
	if aliases == nil {
		aliases = asList(asMap(asMap(asMap(asMap(base["services"])[service])["networks"])[key])["aliases"])
	}
	if !slices.Contains(aliases, any(alias)) {
		aliases = append(slices.Clone(aliases), alias)
	}
	settings["aliases"] = aliases
	return entry
}

func applyRelations(target, base map[string]any, project string) {
	services := asMap(base["services"])
	for _, name := range sortedKeys(services) {
		service := asMap(services[name])
		if service["network_mode"] != nil {
			continue
		}
		for _, key := range networkKeys(service) {
			addAlias(target, base, name, key, relation(name, project))
		}
	}
}

func namesClash(snapshot Snapshot, project string, names map[string]string) error {
	inStacks := map[string]bool{}
	projects := []string{project}
	for _, stack := range snapshot.Stacks {
		for _, container := range stack.Containers {
			inStacks[container] = true
		}
		projects = append(projects, stack.Project)
	}
	for _, service := range slices.Sorted(maps.Keys(names)) {
		name := names[service]
		for _, owner := range projects {
			if strings.HasSuffix(name, "."+owner) {
				return fmt.Errorf("%s ends in .%s, the name Krynodes gives the services of %s", name, owner, owner)
			}
		}
		for _, stack := range snapshot.Stacks {
			switch {
			case stack.Project == project:
			case slices.Contains(stack.Containers, name):
				return fmt.Errorf("%s is a container of %s on this server", name, stack.Project)
			case slices.Contains(stack.Services, name):
				return fmt.Errorf("%s is a service of %s on this server", name, stack.Project)
			}
		}
		if slices.ContainsFunc(snapshot.Services, func(entry Service) bool {
			return entry.Kind == "docker" && entry.Name == name && !inStacks[name]
		}) {
			return fmt.Errorf("this server already runs a container named %s", name)
		}
	}
	return nil
}

func (e Executor) leftover(ctx context.Context, name string) bool {
	entries, err := os.ReadDir(filepath.Join(e.StateDir, "compose", name))
	if err == nil && len(entries) > 0 {
		return true
	}
	volumes, err := e.docker(ctx, collectTimeout, "list volumes", "volume", "ls", "-q", "--filter", "label=com.docker.compose.project="+name)
	return err == nil && strings.TrimSpace(string(volumes)) != ""
}

func (e Executor) leftovers(ctx context.Context, snapshot Snapshot) []string {
	bin, _ := e.readBin()
	kept := func(name string) bool {
		_, waiting := bin.Stacks[name]
		return projectName.MatchString(name) && !waiting && !slices.ContainsFunc(snapshot.Stacks, func(stack Stack) bool { return stack.Project == name })
	}
	found := []string{}
	folders, _ := os.ReadDir(filepath.Join(e.StateDir, "compose"))
	for _, folder := range folders {
		inside, err := os.ReadDir(filepath.Join(e.StateDir, "compose", folder.Name()))
		if folder.IsDir() && err == nil && len(inside) > 0 && kept(folder.Name()) {
			found = append(found, folder.Name())
		}
	}
	if snapshot.Docker != "missing" {
		labels, err := e.docker(ctx, collectTimeout, "list volumes", "volume", "ls", "--filter", "label=com.docker.compose.project", "--format", `{{.Label "com.docker.compose.project"}}`)
		if err == nil {
			for _, name := range strings.Fields(string(labels)) {
				if kept(name) && !slices.Contains(found, name) {
					found = append(found, name)
				}
			}
		}
	}
	slices.Sort(found)
	if len(found) > maxStacks {
		found = found[:maxStacks]
	}
	return found
}

func (e Executor) containerOf(ctx context.Context, project, service string) (string, error) {
	names, err := e.docker(ctx, collectTimeout, "find", "ps", "--filter", "label=com.docker.compose.project="+project, "--filter", "label=com.docker.compose.service="+service, "--format", "{{.Names}}")
	return strings.TrimSpace(strings.Split(string(names), "\n")[0]), err
}

func (e Executor) answersTo(ctx context.Context, container, network, name string) bool {
	aliases, err := e.docker(ctx, collectTimeout, "inspect", "inspect", "--format", fmt.Sprintf(`{{with index .NetworkSettings.Networks %q}}{{join .Aliases " "}}{{end}}`, network), container)
	return err == nil && slices.Contains(strings.Fields(string(aliases)), name)
}

func (e Executor) rehost(ctx context.Context, cf *cloudflare.Client, addresses map[string]webAddress) {
	moves := map[[2]string]map[string]string{}
	for _, hostname := range slices.Sorted(maps.Keys(addresses)) {
		address := addresses[hostname]
		name := relation(address.Service, address.Project)
		if address.Host == name || address.Tunnel == "" || address.Service == "" {
			continue
		}
		container, err := e.containerOf(ctx, address.Project, address.Service)
		if err != nil || container == "" || !e.answersTo(ctx, container, address.Network, name) {
			continue
		}
		key := [2]string{address.Account, address.Tunnel}
		if moves[key] == nil {
			moves[key] = map[string]string{}
		}
		moves[key][hostname] = name
	}
	for key, hosts := range moves {
		if err := cf.Rehost(ctx, key[0], key[1], hosts); err != nil {
			log.Printf("move web addresses to their relation names: %v", err)
			continue
		}
		for hostname, name := range hosts {
			address := addresses[hostname]
			address.Host = name
			addresses[hostname] = address
		}
	}
}
