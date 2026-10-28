package actions

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxStackNames = 64

var (
	containerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{1,127}$`)
	serviceName   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

func titleFrom(command Command, current string) (string, error) {
	title, given := command.Args["title"]
	if !given {
		return current, nil
	}
	if title == "" || utf8.RuneCountInString(title) > 64 || strings.TrimSpace(title) != title || strings.ContainsFunc(title, unicode.IsControl) {
		return "", errors.New("the display name must be 1 to 64 characters on one line, with no space at either end")
	}
	return title, nil
}

func namesFrom(command Command, current map[string]string) (map[string]string, error) {
	text, given := command.Args["names"]
	if !given {
		return current, nil
	}
	if text == "" {
		return nil, nil
	}
	names, used := map[string]string{}, map[string]bool{}
	for _, entry := range strings.Split(text, ",") {
		service, name, found := strings.Cut(entry, "=")
		_, twice := names[service]
		if !found || twice || used[name] || len(names) == maxStackNames || !serviceName.MatchString(service) || !containerName.MatchString(name) {
			return nil, errors.New("container names start with a letter or digit, hold letters, digits, -, _ and ., and are used once")
		}
		names[service], used[name] = name, true
	}
	return names, nil
}

func copiesOf(service map[string]any) float64 {
	if replicas, ok := asMap(service["deploy"])["replicas"].(float64); ok {
		return replicas
	}
	if scale, ok := service["scale"].(float64); ok {
		return scale
	}
	return 1
}

func nameable(config map[string]any, names map[string]string) map[string]string {
	services := asMap(config["services"])
	kept := map[string]string{}
	for service, name := range names {
		if entry, found := services[service]; found && copiesOf(asMap(entry)) <= 1 {
			kept[service] = name
		}
	}
	if len(kept) == 0 {
		return nil
	}
	return kept
}

func (e Executor) formerNames(project string, config map[string]any, names map[string]string) map[string]map[string]string {
	keys := map[string]string{}
	for key, network := range asMap(config["networks"]) {
		keys[asText(asMap(network)["name"])] = key
	}
	former := map[string]map[string]string{}
	for _, address := range e.addresses() {
		name, renamed := names[address.Service]
		key, joined := keys[address.Network]
		if address.Project != project || !renamed || name == address.Container || !joined || address.Host == relation(address.Service, address.Project) {
			continue
		}
		if former[address.Service] == nil {
			former[address.Service] = map[string]string{}
		}
		former[address.Service][key] = address.Container
	}
	return former
}

func applyNames(target, base map[string]any, names map[string]string, former map[string]map[string]string) {
	services := asMap(target["services"])
	if services == nil {
		services = map[string]any{}
		target["services"] = services
	}
	for service, name := range names {
		entry := asMap(services[service])
		if entry == nil {
			entry = map[string]any{}
			services[service] = entry
		}
		entry["container_name"] = name
		for key, old := range former[service] {
			addAlias(target, base, service, key, old)
		}
	}
}

func serviceNetwork(service map[string]any, key string) map[string]any {
	networks := asMap(service["networks"])
	if networks == nil {
		networks = map[string]any{}
		for _, listed := range asList(service["networks"]) {
			networks[asText(listed)] = nil
		}
		service["networks"] = networks
	}
	settings := asMap(networks[key])
	if settings == nil {
		settings = map[string]any{}
		networks[key] = settings
	}
	return settings
}
