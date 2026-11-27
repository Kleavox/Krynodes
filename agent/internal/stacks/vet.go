package stacks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxComposeBytes = 32 << 10
	bridgeOption    = "com.docker.network.bridge.name"
)

var (
	otherFiles = regexp.MustCompile(`\b(include|extends)\b`)
	textRules  = []struct {
		pattern *regexp.Regexp
		message string
	}{
		{regexp.MustCompile(`\\[xuU]`), `the compose file uses \x, \u or \U escapes; write the characters themselves`},
		{regexp.MustCompile(`(?m)\\\r?$`), `the compose file continues a line with \; write it on one line`},
		{regexp.MustCompile(`!!`), "the compose file uses a !! tag; write plain values"},
		{regexp.MustCompile(`(?m)^\s*\?\s`), "the compose file uses an explicit ? key; write keys plainly"},
		{regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x{feff}]`), "the compose file holds control characters"},
		{regexp.MustCompile(`\r(?:[^\n]|$)|[\x{85}\x{2028}\x{2029}]`), "the compose file breaks lines with something other than a newline"},
		{regexp.MustCompile(`(?m)^[ \t]*%`), "the compose file uses a % directive; write plain values"},
		{regexp.MustCompile(`!<`), "the compose file uses a !< tag; write plain values"},
	}
	tagStart    = regexp.MustCompile(`(?m)(?:^|[\s\[{,:?-])!([^\s\[\]{},]*)`)
	numericHost = regexp.MustCompile(`^(?:\d+|0[xX][0-9a-fA-F]*)(?:\.(?:\d+|0[xX][0-9a-fA-F]*))*\.?$`)
	meshRanges  = []netip.Prefix{netip.MustParsePrefix("10.88.0.0/16"), netip.MustParsePrefix("fd88:88::/64")}
	lookupIP    = func(ctx context.Context, host string) ([]net.IP, error) {
		return net.DefaultResolver.LookupIP(ctx, "ip", host)
	}
	interfaceIPs = func() []net.IP {
		addresses, _ := net.InterfaceAddrs()
		var found []net.IP
		for _, address := range addresses {
			if network, ok := address.(*net.IPNet); ok {
				found = append(found, network.IP)
			}
		}
		return found
	}
)

var (
	errComposeEmpty = errors.New("the compose file is empty")
	errComposeLarge = errors.New("the compose file is larger than 32 KB")
)

var containedTop = []string{"name", "services", "networks", "volumes", "secrets", "configs"}

var containedKeys = []string{
	"attach", "blkio_config", "cap_add", "cap_drop", "cgroup", "command", "configs",
	"container_name", "cpu_count", "cpu_percent", "cpu_period", "cpu_quota", "cpu_rt_period",
	"cpu_rt_runtime", "cpu_shares", "cpus", "cpuset", "depends_on", "deploy", "device_cgroup_rules",
	"devices", "dns", "dns_opt", "dns_search", "domainname", "entrypoint", "env_file", "environment",
	"expose", "external_links", "extra_hosts", "gpus", "group_add", "healthcheck", "hostname", "image",
	"init", "ipc", "label_file", "labels", "links", "logging", "mac_address", "mem_limit",
	"mem_reservation", "mem_swappiness", "memswap_limit", "network_mode", "networks", "oom_kill_disable",
	"oom_score_adj", "pid", "pids_limit", "platform", "ports", "post_start", "pre_stop", "privileged",
	"profiles", "pull_policy", "read_only", "restart", "runtime", "scale", "secrets", "security_opt",
	"shm_size", "stdin_open", "stop_grace_period", "stop_signal", "storage_opt", "sysctls", "tmpfs", "tty",
	"ulimits", "user", "userns_mode", "uts", "volumes", "volumes_from", "working_dir",
}

var dollarKeys = []string{
	"image", "pid", "ipc", "uts", "userns_mode", "cgroup", "network_mode", "volumes", "devices", "networks",
	"ports", "runtime", "logging", "cap_add", "security_opt", "sysctls", "volumes_from",
}

type shareLimit struct {
	key, deployKey, label string
	max                   float64
}

var shareLimits = []shareLimit{
	{"cpus", "cpus", "1 CPU", 1},
	{"mem_limit", "memory", "1 GB of memory", 1 << 30},
	{"pids_limit", "pids", "512 processes", 512},
}

var units = []struct {
	suffix string
	scale  float64
}{{"kb", 1 << 10}, {"mb", 1 << 20}, {"gb", 1 << 30}, {"k", 1 << 10}, {"m", 1 << 20}, {"g", 1 << 30}, {"b", 1}}

func CheckText(text, access string) error {
	switch {
	case strings.TrimSpace(text) == "":
		return errComposeEmpty
	case len(text) > maxComposeBytes:
		return errComposeLarge
	case access != "contained":
		return nil
	}
	if word := otherFiles.FindString(text); word != "" {
		return fmt.Errorf("%s is not allowed; paste a single compose file", word)
	}
	if !utf8.ValidString(text) {
		return errors.New("the compose file is not UTF-8")
	}
	for _, rule := range textRules {
		if rule.pattern.MatchString(text) {
			return errors.New(rule.message)
		}
	}
	for _, tag := range tagStart.FindAllStringSubmatch(text, -1) {
		if tag[1] != "reset" && tag[1] != "override" {
			return errors.New("the compose file uses a ! tag; only !reset and !override are allowed")
		}
	}
	return nil
}

func Vet(normalised map[string]any, directory string, access string) error {
	switch access {
	case "full":
		services := asMap(normalised["services"])
		for _, name := range sortedKeys(services) {
			if asMap(services[name])["build"] != nil {
				return fmt.Errorf("service %s builds from source; only ready images can run", name)
			}
		}
		networks := asMap(normalised["networks"])
		for _, name := range sortedKeys(networks) {
			if err := meshOverlap(name, asMap(networks[name])); err != nil {
				return err
			}
		}
		return nil
	case "contained":
		project := asText(normalised["name"])
		if project == "" {
			project = filepath.Base(directory)
		}
		if err := vet(normalised, project); err != nil {
			return err
		}
		if err := checkRegistries(normalised); err != nil {
			return err
		}
		return contain(normalised, project)
	}
	return fmt.Errorf("unknown access %q", access)
}

func asMap(value any) map[string]any {
	found, _ := value.(map[string]any)
	return found
}

func asList(value any) []any {
	found, _ := value.([]any)
	return found
}

func asText(value any) string {
	found, _ := value.(string)
	return found
}

func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func filePath(value any) string {
	if path := asText(value); path != "" {
		return path
	}
	return asText(asMap(value)["path"])
}

func unknownKey(values map[string]any, allowed []string) string {
	for _, key := range sortedKeys(values) {
		if !strings.HasPrefix(key, "x-") && !slices.Contains(allowed, key) {
			return key
		}
	}
	return ""
}

func hasDollar(value any) bool {
	encoded, err := json.Marshal(value)
	return err != nil || strings.Contains(string(encoded), "$")
}

func number(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case string:
		text := strings.ToLower(strings.TrimSpace(typed))
		scale := 1.0
		for _, unit := range units {
			if strings.HasSuffix(text, unit.suffix) {
				text, scale = strings.TrimSpace(strings.TrimSuffix(text, unit.suffix)), unit.scale
				break
			}
		}
		parsed, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return 0, false
		}
		return parsed * scale, true
	}
	return 0, false
}

func bridgeName(project, network string) string {
	sum := sha256.Sum256([]byte(project + "/" + network))
	return "krc" + hex.EncodeToString(sum[:])[:12]
}

func vet(config map[string]any, project string) error {
	for _, section := range []string{"networks", "volumes"} {
		if hasDollar(config[section]) {
			return fmt.Errorf("the compose file writes $ in %s; a Contained stack cannot use it there", section)
		}
	}
	networks := asMap(config["networks"])
	for _, name := range sortedKeys(networks) {
		if err := vetNetwork(name, asMap(networks[name]), project); err != nil {
			return err
		}
	}
	volumes := asMap(config["volumes"])
	for _, name := range sortedKeys(volumes) {
		volume := asMap(volumes[name])
		options := asMap(volume["driver_opts"])
		if volume["external"] == true {
			return fmt.Errorf("volume %s is external; a stack may only use its own volumes", name)
		}
		if strings.Contains(name, "_") {
			return fmt.Errorf("volume %s has _ in its name; a Contained stack names its volumes without _", name)
		}
		if own := asText(volume["name"]); own != "" && own != project+"_"+name {
			return fmt.Errorf("volume %s is named %s; a Contained stack may only use its own volumes", name, own)
		}
		if driver := asText(volume["driver"]); driver != "" && driver != "local" {
			return fmt.Errorf("volume %s uses the %s driver; a Contained stack uses local volumes", name, driver)
		}
		if asText(options["device"]) != "" || strings.Contains(asText(options["o"]), "bind") {
			return fmt.Errorf("volume %s binds a path on the server", name)
		}
		if len(options) > 0 {
			return fmt.Errorf("volume %s sets driver options; a Contained stack uses plain volumes", name)
		}
	}
	for _, section := range []string{"secrets", "configs"} {
		entries := asMap(config[section])
		for _, name := range sortedKeys(entries) {
			entry := asMap(entries[name])
			if file := asText(entry["file"]); file != "" {
				return fmt.Errorf("%s %s reads %s from the server", strings.TrimSuffix(section, "s"), name, file)
			}
			if variable := asText(entry["environment"]); variable != "" {
				return fmt.Errorf("%s %s reads %s from the server's environment", strings.TrimSuffix(section, "s"), name, variable)
			}
		}
	}
	if len(asMap(config["models"])) > 0 {
		return errors.New("models run through a program on the server; a Contained stack cannot use them")
	}
	if key := unknownKey(config, containedTop); key != "" {
		return fmt.Errorf("the compose file uses %s, which a Contained stack does not allow; choose Full access to run it", key)
	}
	services := asMap(config["services"])
	for _, name := range sortedKeys(services) {
		if err := vetService(name, asMap(services[name])); err != nil {
			return err
		}
	}
	for _, name := range sortedKeys(services) {
		if err := limit(name, asMap(services[name])); err != nil {
			return err
		}
	}
	return nil
}

func vetNetwork(name string, network map[string]any, project string) error {
	if network["external"] == true {
		return fmt.Errorf("network %s is external; a Contained stack may only use its own networks", name)
	}
	if strings.Contains(name, "_") {
		return fmt.Errorf("network %s has _ in its name; a Contained stack names its networks without _", name)
	}
	if own := asText(network["name"]); own != "" && own != project+"_"+name {
		return fmt.Errorf("network %s is named %s; a Contained stack may only use its own networks", name, own)
	}
	if network["enable_ipv6"] == true {
		return fmt.Errorf("network %s turns on IPv6, which a Contained stack cannot use", name)
	}
	switch driver := asText(network["driver"]); driver {
	case "", "bridge":
	case "host", "macvlan", "ipvlan":
		return fmt.Errorf("network %s uses the %s driver, which reaches the server's own network", name, driver)
	default:
		return fmt.Errorf("network %s uses the %s driver; a Contained stack uses bridge networks", name, driver)
	}
	if options := asMap(network["driver_opts"]); len(options) > 0 && (len(options) != 1 || options[bridgeOption] != bridgeName(project, name)) {
		return fmt.Errorf("network %s sets driver options; a Contained stack uses plain networks", name)
	}
	if ipam, set := network["ipam"]; set && (asMap(ipam) == nil || len(asMap(ipam)) > 0) {
		return fmt.Errorf("network %s chooses its own addresses; a Contained stack lets Docker choose them", name)
	}
	return nil
}

func meshOverlap(name string, network map[string]any) error {
	for _, raw := range asList(asMap(network["ipam"])["config"]) {
		for _, key := range []string{"subnet", "ip_range"} {
			text := asText(asMap(raw)[key])
			if text == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(text)
			if err != nil {
				return fmt.Errorf("network %s has the %s %s, which is not an address range", name, key, text)
			}
			if slices.ContainsFunc(meshRanges, prefix.Overlaps) {
				return fmt.Errorf("network %s uses %s, which overlaps the private network", name, text)
			}
		}
	}
	return nil
}

func vetService(name string, service map[string]any) error {
	for _, key := range dollarKeys {
		if value, set := service[key]; set && hasDollar(value) {
			return fmt.Errorf("service %s writes $ in %s; a Contained stack cannot use it there", name, key)
		}
	}
	if service["extends"] != nil {
		return fmt.Errorf("service %s uses extends; paste a single compose file", name)
	}
	if service["build"] != nil {
		return fmt.Errorf("service %s builds from source; only ready images can run", name)
	}
	if service["privileged"] == true {
		return fmt.Errorf("service %s asks for privileged mode", name)
	}
	for _, hook := range append(asList(service["post_start"]), asList(service["pre_stop"])...) {
		if asMap(hook)["privileged"] == true {
			return fmt.Errorf("service %s runs a privileged hook", name)
		}
	}
	if service["provider"] != nil {
		return fmt.Errorf("service %s is a provider, which runs a program on the server", name)
	}
	if runtime := asText(service["runtime"]); runtime != "" && runtime != "runc" {
		return fmt.Errorf("service %s asks for the runtime %s", name, runtime)
	}
	if host := registryHost(asText(service["image"])); host != "" {
		return fmt.Errorf("service %s pulls its image from %s, which is the server itself", name, host)
	}
	logging := asMap(service["logging"])
	if driver := asText(logging["driver"]); !slices.Contains([]string{"", "local", "json-file", "none"}, driver) {
		return fmt.Errorf("service %s sends its logs through %s, which runs on the server's own network", name, driver)
	}
	for _, option := range sortedKeys(asMap(logging["options"])) {
		if !slices.Contains([]string{"max-size", "max-file", "compress"}, option) {
			return fmt.Errorf("service %s sets the logs option %s; only max-size, max-file and compress are allowed", name, option)
		}
	}
	for _, key := range []string{"network_mode", "pid", "ipc", "uts", "userns_mode", "cgroup"} {
		value := asText(service[key])
		label := strings.TrimSuffix(key, "_mode")
		if value == "host" {
			return fmt.Errorf("service %s shares the server's %s", name, label)
		}
		if strings.HasPrefix(value, "container:") {
			return fmt.Errorf("service %s shares the %s of another container", name, label)
		}
	}
	mode := asText(service["network_mode"])
	if mode != "" && mode != "none" && !strings.HasPrefix(mode, "service:") {
		return fmt.Errorf("service %s joins the network %s; a Contained stack uses only its own networks", name, mode)
	}
	joined := service["networks"]
	if mode == "" && len(asMap(joined)) == 0 && len(asList(joined)) == 0 {
		return fmt.Errorf("service %s is on no network; a Contained stack keeps every service on its own networks", name)
	}
	for _, key := range sortedKeys(asMap(joined)) {
		settings := asMap(asMap(joined)[key])
		for _, field := range []string{"ipv4_address", "ipv6_address", "link_local_ips"} {
			if settings[field] != nil {
				return fmt.Errorf("service %s chooses its own address on network %s; a Contained stack lets Docker choose it", name, key)
			}
		}
	}
	if swap, ok := number(service["memswap_limit"]); ok && (swap < 0 || swap > 2<<30) {
		return fmt.Errorf("service %s asks for more than 2 GB of memory with swap; a Contained stack gets at most that", name)
	}
	for _, copies := range []any{service["scale"], asMap(service["deploy"])["replicas"]} {
		if count, ok := number(copies); ok && count > 1 {
			return fmt.Errorf("service %s asks for %d copies; a Contained service runs one, so its limits hold", name, int(count))
		}
	}
	if len(asList(service["cap_add"])) > 0 {
		return fmt.Errorf("service %s asks for extra capabilities", name)
	}
	reserved := asList(asMap(asMap(asMap(service["deploy"])["resources"])["reservations"])["devices"])
	if len(asList(service["devices"])) > 0 || len(asList(service["device_cgroup_rules"])) > 0 || service["gpus"] != nil || len(reserved) > 0 {
		return fmt.Errorf("service %s asks for devices", name)
	}
	for _, option := range asList(service["security_opt"]) {
		if text := asText(option); !strings.HasPrefix(text, "no-new-privileges") {
			return fmt.Errorf("service %s changes its confinement (%s)", name, text)
		}
	}
	if err := vetMounts(name, service); err != nil {
		return err
	}
	if key := unknownKey(service, containedKeys); key != "" {
		return fmt.Errorf("service %s uses %s, which a Contained stack does not allow; choose Full access to run it", name, key)
	}
	return nil
}

func vetMounts(name string, service map[string]any) error {
	if raw, set := service["volumes"]; set && raw != nil && asList(raw) == nil {
		return fmt.Errorf("service %s lists its volumes in a shape compose does not write", name)
	}
	for _, raw := range asList(service["volumes"]) {
		volume := asMap(raw)
		switch kind := asText(volume["type"]); {
		case volume == nil:
			return fmt.Errorf("service %s lists a volume compose did not resolve", name)
		case kind == "bind":
			return fmt.Errorf("service %s mounts %s from the server; a Contained stack keeps its data in named volumes", name, asText(volume["source"]))
		case kind != "volume" && kind != "tmpfs":
			return fmt.Errorf("service %s mounts a %s volume; a Contained stack keeps its data in named volumes", name, kind)
		}
	}
	for _, raw := range asList(service["volumes_from"]) {
		if strings.HasPrefix(asText(raw), "container:") {
			return fmt.Errorf("service %s uses the volumes of another container", name)
		}
	}
	for _, key := range []string{"env_file", "label_file"} {
		raw, set := service[key]
		if !set {
			continue
		}
		path := filePath(raw)
		if listed := asList(raw); len(listed) > 0 {
			path = filePath(listed[0])
		}
		if path == "" {
			path = key
		}
		return fmt.Errorf("service %s reads %s from the server", name, path)
	}
	return nil
}

func limit(name string, service map[string]any) error {
	limits := asMap(asMap(asMap(service["deploy"])["resources"])["limits"])
	for _, share := range shareLimits {
		value, set := number(service[share.key])
		deployed, deploySet := number(limits[share.deployKey])
		if (set && (value <= 0 || value > share.max)) || (deploySet && (deployed <= 0 || deployed > share.max)) {
			return fmt.Errorf("service %s asks for more than %s; a Contained stack gets at most that per service, so choose Full access for more", name, share.label)
		}
		if !set && !deploySet {
			service[share.key] = share.max
		}
	}
	return nil
}

func contain(config map[string]any, project string) error {
	networks := asMap(config["networks"])
	for _, name := range sortedKeys(networks) {
		network := asMap(networks[name])
		if network == nil {
			network = map[string]any{}
			networks[name] = network
		}
		network["driver_opts"] = map[string]any{bridgeOption: bridgeName(project, name)}
		network["enable_ipv6"] = false
	}
	services := asMap(config["services"])
	for _, name := range sortedKeys(services) {
		service := asMap(services[name])
		if raw, set := service["cap_drop"]; set && raw != nil && asList(raw) == nil {
			return fmt.Errorf("service %s lists cap_drop in a shape compose does not write", name)
		}
		if dropped := asList(service["cap_drop"]); !slices.Contains(dropped, any("NET_RAW")) {
			service["cap_drop"] = append(dropped, "NET_RAW")
		}
	}
	return nil
}

func registryOf(image string) string {
	first, _, found := strings.Cut(image, "/")
	if !found || !strings.ContainsAny(first, ".:[") && first != "localhost" {
		return ""
	}
	host := first
	if strings.HasPrefix(host, "[") {
		host, _, _ = strings.Cut(strings.TrimPrefix(host, "["), "]")
	} else if name, _, cut := strings.Cut(host, ":"); cut {
		host = name
	}
	return host
}

func serverAddress(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || slices.ContainsFunc(interfaceIPs(), ip.Equal)
}

func registryHost(image string) string {
	host := registryOf(image)
	switch {
	case host == "":
		return ""
	case strings.EqualFold(strings.TrimSuffix(host, "."), "localhost"), strings.Contains(host, "%"):
		return host
	}
	if ip := net.ParseIP(host); ip != nil {
		if serverAddress(ip) {
			return host
		}
		return ""
	}
	if numericHost.MatchString(host) {
		return host
	}
	return ""
}

func checkRegistries(config map[string]any) error {
	services := asMap(config["services"])
	for _, name := range sortedKeys(services) {
		host := registryOf(asText(asMap(services[name])["image"]))
		if host == "" || net.ParseIP(host) != nil || registryHost(asText(asMap(services[name])["image"])) != "" {
			continue
		}
		resolving, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		addresses, err := lookupIP(resolving, host)
		cancel()
		if err != nil || len(addresses) == 0 {
			return fmt.Errorf("could not resolve registry %s for service %s", host, name)
		}
		if slices.ContainsFunc(addresses, serverAddress) {
			return fmt.Errorf("service %s pulls its image from %s, which points at the server itself", name, host)
		}
	}
	return nil
}
