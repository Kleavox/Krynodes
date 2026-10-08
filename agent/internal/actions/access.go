package actions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	guardBridges    = "krc+"
	metadataAddress = "169.254.169.254"
	metadataIPv6    = "fd00:ec2::254"
	diskReserve     = 1_000_000_000
)

type stackMeta struct {
	Access string `json:"access"`
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

func (e Executor) accessOf(directory string) string {
	if !e.ownStack(directory) {
		return ""
	}
	meta, err := readState[stackMeta](directory, "krynodes.json")
	if err == nil && (meta.Access == "contained" || meta.Access == "full") {
		return meta.Access
	}
	if regularFile(filepath.Join(directory, "compose.krynodes.json")) {
		return "contained"
	}
	return ""
}

func (e Executor) hasContained() bool {
	entries, err := os.ReadDir(filepath.Join(e.StateDir, "compose"))
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() && e.accessOf(filepath.Join(e.StateDir, "compose", entry.Name())) == "contained" {
			return true
		}
	}
	return false
}

var guardRules = [][]string{
	{"iptables", "DOCKER-USER", "-i", guardBridges, "-d", metadataAddress, "-j", "DROP"},
	{"iptables", "INPUT", "-i", guardBridges, "-j", "DROP"},
	{"ip6tables", "INPUT", "-i", guardBridges, "-j", "DROP"},
	{"ip6tables", "DOCKER-USER", "-i", guardBridges, "-d", metadataIPv6, "-j", "DROP"},
}

func (e Executor) Contain(ctx context.Context) {
	if !e.hasContained() {
		return
	}
	e.guard(ctx)
}

func (e Executor) guard(ctx context.Context) {
	for _, tool := range []string{"iptables", "ip6tables"} {
		chainCtx, cancel := context.WithTimeout(ctx, collectTimeout)
		e.Run(chainCtx, tool, "-N", "DOCKER-USER")
		cancel()
	}
	for _, rule := range guardRules {
		ctx, cancel := context.WithTimeout(ctx, collectTimeout)
		if _, _, err := e.Run(ctx, rule[0], append([]string{"-C"}, rule[1:]...)...); err != nil {
			if _, _, err := e.Run(ctx, rule[0], append([]string{"-I"}, rule[1:]...)...); err != nil {
				log.Printf("contain %s %s: %v", rule[0], rule[1], err)
			}
		}
		cancel()
	}
}

var units = []struct {
	suffix string
	scale  float64
}{{"kb", 1 << 10}, {"mb", 1 << 20}, {"gb", 1 << 30}, {"k", 1 << 10}, {"m", 1 << 20}, {"g", 1 << 30}, {"b", 1}}

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

func limit(name string, service map[string]any) error {
	limits := asMap(asMap(asMap(service["deploy"])["resources"])["limits"])
	for _, share := range shareLimits {
		value, set := number(service[share.key])
		deployed, deploySet := number(limits[share.deployKey])
		for _, found := range []struct {
			value float64
			set   bool
		}{{value, set}, {deployed, deploySet}} {
			if found.set && (found.value <= 0 || found.value > share.max) {
				return fmt.Errorf("service %s asks for more than %s; a Contained stack gets at most that per service, so choose Full access for more", name, share.label)
			}
		}
		if !set && !deploySet {
			service[share.key] = share.max
		}
	}
	return nil
}

func bridgeName(project, network string) string {
	sum := sha256.Sum256([]byte(project + "/" + network))
	return "krc" + hex.EncodeToString(sum[:])[:12]
}

func contain(config map[string]any, project string) error {
	services := asMap(config["services"])
	for _, name := range sortedKeys(services) {
		if err := limit(name, asMap(services[name])); err != nil {
			return err
		}
	}
	networks := asMap(config["networks"])
	if networks == nil {
		networks = map[string]any{}
		config["networks"] = networks
	}
	if _, ok := networks["default"]; !ok {
		networks["default"] = map[string]any{"name": project + "_default"}
	}
	for _, name := range sortedKeys(networks) {
		network := asMap(networks[name])
		if network == nil {
			network = map[string]any{}
			networks[name] = network
		}
		if driver := asText(network["driver"]); driver != "" && driver != "bridge" {
			return fmt.Errorf("network %s uses the %s driver; a Contained stack uses bridge networks", name, driver)
		}
		options := asMap(network["driver_opts"])
		if options == nil {
			options = map[string]any{}
			network["driver_opts"] = options
		}
		options["com.docker.network.bridge.name"] = bridgeName(project, name)
	}
	return nil
}

type layers struct {
	Layers []struct {
		Size int64 `json:"size"`
	} `json:"layers"`
}

type platformManifest struct {
	Descriptor struct {
		Platform struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
		} `json:"platform"`
	} `json:"Descriptor"`
	SchemaV2Manifest *layers `json:"SchemaV2Manifest"`
	OCIManifest      *layers `json:"OCIManifest"`
}

func (m platformManifest) size() (int64, bool) {
	found := m.SchemaV2Manifest
	if found == nil {
		found = m.OCIManifest
	}
	if found == nil {
		return 0, false
	}
	var total int64
	for _, layer := range found.Layers {
		total += layer.Size
	}
	return total, true
}

func imageSize(raw []byte, arch string) (int64, bool) {
	var list []platformManifest
	if json.Unmarshal(raw, &list) == nil {
		for _, entry := range list {
			if entry.Descriptor.Platform.OS == "linux" && entry.Descriptor.Platform.Architecture == arch {
				return entry.size()
			}
		}
		return 0, false
	}
	var single platformManifest
	if json.Unmarshal(raw, &single) != nil {
		return 0, false
	}
	return single.size()
}

func gigabytes(size uint64) string {
	return fmt.Sprintf("%.1f GB", float64(size)/1e9)
}

func (e Executor) freeSpace(path string) (uint64, error) {
	if e.Free != nil {
		return e.Free(path)
	}
	return freeBytes(path)
}

func (e Executor) fits(ctx context.Context, config map[string]any) error {
	root, err := e.docker(ctx, collectTimeout, "info", "info", "--format", "{{.DockerRootDir}}")
	if err != nil || strings.TrimSpace(string(root)) == "" {
		return nil
	}
	available, err := e.freeSpace(strings.TrimSpace(string(root)))
	if err != nil {
		return nil
	}
	var needed uint64
	seen := map[string]bool{}
	services := asMap(config["services"])
	for _, name := range sortedKeys(services) {
		service := asMap(services[name])
		image := asText(service["image"])
		if image == "" || service["build"] != nil || seen[image] {
			continue
		}
		seen[image] = true
		if _, err := e.docker(ctx, collectTimeout, "image", "image", "inspect", "--format", "{{.Id}}", image); err == nil {
			continue
		}
		manifest, err := e.docker(ctx, collectTimeout, "manifest", "manifest", "inspect", "-v", image)
		if err != nil {
			continue
		}
		if size, ok := imageSize(manifest, runtime.GOARCH); ok && size > 0 {
			needed += uint64(size)
		}
	}
	if want := needed*2 + diskReserve; needed > 0 && want > available {
		return fmt.Errorf("the images need about %s with room to spare; the server has %s free", gigabytes(want), gigabytes(available))
	}
	return nil
}
