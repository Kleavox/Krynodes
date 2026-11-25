package stacks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/safefile"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

const (
	composeFile  = "compose.yaml"
	envFile      = ".env"
	metaFile     = "labels.json"
	maxEnvBytes  = 16 << 10
	maxMetaBytes = 64 << 10
)

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

type Meta struct {
	Access  string            `json:"access"`
	Title   string            `json:"title,omitempty"`
	Names   map[string]string `json:"names,omitempty"`
	Network []int             `json:"network"`
	Home    string            `json:"home,omitempty"`
}

func Write(dir string, command trust.Command, unseal func(string) ([]byte, error)) error {
	if access := command.Args["access"]; access != "contained" && access != "full" {
		return fmt.Errorf("unknown access %q", access)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
		return fmt.Errorf("%s is not a folder", dir)
	}
	args := command.Args
	meta, _ := ReadMeta(dir)
	meta.Access = args["access"]
	network, err := parseNetwork(args["network"])
	if err != nil {
		return err
	}
	meta.Network = network
	if title, given := args["title"]; given {
		meta.Title = title
	}
	if names, given := args["names"]; given {
		if meta.Names, err = parseNames(names); err != nil {
			return err
		}
	}
	if sealed := args["env"]; sealed != "" {
		plain, err := unseal(sealed)
		if err != nil {
			return fmt.Errorf("the .env: %w", err)
		}
		if len(plain) > maxEnvBytes || bytes.IndexByte(plain, 0) >= 0 {
			return errors.New("the .env must be text of at most 16 KB")
		}
		if err := safefile.Write(filepath.Join(dir, envFile), plain, 0o600); err != nil {
			return err
		}
	}
	if err := safefile.Write(filepath.Join(dir, composeFile), []byte(args["compose"]), 0o640); err != nil {
		return err
	}
	return writeMeta(dir, meta)
}

func writeMeta(dir string, meta Meta) error {
	encoded, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return safefile.Write(filepath.Join(dir, metaFile), encoded, 0o640)
}

func Read(dir string) (string, []string, error) {
	text, err := safefile.Read(filepath.Join(dir, composeFile), maxComposeBytes+1)
	if err != nil {
		return "", nil, err
	}
	if len(text) > maxComposeBytes {
		return "", nil, errors.New("the compose file is larger than 32 KB")
	}
	raw, err := readEnv(dir)
	if err != nil {
		return "", nil, err
	}
	names := []string{}
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
		name, _, found := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if found && !strings.HasPrefix(line, "#") && envName.MatchString(name) && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return string(text), names, nil
}

func readEnv(dir string) ([]byte, error) {
	raw, err := safefile.Read(filepath.Join(dir, envFile), maxEnvBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return raw, err
}

func ReadMeta(dir string) (Meta, error) {
	meta := Meta{Network: []int{}}
	raw, err := safefile.Read(filepath.Join(dir, metaFile), maxMetaBytes)
	if err != nil {
		return meta, err
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return Meta{Network: []int{}}, err
	}
	if meta.Network == nil {
		meta.Network = []int{}
	}
	return meta, nil
}

func parseNetwork(text string) ([]int, error) {
	ports := []int{}
	if text == "" {
		return ports, nil
	}
	for entry := range strings.SplitSeq(text, ",") {
		port, err := strconv.Atoi(entry)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("%s is not a port between 1 and 65535", entry)
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func parseNames(text string) (map[string]string, error) {
	if text == "" {
		return nil, nil
	}
	names := map[string]string{}
	for entry := range strings.SplitSeq(text, ",") {
		service, name, found := strings.Cut(entry, "=")
		if _, twice := names[service]; !found || twice || service == "" || name == "" || strings.Contains(name, "=") {
			return nil, errors.New("container names are written as service=name, each service once")
		}
		names[service] = name
	}
	return names, nil
}
