package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/safefile"
)

type Config struct {
	Endpoint string `json:"endpoint"`
	NodeID   string `json:"node_id"`
	Token    string `json:"token"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}

	var raw Config
	if err := json.Unmarshal(data, &raw); err != nil {
		return Config{}, fmt.Errorf("parse config %q: %w", path, err)
	}

	return validate(raw)
}

func Save(path string, cfg Config) error {
	validated, err := validate(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	data, err := json.MarshalIndent(validated, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')
	if err := safefile.Write(path, data, 0o600); err != nil {
		return fmt.Errorf("write config %q: %w", path, err)
	}
	return nil
}

func Valid(cfg Config) error {
	_, err := validate(cfg)
	return err
}

func validate(raw Config) (Config, error) {
	raw.Endpoint = strings.TrimRight(strings.TrimSpace(raw.Endpoint), "/")
	raw.NodeID = strings.TrimSpace(raw.NodeID)
	raw.Token = strings.TrimSpace(raw.Token)

	endpoint, err := url.Parse(raw.Endpoint)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return Config{}, fmt.Errorf("endpoint must be an absolute HTTP URL")
	}
	if endpoint.Scheme != "https" && !isLocalEndpoint(endpoint) {
		return Config{}, fmt.Errorf("endpoint must use HTTPS outside local development")
	}
	if raw.NodeID == "" {
		return Config{}, fmt.Errorf("node_id is required")
	}
	if raw.Token == "" {
		return Config{}, fmt.Errorf("token is required")
	}
	return raw, nil
}

func isLocalEndpoint(endpoint *url.URL) bool {
	host := endpoint.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
