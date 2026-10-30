package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

type prefs struct {
	CorpDNS         bool     `json:"CorpDNS"`
	AdvertiseRoutes []string `json:"AdvertiseRoutes"`
}

func readPrefs(ctx context.Context, run Runner) (prefs, error) {
	ctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	output, _, err := run(ctx, "tailscale", "debug", "prefs")
	if err != nil {
		return prefs{}, err
	}
	var parsed prefs
	err = json.Unmarshal(output, &parsed)
	return parsed, err
}

func exitRoutes(routes []string) bool {
	return slices.Contains(routes, "0.0.0.0/0") || slices.Contains(routes, "::/0")
}

func Set(ctx context.Context, run Runner, flag string) error {
	ctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	output, _, err := run(ctx, "tailscale", "set", flag)
	if err == nil {
		return nil
	}
	if text := strings.TrimSpace(string(output)); text != "" {
		return errors.New(text)
	}
	return err
}
