package tailscale

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

type Runner func(ctx context.Context, name string, args ...string) ([]byte, int, error)

const (
	Binary        = "/usr/bin/tailscale"
	statusTimeout = 10 * time.Second
	maxAddresses  = 8
)

type status struct {
	BackendState string `json:"BackendState"`
	AuthURL      string `json:"AuthURL"`
	Self         *struct {
		DNSName      string     `json:"DNSName"`
		TailscaleIPs []string   `json:"TailscaleIPs"`
		KeyExpiry    *time.Time `json:"KeyExpiry"`
	} `json:"Self"`
}

func read(ctx context.Context, run Runner) (status, error) {
	ctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	output, _, err := run(ctx, "tailscale", "status", "--json")
	if err != nil {
		return status{}, err
	}
	var parsed status
	err = json.Unmarshal(output, &parsed)
	return parsed, err
}

func Status(ctx context.Context, run Runner) reporter.TailscaleReport {
	report := reporter.TailscaleReport{State: "stopped", Addresses: []string{}}
	parsed, err := read(ctx, run)
	if err != nil {
		return report
	}
	report.State = "needs-login"
	if parsed.BackendState != "Running" || parsed.Self == nil {
		return report
	}
	report.State = "running"
	for _, address := range parsed.Self.TailscaleIPs {
		if len(report.Addresses) < maxAddresses {
			report.Addresses = append(report.Addresses, address)
		}
	}
	if name := strings.TrimSuffix(parsed.Self.DNSName, "."); name != "" {
		report.Name = &name
	}
	if expiry := parsed.Self.KeyExpiry; expiry != nil && !expiry.IsZero() {
		text := expiry.UTC().Format(time.RFC3339Nano)
		report.KeyExpiry = &text
	}
	return report
}
