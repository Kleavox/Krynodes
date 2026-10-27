package tailscale

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

type Runner func(ctx context.Context, name string, args ...string) ([]byte, int, error)

type Local func(ctx context.Context, path string) ([]byte, error)

const (
	Binary        = "/usr/bin/tailscale"
	statusTimeout = 10 * time.Second
	maxAddresses  = 8
	maxTags       = 8
	filterPath    = "/localapi/v0/debug-packet-filter-rules"
)

type node struct {
	ID           string     `json:"ID"`
	DNSName      string     `json:"DNSName"`
	TailscaleIPs []string   `json:"TailscaleIPs"`
	KeyExpiry    *time.Time `json:"KeyExpiry"`
	Tags         []string   `json:"Tags"`
}

type status struct {
	BackendState   string          `json:"BackendState"`
	AuthURL        string          `json:"AuthURL"`
	MagicDNSSuffix string          `json:"MagicDNSSuffix"`
	Self           *node           `json:"Self"`
	Peer           map[string]node `json:"Peer"`
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

func label(name string) string {
	first, _, _ := strings.Cut(strings.TrimSuffix(name, "."), ".")
	return first
}

func Status(ctx context.Context, run Runner) reporter.TailscaleReport {
	return Report(ctx, run, nil)
}

func Report(ctx context.Context, run Runner, local Local) reporter.TailscaleReport {
	report := reporter.TailscaleReport{State: "stopped", Addresses: []string{}, Tags: []string{}, Names: map[string]string{}}
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
	if id := parsed.Self.ID; id != "" {
		report.ID = &id
	}
	if suffix := strings.TrimSuffix(parsed.MagicDNSSuffix, "."); suffix != "" {
		report.Tailnet = &suffix
	}
	for _, tag := range parsed.Self.Tags {
		if len(report.Tags) < maxTags {
			report.Tags = append(report.Tags, tag)
		}
	}
	report.Peers = len(parsed.Peer)
	if local == nil {
		return report
	}
	ctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	rules, err := local(ctx, filterPath)
	if err != nil {
		return report
	}
	peers := map[string]string{}
	for _, peer := range parsed.Peer {
		for _, address := range peer.TailscaleIPs {
			peers[address] = label(peer.DNSName)
		}
	}
	if reach, names := Reach(rules, parsed.Self.TailscaleIPs, peers); reach != nil {
		report.Reach, report.Names = &reach, names
	}
	return report
}
