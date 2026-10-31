package actions

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

var (
	publishFiles   = map[string]string{"iptables": "publish.v4", "ip6tables": "publish.v6"}
	tailscaleFiles = map[string]string{"iptables": "tailscale.v4", "ip6tables": "tailscale.v6"}
)

func (e Executor) syncPublish(ctx context.Context) error {
	state := e.readFirewall()
	var failed []error
	for _, tool := range containTools {
		ipv6 := tool == "ip6tables"
		var publish, tailscale []string
		if state.Closed {
			publish = network.Publish(state.Open, ipv6)
			e.firewall(ctx, tool, "-N", dockerUser)
		}
		if state.Closed && state.Tool == "firewalld" {
			tailscale = network.TailscaleGuard(state.Open, ipv6)
		}
		if err := e.syncChain(ctx, tool, network.PublishChain, dockerUser, publishFiles[tool], publish); err != nil {
			failed = append(failed, fmt.Errorf("close Docker's published ports with %s: %w", tool, err))
		}
		if err := e.syncChain(ctx, tool, network.TailscaleChain, "INPUT", tailscaleFiles[tool], tailscale); err != nil {
			failed = append(failed, fmt.Errorf("keep Tailscale ports to Tailscale with %s: %w", tool, err))
		}
	}
	return errors.Join(failed...)
}

func (e Executor) syncChain(ctx context.Context, tool, chain, parent, name string, wanted []string) error {
	file := filepath.Join(e.StateDir, name)
	if wanted == nil {
		if _, err := os.Stat(file); err != nil {
			return nil
		}
		if strings.Contains(e.listed(ctx, tool, chain), "-N "+chain) {
			e.firewall(ctx, tool, "-D", parent, "-j", chain)
			e.firewall(ctx, tool, "-F", chain)
			e.firewall(ctx, tool, "-X", chain)
		}
		os.Remove(file)
		return nil
	}
	current := e.listed(ctx, tool, chain)
	if current != strings.Join(append([]string{"-N " + chain}, wanted...), "\n") {
		restore := "*filter\n:" + chain + " - [0:0]\n" + strings.Join(wanted, "\n") + "\nCOMMIT\n"
		if last, err := os.ReadFile(file); err == nil && string(last) == restore {
			e.removedRule(map[string]string{chain: current}, map[string][]string{chain: wanted})
		}
		if err := writeWhole(e.StateDir, name, []byte(restore), 0o600); err != nil {
			return err
		}
		if err := e.firewall(ctx, tool+"-restore", "--noflush", file); err != nil {
			return err
		}
	}
	if err := e.ensure(ctx, tool, []string{"-I", parent, "1"}, parent, []string{"-j", chain}); err != nil {
		return fmt.Errorf("send traffic through %s: %w", chain, err)
	}
	return nil
}
