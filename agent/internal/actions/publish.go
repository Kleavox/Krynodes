package actions

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
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
		var publish []string
		if state.Closed {
			publish = network.Publish(slices.Concat(state.Open, state.Filed), ipv6)
			e.firewall(ctx, tool, "-N", dockerUser)
		}
		if err := e.syncChain(ctx, tool, network.PublishChain, dockerUser, publishFiles[tool], publish); err != nil {
			failed = append(failed, fmt.Errorf("close Docker's published ports with %s: %w", tool, err))
		}
		if err := e.keepTailscaleGuard(ctx, tool); err != nil {
			failed = append(failed, fmt.Errorf("keep Tailscale ports to Tailscale with %s: %w", tool, err))
		}
	}
	return errors.Join(failed...)
}

func (e Executor) keepTailscaleGuard(ctx context.Context, tool string) error {
	file := filepath.Join(e.StateDir, tailscaleFiles[tool])
	raw, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	wanted := []string{"-N " + network.TailscaleChain}
	for line := range strings.SplitSeq(string(raw), "\n") {
		switch line = strings.TrimSpace(line); {
		case line == "", line == "*filter", line == ":"+network.TailscaleChain+" - [0:0]", line == "COMMIT":
		case strings.HasPrefix(line, "-A "+network.TailscaleChain+" "):
			wanted = append(wanted, line)
		default:
			log.Printf("leave %s alone: it holds more than the Tailscale guard", file)
			return nil
		}
	}
	if e.listed(ctx, tool, network.TailscaleChain) != strings.Join(wanted, "\n") {
		if err := e.firewall(ctx, tool+"-restore", "--noflush", file); err != nil {
			return err
		}
	}
	return e.ensure(ctx, tool, []string{"-I", "INPUT", "1"}, "INPUT", []string{"-j", network.TailscaleChain})
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
