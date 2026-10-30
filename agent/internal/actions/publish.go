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

var publishFiles = map[string]string{"iptables": "publish.v4", "ip6tables": "publish.v6"}

func (e Executor) syncPublish(ctx context.Context) error {
	state := e.readFirewall()
	var failed []error
	for _, tool := range containTools {
		file := filepath.Join(e.StateDir, publishFiles[tool])
		if !state.Closed {
			if _, err := os.Stat(file); err != nil {
				continue
			}
			if strings.Contains(e.listed(ctx, tool, network.PublishChain), "-N "+network.PublishChain) {
				e.firewall(ctx, tool, "-D", dockerUser, "-j", network.PublishChain)
				e.firewall(ctx, tool, "-F", network.PublishChain)
				e.firewall(ctx, tool, "-X", network.PublishChain)
			}
			os.Remove(file)
			continue
		}
		wanted := network.Publish(state.Open, tool == "ip6tables")
		current := e.listed(ctx, tool, network.PublishChain)
		if current != strings.Join(append([]string{"-N " + network.PublishChain}, wanted...), "\n") {
			restore := "*filter\n:" + network.PublishChain + " - [0:0]\n" + strings.Join(wanted, "\n") + "\nCOMMIT\n"
			if last, err := os.ReadFile(file); err == nil && string(last) == restore {
				e.removedRule(map[string]string{network.PublishChain: current}, map[string][]string{network.PublishChain: wanted})
			}
			if err := writeWhole(e.StateDir, publishFiles[tool], []byte(restore), 0o600); err != nil {
				failed = append(failed, err)
				continue
			}
			if err := e.firewall(ctx, tool+"-restore", "--noflush", file); err != nil {
				failed = append(failed, fmt.Errorf("close Docker's published ports with %s: %w", tool, err))
				continue
			}
		}
		e.firewall(ctx, tool, "-N", dockerUser)
		if err := e.ensure(ctx, tool, []string{"-I", dockerUser, "1"}, dockerUser, []string{"-j", network.PublishChain}); err != nil {
			failed = append(failed, fmt.Errorf("send Docker's published ports through %s: %w", network.PublishChain, err))
		}
	}
	return errors.Join(failed...)
}
