package daemon

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/trust"
	"github.com/Kleavox/krynodes/agent/internal/update"
)

var releaseVersion = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func (d *Daemon) ApplyTrust(_ context.Context, cmd trust.Command, _ func(string)) (string, error) {
	d.trustMu.Lock()
	defer d.trustMu.Unlock()
	next, err := trust.ApplyTrustChange(d.Trust(), []byte(cmd.Args["change"]), d.Now())
	if err != nil {
		return "", err
	}
	if err := d.SaveTrust(next); err != nil {
		return "", fmt.Errorf("save the trust: %w", err)
	}
	return fmt.Sprintf("This server trusts %d passkeys; %d reach it.", len(next.Core), len(next.Access)), nil
}

func AfterAck(d *Daemon, limit time.Duration, message string, act func()) Handler {
	return func(_ context.Context, cmd trust.Command, _ func(string)) (string, error) {
		d.afterAck(cmd.ID, limit, act)
		return message, nil
	}
}

func Update(current string, grace time.Duration, run func(ctx context.Context, target string) error) Handler {
	return func(ctx context.Context, cmd trust.Command, progress func(string)) (string, error) {
		target := cmd.Args["version"]
		if !releaseVersion.MatchString(target) {
			return "", fmt.Errorf("%q is not a release version", target)
		}
		newer, err := update.IsNewer(target, current)
		if err != nil {
			return "", err
		}
		if !newer {
			return "", fmt.Errorf("this server already runs %s", current)
		}
		progress("Updating to " + target)
		if err := run(ctx, target); err != nil {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(grace):
				return "", err
			}
		}
		return "", errors.New("the update ended without restarting the agent")
	}
}

func Resume(current string, failure func() string) func(context.Context, trust.Command) (string, error) {
	return func(_ context.Context, cmd trust.Command) (string, error) {
		if cmd.Kind != "agent" || cmd.Action != "update" {
			return "", errStopped
		}
		if cmd.Args["version"] == current {
			return "Updated to " + current + ".", nil
		}
		return "", errors.New(failure())
	}
}
