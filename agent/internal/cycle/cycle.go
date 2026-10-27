package cycle

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/checks"
	"github.com/Kleavox/krynodes/agent/internal/metrics"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

type Reporter interface {
	SendHeartbeat(context.Context, reporter.Heartbeat) (reporter.HeartbeatResponse, error)
	FetchConfig(context.Context) (reporter.AgentConfig, error)
}

type Cycle interface {
	Execute(context.Context, string) (int, error)
	ConfigChanged() bool
}

type Updater interface {
	Request(version, requestedAt string) error
	Failure() *reporter.UpdateFailure
}

type Actions interface {
	Enqueue([]reporter.ActionRequest) error
	Refresh() error
	NetworkBeat() *reporter.NetworkBeat
	NetworkReply(*reporter.NetworkReply) error
	Report(*reporter.Heartbeat)
	Answer(reporter.HeartbeatResponse) error
}

type implementation struct {
	reporter Reporter
	host     reporter.Host
	updates  Updater
	actions  Actions
	config   *reporter.AgentConfig
	changed  bool
}

func New(server Reporter, host reporter.Host, updates Updater, actions Actions) Cycle {
	return &implementation{reporter: server, host: host, updates: updates, actions: actions}
}

func (cycle *implementation) Execute(ctx context.Context, nodeID string) (int, error) {
	var configErr error
	if cycle.config == nil {
		agentConfig, err := cycle.reporter.FetchConfig(ctx)
		if err != nil {
			configErr = describeResponseError("fetch checks", err)
		} else {
			cycle.config = &agentConfig
		}
	}

	snapshot, err := metrics.Collect()
	if err != nil {
		return 0, fmt.Errorf("collect metrics: %w", err)
	}
	beat := reporter.Heartbeat{NodeID: nodeID, Host: cycle.host, Metrics: snapshot}
	if cycle.updates != nil {
		beat.Update = cycle.updates.Failure()
	}
	if cycle.actions != nil {
		beat.Network = cycle.actions.NetworkBeat()
		cycle.actions.Report(&beat)
	}
	interval := 0
	if cycle.config != nil {
		beat.Results = checks.RunAll(ctx, cycle.config.Checks)
		interval = cycle.config.IntervalSeconds
	}

	response, err := cycle.reporter.SendHeartbeat(ctx, beat)
	if err != nil {
		return 0, describeResponseError("heartbeat", err)
	}
	if cycle.config != nil && (response.ConfigVersion == "" || response.ConfigVersion != cycle.config.ConfigVersion) {
		cycle.changed = response.ConfigVersion != ""
		cycle.config = nil
	}
	if configErr != nil {
		return 0, configErr
	}
	if response.Update != nil && cycle.updates != nil {
		if err := cycle.updates.Request(response.Update.Version, response.Update.RequestedAt); err != nil {
			return 0, fmt.Errorf("request update to %s: %w", response.Update.Version, err)
		}
	}
	if cycle.actions != nil {
		if len(response.Actions) > 0 {
			if err := cycle.actions.Enqueue(response.Actions); err != nil {
				return 0, fmt.Errorf("queue service actions: %w", err)
			}
		}
		if response.Refresh {
			if err := cycle.actions.Refresh(); err != nil {
				return 0, fmt.Errorf("refresh services: %w", err)
			}
		}
		if err := cycle.actions.NetworkReply(response.Network); err != nil {
			return 0, fmt.Errorf("queue private network changes: %w", err)
		}
		if err := cycle.actions.Answer(response); err != nil {
			return 0, fmt.Errorf("keep what the dashboard heard: %w", err)
		}
	}
	if response.IntervalSeconds > 0 {
		return response.IntervalSeconds, nil
	}
	return interval, nil
}

func describeResponseError(action string, err error) error {
	var responseError *reporter.ResponseError
	if errors.As(err, &responseError) {
		return fmt.Errorf(
			"%s failed with HTTP %d: %s",
			action,
			responseError.Status,
			strings.TrimSpace(responseError.Body),
		)
	}
	return fmt.Errorf("%s failed: %w", action, err)
}

func (cycle *implementation) ConfigChanged() bool {
	changed := cycle.changed
	cycle.changed = false
	return changed
}
