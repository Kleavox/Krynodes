package checks

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/containers"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

func systemctlArgs(units []string) []string {
	return append([]string{"show", "--property=ActiveState,ActiveEnterTimestamp", "--"}, units...)
}

func systemctl(ctx context.Context, units []string) *exec.Cmd {
	command := exec.CommandContext(ctx, "systemctl", systemctlArgs(units)...)
	command.Env = append(os.Environ(), "TZ=UTC", "LC_ALL=C")
	return command
}

var serviceStates = func(ctx context.Context, units []string) (string, error) {
	output, err := systemctl(ctx, units).Output()
	if len(output) > 0 {
		return string(output), nil
	}
	return "", err
}

type unitState struct {
	state string
	since *string
}

const showLayout = "Mon 2006-01-02 15:04:05 MST"

func parseShow(output string) []unitState {
	var units []unitState
	for block := range strings.SplitSeq(strings.ReplaceAll(output, "\r\n", "\n"), "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		var unit unitState
		for line := range strings.SplitSeq(block, "\n") {
			key, value, _ := strings.Cut(line, "=")
			switch key {
			case "ActiveState":
				unit.state = value
			case "ActiveEnterTimestamp":
				if at, err := time.Parse(showLayout, value); err == nil {
					since := at.UTC().Format(time.RFC3339)
					unit.since = &since
				}
			}
		}
		units = append(units, unit)
	}
	return units
}

var containerState = func() (containers.State, error) {
	return containers.Read("/var/lib/kry-exec/" + containers.File)
}

func containerResult(check reporter.Check, state containers.State, err error) reporter.CheckResult {
	found := result(check, time.Now(), containers.Verdict(state, err, check.Target, time.Now()))
	found.LatencyMS = nil
	if container, listed := containers.Find(state, check.Target); listed && found.Status == "UP" && container.Started != "" {
		found.Since = &container.Started
	}
	return found
}

var (
	recheckDelay  = 5 * time.Second
	recheckBudget = 40 * time.Second
)

const rechecks = 2

func RunAll(ctx context.Context, definitions []reporter.Check) []reporter.CheckResult {
	started := time.Now()
	results := runOnce(ctx, definitions)
	for range rechecks {
		var failed []int
		for index, result := range results {
			if result.Status == "DOWN" {
				failed = append(failed, index)
			}
		}
		if len(failed) == 0 || time.Since(started) > recheckBudget {
			break
		}
		select {
		case <-ctx.Done():
			return results
		case <-time.After(recheckDelay):
		}
		again := make([]reporter.Check, len(failed))
		for position, index := range failed {
			again[position] = definitions[index]
		}
		for position, result := range runOnce(ctx, again) {
			results[failed[position]] = result
		}
	}
	return results
}

func runOnce(ctx context.Context, definitions []reporter.Check) []reporter.CheckResult {
	results := make([]reporter.CheckResult, len(definitions))
	semaphore := make(chan struct{}, 4)
	var wait sync.WaitGroup
	var services []int
	var state *containers.State
	var stateErr error

	for index, definition := range definitions {
		if definition.Kind == "SERVICE" {
			services = append(services, index)
			continue
		}
		if definition.Kind == "CONTAINER" {
			if state == nil {
				read, err := containerState()
				state, stateErr = &read, err
			}
			results[index] = containerResult(definition, *state, stateErr)
			continue
		}
		wait.Add(1)
		go func() {
			defer wait.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			results[index] = Run(ctx, definition)
		}()
	}
	if len(services) > 0 {
		runServices(ctx, definitions, services, results)
	}
	wait.Wait()
	return results
}

func timeoutOf(check reporter.Check) time.Duration {
	timeout := time.Duration(check.TimeoutSeconds) * time.Second
	if timeout < time.Second || timeout > 30*time.Second {
		return 10 * time.Second
	}
	return timeout
}

func runServices(ctx context.Context, definitions []reporter.Check, services []int, results []reporter.CheckResult) {
	timeout := time.Duration(0)
	var units []string
	for _, index := range services {
		if validUnit(definitions[index].Target) {
			timeout = max(timeout, timeoutOf(definitions[index]))
			units = append(units, definitions[index].Target)
		}
	}
	var states []unitState
	var err error
	if len(units) > 0 {
		serviceCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		var output string
		output, err = serviceStates(serviceCtx, units)
		states = parseShow(output)
		if err == nil && len(states) != len(units) {
			err = fmt.Errorf("systemctl answered %d of %d units", len(states), len(units))
		}
	}
	asked := 0
	for _, index := range services {
		var unit unitState
		failure := errors.New("invalid service unit")
		if validUnit(definitions[index].Target) {
			failure = err
			if err == nil {
				unit = states[asked]
				if unit.state != "active" {
					failure = errors.New(cmp.Or(unit.state, "systemctl gave no answer"))
				}
			}
			asked++
		}
		found := result(definitions[index], time.Now(), failure)
		found.LatencyMS = nil
		if failure == nil {
			found.Since = unit.since
		}
		results[index] = found
	}
}

func Run(ctx context.Context, check reporter.Check) reporter.CheckResult {
	checkCtx, cancel := context.WithTimeout(ctx, timeoutOf(check))
	defer cancel()

	started := time.Now()
	var err error
	switch check.Kind {
	case "HTTP":
		err = runHTTP(checkCtx, check.Target)
	case "TCP":
		err = runTCP(checkCtx, check.Target)
	case "SERVICE":
		results := make([]reporter.CheckResult, 1)
		runServices(ctx, []reporter.Check{check}, []int{0}, results)
		return results[0]
	case "CONTAINER":
		state, readErr := containerState()
		return containerResult(check, state, readErr)
	default:
		err = fmt.Errorf("unsupported check kind")
	}
	return result(check, started, err)
}

func result(check reporter.Check, started time.Time, err error) reporter.CheckResult {
	latency := time.Since(started).Milliseconds()
	checkedAt := time.Now().UTC().Format(time.RFC3339)
	if err != nil {
		message := truncate(err.Error(), 500)
		return reporter.CheckResult{
			CheckID: check.ID, Status: "DOWN", LatencyMS: &latency,
			Message: &message, CheckedAt: checkedAt,
		}
	}
	return reporter.CheckResult{
		CheckID: check.ID, Status: "UP", LatencyMS: &latency,
		CheckedAt: checkedAt,
	}
}

func runHTTP(ctx context.Context, target string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "kry-agent-check")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode >= 500 {
		return fmt.Errorf("HTTP %d", response.StatusCode)
	}
	return nil
}

func runTCP(ctx context.Context, target string) error {
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	return connection.Close()
}

func validUnit(target string) bool {
	return target != "" && !strings.ContainsAny(target, " \t\r\n/\\;&|`$(){}[]")
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
