package actions

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/recipes"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const firewallFile = "firewall.json"

type closedFirewall struct {
	Closed bool              `json:"closed"`
	Tool   string            `json:"tool,omitempty"`
	Open   []network.Opening `json:"open"`
	Other  []string          `json:"other,omitempty"`
	Known  []string          `json:"known,omitempty"`
	Drift  []string          `json:"drift,omitempty"`
}

func (e Executor) readFirewall() closedFirewall {
	state, _ := readState[closedFirewall](e.StateDir, firewallFile)
	return state
}

func (e Executor) networkPort() string {
	if record := e.readNetwork(); record.Joined && record.Port != 0 {
		return strconv.Itoa(record.Port)
	}
	return ""
}

func (e Executor) rememberClosed(ctx context.Context, env recipes.Env, ports string) error {
	open, err := network.ParseOpenings(ports)
	if err != nil {
		return err
	}
	rules := recipes.ReadRules(ctx, env)
	other := recipes.Adopt(ctx, env, rules, e.networkPort()).Other
	return writeJSON(e.StateDir, firewallFile, closedFirewall{Closed: true, Tool: rules.Tool, Open: open, Other: other, Known: rules.Lines}, 0o640)
}

func (e Executor) keepUnseen(ctx context.Context, env recipes.Env, ports string) string {
	shown, _ := readState[securityState](e.StateDir, "security.json")
	listed, err := network.ParseOpenings(ports)
	rules := recipes.ReadRules(ctx, env)
	if shown.Firewall == nil || err != nil || !rules.Active {
		return ports
	}
	key := func(opening network.Opening) func(network.Opening) bool {
		return func(other network.Opening) bool { return other.Key() == opening.Key() }
	}
	for _, opening := range recipes.Adopt(ctx, env, rules, e.networkPort()).Open {
		if !slices.ContainsFunc(shown.Firewall.Open, key(opening)) && !slices.ContainsFunc(listed, key(opening)) {
			listed = append(listed, opening)
			ports = strings.TrimPrefix(ports+","+opening.String(), ",")
		}
	}
	return ports
}

func (e Executor) reopenNetwork(ctx context.Context) {
	record := e.readNetwork()
	if !record.Joined || record.Port == 0 {
		return
	}
	for _, command := range network.Open(record.Firewall, record.Port) {
		if err := e.networkCommand(ctx, command[0], command[1:]...); err != nil {
			log.Printf("open the private network's port again: %v", err)
			return
		}
	}
}

func (e Executor) learnRules(ctx context.Context, before []string) {
	state := e.readFirewall()
	if !state.Closed || before == nil {
		return
	}
	after := recipes.ReadRules(ctx, e.recipeEnv()).Lines
	known := []string{}
	for _, line := range after {
		if slices.Contains(state.Known, line) || !slices.Contains(before, line) {
			known = append(known, line)
		}
	}
	gone := func(line string) bool { return !slices.Contains(after, line) }
	state.Known, state.Drift, state.Other = known, slices.DeleteFunc(state.Drift, gone), slices.DeleteFunc(state.Other, gone)
	if err := writeJSON(e.StateDir, firewallFile, state, 0o640); err != nil {
		log.Printf("remember the firewall's rules: %v", err)
	}
}

func fromText(opening network.Opening) string {
	switch opening.From {
	case network.FromEveryone:
		return "everyone"
	case network.FromTailscale:
		return "Tailscale"
	}
	return strings.Join(opening.Addresses, ", ")
}

func (e Executor) changeFirewall(ctx context.Context, request Request, command Command) Result {
	if request.Name != "firewall" {
		return e.refuse(request.ID, fmt.Errorf("%s has no ports to open", request.Name))
	}
	state := e.readFirewall()
	if !state.Closed {
		return e.refuse(request.ID, errors.New("the firewall is not closed by Krynodes; close everything else first"))
	}
	env, port := e.recipeEnv(), e.networkPort()
	key := command.Args["port"] + "/" + command.Args["protocol"]
	at := slices.IndexFunc(state.Open, func(opening network.Opening) bool { return opening.Key() == key })
	var output string
	switch request.Action {
	case "open":
		opening, err := network.ParseOpening(command.Args["port"], command.Args["protocol"], command.Args["from"])
		if err != nil {
			return e.refuse(request.ID, err)
		}
		var before *network.Opening
		if at >= 0 {
			before = &state.Open[at]
		}
		if err := recipes.OpenPort(ctx, env, before, opening, port); err != nil {
			return e.refuse(request.ID, err)
		}
		if at >= 0 {
			state.Open[at] = opening
		} else {
			state.Open = append(state.Open, opening)
		}
		output = opening.Key() + " is open to " + fromText(opening)
	case "close":
		if at < 0 {
			return e.refuse(request.ID, fmt.Errorf("%.20s is not an open port", key))
		}
		if err := recipes.ClosePort(ctx, env, state.Open[at], port); err != nil {
			return e.refuse(request.ID, err)
		}
		state.Open = slices.Delete(state.Open, at, at+1)
		output = key + " is closed"
	case "putback":
		rule := command.Args["rule"]
		if err := recipes.RemoveRule(ctx, env, rule, port); err != nil {
			return e.refuse(request.ID, err)
		}
		same := func(line string) bool { return line == rule }
		state.Other, state.Drift, state.Known = slices.DeleteFunc(state.Other, same), slices.DeleteFunc(state.Drift, same), slices.DeleteFunc(state.Known, same)
		output = "the rule is gone from the firewall"
	}
	if err := writeJSON(e.StateDir, firewallFile, state, 0o640); err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: output, FinishedAt: e.stamp()}
}

func (e Executor) firewallDrift(ctx context.Context) {
	state := e.readFirewall()
	if !state.Closed || e.hostBusy(ctx) {
		return
	}
	rules := recipes.LiveRules(ctx, e.recipeEnv())
	if rules.Tool == "" {
		return
	}
	hour := strconv.FormatInt(e.Now().Truncate(time.Hour).Unix(), 10)
	drift := recipes.Drift(ctx, e.recipeEnv(), rules, state.Known, e.networkPort())
	for _, line := range drift {
		e.event("firewall", "firewall:"+shortHash(line, hour), map[string]string{"rule": line, "item": line})
	}
	if !slices.Equal(drift, state.Drift) {
		state.Drift = drift
		writeJSON(e.StateDir, firewallFile, state, 0o640)
	}
}

func (e Executor) acceptFirewall(request Request, rule string) Result {
	state := e.readFirewall()
	if !state.Closed {
		return e.refuse(request.ID, errors.New("the firewall is not closed by Krynodes"))
	}
	if slices.Contains(state.Known, rule) {
		return Result{ID: request.ID, OK: true, Output: "already accepted", FinishedAt: e.stamp()}
	}
	state.Known = append(state.Known, rule)
	state.Drift = slices.DeleteFunc(state.Drift, func(line string) bool { return line == rule })
	opening, single := recipes.OpeningOf(state.Tool, rule)
	if single && !slices.ContainsFunc(state.Open, func(open network.Opening) bool { return open.Key() == opening.Key() }) {
		state.Open = append(state.Open, opening)
	} else {
		state.Other = append(state.Other, rule)
	}
	if err := writeJSON(e.StateDir, firewallFile, state, 0o640); err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: "accepted: it no longer warns", FinishedAt: e.stamp()}
}

func (e Executor) adoptable(ctx context.Context) *reporter.Firewall {
	if e.readFirewall().Closed {
		return nil
	}
	env := e.recipeEnv()
	rules := recipes.ReadRules(ctx, env)
	if !rules.Active {
		return nil
	}
	adopted := recipes.Adopt(ctx, env, rules, e.networkPort())
	return fitReport(&reporter.Firewall{Open: adopted.Open, Other: adopted.Other})
}

const (
	reportedOpen  = 256
	reportedLines = 100
	reportedWidth = 300
)

func fitLines(lines []string) []string {
	fit := []string{}
	for _, line := range lines {
		if len(fit) < reportedLines && len(line) <= reportedWidth {
			fit = append(fit, line)
		}
	}
	return fit
}

func fitReport(report *reporter.Firewall) *reporter.Firewall {
	report.Open = append([]network.Opening{}, report.Open[:min(len(report.Open), reportedOpen)]...)
	report.Other = fitLines(report.Other)
	if report.Drift != nil {
		report.Drift = fitLines(report.Drift)
	}
	return report
}

func (e Executor) firewallReport(cached *reporter.Firewall) *reporter.Firewall {
	state := e.readFirewall()
	if !state.Closed {
		return cached
	}
	return fitReport(&reporter.Firewall{Closed: true, Open: state.Open, Other: state.Other, Drift: state.Drift})
}

const exitNodeState = "exit-node.json"

type exitNodeRecord struct {
	Masquerade string `json:"masquerade,omitempty"`
}

func (e Executor) masquerade(ctx context.Context, on bool) error {
	if !on {
		record, _ := readState[exitNodeRecord](e.StateDir, exitNodeState)
		if record.Masquerade == "" {
			return nil
		}
		if err := e.firewall(ctx, "firewall-cmd", "--permanent", "--zone="+record.Masquerade, "--remove-masquerade"); err != nil {
			return fmt.Errorf("stop masquerading for the exit node: %w", err)
		}
		os.Remove(filepath.Join(e.StateDir, exitNodeState))
		return e.firewall(ctx, "firewall-cmd", "--reload")
	}
	env := e.recipeEnv()
	if recipes.Detect(env).Family != recipes.RHEL {
		return nil
	}
	rules := recipes.ReadRules(ctx, env)
	if rules.Tool != "firewalld" || !rules.Active || e.firewall(ctx, "firewall-cmd", "--permanent", "--zone="+rules.Zone, "--query-masquerade") == nil {
		return nil
	}
	if err := e.firewall(ctx, "firewall-cmd", "--permanent", "--zone="+rules.Zone, "--add-masquerade"); err != nil {
		return fmt.Errorf("firewalld could not masquerade for the exit node: %w", err)
	}
	if err := writeJSON(e.StateDir, exitNodeState, exitNodeRecord{Masquerade: rules.Zone}, 0o640); err != nil {
		return err
	}
	return e.firewall(ctx, "firewall-cmd", "--reload")
}
