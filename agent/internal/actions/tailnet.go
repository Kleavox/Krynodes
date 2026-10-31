package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/config"
	"github.com/Kleavox/krynodes/agent/internal/seal"
	"github.com/Kleavox/krynodes/agent/internal/tailscale"
)

const (
	authKeySeconds = 600
	maxDevices     = 200
	joinKeyFile    = "tailscale-key"
)

func (e Executor) inspectTailnet(ctx context.Context, request Request) Result {
	if _, err := os.Stat(e.path(tailscale.Binary)); err != nil {
		return e.refuse(request.ID, errors.New("tailscale is not installed"))
	}
	status := tailscale.Status(ctx, tailscale.Runner(e.Run))
	if status.State != "running" {
		return e.refuse(request.ID, errors.New("this server is not on a tailnet"))
	}
	listening, _ := e.output(ctx, "ss", "-H", "-tuln")
	established, _ := e.output(ctx, "ss", "-H", "-tn", "state", "established")
	conntrack, _ := os.ReadFile(e.path("/proc/net/nf_conntrack"))
	used := tailscale.InUse(established, string(conntrack), status.Addresses, tailscale.Listening(listening))
	return e.answer(request, map[string]any{"at": e.stamp(), "inUse": used}, true)
}

func (e Executor) tailnetJob(ctx context.Context, request Request, command Command) Result {
	if request.Name != "tailscale" {
		return e.refuse(request.ID, fmt.Errorf("unknown action %q", request.Action))
	}
	client := command.Args["client"]
	if client == "" {
		return e.refuse(request.ID, errors.New("name the Tailscale client"))
	}
	file, err := e.readVault("tailscale")
	if err != nil {
		return e.refuse(request.ID, err)
	}
	if file.Holders > 1 && request.Attachment == "" {
		return e.refuse(request.ID, errors.New("the second piece of the Tailscale credential is missing"))
	}
	secret, err := e.secret(request, command, "tailscale")
	if err != nil {
		return e.refuse(request.ID, err)
	}
	defer clear(secret)
	api := &tailscale.API{Base: e.TailscaleBase, HTTP: e.TailscaleHTTP, ID: client, Secret: string(secret)}
	switch request.Action {
	case "policy":
		return e.readPolicy(ctx, request, api)
	case "save":
		return e.savePolicy(ctx, request, command, api)
	case "key":
		authKey, err := api.AuthKey(ctx, []string{tailscale.Tag}, authKeySeconds)
		if err != nil {
			return e.refuse(request.ID, err)
		}
		plain, _ := json.Marshal(map[string]string{"authKey": authKey})
		sealed, err := seal.Seal(command.Args["key"], plain)
		if err != nil {
			return e.refuse(request.ID, errors.New("the joining server's key is not usable"))
		}
		return Result{ID: request.ID, OK: true, Output: sealed, FinishedAt: e.stamp()}
	case "remove":
		device := command.Args["device"]
		if !targetName.MatchString(device) {
			return e.refuse(request.ID, errors.New("name the device to remove"))
		}
		if err := api.Delete(ctx, device); err != nil {
			return e.refuse(request.ID, err)
		}
		return e.answer(request, map[string]string{"removed": device}, true)
	}
	return e.refuse(request.ID, fmt.Errorf("unknown action %q", request.Action))
}

func (e Executor) readPolicy(ctx context.Context, request Request, api *tailscale.API) Result {
	body, etag, err := api.Policy(ctx)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	devices, err := api.Devices(ctx)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	policy, err := tailscale.Read(body)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	var open *string
	if policy.Open != "" {
		open = &policy.Open
	}
	return e.answer(request, map[string]any{"at": e.stamp(), "etag": etag, "kry": policy.Kry, "open": open, "block": policy.Block, "hash": tailscale.BlockHash(policy.Block), "tags": policy.Tags, "devices": devices[:min(len(devices), maxDevices)]}, true)
}

func (e Executor) savePolicy(ctx context.Context, request Request, command Command, api *tailscale.API) Result {
	args := command.Args
	var rules []tailscale.Rule
	var servers map[string][]string
	if json.Unmarshal([]byte(args["rules"]), &rules) != nil || json.Unmarshal([]byte(args["servers"]), &servers) != nil {
		return e.refuse(request.ID, errors.New("the rules are not valid"))
	}
	body, etag, err := api.Policy(ctx)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	devices, err := api.Devices(ctx)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	policy, err := tailscale.Read(body)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	if hash := tailscale.BlockHash(policy.Block); hash != args["expected"] {
		now := policy.Block
		if now == nil {
			now = []string{}
		}
		return e.answer(request, map[string]any{"saved": false, "block": hash, "changed": map[string][]string{"now": now}}, true)
	}
	var tagged []string
	if args["tag"] != "" {
		tagged = strings.Split(args["tag"], ",")
	}
	for _, id := range tagged {
		index := slices.IndexFunc(devices, func(device tailscale.Device) bool { return device.ID == id })
		if index < 0 {
			return e.refuse(request.ID, fmt.Errorf("%s is not on your tailnet", id))
		}
		if !slices.Contains(devices[index].Tags, tailscale.Tag) {
			if err := api.Tag(ctx, id, slices.Concat(devices[index].Tags, []string{tailscale.Tag})); err != nil {
				return e.refuse(request.ID, err)
			}
		}
		if err := api.NoExpiry(ctx, id); err != nil {
			return e.refuse(request.ID, err)
		}
	}
	lines, err := tailscale.Grants(rules, servers, tailscale.Rest(devices, policy.Tags))
	if err != nil {
		return e.refuse(request.ID, err)
	}
	next := tailscale.ApproveExitNodes(tailscale.Splice(body, policy, lines, args["expected"] == ""))
	if err := api.Validate(ctx, next); err != nil {
		return e.refuse(request.ID, err)
	}
	if err := api.SetPolicy(ctx, next, etag); err != nil {
		return e.refuse(request.ID, err)
	}
	members, ids := []string{}, []string{}
	for _, device := range devices {
		ids = append(ids, device.ID)
		if device.User && !slices.Contains(tagged, device.ID) {
			members = append(members, device.Addresses...)
		}
	}
	return e.answer(request, map[string]any{"saved": true, "at": e.stamp(), "etag": etag, "block": tailscale.BlockHash(lines), "lines": lines, "members": members, "devices": ids}, true)
}

func (e Executor) joinTailnet(ctx context.Context, request Request) Result {
	if _, err := os.Stat(e.path(tailscale.Binary)); err != nil {
		return e.refuse(request.ID, errors.New("tailscale is not installed"))
	}
	run := tailscale.Runner(e.Run)
	if tailscale.Status(ctx, run).State == "running" {
		return e.refuse(request.ID, errors.New("this server is already on a tailnet"))
	}
	var key struct {
		AuthKey string `json:"authKey"`
	}
	if err := e.opened(request.Attachment, &key); err != nil || !strings.HasPrefix(key.AuthKey, "tskey-") {
		return e.refuse(request.ID, errors.New("the one-time key could not be opened"))
	}
	path := filepath.Join(e.StateDir, joinKeyFile)
	defer os.Remove(path)
	if err := writeWhole(e.StateDir, joinKeyFile, []byte(key.AuthKey), 0o600); err != nil {
		return e.failed(request, err, "")
	}
	if err := tailscale.Join(ctx, e.Stream, path); err != nil {
		return e.refuse(request.ID, errors.New(strings.ReplaceAll(err.Error(), key.AuthKey, "the one-time key")))
	}
	status := tailscale.Status(ctx, run)
	return e.answer(request, struct {
		ID        *string  `json:"id"`
		Addresses []string `json:"addresses"`
		Name      *string  `json:"name"`
	}{status.ID, status.Addresses, status.Name}, true)
}

const (
	exitNodeConf = "/etc/sysctl.d/99-krynodes-exit-node.conf"
	exitNodeOff  = "exit-node-off"
	forwarding   = "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n"
	dnsSettle    = 20 * time.Second
	dnsEvery     = 2 * time.Second
)

func onOff(args map[string]string) (bool, error) {
	switch args["on"] {
	case "1":
		return true, nil
	case "0":
		return false, nil
	}
	return false, errors.New("turn it on or off")
}

func (e Executor) onTailnet(ctx context.Context, args map[string]string) (bool, error) {
	on, err := onOff(args)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(e.path(tailscale.Binary)); err != nil {
		return false, errors.New("tailscale is not installed")
	}
	if tailscale.Status(ctx, tailscale.Runner(e.Run)).State != "running" {
		return false, errors.New("this server is not on a tailnet")
	}
	return on, nil
}

func (e Executor) sysctl(ctx context.Context) error {
	if output, _, err := e.Run(ctx, "sysctl", "--system"); err != nil {
		return fmt.Errorf("sysctl --system: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (e Executor) exitNode(ctx context.Context, request Request, command Command) Result {
	on, err := e.onTailnet(ctx, command.Args)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	run, file := tailscale.Runner(e.Run), e.path(exitNodeConf)
	if !on {
		if err := tailscale.Set(ctx, run, "--advertise-exit-node=false"); err != nil {
			return e.refuse(request.ID, err)
		}
		if err := e.dropForwarding(ctx); err != nil {
			return e.failed(request, err, "")
		}
		return Result{ID: request.ID, OK: true, Output: "no longer an exit node", FinishedAt: e.stamp()}
	}
	if err := writeWhole(filepath.Dir(file), filepath.Base(file), []byte(forwarding), 0o644); err != nil {
		return e.failed(request, err, "")
	}
	err = e.sysctl(ctx)
	if err == nil {
		err = e.masquerade(ctx, true)
	}
	if err == nil {
		err = tailscale.Set(ctx, run, "--advertise-exit-node=true")
	}
	if err != nil {
		os.Remove(file)
		e.sysctl(ctx)
		e.masquerade(ctx, false)
		return e.refuse(request.ID, err)
	}
	return Result{ID: request.ID, OK: true, Output: "offered as an exit node", FinishedAt: e.stamp()}
}

func (e Executor) tailscaleDNS(ctx context.Context, request Request, command Command) Result {
	on, err := e.onTailnet(ctx, command.Args)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	run := tailscale.Runner(e.Run)
	if !on {
		if err := tailscale.Set(ctx, run, "--accept-dns=false"); err != nil {
			return e.refuse(request.ID, err)
		}
		return Result{ID: request.ID, OK: true, Output: "no longer uses Tailscale DNS", FinishedAt: e.stamp()}
	}
	cfg, err := config.Load(e.ConfigPath)
	if err != nil {
		return e.failed(request, err, "")
	}
	endpoint, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return e.failed(request, err, "")
	}
	host := endpoint.Hostname()
	if err := tailscale.Set(ctx, run, "--accept-dns=true"); err != nil {
		return e.refuse(request.ID, err)
	}
	if e.resolves(ctx, host) {
		return Result{ID: request.ID, OK: true, Output: "uses Tailscale DNS", FinishedAt: e.stamp()}
	}
	failure := fmt.Errorf("Tailscale DNS was turned back off: this server could not resolve %s with it.", host)
	if err := tailscale.Set(ctx, run, "--accept-dns=false"); err != nil {
		failure = fmt.Errorf("this server could not resolve %s with Tailscale DNS, and turning it back off failed: %w", host, err)
	}
	return e.refuse(request.ID, failure)
}

func (e Executor) resolves(ctx context.Context, host string) bool {
	timeout, every := e.HealthTimeout, e.HealthEvery
	if timeout == 0 {
		timeout = dnsSettle
	}
	if every == 0 {
		every = dnsEvery
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	lookup := e.lookupIP()
	for {
		if addresses, err := lookup(ctx, host); err == nil && len(addresses) > 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(every):
		}
	}
}

func (e Executor) dropForwarding(ctx context.Context) error {
	if err := os.Remove(e.path(exitNodeConf)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := e.sysctl(ctx); err != nil {
		log.Printf("exit node off: %v", err)
	}
	if err := e.masquerade(ctx, false); err != nil {
		log.Printf("exit node off: %v", err)
	}
	return nil
}

func (e Executor) quarantined() bool {
	if e.QuarantineMark == "" {
		return false
	}
	_, err := os.Stat(e.QuarantineMark)
	return err == nil
}

func (e Executor) leaveExitNodeWhenQuarantined(ctx context.Context) {
	if !e.quarantined() {
		return
	}
	if _, err := os.Stat(e.path(exitNodeConf)); err != nil {
		return
	}
	host := filepath.Join(e.StateDir, "host")
	if _, err := os.Stat(filepath.Join(host, exitNodeOff)); err == nil {
		return
	}
	if err := tailscale.Set(ctx, tailscale.Runner(e.Run), "--advertise-exit-node=false"); err != nil {
		log.Printf("quarantined exit node: %v", err)
		return
	}
	if err := writeJSON(host, exitNodeOff, struct{}{}, 0o640); err != nil {
		log.Printf("quarantined exit node: %v", err)
	}
}

func (e Executor) finishExitNodeOff(ctx context.Context, dir string) {
	marker := filepath.Join(dir, exitNodeOff)
	if _, err := os.Stat(marker); err != nil {
		return
	}
	os.Remove(marker)
	if !e.quarantined() {
		return
	}
	if err := e.dropForwarding(ctx); err != nil {
		log.Printf("quarantined exit node: %v", err)
	}
}
