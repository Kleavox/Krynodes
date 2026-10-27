package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

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
	next := tailscale.Splice(body, policy, lines, args["expected"] == "")
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
