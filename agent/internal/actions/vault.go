package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/cloudflare"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/seal"
	"github.com/Kleavox/krynodes/agent/internal/shamir"
)

const cloudflaredImage = "cloudflare/cloudflared:2026.9.3@sha256:072c067d25ccbe61d46e18f0d0723255f2bb5304f7317caa95b27031520ff92c"

var (
	hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	pathPattern     = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,200}$`)
	setPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type vaultPiece struct {
	Set   string `json:"set"`
	Piece []byte `json:"piece"`
}

type vaultFile struct {
	Set     string `json:"set"`
	Holders int    `json:"holders"`
	Piece   []byte `json:"piece"`
}

type webAddress struct {
	Project   string `json:"project"`
	Service   string `json:"service"`
	Container string `json:"container"`
	Network   string `json:"network"`
	Domain    string `json:"domain"`
	Tunnel    string `json:"tunnel"`
	Account   string `json:"account"`
}

func (e Executor) readVault() (vaultFile, error) {
	file, err := readState[vaultFile](e.StateDir, "vault.json")
	if err != nil {
		return file, err
	}
	if file.Set == "" || len(file.Piece) == 0 {
		return file, errors.New("this server holds no piece of the Cloudflare token")
	}
	return file, nil
}

func (e Executor) vaultReport() *reporter.VaultReport {
	file, err := e.readVault()
	if err != nil {
		return nil
	}
	return &reporter.VaultReport{Set: file.Set, Holders: file.Holders}
}

func (e Executor) cloudflare(token []byte) *cloudflare.Client {
	return &cloudflare.Client{Token: string(token), Base: e.CloudflareBase, HTTP: e.CloudflareHTTP}
}

func (e Executor) token(request Request) ([]byte, error) {
	own, err := e.readVault()
	if err != nil {
		return nil, err
	}
	pieces := [][]byte{own.Piece}
	if request.Attachment != "" {
		var other vaultPiece
		if err := e.opened(request.Attachment, &other); err != nil {
			return nil, fmt.Errorf("the second piece: %w", err)
		}
		if other.Set != own.Set {
			return nil, errors.New("the second piece belongs to another split; spread the token again")
		}
		pieces = append(pieces, other.Piece)
	}
	return shamir.Combine(pieces)
}

func (e Executor) vault(ctx context.Context, request Request) Result {
	if err := expired(request, e.Now()); err != nil {
		return e.refuse(request.ID, err)
	}
	command, err := e.authorize(request)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	ok := func(output string) Result {
		return Result{ID: request.ID, OK: true, Output: output, FinishedAt: e.stamp()}
	}
	switch request.Action {
	case "store":
		sealed := command.Piece
		if sealed == "" {
			sealed = request.Attachment
		}
		var piece vaultPiece
		if err := e.opened(sealed, &piece); err != nil {
			return e.refuse(request.ID, fmt.Errorf("the piece: %w", err))
		}
		holders, err := strconv.Atoi(command.Args["holders"])
		if err != nil || holders < 1 || !setPattern.MatchString(command.Args["set"]) || piece.Set != command.Args["set"] || len(piece.Piece) < 2 {
			return e.refuse(request.ID, errors.New("the piece belongs to another split"))
		}
		if err := writeJSON(e.StateDir, "vault.json", vaultFile{Set: piece.Set, Holders: holders, Piece: piece.Piece}, 0o600); err != nil {
			return e.failed(request, err, "")
		}
		return ok("stored")
	case "release":
		own, err := e.readVault()
		if err != nil {
			return e.refuse(request.ID, err)
		}
		if set := command.Args["set"]; set != "" && set != own.Set {
			return e.refuse(request.ID, errors.New("this server holds a piece of another split"))
		}
		encoded, _ := json.Marshal(vaultPiece{Set: own.Set, Piece: own.Piece})
		sealed, err := seal.Seal(command.Args["key"], encoded)
		if err != nil {
			return e.refuse(request.ID, err)
		}
		return ok(sealed)
	case "reshare":
		return e.reshare(ctx, request, command)
	case "forget":
		if err := os.Remove(filepath.Join(e.StateDir, "vault.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return e.failed(request, err, "")
		}
		return ok("forgotten")
	}
	return e.refuse(request.ID, fmt.Errorf("unknown action %q", request.Action))
}

func (e Executor) reshare(ctx context.Context, request Request, command Command) Result {
	if !setPattern.MatchString(command.Args["set"]) {
		return e.refuse(request.ID, errors.New("the new split has no valid id"))
	}
	type holder struct{ node, key string }
	var holders []holder
	for entry := range strings.SplitSeq(command.Args["holders"], ",") {
		node, key, found := strings.Cut(entry, ":")
		if !found || node == "" || key == "" {
			return e.refuse(request.ID, errors.New("the holders are not valid"))
		}
		holders = append(holders, holder{node, key})
	}
	token, err := e.token(request)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	split, err := shamir.Split(token, len(holders))
	if err != nil {
		return e.refuse(request.ID, err)
	}
	sealed := map[string]string{}
	for index, entry := range holders {
		encoded, _ := json.Marshal(vaultPiece{Set: command.Args["set"], Piece: split[index]})
		if sealed[entry.node], err = seal.Seal(entry.key, encoded); err != nil {
			return e.refuse(request.ID, fmt.Errorf("the key of %s: %w", entry.node, err))
		}
	}
	if gone := command.Args["cleanup"]; gone != "" {
		cf := e.cloudflare(token)
		zone, err := cf.Zone(ctx, command.Args["zone"])
		if err != nil {
			return e.failed(request, err, "")
		}
		if err := cf.Clean(ctx, zone.AccountID, zone.ID, "krynodes-"+gone); err != nil {
			return e.failed(request, err, "")
		}
	}
	output, err := json.Marshal(sealed)
	if err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: string(output), FinishedAt: e.stamp()}
}

func (e Executor) addresses() map[string]webAddress {
	found, _ := readState[map[string]webAddress](e.StateDir, "addresses.json")
	if found == nil {
		found = map[string]webAddress{}
	}
	return found
}

func (e Executor) expose(ctx context.Context, request Request, command Command, stack Stack) Result {
	args := command.Args
	hostname, zoneName, mode := args["hostname"], args["zone"], args["mode"]
	port, err := strconv.Atoi(args["port"])
	switch {
	case !hostnamePattern.MatchString(hostname) || zoneName == "" || !strings.HasSuffix(hostname, "."+zoneName):
		return e.refuse(request.ID, fmt.Errorf("%q is not a name under %s", hostname, zoneName))
	case err != nil || port < 1 || port > 65535:
		return e.refuse(request.ID, errors.New("the port must be 1 to 65535"))
	case !ValidTarget("docker", args["service"]):
		return e.refuse(request.ID, errors.New("name the service to open"))
	case mode != "allow" && mode != "path" && mode != "everyone":
		return e.refuse(request.ID, fmt.Errorf("unknown access %q", mode))
	case mode == "path" && !pathPattern.MatchString(args["path"]):
		return e.refuse(request.ID, errors.New("the path must start with /"))
	}
	token, err := e.token(request)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	names, err := e.docker(ctx, collectTimeout, "find", "ps", "--filter", "label=com.docker.compose.project="+stack.Project, "--filter", "label=com.docker.compose.service="+args["service"], "--format", "{{.Names}}")
	container := strings.TrimSpace(strings.Split(string(names), "\n")[0])
	if err != nil || container == "" {
		return e.refuse(request.ID, fmt.Errorf("service %s is not running", args["service"]))
	}
	networks, err := e.docker(ctx, collectTimeout, "inspect", "inspect", "--format", "{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}", container)
	network := ""
	for _, name := range strings.Fields(string(networks)) {
		if name != "host" && name != "none" {
			network = name
			break
		}
	}
	if err != nil || network == "" {
		return e.refuse(request.ID, fmt.Errorf("service %s is on the server's own network; give it a bridge network for a Web address", args["service"]))
	}
	cf := e.cloudflare(token)
	zone, err := cf.Zone(ctx, zoneName)
	if err != nil {
		return e.failed(request, err, "")
	}
	tunnel, err := cf.Tunnel(ctx, zone.AccountID, "krynodes-"+command.NodeID)
	if err != nil {
		return e.failed(request, err, "")
	}
	addresses := e.addresses()
	if previous, ok := addresses[hostname]; ok && previous.Domain != "" {
		if err := cf.Unguard(ctx, zone.AccountID, previous.Domain); err != nil {
			return e.failed(request, err, "")
		}
	}
	if err := cf.Route(ctx, zone.AccountID, tunnel, hostname, fmt.Sprintf("http://%s:%d", container, port)); err != nil {
		return e.failed(request, err, "")
	}
	if err := cf.Point(ctx, zone.ID, hostname, tunnel); err != nil {
		return e.refuse(request.ID, err)
	}
	domain := ""
	switch mode {
	case "allow":
		domain = hostname
	case "path":
		domain = hostname + args["path"]
	}
	if domain != "" {
		if err := cf.Guard(ctx, zone.AccountID, domain, args["aud"]); err != nil {
			return e.failed(request, err, "")
		}
	}
	tunnelToken, err := cf.TunnelToken(ctx, zone.AccountID, tunnel)
	if err != nil {
		return e.failed(request, err, "")
	}
	if err := e.ensureTunnel(ctx, tunnelToken); err != nil {
		return e.failed(request, err, "")
	}
	if !slices.ContainsFunc(mapValues(addresses), func(address webAddress) bool { return address.Network == network }) {
		e.docker(ctx, collectTimeout, "connect", "network", "connect", network, TunnelContainer)
	}
	addresses[hostname] = webAddress{Project: stack.Project, Service: args["service"], Container: container, Network: network, Domain: domain, Tunnel: tunnel, Account: zone.AccountID}
	if err := writeJSON(e.StateDir, "addresses.json", addresses, 0o640); err != nil {
		return e.failed(request, err, "")
	}
	expires, _ := cf.Expires(ctx, zone.AccountID)
	output, _ := json.Marshal(map[string]string{"hostname": hostname, "expires": expires})
	return Result{ID: request.ID, OK: true, Output: string(output), FinishedAt: e.stamp()}
}

func mapValues(addresses map[string]webAddress) []webAddress {
	values := make([]webAddress, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, address)
	}
	return values
}

func (e Executor) ensureTunnel(ctx context.Context, token string) error {
	path := filepath.Join(e.StateDir, "tunnel.env")
	wanted := "TUNNEL_TOKEN=" + token + "\n"
	current, _ := os.ReadFile(path)
	state, err := e.docker(ctx, collectTimeout, "inspect", "inspect", "--format", "{{.State.Running}}", TunnelContainer)
	if err == nil && string(current) == wanted && strings.TrimSpace(string(state)) != "false" {
		return nil
	}
	if err := os.WriteFile(path, []byte(wanted), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	if err == nil {
		e.docker(ctx, collectTimeout, "remove", "rm", "-f", TunnelContainer)
	}
	if _, err := e.docker(ctx, pullTimeout, "run", "run", "-d", "--name", TunnelContainer, "--restart", "unless-stopped", "--env-file", path, cloudflaredImage, "tunnel", "--no-autoupdate", "run"); err != nil {
		return err
	}
	for _, address := range e.addresses() {
		e.docker(ctx, collectTimeout, "connect", "network", "connect", address.Network, TunnelContainer)
	}
	return nil
}

func (e Executor) unexpose(ctx context.Context, request Request, command Command) Result {
	hostname := command.Args["hostname"]
	if !hostnamePattern.MatchString(hostname) {
		return e.refuse(request.ID, fmt.Errorf("%q is not a name", hostname))
	}
	token, err := e.token(request)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	cf := e.cloudflare(token)
	zone, err := cf.Zone(ctx, command.Args["zone"])
	if err != nil {
		return e.failed(request, err, "")
	}
	addresses := e.addresses()
	address, known := addresses[hostname]
	if known && address.Tunnel != "" {
		if err := cf.Unroute(ctx, zone.AccountID, address.Tunnel, hostname); err != nil {
			return e.failed(request, err, "")
		}
	}
	if err := cf.Unpoint(ctx, zone.ID, hostname); err != nil {
		return e.failed(request, err, "")
	}
	for _, domain := range []string{hostname, address.Domain} {
		if domain != "" {
			if err := cf.Unguard(ctx, zone.AccountID, domain); err != nil {
				return e.failed(request, err, "")
			}
		}
	}
	delete(addresses, hostname)
	if known && !slices.ContainsFunc(mapValues(addresses), func(other webAddress) bool { return other.Network == address.Network }) {
		e.docker(ctx, collectTimeout, "disconnect", "network", "disconnect", address.Network, TunnelContainer)
	}
	if len(addresses) == 0 {
		e.docker(ctx, collectTimeout, "remove", "rm", "-f", TunnelContainer)
		os.Remove(filepath.Join(e.StateDir, "tunnel.env"))
	}
	if err := writeJSON(e.StateDir, "addresses.json", addresses, 0o640); err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: "removed " + hostname, FinishedAt: e.stamp()}
}
