package actions

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

const (
	tailnetFile      = "tailnet.json"
	tailnetChain     = "KRY-TAILNET"
	tailnetInterface = "tailscale0"
	maxTailnet       = 16
)

var tailnetTools = []string{"iptables", "ip6tables"}

type tailnetBlock struct {
	Addresses []string `json:"addresses"`
}

func (e Executor) dropMember(ctx context.Context, request Request, args map[string]string) Result {
	node, key := args["node"], args["key"]
	address, err := netip.ParseAddr(args["address"])
	raw, keyErr := base64.StdEncoding.DecodeString(key)
	if len(args) != 3 || node == "" || len(node) > 64 || err != nil || !address.Is4() || keyErr != nil || len(raw) != 32 {
		return e.refuse(request.ID, errors.New("a drop names a member, its key and its address"))
	}
	record := e.readNetwork()
	if !record.Joined || record.Document == nil {
		return Result{ID: request.ID, OK: true, Output: "not in the private network", FinishedAt: e.stamp()}
	}
	self, err := e.selfNode()
	if err != nil {
		return e.refuse(request.ID, err)
	}
	if node == self {
		return e.refuse(request.ID, errors.New("a server does not drop itself"))
	}
	changed := false
	add := func(list *[]string, value string) {
		if !slices.Contains(*list, value) {
			*list = append(*list, value)
			changed = true
		}
	}
	add(&record.Applied.Blocked, key)
	add(&record.Dropped, address.String())
	document := *record.Document
	document.Members = slices.Clone(document.Members)
	for index, entry := range document.Members {
		if entry.Node == node || entry.Key == key {
			add(&record.Applied.Blocked, entry.Key)
			if !entry.Cut {
				document.Members[index].Cut, changed = true, true
			}
		}
	}
	if !changed {
		return Result{ID: request.ID, OK: true, Output: "already dropped", FinishedAt: e.stamp()}
	}
	slices.Sort(record.Applied.Blocked)
	record.Document = &document
	own, ok := member(document, self)
	keys, err := network.Load(e.networkDir(), false)
	if !ok || err != nil {
		return e.failed(request, errors.New("this server has no network key"), "")
	}
	psk, err := e.presharedKeys(own, document)
	if err != nil {
		return e.failed(request, err, "")
	}
	if err := e.writeNetwork(ctx, &record, document, own, keys, psk); err != nil {
		return e.failed(request, err, "")
	}
	if err := e.saveNetwork(record); err != nil {
		return e.failed(request, err, "")
	}
	if err := e.syncRules(ctx); err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: "dropped " + address.String(), FinishedAt: e.stamp()}
}

func (e Executor) tighten(request Request, args map[string]string) Result {
	scan, err := strconv.Atoi(args["scan"])
	if len(args) != 2 || err != nil || !slices.Contains([]int{5, 10, 20}, scan) || (args["stop"] != "true" && args["stop"] != "false") {
		return e.refuse(request.ID, errors.New("a scan counts from 5, 10 or 20 places, and a stack stops or only warns"))
	}
	record := e.readNetwork()
	next := network.Knocks{Scan: scan, Stop: args["stop"] == "true"}
	if record.Tightened != nil {
		next.Scan, next.Stop = min(next.Scan, record.Tightened.Scan), next.Stop || record.Tightened.Stop
	}
	record.Tightened = &next
	if err := e.saveNetwork(record); err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: fmt.Sprintf("a scan is %d places now", next.Scan), FinishedAt: e.stamp()}
}

func tailnetAddresses(text string) ([]string, error) {
	fields := strings.Fields(text)
	if len(fields) == 0 || len(fields) > maxTailnet {
		return nil, errors.New("name one to 16 Tailscale addresses")
	}
	var addresses []string
	for _, field := range fields {
		address, err := netip.ParseAddr(field)
		if err != nil || address.Zone() != "" {
			return nil, fmt.Errorf("%q is not an address", field)
		}
		if text := address.Unmap().String(); !slices.Contains(addresses, text) {
			addresses = append(addresses, text)
		}
	}
	return addresses, nil
}

func (e Executor) blockTailnet(ctx context.Context, request Request) Result {
	args, err := asked(request)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	addresses, err := tailnetAddresses(args["addresses"])
	if err != nil || len(args) != 1 {
		return e.refuse(request.ID, errors.Join(errors.New("a block names the addresses to drop"), err))
	}
	state, _ := readState[tailnetBlock](e.StateDir, tailnetFile)
	for _, address := range addresses {
		if !slices.Contains(state.Addresses, address) && len(state.Addresses) < maxTailnet*4 {
			state.Addresses = append(state.Addresses, address)
		}
	}
	if err := writeJSON(e.StateDir, tailnetFile, state, 0o640); err != nil {
		return e.failed(request, err, "")
	}
	e.syncTailnet(ctx)
	return Result{ID: request.ID, OK: true, Output: "blocked " + strings.Join(addresses, ", ") + " on Tailscale", FinishedAt: e.stamp()}
}

func (e Executor) unblockTailnet(ctx context.Context, request Request) Result {
	command, err := e.authorize(request)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	addresses, err := tailnetAddresses(command.Args["addresses"])
	if err != nil {
		return e.refuse(request.ID, err)
	}
	state, _ := readState[tailnetBlock](e.StateDir, tailnetFile)
	state.Addresses = slices.DeleteFunc(state.Addresses, func(address string) bool { return slices.Contains(addresses, address) })
	if len(state.Addresses) == 0 {
		if err := os.Remove(filepath.Join(e.StateDir, tailnetFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return e.failed(request, err, "")
		}
		for _, tool := range tailnetTools {
			for _, parent := range []string{"INPUT", "FORWARD"} {
				e.firewall(ctx, tool, "-D", parent, "-i", tailnetInterface, "-j", tailnetChain)
			}
			e.firewall(ctx, tool, "-F", tailnetChain)
			e.firewall(ctx, tool, "-X", tailnetChain)
		}
	} else if err := writeJSON(e.StateDir, tailnetFile, state, 0o640); err != nil {
		return e.failed(request, err, "")
	}
	e.syncTailnet(ctx)
	return Result{ID: request.ID, OK: true, Output: "no longer blocks " + strings.Join(addresses, ", "), FinishedAt: e.stamp()}
}

func (e Executor) syncTailnet(ctx context.Context) {
	state, _ := readState[tailnetBlock](e.StateDir, tailnetFile)
	if len(state.Addresses) == 0 {
		return
	}
	for _, tool := range tailnetTools {
		lines := []string{"-N " + tailnetChain}
		for _, text := range state.Addresses {
			if address, err := netip.ParseAddr(text); err == nil && address.Is4() == (tool == "iptables") {
				lines = append(lines, fmt.Sprintf("-A %s -s %s/%d -j DROP", tailnetChain, address, address.BitLen()))
			}
		}
		e.firewall(ctx, tool, "-N", tailnetChain)
		if e.listed(ctx, tool, tailnetChain) != strings.Join(lines, "\n") {
			e.firewall(ctx, tool, "-F", tailnetChain)
			for _, line := range lines[1:] {
				e.firewall(ctx, tool, strings.Fields(line)...)
			}
		}
		for _, parent := range []string{"INPUT", "FORWARD"} {
			e.ensure(ctx, tool, []string{"-I", parent, "1"}, parent, []string{"-i", tailnetInterface, "-j", tailnetChain})
		}
	}
}
