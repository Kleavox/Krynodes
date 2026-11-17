package actions

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

func (e Executor) dropMember(ctx context.Context, request Request, args map[string]string) Result {
	defer e.lockNetwork()()
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
	defer e.lockNetwork()()
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
