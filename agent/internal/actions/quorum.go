package actions

import (
	"errors"
	"fmt"
	"slices"
)

type quorumInput struct {
	Current struct {
		Core     []string          `json:"core"`
		Access   []string          `json:"access"`
		Accounts map[string]string `json:"accounts"`
	} `json:"current"`
	Change struct {
		Core     []string          `json:"core"`
		Access   []string          `json:"access"`
		Accounts map[string]string `json:"accounts"`
	} `json:"change"`
	Approvals []string `json:"approvals"`
	Unsynced  []string `json:"unsynced"`
}

var errWithAccess = errors.New("needs approval from another device that reaches this server")

const otherAccount = "from another account or a passkey that is not synced"

func quorum(devices int) int {
	if devices > 2 {
		return 2
	}
	return 1
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, item := range a {
		if !slices.Contains(b, item) {
			return false
		}
	}
	return true
}

func evaluateQuorum(in quorumInput) error {
	var approvers []string
	for _, id := range in.Approvals {
		if !slices.Contains(approvers, id) {
			approvers = append(approvers, id)
		}
	}
	if len(approvers) == 0 {
		return errors.New("needs an approval")
	}
	for _, id := range approvers {
		if !slices.Contains(in.Current.Core, id) {
			return errors.New("an approval comes from a device the servers do not trust")
		}
	}
	core := in.Change.Core
	if core == nil {
		core = in.Current.Core
	}
	for _, id := range in.Change.Access {
		if !slices.Contains(core, id) {
			return errors.New("access names a device the servers do not trust")
		}
	}
	owners, named := in.Current.Accounts, in.Change.Accounts
	stored := slices.ContainsFunc(in.Current.Core, func(id string) bool { return owners[id] != "" })
	unnamed := func(id string) bool { return named[id] == "" }
	if (stored || slices.ContainsFunc(in.Change.Core, func(id string) bool { return named[id] != "" })) && slices.ContainsFunc(in.Change.Core, unnamed) {
		return errors.New("every passkey needs its account")
	}
	var moved []string
	for _, id := range in.Change.Core {
		if slices.Contains(in.Current.Core, id) && named[id] != owners[id] {
			moved = append(moved, id)
		}
	}
	coreChanged := in.Change.Core != nil && (!sameSet(in.Change.Core, in.Current.Core) || len(moved) > 0)
	need := quorum(len(in.Current.Core))
	var accounts []string
	for _, id := range in.Current.Core {
		if owners[id] != "" && !slices.Contains(accounts, owners[id]) {
			accounts = append(accounts, owners[id])
		}
	}
	strict := need == 2 && len(accounts) > 1 && !slices.ContainsFunc(approvers, func(id string) bool { return slices.Contains(in.Unsynced, id) })
	if coreChanged && len(approvers) < need {
		missing := need - len(approvers)
		plural := "s"
		if missing == 1 {
			plural = ""
		}
		tail := ""
		if strict {
			tail = ", " + otherAccount
		}
		return fmt.Errorf("needs %d more approval%s%s", missing, plural, tail)
	}
	for _, id := range moved {
		if owners[id] != "" && !slices.ContainsFunc(approvers, func(approver string) bool { return owners[approver] == owners[id] }) {
			return errors.New("needs approval from a passkey of the account it leaves")
		}
	}
	if coreChanged && strict {
		var signing []string
		for _, id := range approvers {
			if !slices.Contains(signing, owners[id]) {
				signing = append(signing, owners[id])
			}
		}
		if len(signing) < 2 {
			return errors.New("needs approval from another account's passkey, or from one that is not synced")
		}
	}
	for _, id := range in.Change.Access {
		if slices.Contains(in.Current.Access, id) {
			continue
		}
		others := slices.DeleteFunc(slices.Clone(approvers), func(approver string) bool { return approver == id })
		if slices.ContainsFunc(others, func(approver string) bool { return slices.Contains(in.Current.Access, approver) }) {
			continue
		}
		if slices.ContainsFunc(in.Current.Access, func(member string) bool { return member != id }) {
			return errWithAccess
		}
		rest := slices.DeleteFunc(slices.Clone(in.Current.Core), func(member string) bool { return member == id })
		need := max(1, min(quorum(len(in.Current.Core)), len(rest)))
		if len(others) < need {
			if need == 1 {
				return errors.New("needs approval from another trusted device")
			}
			return errors.New("needs approval from two other trusted devices")
		}
	}
	for _, id := range in.Current.Access {
		if slices.Contains(in.Change.Access, id) {
			continue
		}
		if coreChanged && !slices.Contains(core, id) {
			continue
		}
		if !slices.ContainsFunc(approvers, func(approver string) bool {
			return approver == id || slices.Contains(in.Current.Access, approver)
		}) {
			return errWithAccess
		}
	}
	return nil
}
