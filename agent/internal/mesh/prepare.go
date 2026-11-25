package mesh

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/platform"
)

const tools = "wireguard-tools"

var errJoined = errors.New("this server is already in the private network")

func (m *Mesh) platform() platform.Env {
	return platform.Env{Root: m.Root, Run: platform.Runner(m.Run)}
}

func (m *Mesh) tablesPackage() string {
	if manager := platform.Detect(m.platform()).Manager; manager == "dnf" || manager == "yum" {
		return "iptables-nft"
	}
	return "iptables"
}

func (m *Mesh) purgeTables(ctx context.Context, current *record) error {
	if !current.Iptables {
		return nil
	}
	pkg := m.tablesPackage()
	if platform.Alone(ctx, m.platform(), pkg) {
		if err := platform.Purge(ctx, m.platform(), pkg); err != nil {
			return fmt.Errorf("remove %s: %w", pkg, err)
		}
	} else {
		log.Printf("private network: %s was kept because other packages need it", pkg)
	}
	current.Iptables = false
	return nil
}

func (m *Mesh) locked(change func(*record) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, err := m.load()
	if err != nil {
		return err
	}
	if err := change(&current); err != nil {
		return err
	}
	return m.save(current)
}

func notJoined(current *record) error {
	if current.Joined {
		return errJoined
	}
	return nil
}

func (m *Mesh) prepare(ctx context.Context, args map[string]string) (string, error) {
	networkRange, port, parent, err := network.PrepareArgs(args)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	current, err := m.load()
	m.mu.Unlock()
	if err != nil {
		return "", err
	}
	if err := notJoined(&current); err != nil {
		return "", err
	}
	found, reason, err := m.read(ctx)
	switch {
	case err != nil:
		return "", err
	case reason != "":
		return "", errors.New(reason)
	case !found.Free(port):
		return "", fmt.Errorf("%d/udp is taken on this server; check it again", port)
	case network.Clashes(networkRange, found.Used):
		return "", fmt.Errorf("%s is already used on this server", networkRange)
	}
	var wanted, installed []string
	var failed error
	tablesPackage := m.tablesPackage()
	if !found.Tools {
		wanted = append(wanted, tools)
	}
	if !found.Iptables {
		wanted = append(wanted, tablesPackage)
	}
	if len(wanted) > 0 {
		installed, failed = platform.Install(ctx, m.platform(), wanted...)
		if failed == nil && !found.Iptables {
			if said := m.tables(ctx); said != "" {
				failed = errors.New(said)
			}
		}
	}
	keys, keyErr := network.Load(m.keysDir(), true)
	saved := m.locked(func(current *record) error {
		if err := notJoined(current); err != nil {
			return err
		}
		current.Tools = current.Tools || slices.Contains(installed, tools)
		current.Iptables = current.Iptables || slices.Contains(installed, tablesPackage)
		if failed == nil && keyErr == nil {
			current.Prepared = &prepared{Range: networkRange, Port: port, MTU: found.MTU, Parent: parent}
		}
		return nil
	})
	switch {
	case failed != nil:
		return "", errors.Join(fmt.Errorf("install %s: %w", strings.Join(wanted, " and "), failed), saved)
	case keyErr != nil:
		return "", errors.Join(keyErr, saved)
	case saved != nil:
		return "", saved
	}
	return answer(struct {
		Key    string `json:"key"`
		Signer string `json:"signer"`
		Port   int    `json:"port"`
		MTU    *int   `json:"mtu"`
	}{keys.Public, keys.Signer, port, found.MTU})
}

func (m *Mesh) unprepare(ctx context.Context, args map[string]string) (string, error) {
	if err := none(args, "unprepare"); err != nil {
		return "", err
	}
	found, _, err := m.read(ctx)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, err := m.load()
	if err != nil {
		return "", err
	}
	if current.Joined {
		return "", errors.New("this server is in the private network; remove it from the network instead")
	}
	var problems []error
	if current.Tools && len(found.Others) == 0 {
		if err := platform.Purge(ctx, m.platform(), tools); err != nil {
			problems = append(problems, fmt.Errorf("remove %s: %w", tools, err))
		} else {
			current.Tools = false
		}
	}
	if err := m.purgeTables(ctx, &current); err != nil {
		problems = append(problems, err)
	}
	current.Prepared = nil
	if err := m.save(current); err != nil {
		problems = append(problems, err)
	}
	if err := errors.Join(problems...); err != nil {
		return "", err
	}
	return "Removed what Krynodes prepared; the network keys stay.", nil
}

func (m *Mesh) rekey(ctx context.Context, args map[string]string) (string, error) {
	if err := none(args, "rekey"); err != nil {
		return "", err
	}
	node, err := m.self()
	if err != nil {
		return "", err
	}
	sealKey := m.SealKey()
	if sealKey == "" {
		return "", errors.New("this server has no seal key")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, err := m.load()
	if err != nil {
		return "", err
	}
	if _, err := network.Load(m.keysDir(), false); err != nil {
		return "", errors.New("this server has no network keys")
	}
	keys, err := m.nextKey(&current, node)
	if err != nil {
		return "", err
	}
	if current.Joined && current.Document != nil {
		if err := m.reconfigure(ctx, current, true); err != nil {
			return "", fmt.Errorf("the new key is made, but kry0 still runs the old one: %w", err)
		}
	}
	return answer(struct {
		Key         string `json:"key"`
		Signer      string `json:"signer"`
		Fingerprint string `json:"fingerprint"`
		Signature   string `json:"signature"`
	}{keys.Public, keys.Signer, network.Fingerprint(keys.Public, keys.Signer, sealKey), current.Announce.Signature})
}

func (m *Mesh) drop(ctx context.Context, args map[string]string) (string, error) {
	node, key := args["node"], args["key"]
	address, err := netip.ParseAddr(args["address"])
	raw, keyErr := base64.StdEncoding.DecodeString(key)
	if len(args) != 3 || node == "" || len(node) > 64 || err != nil || !address.Is4() || keyErr != nil || len(raw) != 32 {
		return "", errors.New("a drop names a member, its key and its address")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, err := m.load()
	if err != nil {
		return "", err
	}
	if !current.Joined || current.Document == nil {
		return "This server is not in the private network.", nil
	}
	self, err := m.self()
	if err != nil {
		return "", err
	}
	own, _ := member(*current.Document, self)
	mine := []string{own.Key}
	if keys, err := network.Load(m.keysDir(), false); err == nil {
		mine = append(mine, keys.Public)
	}
	if node == self || slices.Contains(mine, key) || address.String() == own.Address {
		return "", errors.New("a server does not drop itself")
	}
	changed := false
	add := func(list *[]string, value string) {
		if !slices.Contains(*list, value) {
			*list = append(*list, value)
			changed = true
		}
	}
	add(&current.Applied.Blocked, key)
	add(&current.Dropped, address.String())
	peers := []string{key}
	cut := func(document network.Document) network.Document {
		document.Members = slices.Clone(document.Members)
		for index, entry := range document.Members {
			if entry.Node == node || entry.Key == key {
				add(&current.Applied.Blocked, entry.Key)
				if !slices.Contains(peers, entry.Key) {
					peers = append(peers, entry.Key)
				}
				if !entry.Cut {
					document.Members[index].Cut, changed = true, true
				}
			}
		}
		return document
	}
	document := cut(*current.Document)
	if current.Next != nil {
		current.Next = &staged{Document: cut(current.Next.Document), Dropped: slices.Clone(current.Next.Dropped)}
		add(&current.Next.Dropped, address.String())
	}
	if !changed {
		return "Already dropped.", nil
	}
	slices.Sort(current.Applied.Blocked)
	current.Document = &document
	if err := m.save(current); err != nil {
		return "", err
	}
	if err := m.enforce(ctx, m.view(current), current.Dropped); err != nil {
		return "", fmt.Errorf("the drop is recorded, but the rules are not in place: %w", err)
	}
	var problems []string
	for _, peer := range peers {
		if err := m.command(ctx, "wg", "set", network.Interface, "peer", peer, "remove"); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) > 0 {
		return "", fmt.Errorf("the rules drop %s, but kry0 still has its peer: %s", address, strings.Join(problems, "; "))
	}
	if err := m.reconfigure(ctx, current, false); err != nil {
		return "", fmt.Errorf("kry0 no longer has %s, but kry0.conf still names it: %w", address, err)
	}
	return "Dropped " + address.String() + ".", nil
}
