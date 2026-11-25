package mesh

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/platform"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/safefile"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

func (m *Mesh) write(name string, data []byte, mode os.FileMode) error {
	path := m.path(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return safefile.Write(path, data, mode)
}

func (m *Mesh) send(message any) {
	if m.Send == nil {
		return
	}
	if err := m.Send(message); err != nil {
		log.Printf("private network: %v", err)
	}
}

func withHeld(document network.Document, held bool, self string) network.Document {
	if !held {
		return document
	}
	document.Members = slices.Clone(document.Members)
	for index := range document.Members {
		if document.Members[index].Node == self {
			document.Members[index].Exit = false
		}
	}
	return document
}

func (m *Mesh) view(current record) network.Document {
	return withHeld(withAnnounced(*current.Document, current.Announced), current.Held || current.NoExit, m.Trust().NodeID)
}

func between(old, next network.Document) network.Document {
	merged := next
	merged.Members = slices.Clone(next.Members)
	for _, entry := range old.Members {
		if _, ok := member(next, entry.Node); !ok {
			merged.Members = append(merged.Members, entry)
		}
	}
	merged.Allow = append(slices.Clone(next.Allow), old.Allow...)
	return merged
}

func (m *Mesh) Document(ctx context.Context, version int, signed string) reporter.Applied {
	m.mu.Lock()
	message, at, err := m.apply(ctx, version, []byte(signed))
	left := m.left
	m.left = false
	m.mu.Unlock()
	applied := reporter.Applied{Type: "applied", Version: at, OK: err == nil, Message: message}
	if err != nil {
		applied.Message = err.Error()
	}
	applied.Message = clip(applied.Message, maxMessage)
	m.send(applied)
	if left && m.Left != nil {
		m.Left()
	}
	return applied
}

func (m *Mesh) nextKey(current *record, self string) (network.Keys, error) {
	keys, err := network.Next(m.keysDir())
	if err != nil {
		return network.Keys{}, err
	}
	current.Announce = &announcement{Key: keys.Public, Signature: keys.Announce(self)}
	if err := m.save(*current); err != nil {
		return network.Keys{}, err
	}
	return keys, keys.Keep(m.keysDir())
}

func (m *Mesh) apply(ctx context.Context, version int, signed []byte) (string, int, error) {
	current, err := m.load()
	if err != nil {
		return "", version, err
	}
	if version <= current.Applied.Version {
		return "Already applied.", current.Applied.Version, nil
	}
	message, err := m.accept(ctx, current, version, signed)
	return message, version, err
}

func (m *Mesh) accept(ctx context.Context, current record, version int, signed []byte) (string, error) {
	self, err := m.self()
	if err != nil {
		return "", err
	}
	body, err := trust.VerifyDocument(m.Trust(), signed, m.Now())
	if err != nil {
		return "", err
	}
	document, err := network.Parse(body)
	if err != nil {
		return "", err
	}
	if document.Version != version {
		return "", fmt.Errorf("the signed document is version %d, not %d", document.Version, version)
	}
	hash := network.BodyHash(body)
	me, err := network.Accept(document, current.Applied, self, current.Joined)
	if errors.Is(err, network.ErrLeave) {
		return m.leaveBy(ctx, current, current.Applied.After(document, hash))
	}
	if err != nil {
		return "", err
	}
	if !current.Joined && current.Prepared == nil {
		return "", errors.New("this server is not prepared for the private network")
	}
	if !current.Joined && (document.Parent != current.Prepared.Parent || document.Range != current.Prepared.Range || me.Port != current.Prepared.Port) {
		return "", fmt.Errorf("version %d is not the one this server was prepared for; approve it again", document.Version)
	}
	keys, err := network.Load(m.keysDir(), false)
	if err != nil {
		return "", errors.New("this server has no network keys")
	}
	own := ""
	if current.Document != nil {
		if entry, ok := member(*current.Document, self); ok {
			own = entry.Key
		}
	}
	pending := current.Announce != nil && current.Announce.Key == keys.Public
	if me.Signer != keys.Signer || (me.Key != keys.Public && (!pending || me.Key != own)) {
		return "", fmt.Errorf("the document names another key for %s", me.Name)
	}
	if m.SealKey == nil || me.SealKey != m.SealKey() {
		return "", fmt.Errorf("the document names another seal key for %s", me.Name)
	}
	psk, err := m.presharedKeys(me, document)
	if err != nil {
		return "", err
	}
	next := current
	if me.Key == keys.Public {
		next.Announce = nil
	}
	if me.Key == keys.Public && me.Rekey {
		if keys, err = m.nextKey(&current, self); err != nil {
			return "", err
		}
		next.Announce = current.Announce
	}
	next.Announced = maps.Clone(current.Announced)
	for node, key := range next.Announced {
		if entry, ok := member(document, node); !ok || entry.Cut || entry.Key == key || slices.Contains(document.Blocked, key) {
			delete(next.Announced, node)
		}
	}
	next.Document, next.Prepared, next.NoExit, next.Next = &document, nil, false, nil
	next.Applied = current.Applied.After(document, hash)
	next.Dropped = slices.DeleteFunc(slices.Clone(current.Dropped), func(address string) bool {
		return slices.ContainsFunc(document.Members, func(entry network.Member) bool {
			return entry.Address == address && !entry.Cut && !slices.Contains(next.Applied.Blocked, entry.Key)
		})
	})
	message, err := m.put(ctx, current, next, keys, psk)
	if err == nil && next.Announce != nil {
		m.send(reporter.Announce{Type: "announce", Key: next.Announce.Key, Signature: next.Announce.Signature})
	}
	return message, err
}

func (m *Mesh) presharedKeys(me network.Member, document network.Document) (map[string]string, error) {
	keys := map[string]string{}
	for node, sealed := range me.PSK {
		var plain []byte
		err := errors.New("this server cannot open sealed keys")
		if m.Unseal != nil {
			plain, err = m.Unseal(sealed)
		}
		if err != nil || len(plain) != 32 {
			peer, _ := member(document, node)
			return nil, fmt.Errorf("the preshared key for %s cannot be opened on this server", peer.Name)
		}
		keys[node] = base64.StdEncoding.EncodeToString(plain)
	}
	return keys, nil
}

func (m *Mesh) exit6(document network.Document, me network.Member) bool {
	forward, _ := network.Exit(me, document.Members, m.uplink(6), 6)
	return forward != nil
}

func (m *Mesh) put(ctx context.Context, current, next record, keys network.Keys, psk map[string]string) (string, error) {
	view := m.view(next)
	self := m.Trust().NodeID
	me, _ := member(view, self)
	config := network.Render(view, me, keys.Private, psk, next.Meetings, m.exit6(view, me))
	before, err := os.ReadFile(m.path(network.ConfigPath))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	hosts, err := os.ReadFile(m.path(network.HostsPath))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	peers := false
	fail := func(step string, err error) (string, error) {
		err = fmt.Errorf("%s: %w", step, err)
		if problem := m.putBack(ctx, current, next, before, hosts, peers); problem != nil {
			err = fmt.Errorf("%w; putting the previous network back: %v", err, problem)
		}
		return "", err
	}
	rules := view
	if current.Joined && current.Document != nil {
		rules = between(m.view(current), view)
	}
	if err := m.enforce(ctx, rules, next.Dropped); err != nil {
		return fail("rules", err)
	}
	stage := current
	stage.Next = &staged{Document: *next.Document, Dropped: next.Dropped}
	if err := m.save(stage); err != nil {
		return fail("rules", err)
	}
	peers = true
	if err := m.write(network.ConfigPath, []byte(config), 0o600); err != nil {
		return fail("peers", err)
	}
	if current.Joined {
		if err := m.reload(ctx, string(before), config); err != nil {
			return fail("peers", err)
		}
		if err := m.enforce(ctx, view, next.Dropped); err != nil {
			return fail("rules", err)
		}
	} else if err := m.join(ctx, &next, me.Port, view); err != nil {
		return fail("join", err)
	}
	if err := m.writeHosts(view.Members); err != nil {
		return fail("hosts", err)
	}
	message := fmt.Sprintf("Applied version %d.", next.Applied.Version)
	if failed := m.exit(ctx, view, me); failed != nil {
		next.NoExit, stage.NoExit = true, true
		off := m.view(next)
		offMe, _ := member(off, self)
		problem := errors.Join(m.save(stage), m.enforce(ctx, off, next.Dropped), m.exit(ctx, off, offMe))
		if problem == nil && m.exit6(view, me) {
			problem = m.reconfigure(ctx, next, true)
		}
		if problem != nil {
			return fail("exit", errors.Join(failed, problem))
		}
		message = fmt.Sprintf("Applied version %d, but the exit for laptops is off: %v", next.Applied.Version, failed)
	}
	if err := m.syncRelayPorts(ctx, &next, view, me); err != nil {
		log.Printf("applied version %d, but %v", next.Applied.Version, err)
	}
	if err := m.save(next); err != nil {
		return fail("save", err)
	}
	return message, nil
}

func (m *Mesh) firewallName(ctx context.Context) string {
	state := m.firewallOf(ctx)
	switch {
	case state.firewalld:
		return "firewalld"
	case state.active:
		return "ufw"
	}
	return ""
}

func (m *Mesh) commands(ctx context.Context, commands [][]string) error {
	for _, command := range commands {
		if err := m.command(ctx, command[0], command[1:]...); err != nil {
			return err
		}
	}
	return nil
}

func (m *Mesh) join(ctx context.Context, next *record, port int, view network.Document) error {
	if !strings.HasPrefix(m.Executable, "/") {
		return errors.New("the agent does not know where it is installed")
	}
	next.Firewall = m.firewallName(ctx)
	next.Joined, next.Port = true, port
	if err := m.commands(ctx, network.Open(next.Firewall, port)); err != nil {
		return fmt.Errorf("open %d/udp: %w", port, err)
	}
	if err := m.enforce(ctx, view, next.Dropped); err != nil {
		return fmt.Errorf("rules after the firewall reload: %w", err)
	}
	if err := m.write(network.RulesDropInPath, []byte(network.RulesDropIn(m.Executable)), 0o644); err != nil {
		return err
	}
	if err := m.write(network.DropInPath, []byte(network.DropInBody), 0o644); err != nil {
		return err
	}
	if err := m.command(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := m.command(ctx, "systemctl", "enable", "--now", unit); err != nil {
		return fmt.Errorf("start kry0: %w", err)
	}
	return nil
}

func (m *Mesh) reload(ctx context.Context, before, after string) error {
	if network.NeedsRestart(before, after) {
		if err := m.command(ctx, "systemctl", "restart", unit); err != nil {
			return fmt.Errorf("restart kry0: %w", err)
		}
		return nil
	}
	file, err := os.CreateTemp(m.keysDir(), "sync-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, err = file.WriteString(network.Strip(after))
	if closed := file.Close(); err == nil {
		err = closed
	}
	if err != nil {
		return err
	}
	if err := m.command(ctx, "wg", "syncconf", network.Interface, file.Name()); err != nil {
		if again := m.command(ctx, "systemctl", "restart", unit); again != nil {
			return fmt.Errorf("update kry0: %w; restarting it also failed: %v", err, again)
		}
	}
	return nil
}

func (m *Mesh) reconfigure(ctx context.Context, current record, sync bool) error {
	view := m.view(current)
	me, ok := member(view, m.Trust().NodeID)
	if !ok {
		return errors.New("this server is not in its network document")
	}
	keys, err := network.Load(m.keysDir(), false)
	if err != nil {
		return err
	}
	psk, err := m.presharedKeys(me, *current.Document)
	if err != nil {
		return err
	}
	config := network.Render(view, me, keys.Private, psk, current.Meetings, m.exit6(view, me))
	before, _ := os.ReadFile(m.path(network.ConfigPath))
	if err := m.write(network.ConfigPath, []byte(config), 0o600); err != nil {
		return err
	}
	if !sync {
		return nil
	}
	return m.reload(ctx, string(before), config)
}

func (m *Mesh) putBack(ctx context.Context, current, next record, config, hosts []byte, peers bool) error {
	current.Next = nil
	problems := []error{m.save(current)}
	if current.Joined && current.Document != nil {
		if peers {
			problems = append(problems, m.putConfig(ctx, config))
		}
		view := m.view(current)
		me, _ := member(view, m.Trust().NodeID)
		problems = append(problems, m.enforce(ctx, view, current.Dropped), m.exit(ctx, view, me))
		for _, port := range next.Relays {
			if !slices.Contains(current.Relays, port) {
				problems = append(problems, m.closeRelay(ctx, next.Firewall, port))
			}
		}
	} else {
		for _, problem := range m.takeDown(ctx, next) {
			problems = append(problems, errors.New(problem))
		}
	}
	return errors.Join(append(problems, m.putHosts(hosts))...)
}

func (m *Mesh) putConfig(ctx context.Context, previous []byte) error {
	now, _ := os.ReadFile(m.path(network.ConfigPath))
	if previous == nil {
		return os.Remove(m.path(network.ConfigPath))
	}
	if err := m.write(network.ConfigPath, previous, 0o600); err != nil {
		return err
	}
	return m.reload(ctx, string(now), string(previous))
}

func (m *Mesh) putHosts(saved []byte) error {
	now, err := os.ReadFile(m.path(network.HostsPath))
	switch {
	case saved == nil && errors.Is(err, os.ErrNotExist):
		return nil
	case saved == nil:
		return os.Remove(m.path(network.HostsPath))
	case err == nil && string(now) == string(saved):
		return nil
	}
	return m.write(network.HostsPath, saved, 0o644)
}

func (m *Mesh) writeHosts(members []network.Member) error {
	current, err := os.ReadFile(m.path(network.HostsPath))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	live := slices.DeleteFunc(slices.Clone(members), func(entry network.Member) bool { return entry.Cut })
	next := network.Hosts(string(current), live)
	if next == string(current) {
		return nil
	}
	return m.write(network.HostsPath, []byte(next), 0o644)
}

func (m *Mesh) unjump(ctx context.Context, tool string, specs [][]string) error {
	var problems []error
	for _, spec := range specs {
		for range 8 {
			if m.command(ctx, tool, append([]string{"-w", "-C"}, spec...)...) != nil {
				break
			}
			if err := m.command(ctx, tool, append([]string{"-w", "-D"}, spec...)...); err != nil {
				problems = append(problems, err)
				break
			}
		}
	}
	return errors.Join(problems...)
}

func (m *Mesh) unrules(ctx context.Context) error {
	chains := []string{network.InChain, network.ForwardChain, network.ExitChain, network.EdgeChain}
	var problems []error
	for _, entry := range families {
		problems = append(problems, m.unjump(ctx, entry.tool, append(network.Jumps(), network.ExitJumps...)))
		var present []string
		for _, chain := range chains {
			if _, ok := m.output(ctx, entry.tool, "-w", "-S", chain); ok {
				present = append(present, chain)
				problems = append(problems, m.command(ctx, entry.tool, "-w", "-F", chain))
			}
		}
		for _, chain := range present {
			problems = append(problems, m.command(ctx, entry.tool, "-w", "-X", chain))
		}
		if listed, ok := m.output(ctx, entry.tool, "-w", "-S", network.DockerUser); ok && strings.TrimSpace(listed) == "-N "+network.DockerUser {
			m.command(ctx, entry.tool, "-w", "-X", network.DockerUser)
		}
	}
	return errors.Join(problems...)
}

func (m *Mesh) takeDown(ctx context.Context, current record) []string {
	var problems []string
	step := func(what string, err error) {
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			problems = append(problems, what+": "+err.Error())
		}
	}
	step("stop kry0", m.command(ctx, "systemctl", "disable", "--now", unit))
	step("remove kry0.conf", os.Remove(m.path(network.ConfigPath)))
	numbered, listed := "", true
	if current.Firewall == "ufw" {
		numbered, listed = m.output(ctx, "ufw", "status", "numbered")
	}
	if !listed {
		problems = append(problems, "firewall: ufw cannot list its rules")
	} else {
		ports := slices.DeleteFunc(append([]int{current.Port}, current.Relays...), func(port int) bool { return port == 0 })
		for _, command := range network.Close(current.Firewall, ports, numbered) {
			step("firewall", m.command(ctx, command[0], command[1:]...))
		}
	}
	step("rules", m.unrules(ctx))
	step("laptop exit", m.exitOff(ctx, rangeOf(current.Document)))
	step("remove the Docker drop-in", os.Remove(m.path(network.DropInPath)))
	step("remove the rules drop-in", os.Remove(m.path(network.RulesDropInPath)))
	for _, name := range []string{network.RulesDropInPath, network.DropInPath} {
		os.Remove(filepath.Dir(m.path(name)))
	}
	step("reload systemd", m.command(ctx, "systemctl", "daemon-reload"))
	return problems
}

func (m *Mesh) leave(ctx context.Context, current record) (record, []string) {
	var problems []string
	if current.Next != nil {
		current = m.staged(ctx, current)
	}
	if current.Joined {
		problems = m.takeDown(ctx, current)
	}
	if err := m.writeHosts(nil); err != nil {
		problems = append(problems, "hosts: "+err.Error())
	}
	kept := record{Tools: current.Tools, Iptables: current.Iptables}
	if kept.Tools {
		found, _, err := m.read(ctx)
		switch {
		case err != nil:
			problems = append(problems, "remove "+tools+": "+err.Error())
		case len(found.Others) == 0:
			if err := platform.Purge(ctx, m.platform(), tools); err != nil {
				problems = append(problems, "remove "+tools+": "+err.Error())
			} else {
				kept.Tools = false
			}
		}
	}
	if err := m.purgeTables(ctx, &kept); err != nil {
		problems = append(problems, err.Error())
	}
	if err := network.Forget(m.keysDir()); err != nil {
		problems = append(problems, "remove the network keys: "+err.Error())
	}
	return kept, problems
}

func (m *Mesh) staged(ctx context.Context, current record) record {
	me, _ := member(current.Next.Document, m.Trust().NodeID)
	if !current.Joined {
		current.Joined, current.Port, current.Firewall = true, me.Port, m.firewallName(ctx)
	}
	if current.Document == nil {
		current.Document = &current.Next.Document
	}
	for _, port := range relayPorts(current.Next.Document, me) {
		if !slices.Contains(current.Relays, port) {
			current.Relays = append(current.Relays, port)
		}
	}
	return current
}

func (m *Mesh) leaveBy(ctx context.Context, current record, applied network.Applied) (string, error) {
	if !current.Joined && current.Next == nil {
		current.Applied = applied
		if err := m.save(current); err != nil {
			return "", err
		}
		return "This server is not in the private network.", nil
	}
	kept, problems := m.leave(ctx, current)
	if _, err := network.Load(m.keysDir(), true); err != nil {
		problems = append(problems, "make new network keys: "+err.Error())
	}
	kept.Applied = applied
	if err := m.save(kept); err != nil {
		problems = append(problems, err.Error())
	} else {
		m.left = true
	}
	if len(problems) > 0 {
		return "", fmt.Errorf("left the private network, but: %s", strings.Join(problems, "; "))
	}
	return "Left the private network.", nil
}

func (m *Mesh) krynodesPorts(ctx context.Context) []int {
	listed, _ := m.output(ctx, "firewall-cmd", "--permanent", "--list-ports")
	var ports []int
	for _, entry := range strings.Fields(listed) {
		number, protocol, _ := strings.Cut(entry, "/")
		port, err := strconv.Atoi(number)
		if protocol == "udp" && err == nil && port >= network.FirstPort && port <= network.LastRelayPort {
			ports = append(ports, port)
		}
	}
	return ports
}

func (m *Mesh) Leave(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, err := m.load()
	if err != nil {
		current = record{Joined: true, Firewall: m.firewallName(ctx)}
		if current.Firewall == "firewalld" {
			current.Relays = m.krynodesPorts(ctx)
		}
	}
	_, problems := m.leave(ctx, current)
	if err := os.Remove(m.statePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		return fmt.Errorf("the private network is not fully removed: %s", strings.Join(problems, "; "))
	}
	return nil
}
