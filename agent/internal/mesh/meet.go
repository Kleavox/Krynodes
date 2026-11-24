package mesh

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"slices"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/relay"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

func (m *Mesh) Hints(ctx context.Context, hints reporter.Hints) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, err := m.load()
	self := m.Trust().NodeID
	if err != nil || !current.Joined || current.Document == nil || self == "" {
		return
	}
	if err := m.hint(ctx, &current, self, hints); err != nil {
		log.Printf("private network hints: %v", err)
	}
}

func (m *Mesh) hint(ctx context.Context, current *record, self string, hints reporter.Hints) error {
	keys := false
	for _, hint := range hints.Announced {
		peer, ok := member(*current.Document, hint.Node)
		if !ok || hint.Node == self || peer.Cut || slices.Contains(current.Applied.Blocked, hint.Key) || !network.Announced(peer.Signer, hint.Node, hint.Key, hint.Signature) {
			continue
		}
		if inUse, _ := member(withAnnounced(*current.Document, current.Announced), hint.Node); inUse.Key == hint.Key {
			continue
		}
		if current.Announced == nil {
			current.Announced = map[string]string{}
		}
		current.Announced[hint.Node], keys = hint.Key, true
	}
	document := withAnnounced(*current.Document, current.Announced)
	moved, err := m.meet(ctx, current, document, self, hints.Meetings)
	m.endpoints(ctx, document, self, hints.Endpoints)
	held := slices.Contains(hints.Held, self)
	changed := held != current.Held
	current.Held = held
	if !keys && !moved && !changed {
		return err
	}
	if saved := m.save(*current); saved != nil {
		return errors.Join(err, saved)
	}
	if changed {
		view := m.view(*current)
		me, _ := member(view, self)
		err = errors.Join(err, m.enforce(ctx, view, current.Dropped), m.exit(ctx, view, me))
	}
	return errors.Join(err, m.reconfigure(ctx, *current, keys || changed))
}

func (m *Mesh) meet(ctx context.Context, current *record, document network.Document, self string, meetings []reporter.HintMeeting) (bool, error) {
	if me, _ := member(document, self); !me.NAT {
		return false, nil
	}
	moved := false
	var problems []error
	for _, hint := range meetings {
		laptop, isLaptop := member(document, hint.Laptop)
		via, isVia := member(document, hint.Via)
		if !isLaptop || !laptop.IsLaptop() || laptop.Cut || !isVia || !network.MeetingPoint(via) || current.Meetings[laptop.Node] == via.Node {
			continue
		}
		endpoint, ok := network.RelayEndpoint(document, via.Node, laptop.Node, self)
		if !ok {
			continue
		}
		if err := m.command(ctx, "wg", "set", network.Interface, "peer", laptop.Key, "endpoint", endpoint); err != nil {
			problems = append(problems, fmt.Errorf("move %s to %s: %w", laptop.Name, via.Name, err))
			continue
		}
		if current.Meetings == nil {
			current.Meetings = map[string]string{}
		}
		current.Meetings[laptop.Node], moved = via.Node, true
	}
	return moved, errors.Join(problems...)
}

func (m *Mesh) endpoints(ctx context.Context, document network.Document, self string, endpoints []reporter.HintEndpoint) {
	listening := map[string]bool{}
	for _, entry := range document.Members {
		listening[entry.Key] = !entry.NAT && !entry.IsLaptop() && !entry.Cut && entry.Node != self
	}
	for _, hint := range endpoints {
		parsed, err := netip.ParseAddrPort(hint.Endpoint)
		if !listening[hint.Key] || err != nil || parsed.Port() < network.FirstPort || parsed.Port() > network.LastPort {
			continue
		}
		if err := m.command(ctx, "wg", "set", network.Interface, "peer", hint.Key, "endpoint", parsed.String()); err != nil {
			log.Printf("private network endpoint: %v", err)
		}
	}
}

func (m *Mesh) meetingEndpoints(current record) map[string]string {
	if !current.Joined || current.Document == nil {
		return nil
	}
	self := m.Trust().NodeID
	document := withAnnounced(*current.Document, current.Announced)
	me, ok := member(document, self)
	if !ok || !me.NAT {
		return nil
	}
	wanted := map[string]string{}
	for _, laptop := range network.Laptops(document.Members) {
		if endpoint, ok := network.RelayEndpoint(document, current.Meetings[laptop.Node], laptop.Node, self); ok {
			wanted[laptop.Key] = endpoint
		}
	}
	return wanted
}

func roamed(wanted map[string]string, links []network.Link) []string {
	var keys []string
	for key, endpoint := range wanted {
		link := linkOf(links, key)
		if link.Key == "" {
			continue
		}
		if link.Endpoint == nil || !network.SameEndpoint(*link.Endpoint, endpoint) {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	return keys
}

func (m *Mesh) holdMeetings(ctx context.Context) {
	current, err := m.load()
	if err != nil || len(m.meetingEndpoints(current)) == 0 {
		return
	}
	links := m.dump(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	if current, err = m.load(); err != nil {
		return
	}
	wanted := m.meetingEndpoints(current)
	for _, key := range roamed(wanted, links) {
		if err := m.command(ctx, "wg", "set", network.Interface, "peer", key, "endpoint", wanted[key]); err != nil {
			log.Printf("meeting point: %v", err)
		}
	}
}

func relayPorts(document network.Document, me network.Member) []int {
	if !network.MeetingPoint(me) {
		return nil
	}
	var ports []int
	for _, pair := range network.Pairs(document) {
		ports = append(ports, pair.Port)
	}
	slices.Sort(ports)
	return ports
}

func (m *Mesh) syncRelayPorts(ctx context.Context, current *record, document network.Document, me network.Member) error {
	wanted := relayPorts(document, me)
	var open []int
	var problems []error
	for _, port := range current.Relays {
		if slices.Contains(wanted, port) {
			open = append(open, port)
			continue
		}
		if err := m.closeRelay(ctx, current.Firewall, port); err != nil {
			problems = append(problems, fmt.Errorf("close relay port %d: %w", port, err))
			open = append(open, port)
		}
	}
	for _, port := range wanted {
		if slices.Contains(current.Relays, port) {
			continue
		}
		if err := m.commands(ctx, network.OpenRelay(current.Firewall, []int{port})); err != nil {
			problems = append(problems, fmt.Errorf("open relay port %d: %w", port, err))
			continue
		}
		open = append(open, port)
	}
	slices.Sort(open)
	current.Relays = open
	return errors.Join(problems...)
}

func (m *Mesh) closeRelay(ctx context.Context, firewall string, port int) error {
	numbered := ""
	if firewall == "ufw" {
		var listed bool
		if numbered, listed = m.output(ctx, "ufw", "status", "numbered"); !listed {
			return errors.New("ufw cannot list its rules")
		}
	}
	return m.commands(ctx, network.CloseRelay(firewall, []int{port}, numbered))
}

func relayPairs(document network.Document, me network.Member) []relay.Pair {
	if !network.MeetingPoint(me) {
		return nil
	}
	var host netip.Addr
	if signed, err := netip.ParseAddrPort(*me.Endpoint); err == nil {
		host = signed.Addr().Unmap()
	}
	var pairs []relay.Pair
	for _, pair := range network.Pairs(document) {
		pairs = append(pairs, relay.Pair{Port: pair.Port, Sides: [2]string{pair.Laptop.Key, pair.NAT.Key}, Host: host})
	}
	return pairs
}
