package relay

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

const (
	maxDatagram  = 65535
	rereadAfter  = time.Second
	refreshEvery = 10 * time.Second
	askTimeout   = 5 * time.Second
)

var families = [2]string{"udp4", "udp6"}

type Pair struct {
	Port  int
	Sides [2]string
	Host  netip.Addr
}

type conn interface {
	ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
	Close() error
}

type Relay struct {
	run    network.Runner
	now    func() time.Time
	listen func(family string, host netip.Addr, port int) (conn, error)

	mu      sync.Mutex
	ports   map[int]*port
	failing map[int]bool

	table     sync.Mutex
	endpoints map[string]netip.AddrPort
	read      time.Time
	reading   bool
}

type port struct {
	pair  Pair
	mu    sync.Mutex
	conns [2]conn
	last  [2]netip.AddrPort
	exact [2]bool
}

func New(run network.Runner) *Relay {
	return &Relay{run: run, now: time.Now, listen: listenUDP, ports: map[int]*port{}, failing: map[int]bool{}}
}

func listenUDP(family string, host netip.Addr, number int) (conn, error) {
	if host.IsValid() && host.Is4() == (family == "udp4") {
		if socket, err := net.ListenUDP(family, net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, uint16(number)))); err == nil {
			return socket, nil
		}
	}
	socket, err := net.ListenUDP(family, &net.UDPAddr{Port: number})
	if err != nil {
		return nil, err
	}
	return socket, nil
}

func (r *Relay) Set(pairs []Pair) {
	wanted := map[int]Pair{}
	for _, pair := range pairs {
		wanted[pair.Port] = pair
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for number, open := range r.ports {
		if pair, ok := wanted[number]; !ok || pair != open.pair {
			open.close()
			delete(r.ports, number)
		}
	}
	for number := range r.failing {
		if _, ok := wanted[number]; !ok {
			delete(r.failing, number)
		}
	}
	opened := false
	for number, pair := range wanted {
		open, known := r.ports[number]
		if !known {
			open = &port{pair: pair}
		}
		problems := r.bind(open, number)
		if known {
			continue
		}
		if !open.bound() {
			if !r.failing[number] {
				log.Printf("relay port %d: %v", number, errors.Join(problems...))
			}
			r.failing[number] = true
			continue
		}
		delete(r.failing, number)
		r.ports[number] = open
		opened = true
	}
	if opened {
		r.table.Lock()
		r.refresh(r.now())
		r.table.Unlock()
	}
}

func (r *Relay) Close() {
	r.Set(nil)
}

func (r *Relay) bind(open *port, number int) []error {
	var problems []error
	for index, family := range families {
		open.mu.Lock()
		have := open.conns[index] != nil
		open.mu.Unlock()
		if have {
			continue
		}
		socket, err := r.listen(family, open.pair.Host, number)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		open.mu.Lock()
		open.conns[index] = socket
		open.mu.Unlock()
		go r.serve(open, socket)
	}
	return problems
}

func (p *port) bound() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conns[0] != nil || p.conns[1] != nil
}

func (p *port) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, socket := range p.conns {
		if socket != nil {
			socket.Close()
		}
	}
}

func (r *Relay) serve(open *port, socket conn) {
	buffer := make([]byte, maxDatagram)
	for {
		size, from, err := socket.ReadFromUDPAddrPort(buffer)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		side, current, ok := r.side(open.pair, from)
		if !ok {
			continue
		}
		exact := from == current
		open.mu.Lock()
		if exact || !open.exact[side] || open.last[side] != current {
			open.last[side], open.exact[side] = from, exact
		}
		to := open.last[1-side]
		out := open.conns[0]
		if to.Addr().Is6() {
			out = open.conns[1]
		}
		open.mu.Unlock()
		if to.IsValid() && out != nil {
			out.WriteToUDPAddrPort(buffer[:size], to)
		}
	}
}

func (r *Relay) side(pair Pair, from netip.AddrPort) (int, netip.AddrPort, bool) {
	r.table.Lock()
	defer r.table.Unlock()
	now := r.now()
	side, current, ok := match(r.endpoints, pair, from)
	if now.Sub(r.read) >= refreshEvery || (!ok && now.Sub(r.read) >= rereadAfter) {
		r.refresh(now)
	}
	return side, current, ok
}

func (r *Relay) refresh(now time.Time) {
	if r.reading {
		return
	}
	r.reading, r.read = true, now
	go r.reread()
}

func (r *Relay) reread() {
	ctx, cancel := context.WithTimeout(context.Background(), askTimeout)
	defer cancel()
	output, _, err := r.run(ctx, "wg", "show", network.Interface, "endpoints")
	var found map[string]netip.AddrPort
	if err == nil {
		found = endpoints(string(output))
	}
	r.table.Lock()
	r.endpoints, r.reading = found, false
	r.table.Unlock()
}

func endpoints(output string) map[string]netip.AddrPort {
	found := map[string]netip.AddrPort{}
	for line := range strings.SplitSeq(output, "\n") {
		key, text, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok {
			continue
		}
		at, err := netip.ParseAddrPort(strings.TrimSpace(text))
		if err != nil {
			continue
		}
		found[key] = netip.AddrPortFrom(at.Addr().Unmap(), at.Port())
	}
	return found
}

func match(endpoints map[string]netip.AddrPort, pair Pair, from netip.AddrPort) (int, netip.AddrPort, bool) {
	known := [2]netip.AddrPort{endpoints[pair.Sides[0]], endpoints[pair.Sides[1]]}
	for side := range known {
		if known[side] == from {
			return side, known[side], true
		}
	}
	for side := range known {
		if known[side].Addr() == from.Addr() && known[1-side].Addr() != from.Addr() {
			return side, known[side], true
		}
	}
	return 0, netip.AddrPort{}, false
}
