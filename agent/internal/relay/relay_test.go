package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type datagram struct {
	payload []byte
	addr    netip.AddrPort
}

type fakeSocket struct {
	in      chan datagram
	out     chan datagram
	closed  chan struct{}
	once    sync.Once
	entered atomic.Int64
}

func (f *fakeSocket) ReadFromUDPAddrPort(buffer []byte) (int, netip.AddrPort, error) {
	f.entered.Add(1)
	select {
	case got := <-f.in:
		return copy(buffer, got.payload), got.addr, nil
	case <-f.closed:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (f *fakeSocket) WriteToUDPAddrPort(payload []byte, to netip.AddrPort) (int, error) {
	f.out <- datagram{bytes.Clone(payload), to}
	return len(payload), nil
}

func (f *fakeSocket) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeSocket) isClosed() bool {
	select {
	case <-f.closed:
		return true
	default:
		return false
	}
}

type harness struct {
	t       *testing.T
	relay   *Relay
	mu      sync.Mutex
	table   string
	fail    bool
	gate    chan struct{}
	reads   int
	clock   time.Time
	sockets map[string]*fakeSocket
	refuse  map[string]bool
	hosts   map[string]netip.Addr
}

const (
	laptopKey = "key-l"
	natKey    = "key-n"
)

var pair = Pair{Port: 51920, Sides: [2]string{laptopKey, natKey}}

func newHarness(t *testing.T, table string) *harness {
	h := &harness{t: t, table: table, clock: time.Unix(1_800_000_000, 0), sockets: map[string]*fakeSocket{}, refuse: map[string]bool{}, hosts: map[string]netip.Addr{}}
	h.relay = New(func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		if call := name + " " + strings.Join(args, " "); call != "wg show kry0 endpoints" {
			t.Errorf("ran %q", call)
		}
		h.mu.Lock()
		h.reads++
		gate, output, fail := h.gate, h.table, h.fail
		h.mu.Unlock()
		if gate != nil {
			<-gate
		}
		if fail {
			return []byte(output), 1, errors.New("exit status 1")
		}
		return []byte(output), 0, nil
	})
	h.relay.now = func() time.Time {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.clock
	}
	h.relay.listen = func(family string, host netip.Addr, port int) (conn, error) {
		name := fmt.Sprintf("%s/%d", family, port)
		h.mu.Lock()
		defer h.mu.Unlock()
		h.hosts[name] = host
		if h.refuse[name] {
			return nil, errors.New("address already in use")
		}
		socket := &fakeSocket{in: make(chan datagram), out: make(chan datagram, 8), closed: make(chan struct{})}
		h.sockets[name] = socket
		return socket, nil
	}
	t.Cleanup(h.relay.Close)
	return h
}

func (h *harness) start(pairs ...Pair) {
	h.t.Helper()
	h.relay.Set(pairs)
	h.waitReads(1)
}

func (h *harness) socket(name string) *fakeSocket {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sockets[name]
}

func (h *harness) set(table string, after time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.table, h.clock = table, h.clock.Add(after)
}

func (h *harness) readCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reads
}

func (h *harness) waitReads(want int) {
	h.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		h.relay.table.Lock()
		reading := h.relay.reading
		h.relay.table.Unlock()
		if h.readCount() >= want && !reading {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("read %d times, want %d", h.readCount(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func (h *harness) send(socket, from, payload string) {
	h.t.Helper()
	target := h.socket(socket)
	before := target.entered.Load()
	select {
	case target.in <- datagram{[]byte(payload), netip.MustParseAddrPort(from)}:
	case <-time.After(2 * time.Second):
		h.t.Fatalf("%s is not reading", socket)
	}
	for deadline := time.Now().Add(2 * time.Second); target.entered.Load() <= before; time.Sleep(100 * time.Microsecond) {
		if time.Now().After(deadline) {
			h.t.Fatalf("%s never finished %q", socket, payload)
		}
	}
}

func (h *harness) expect(socket, to, payload string) {
	h.t.Helper()
	select {
	case got := <-h.socket(socket).out:
		if string(got.payload) != payload || got.addr != netip.MustParseAddrPort(to) {
			h.t.Fatalf("%s sent %q to %s, want %q to %s", socket, got.payload, got.addr, payload, to)
		}
	case <-time.After(2 * time.Second):
		h.t.Fatalf("%s sent nothing, want %q to %s", socket, payload, to)
	}
}

func (h *harness) quiet() {
	h.t.Helper()
	for name, socket := range h.sockets {
		select {
		case got := <-socket.out:
			h.t.Fatalf("%s sent %q to %s", name, got.payload, got.addr)
		default:
		}
	}
}

const (
	laptopAt = "198.51.100.7:40000"
	natAt    = "203.0.113.50:51820"
	table    = "key-l\t" + laptopAt + "\nkey-n\t" + natAt + "\nkey-x\t203.0.113.60:51820\nkey-z\t(none)\n"
	v4       = "udp4/51920"
	v6       = "udp6/51920"
)

func TestADatagramCrossesOnlyBetweenTheTwoAuthenticatedSides(t *testing.T) {
	h := newHarness(t, table)
	h.start(pair)
	h.send(v4, laptopAt, "first")
	h.send(v4, "203.0.113.50:61000", "from-nat")
	h.expect(v4, laptopAt, "from-nat")
	h.send(v4, laptopAt, "from-laptop")
	h.expect(v4, "203.0.113.50:61000", "from-laptop")
	for _, stranger := range []string{"192.0.2.1:51820", "203.0.113.60:51820", "203.0.113.60:40000", "198.51.100.70:40000"} {
		h.send(v4, stranger, "stranger")
	}
	h.send(v4, laptopAt, "after")
	h.expect(v4, "203.0.113.50:61000", "after")
	h.send(v4, natAt, "back")
	h.expect(v4, laptopAt, "back")
	h.send(v4, laptopAt, "learned")
	h.expect(v4, natAt, "learned")
	h.quiet()
	large := strings.Repeat("x", 70000)
	h.socket(v4).in <- datagram{[]byte(large), netip.MustParseAddrPort(natAt)}
	if got := <-h.socket(v4).out; len(got.payload) != maxDatagram {
		t.Fatalf("a datagram of %d bytes", len(got.payload))
	}
	if h.readCount() != 1 {
		t.Fatalf("strangers made %d reads within a second", h.readCount()-1)
	}
}

func TestAnIPOnlyMatchNeverTakesAnAddressLearnedExactly(t *testing.T) {
	h := newHarness(t, table)
	h.start(pair)
	h.send(v4, natAt, "nat")
	h.send(v4, laptopAt, "laptop")
	h.expect(v4, natAt, "laptop")
	h.send(v4, "198.51.100.7:41000", "same-ip")
	h.expect(v4, natAt, "same-ip")
	h.send(v4, natAt, "to-laptop")
	h.expect(v4, laptopAt, "to-laptop")
	h.send(v4, "203.0.113.50:61000", "nat-same-ip")
	h.expect(v4, laptopAt, "nat-same-ip")
	h.send(v4, laptopAt, "to-nat")
	h.expect(v4, natAt, "to-nat")
	h.quiet()
}

func TestAnIPOnlyAddressFollowsTheNextIPOnlyMatch(t *testing.T) {
	h := newHarness(t, table)
	h.start(pair)
	h.send(v4, laptopAt, "laptop")
	h.send(v4, "203.0.113.50:61000", "first")
	h.expect(v4, laptopAt, "first")
	h.send(v4, "203.0.113.50:62000", "moved")
	h.expect(v4, laptopAt, "moved")
	h.send(v4, laptopAt, "to-moved")
	h.expect(v4, "203.0.113.50:62000", "to-moved")
	h.send(v4, natAt, "exact")
	h.expect(v4, laptopAt, "exact")
	h.send(v4, "203.0.113.50:63000", "after-exact")
	h.expect(v4, laptopAt, "after-exact")
	h.send(v4, laptopAt, "to-exact")
	h.expect(v4, natAt, "to-exact")
	h.quiet()
}

func TestAnExactAddressTheSideHasLeftIsLearnedAgain(t *testing.T) {
	h := newHarness(t, table)
	h.start(pair)
	h.send(v4, natAt, "nat")
	h.send(v4, laptopAt, "laptop")
	h.expect(v4, natAt, "laptop")
	roamed := "100.64.1.2:50000"
	h.set(strings.Replace(table, laptopAt, roamed, 1), 11*time.Second)
	h.send(v4, natAt, "refresh")
	h.expect(v4, laptopAt, "refresh")
	h.waitReads(2)
	h.send(v4, "100.64.1.2:50001", "from-hotspot")
	h.expect(v4, natAt, "from-hotspot")
	h.send(v4, natAt, "to-hotspot")
	h.expect(v4, "100.64.1.2:50001", "to-hotspot")
	rebound := "203.0.113.50:52000"
	h.set(strings.Replace(strings.Replace(table, laptopAt, roamed, 1), natAt, rebound, 1), 11*time.Second)
	h.send(v4, "100.64.1.2:50001", "refresh")
	h.expect(v4, natAt, "refresh")
	h.waitReads(3)
	h.send(v4, "203.0.113.50:52001", "nat-rebound")
	h.expect(v4, "100.64.1.2:50001", "nat-rebound")
	h.send(v4, "100.64.1.2:50001", "to-rebound")
	h.expect(v4, "203.0.113.50:52001", "to-rebound")
	h.quiet()
}

func TestTheIPOnlyFallbackRefusesAnAddressBothSidesShare(t *testing.T) {
	home := "key-l\t203.0.113.50:40000\nkey-n\t203.0.113.50:51820\n"
	h := newHarness(t, home)
	h.start(pair)
	h.send(v4, "203.0.113.50:51820", "nat")
	h.send(v4, "203.0.113.50:40000", "laptop")
	h.expect(v4, "203.0.113.50:51820", "laptop")
	h.send(v4, "203.0.113.50:62000", "either")
	h.send(v4, "203.0.113.50:51820", "nat-again")
	h.expect(v4, "203.0.113.50:40000", "nat-again")
	h.quiet()
}

func TestTheTableIsReadAgainWhenASideMovesButAtMostOnceASecond(t *testing.T) {
	h := newHarness(t, table)
	h.start(pair)
	h.send(v4, natAt, "nat")
	h.send(v4, laptopAt, "laptop")
	h.expect(v4, natAt, "laptop")
	moved := "198.51.100.8:40001"
	h.set(strings.Replace(table, laptopAt, moved, 1), 500*time.Millisecond)
	h.send(v4, moved, "too-soon")
	h.send(v4, natAt, "still-old")
	h.expect(v4, laptopAt, "still-old")
	if h.readCount() != 1 {
		t.Fatalf("read %d times within a second", h.readCount()-1)
	}
	h.set(strings.Replace(table, laptopAt, moved, 1), time.Second)
	h.send(v4, moved, "asks")
	h.waitReads(2)
	h.send(v4, moved, "moved")
	h.expect(v4, natAt, "moved")
	h.send(v4, natAt, "to-moved")
	h.expect(v4, moved, "to-moved")
	if h.readCount() != 2 {
		t.Fatalf("read %d times for one move", h.readCount()-1)
	}
	h.set(strings.Replace(table, laptopAt, moved, 1), 11*time.Second)
	h.send(v4, natAt, "refresh")
	h.expect(v4, moved, "refresh")
	h.waitReads(3)
	h.set("", 11*time.Second)
	h.send(v4, natAt, "stale")
	h.expect(v4, moved, "stale")
	h.waitReads(4)
	h.send(v4, natAt, "gone")
	h.send(v4, moved, "gone")
	h.quiet()
}

func TestAFailedReadForgetsEverySide(t *testing.T) {
	h := newHarness(t, table)
	h.start(pair)
	h.send(v4, natAt, "nat")
	h.send(v4, laptopAt, "laptop")
	h.expect(v4, natAt, "laptop")
	h.mu.Lock()
	h.fail = true
	h.mu.Unlock()
	h.set(table, 11*time.Second)
	h.send(v4, natAt, "before")
	h.expect(v4, laptopAt, "before")
	h.waitReads(2)
	h.send(v4, natAt, "after")
	h.send(v4, laptopAt, "after")
	h.quiet()
	h.mu.Lock()
	h.fail = false
	h.mu.Unlock()
	h.set(table, 2*time.Second)
	h.send(v4, natAt, "asks")
	h.waitReads(3)
	h.send(v4, natAt, "back")
	h.expect(v4, laptopAt, "back")
}

func TestASlowReadStallsNoDatagram(t *testing.T) {
	h := newHarness(t, table)
	h.start(pair)
	h.send(v4, natAt, "nat")
	gate := make(chan struct{})
	h.mu.Lock()
	h.gate = gate
	h.mu.Unlock()
	h.set(table, 11*time.Second)
	h.send(v4, laptopAt, "starts-a-read")
	h.expect(v4, natAt, "starts-a-read")
	for deadline := time.Now().Add(2 * time.Second); h.readCount() < 2; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no read started")
		}
	}
	for _, payload := range []string{"one", "two", "three"} {
		h.send(v4, laptopAt, payload)
		h.expect(v4, natAt, payload)
		h.send(v4, natAt, payload)
		h.expect(v4, laptopAt, payload)
	}
	h.send(v4, "192.0.2.1:1", "stranger")
	if h.readCount() != 2 {
		t.Fatalf("read %d times while one read was running", h.readCount()-1)
	}
	close(gate)
	h.waitReads(2)
	h.quiet()
}

func TestEachFamilySendsOnItsOwnSocket(t *testing.T) {
	laptop6 := "[2001:db8::7]:40000"
	h := newHarness(t, "key-l\t"+laptop6+"\nkey-n\t"+natAt+"\n")
	h.start(pair)
	h.send(v6, laptop6, "hello")
	h.send(v4, natAt, "to-six")
	h.expect(v6, laptop6, "to-six")
	h.send(v6, laptop6, "to-four")
	h.expect(v4, natAt, "to-four")
	h.send(v6, "[::ffff:203.0.113.50]:51820", "mapped")
	h.expect(v6, laptop6, "mapped")
	h.quiet()
}

func TestListenersFollowThePairs(t *testing.T) {
	h := newHarness(t, table)
	other := Pair{Port: 51921, Sides: [2]string{laptopKey, "key-m"}}
	h.relay.Set([]Pair{pair, other})
	first, second := h.socket(v4), h.socket("udp4/51921")
	if first == nil || second == nil || h.socket(v6) == nil || h.socket("udp6/51921") == nil {
		t.Fatalf("sockets %v", h.sockets)
	}
	h.relay.Set([]Pair{pair})
	if !second.isClosed() || !h.socket("udp6/51921").isClosed() || first.isClosed() || h.socket(v4) != first {
		t.Fatal("a pair that is gone keeps its listener, or one that stays was reopened")
	}
	h.relay.Set([]Pair{{Port: 51920, Sides: [2]string{laptopKey, "key-new"}}})
	if !first.isClosed() || h.socket(v4) == first {
		t.Fatal("a pair with a new key keeps the old listener")
	}
	h.mu.Lock()
	h.refuse["udp6/51922"], h.refuse["udp4/51923"], h.refuse["udp6/51923"] = true, true, true
	h.mu.Unlock()
	pairs := []Pair{{Port: 51922, Sides: pair.Sides}, {Port: 51923, Sides: pair.Sides}}
	h.relay.Set(pairs)
	four := h.socket("udp4/51922")
	if four == nil || four.isClosed() || h.socket("udp6/51922") != nil || h.socket("udp4/51923") != nil {
		t.Fatalf("one family is enough: %v", h.sockets)
	}
	h.mu.Lock()
	h.refuse["udp6/51922"], h.refuse["udp4/51923"] = false, false
	h.mu.Unlock()
	h.relay.Set(pairs)
	if h.socket("udp4/51923") == nil || h.socket("udp6/51922") == nil || h.socket("udp4/51922") != four || four.isClosed() {
		t.Fatalf("a family or a port that failed is tried again on the next tick: %v", h.sockets)
	}
	h.relay.Close()
	for name, socket := range h.sockets {
		if !socket.isClosed() {
			t.Fatalf("%s stays open", name)
		}
	}
}

func TestTheEndpointTableSkipsPeersWithoutOne(t *testing.T) {
	found := endpoints("key-a\t203.0.113.1:51820\nkey-b\t(none)\nkey-c\t[2001:db8::3]:51821\nbroken\n")
	if len(found) != 2 || found["key-a"] != netip.MustParseAddrPort("203.0.113.1:51820") || found["key-c"] != netip.MustParseAddrPort("[2001:db8::3]:51821") {
		t.Fatalf("%v", found)
	}
}

func TestALoopbackPairCrossesRealSockets(t *testing.T) {
	laptop, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip(err)
	}
	defer laptop.Close()
	nat, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer nat.Close()
	relay := New(func(context.Context, string, ...string) ([]byte, int, error) {
		return []byte("key-l\t" + laptop.LocalAddr().String() + "\nkey-n\t" + nat.LocalAddr().String() + "\n"), 0, nil
	})
	var listening *net.UDPConn
	relay.listen = func(family string, _ netip.Addr, _ int) (conn, error) {
		if family != "udp4" {
			return nil, errors.New("loopback only")
		}
		socket, err := net.ListenUDP(family, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		listening = socket
		return socket, err
	}
	relay.Set([]Pair{pair})
	defer relay.Close()
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(time.Millisecond) {
		relay.table.Lock()
		ready := relay.endpoints != nil
		relay.table.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the table was never read")
		}
	}
	at := listening.LocalAddr().(*net.UDPAddr).AddrPort()
	read := func(socket *net.UDPConn) string {
		socket.SetReadDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 64)
		size, from, err := socket.ReadFromUDPAddrPort(buffer)
		if err != nil || from != at {
			t.Fatalf("read %q from %s: %v", buffer[:size], from, err)
		}
		return string(buffer[:size])
	}
	nat.WriteToUDPAddrPort([]byte("hello"), at)
	laptop.WriteToUDPAddrPort([]byte("to-nat"), at)
	if got := read(nat); got != "to-nat" {
		t.Fatalf("nat read %q", got)
	}
	nat.WriteToUDPAddrPort([]byte("to-laptop"), at)
	if got := read(laptop); got != "to-laptop" {
		t.Fatalf("laptop read %q", got)
	}
}

func TestAPairPortListensOnTheMeetingPointsSignedHost(t *testing.T) {
	h := newHarness(t, "")
	host := netip.MustParseAddr("203.0.113.1")
	h.relay.Set([]Pair{{Port: 51920, Sides: pair.Sides, Host: host}})
	h.mu.Lock()
	got := h.hosts["udp4/51920"]
	h.mu.Unlock()
	if got != host {
		t.Fatalf("listened on %v, want the signed host", got)
	}
	h.relay.Set([]Pair{{Port: 51920, Sides: pair.Sides, Host: netip.MustParseAddr("203.0.113.2")}})
	h.mu.Lock()
	got = h.hosts["udp4/51920"]
	h.mu.Unlock()
	if got != netip.MustParseAddr("203.0.113.2") {
		t.Fatalf("a moved host kept the old socket: %v", got)
	}
	local, err := listenUDP("udp4", netip.MustParseAddr("127.0.0.1"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	if at := local.(*net.UDPConn).LocalAddr().(*net.UDPAddr).AddrPort().Addr(); at != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("a host on this server is not bound: %v", at)
	}
	foreign, err := listenUDP("udp4", netip.MustParseAddr("203.0.113.9"), 0)
	if err != nil {
		t.Fatalf("a host behind the provider's NAT falls back to every address: %v", err)
	}
	defer foreign.Close()
	if at := foreign.(*net.UDPConn).LocalAddr().(*net.UDPAddr).AddrPort().Addr(); !at.IsUnspecified() {
		t.Fatalf("bound to %v", at)
	}
	other, err := listenUDP("udp6", netip.MustParseAddr("127.0.0.1"), 0)
	if err == nil {
		defer other.Close()
		if at := other.(*net.UDPConn).LocalAddr().(*net.UDPAddr).AddrPort().Addr(); !at.IsUnspecified() {
			t.Fatalf("the other family bound to %v", at)
		}
	}
}
