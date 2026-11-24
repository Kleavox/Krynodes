//go:build linux

package mesh

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/trust"
)

const (
	liveOne       = "a1111111-1111-4111-8111-111111111111"
	liveTwo       = "a2222222-2222-4222-8222-222222222222"
	liveThree     = "a3333333-3333-4333-8333-333333333333"
	liveLaptop    = "a9999999-9999-4999-8999-999999999999"
	liveWait      = 750 * time.Millisecond
	defaultRoute4 = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\neth0\t00000000\t0100710A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
	defaultRoute6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n"
)

var (
	spaceCount atomic.Int32
	tables     = []string{"iptables", "ip6tables", "iptables-restore", "ip6tables-restore"}
	setns      = map[string]uintptr{"amd64": 308, "arm64": 268}
)

type space struct {
	t       *testing.T
	name    string
	mu      sync.Mutex
	closers []io.Closer
}

func newSpace(t *testing.T) *space {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("these checks load the rules into real iptables inside network namespaces, so they run as root")
	}
	if setns[runtime.GOARCH] == 0 {
		t.Skipf("these checks do not know the setns call number on %s", runtime.GOARCH)
	}
	for _, tool := range append([]string{"ip"}, tables...) {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("these checks need %s: %v", tool, err)
		}
	}
	s := &space{t: t, name: fmt.Sprintf("kry-live-%d-%d", os.Getpid(), spaceCount.Add(1))}
	if output, err := exec.Command("ip", "netns", "add", s.name).CombinedOutput(); err != nil {
		t.Skipf("this host cannot make a network namespace: %v: %s", err, output)
	}
	t.Cleanup(func() {
		s.mu.Lock()
		for _, closer := range s.closers {
			closer.Close()
		}
		s.mu.Unlock()
		if output, err := exec.Command("ip", "netns", "del", s.name).CombinedOutput(); err != nil {
			t.Errorf("remove the namespace %s: %v: %s", s.name, err, output)
		}
	})
	s.sh("ip link set lo up")
	return s
}

func (s *space) exec(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	command := exec.CommandContext(ctx, "ip", append([]string{"netns", "exec", s.name, name}, args...)...)
	output, err := command.CombinedOutput()
	code := -1
	if command.ProcessState != nil {
		code = command.ProcessState.ExitCode()
	}
	return output, code, err
}

func (s *space) run(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	if !slices.Contains(tables, name) {
		return nil, 0, nil
	}
	return s.exec(ctx, name, args...)
}

func (s *space) try(line string) error {
	fields := strings.Fields(line)
	output, _, err := s.exec(context.Background(), fields[0], fields[1:]...)
	if err != nil {
		return fmt.Errorf("%s in %s: %w: %s", line, s.name, err, output)
	}
	return nil
}

func (s *space) sh(lines ...string) string {
	s.t.Helper()
	var all strings.Builder
	for _, line := range lines {
		fields := strings.Fields(line)
		output, _, err := s.exec(context.Background(), fields[0], fields[1:]...)
		if err != nil {
			s.t.Fatalf("%s in %s: %v: %s", line, s.name, err, output)
		}
		all.Write(output)
	}
	return all.String()
}

func (s *space) hold(closer io.Closer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closers = append(s.closers, closer)
}

func inside[T any](s *space, do func() (T, error)) (T, error) {
	type result struct {
		value T
		err   error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		file, err := os.Open("/var/run/netns/" + s.name)
		if err != nil {
			done <- result{err: err}
			return
		}
		_, _, errno := syscall.RawSyscall(setns[runtime.GOARCH], file.Fd(), syscall.CLONE_NEWNET, 0)
		file.Close()
		if errno != 0 {
			done <- result{err: errno}
			return
		}
		value, err := do()
		done <- result{value, err}
	}()
	found := <-done
	return found.value, found.err
}

func (s *space) serve(port int) {
	s.t.Helper()
	listener, err := inside(s, func() (net.Listener, error) { return net.Listen("tcp", fmt.Sprintf(":%d", port)) })
	if err != nil {
		s.t.Fatal(err)
	}
	s.hold(listener)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			s.hold(conn)
			go io.Copy(conn, conn)
		}
	}()
}

func (s *space) dial(from, to string) (net.Conn, error) {
	return inside(s, func() (net.Conn, error) {
		dialer := net.Dialer{Timeout: liveWait}
		if from != "" {
			dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(from)}
		}
		return dialer.Dial("tcp", to)
	})
}

func talks(conn net.Conn) bool {
	conn.SetDeadline(time.Now().Add(liveWait))
	if _, err := conn.Write([]byte("ping")); err != nil {
		return false
	}
	got := make([]byte, 4)
	_, err := io.ReadFull(conn, got)
	return err == nil && string(got) == "ping"
}

func (s *space) reaches(from, to string) bool {
	conn, err := s.dial(from, to)
	if err != nil {
		return false
	}
	defer conn.Close()
	return talks(conn)
}

func (s *space) open(from, to string) net.Conn {
	s.t.Helper()
	conn, err := s.dial(from, to)
	if err != nil {
		s.t.Fatalf("from %s %s cannot open %s: %v", s.name, from, to, err)
	}
	s.hold(conn)
	if !talks(conn) {
		s.t.Fatalf("from %s %s, %s does not answer", s.name, from, to)
	}
	return conn
}

func expect(t *testing.T, s *space, from, to string, want bool, what string) {
	t.Helper()
	if got := s.reaches(from, to); got != want {
		t.Errorf("%s: %s reaches %s: %v, want %v", what, from, to, got, want)
	}
}

func wire(a *space, aName string, b *space, bName string) {
	a.sh("ip link add "+aName+" type veth peer name "+bName+" netns "+b.name, "ip link set "+aName+" up")
	b.sh("ip link set " + bName + " up")
}

func neighbours(a *space, aAddress string, b *space, bAddress string) {
	mac := func(s *space) string {
		return strings.TrimSpace(s.sh("cat /sys/class/net/kry0/address"))
	}
	a.sh("ip -6 neigh replace " + bAddress + " lladdr " + mac(b) + " dev kry0 nud permanent")
	b.sh("ip -6 neigh replace " + aAddress + " lladdr " + mac(a) + " dev kry0 nud permanent")
}

func liveMesh(t *testing.T, s *space, node string) *Mesh {
	return &Mesh{
		State:   t.TempDir(),
		Root:    t.TempDir(),
		Run:     s.run,
		Now:     time.Now,
		Trust:   func() trust.Trust { return trust.Trust{NodeID: node} },
		SealKey: func() string { return "" },
		Send:    func(any) error { return nil },
	}
}

func liveApply(t *testing.T, m *Mesh, document network.Document, dropped ...string) {
	t.Helper()
	if err := m.save(record{Applied: network.Applied{Version: document.Version, Hash: "hash"}, Document: &document, Joined: true, Port: network.FirstPort, Dropped: dropped}); err != nil {
		t.Fatal(err)
	}
	if err := m.Rules(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func liveMember(node, name, address string) network.Member {
	return network.Member{Node: node, Name: name, Address: address, Port: network.FirstPort, PSK: map[string]string{}}
}

func liveDocument(members []network.Member, allow ...network.Rule) network.Document {
	return network.Document{V: 1, Version: 1, Range: "10.88.37.0/24", Port: network.FirstPort, MTU: 1420, Blocked: []string{}, Members: members, Allow: allow}
}

func grant(from, to string, ports ...string) network.Rule {
	return network.Rule{From: network.Side{Node: from}, To: network.Side{Node: to}, Ports: network.Ports{List: ports}}
}

func crew(members ...network.Member) []network.Member {
	return members
}

func wideDocument() network.Document {
	one := liveMember(liveOne, "server-1", "10.88.37.1")
	one.Exit = true
	laptop := liveMember(liveLaptop, "laptop-1", "10.88.37.9")
	laptop.Kind = "laptop"
	ports := []string{"22/tcp", "80/tcp", "443/tcp", "8000-8100/tcp", "3000/tcp", "3001/tcp", "3002/tcp", "3003/tcp", "3004/tcp", "3005/tcp", "3006/tcp", "3007/tcp", "3008/tcp", "3009/tcp", "3010/tcp", "3011/tcp", "53/udp", "123/udp", "51900-51910/udp", "5353/udp"}
	return liveDocument(
		crew(one, liveMember(liveTwo, "server-2", "10.88.37.2"), liveMember(liveThree, "server-3", "10.88.37.3"), laptop),
		network.Rule{From: network.Side{Group: "laptops"}, To: network.Side{Group: "servers"}, Ports: network.Ports{All: true}},
		grant(liveTwo, liveOne, ports...),
		network.Rule{From: network.Side{Group: "servers"}, To: network.Side{Group: "servers"}, Ports: network.Ports{List: []string{"9100/tcp"}}},
	)
}

func exitRoutes(t *testing.T, m *Mesh, families ...int) {
	t.Helper()
	if slices.Contains(families, 4) {
		rootFile(t, m, "/proc/net/route", defaultRoute4)
		rootFile(t, m, "/proc/sys/net/ipv4/ip_forward", "0\n")
	}
	if slices.Contains(families, 6) {
		rootFile(t, m, "/proc/net/ipv6_route", defaultRoute6)
		rootFile(t, m, "/proc/sys/net/ipv6/conf/all/forwarding", "0\n")
		rootFile(t, m, "/proc/sys/net/ipv6/conf/eth0/accept_ra", "0\n")
	}
}

func duplicated(listing string) string {
	seen := map[string]bool{}
	for line := range strings.SplitSeq(strings.TrimSpace(listing), "\n") {
		if seen[line] {
			return line
		}
		seen[line] = true
	}
	return ""
}

func checkJumps(t *testing.T, s *space, tool string, specs [][]string) {
	t.Helper()
	for _, spec := range specs {
		if output, _, err := s.exec(t.Context(), tool, append([]string{"-w", "-C"}, spec...)...); err != nil {
			t.Errorf("%s -C %s: %v: %s", tool, strings.Join(spec, " "), err, output)
		}
	}
}

func TestRenderedRulesLoadIntoRealIptables(t *testing.T) {
	s := newSpace(t)
	s.sh("ip link add kry0 type veth peer name peer0")
	m := liveMesh(t, s, liveOne)
	document := wideDocument()
	wants := map[int][]string{
		4: {"-p icmp -m icmp --icmp-type 8 -j ACCEPT", "--ctorigdstport 8000:8100", "-m multiport --dports 22,80,443,8000:8100", "-A KRY-EXIT -s 10.88.37.9/32 -i kry0 -o eth0 -j ACCEPT", "-A KRY-IN -s 10.88.37.3/32 -j DROP"},
		6: {"-p ipv6-icmp -m icmp6 --icmpv6-type 128 -j ACCEPT", "--ctorigdstport 8000:8100", "-A KRY-EXIT -s fd88:88::25:9/128 -i kry0 -o eth0 -j ACCEPT", "-A KRY-EDGE -d fd88:88::/64 -j DROP", "-A KRY-IN -s fd88:88::25:3/128 -j DROP"},
	}
	for _, entry := range families {
		body := network.RenderRules(document, liveOne, []string{"10.88.37.3"}, entry.family, "eth0")
		if err := m.restore(t.Context(), entry.restore, body); err != nil {
			t.Fatalf("%s refused the body: %v\n%s", entry.restore, err, body)
		}
		listing := s.sh(entry.tool + " -w -S")
		if !whole(listing, body) {
			t.Fatalf("%s holds\n%s\nfor the body\n%s", entry.tool, listing, body)
		}
		for _, want := range wants[entry.family] {
			if !strings.Contains(listing, want) {
				t.Errorf("%s has no %q:\n%s", entry.tool, want, listing)
			}
		}
	}
}

func TestRestoreReplacesOnlyKrynodesChains(t *testing.T) {
	s := newSpace(t)
	m := liveMesh(t, s, liveOne)
	small := liveDocument(crew(liveMember(liveOne, "server-1", "10.88.37.1"), liveMember(liveTwo, "server-2", "10.88.37.2")), grant(liveTwo, liveOne, "81/tcp"))
	owner := []string{"-A OWNER -p tcp -m tcp --dport 2222 -j ACCEPT", "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT", "-A DOCKER-USER -p tcp -m tcp --dport 2375 -j DROP"}
	for _, entry := range families {
		s.sh(entry.tool+" -w -N OWNER", entry.tool+" -w -N DOCKER-USER")
		for _, line := range owner {
			s.sh(entry.tool + " -w " + line)
		}
		for index, document := range []network.Document{wideDocument(), wideDocument(), small} {
			body := network.RenderRules(document, liveOne, []string{"10.88.37.3"}, entry.family, "eth0")
			if err := m.restore(t.Context(), entry.restore, body); err != nil {
				t.Fatalf("%s, restore %d: %v", entry.restore, index+1, err)
			}
			listing := s.sh(entry.tool + " -w -S")
			if !whole(listing, body) {
				t.Fatalf("%s, restore %d: the chains are not exactly the body:\n%s\nbody:\n%s", entry.tool, index+1, listing, body)
			}
			if line := duplicated(listing); line != "" {
				t.Fatalf("%s, restore %d: %q is there twice", entry.tool, index+1, line)
			}
			for _, line := range owner {
				if !strings.Contains(listing, line) {
					t.Fatalf("%s, restore %d: the owner's %q is gone:\n%s", entry.tool, index+1, line, listing)
				}
			}
		}
	}
}

func TestEveryJumpIsFoundByCheck(t *testing.T) {
	s := newSpace(t)
	s.sh("ip link add kry0 type veth peer name peer0")
	m := liveMesh(t, s, liveOne)
	exitRoutes(t, m, 4, 6)
	document := wideDocument()
	liveApply(t, m, document)
	first := map[string]string{}
	for _, entry := range families {
		first[entry.tool] = s.sh(entry.tool + " -w -S")
	}
	liveApply(t, m, document)
	for _, entry := range families {
		checkJumps(t, s, entry.tool, append(network.Jumps(), network.ExitJumps...))
		listing := s.sh(entry.tool + " -w -S")
		if listing != first[entry.tool] {
			t.Errorf("%s changed on the second boot:\n%s\nfirst:\n%s", entry.tool, listing, first[entry.tool])
		}
		if line := duplicated(listing); line != "" {
			t.Errorf("%s holds %q twice", entry.tool, line)
		}
	}
}

func TestTheWayBackIsClosed(t *testing.T) {
	one, two := newSpace(t), newSpace(t)
	wire(one, "kry0", two, "kry0")
	addresses := map[*space][2]string{one: {"10.88.37.1", network.Address6("10.88.37.1")}, two: {"10.88.37.2", network.Address6("10.88.37.2")}}
	for s, address := range addresses {
		s.sh("ip addr add "+address[0]+"/24 dev kry0", "ip -6 addr add "+address[1]+"/64 dev kry0 nodad")
		s.serve(81)
	}
	neighbours(one, addresses[one][1], two, addresses[two][1])
	for family := range 2 {
		expect(t, two, "", net.JoinHostPort(addresses[one][family], "81"), true, "before the rules")
	}
	document := liveDocument(crew(liveMember(liveOne, "server-1", "10.88.37.1"), liveMember(liveTwo, "server-2", "10.88.37.2")), grant(liveOne, liveTwo, "81/tcp"))
	liveApply(t, liveMesh(t, one, liveOne), document)
	liveApply(t, liveMesh(t, two, liveTwo), document)
	for family := range 2 {
		conn := one.open("", net.JoinHostPort(addresses[two][family], "81"))
		for range 3 {
			if !talks(conn) {
				t.Errorf("family %d: the replies from server-2 stopped", family)
			}
		}
		expect(t, two, "", net.JoinHostPort(addresses[one][family], "81"), false, "server-2 back to server-1")
	}
}

func dockerLike(s *space, top bool) {
	if s.try("iptables -w -N DOCKER-USER") == nil {
		s.sh("iptables -w -A DOCKER-USER -j RETURN")
	}
	s.sh("iptables -w -N DOCKER", "iptables -w -A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp --dport 80 -j ACCEPT")
	forward := []string{"-j DOCKER-USER", "-o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", "-o docker0 -j DOCKER", "-i docker0 ! -o docker0 -j ACCEPT", "-i docker0 -o docker0 -j ACCEPT"}
	for index := range forward {
		if top {
			s.sh("iptables -w -I FORWARD 1 " + forward[len(forward)-1-index])
		} else {
			s.sh("iptables -w -A FORWARD " + forward[index])
		}
	}
	s.sh("iptables -w -P FORWARD DROP")
}

func TestForwardedTrafficNeedsADNATedGrantedPort(t *testing.T) {
	for _, dockerFirst := range []bool{true, false} {
		name := "Docker's rules below the jumps"
		if !dockerFirst {
			name = "Docker's rules above the jumps"
		}
		t.Run(name, func(t *testing.T) {
			one, two, box := newSpace(t), newSpace(t), newSpace(t)
			wire(one, "kry0", two, "kry0")
			wire(two, "docker0", box, "eth0")
			one.sh("ip addr add 10.88.37.1/24 dev kry0", "ip route add 172.17.0.0/16 via 10.88.37.2")
			two.sh("ip addr add 10.88.37.2/24 dev kry0", "ip addr add 172.17.0.1/16 dev docker0", "sysctl -w net.ipv4.ip_forward=1",
				"iptables -w -t nat -A PREROUTING -i kry0 -p tcp --dport 8081 -j DNAT --to-destination 172.17.0.2:80",
				"iptables -w -t nat -A PREROUTING -i kry0 -p tcp --dport 8082 -j DNAT --to-destination 172.17.0.2:80")
			box.sh("ip addr add 172.17.0.2/16 dev eth0", "ip route add default via 172.17.0.1")
			box.serve(80)
			for _, to := range []string{"172.17.0.2:80", "10.88.37.2:8081", "10.88.37.2:8082"} {
				expect(t, one, "", to, true, "before the rules")
			}
			document := liveDocument(crew(liveMember(liveOne, "server-1", "10.88.37.1"), liveMember(liveTwo, "server-2", "10.88.37.2")), grant(liveOne, liveTwo, "80/tcp", "8081/tcp"))
			m := liveMesh(t, two, liveTwo)
			if dockerFirst {
				dockerLike(two, false)
				liveApply(t, m, document)
			} else {
				liveApply(t, m, document)
				dockerLike(two, true)
			}
			if listing := two.sh("iptables -w -S FORWARD"); !strings.Contains(listing, "-P FORWARD DROP") {
				t.Fatalf("FORWARD policy is not DROP:\n%s", listing)
			}
			expect(t, one, "", "172.17.0.2:80", false, "a granted port straight to a container, not DNATed")
			expect(t, one, "", "10.88.37.2:8081", true, "a granted published port")
			expect(t, one, "", "10.88.37.2:8082", false, "a published port that is not granted")
		})
	}
}

func TestForwardingFromKry0BackIntoKry0IsDropped(t *testing.T) {
	one, two, three := newSpace(t), newSpace(t), newSpace(t)
	two.sh("ip link add kry0 type bridge", "ip link set kry0 up", "ip addr add 10.88.37.2/24 dev kry0")
	wire(two, "port1", one, "kry0")
	wire(two, "port3", three, "kry0")
	two.sh("ip link set port1 master kry0", "ip link set port3 master kry0", "sysctl -w net.ipv4.ip_forward=1",
		"sysctl -w net.ipv4.conf.all.send_redirects=0", "sysctl -w net.ipv4.conf.kry0.send_redirects=0",
		"iptables -w -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", "iptables -w -A FORWARD -j ACCEPT")
	for s, addresses := range map[*space][2]string{one: {"10.88.37.1", "10.88.37.3"}, three: {"10.88.37.3", "10.88.37.1"}} {
		s.sh("sysctl -w net.ipv4.conf.all.accept_redirects=0", "ip addr add "+addresses[0]+"/32 dev kry0", "ip route add 10.88.37.2/32 dev kry0", "ip route add "+addresses[1]+"/32 via 10.88.37.2 dev kry0")
	}
	two.serve(81)
	three.serve(81)
	held := one.open("", "10.88.37.3:81")
	document := liveDocument(crew(liveMember(liveOne, "server-1", "10.88.37.1"), liveMember(liveTwo, "server-2", "10.88.37.2"), liveMember(liveThree, "server-3", "10.88.37.3")), grant(liveOne, liveThree, "81/tcp"), grant(liveOne, liveTwo, "81/tcp"))
	liveApply(t, liveMesh(t, two, liveTwo), document)
	if talks(held) {
		t.Error("an established connection still goes through server-2 from kry0 back into kry0")
	}
	expect(t, one, "", "10.88.37.3:81", false, "a new connection from kry0 back into kry0")
	expect(t, one, "", "10.88.37.2:81", true, "server-2 itself")
}

func TestThePoolIsReachableOnlyFromInside(t *testing.T) {
	one, two, lan := newSpace(t), newSpace(t), newSpace(t)
	wire(one, "kry0", two, "kry0")
	wire(two, "eth0", lan, "eth0")
	one.sh("ip addr add 10.88.37.1/24 dev kry0")
	two.sh("ip addr add 10.88.37.2/24 dev kry0", "ip addr add 203.0.113.2/26 dev eth0")
	lan.sh("ip addr add 203.0.113.1/26 dev eth0", "ip route add 10.88.37.0/24 via 203.0.113.2")
	two.serve(81)
	expect(t, lan, "", "10.88.37.2:81", true, "before the rules")
	document := liveDocument(crew(liveMember(liveOne, "server-1", "10.88.37.1"), liveMember(liveTwo, "server-2", "10.88.37.2")), grant(liveOne, liveTwo, "81/tcp"))
	liveApply(t, liveMesh(t, two, liveTwo), document)
	expect(t, lan, "", "10.88.37.2:81", false, "a LAN neighbour to the pool")
	expect(t, lan, "", "203.0.113.2:81", true, "a LAN neighbour to the server's own LAN address")
	expect(t, one, "", "10.88.37.2:81", true, "server-1 over kry0")
	expect(t, two, "", "10.88.37.2:81", true, "the server itself over lo")
}

func reorder(t *testing.T, m *Mesh, s *space) {
	t.Helper()
	if err := m.unjump(t.Context(), "iptables", append(network.Jumps(), network.ExitJumps...)); err != nil {
		t.Fatal(err)
	}
	for _, spec := range append(slices.Clone(network.ExitJumps), network.Jumps()...) {
		s.sh("iptables -w -I " + spec[0] + " 1 " + strings.Join(spec[1:], " "))
	}
}

func TestTheExitCarriesOnlyLaptops(t *testing.T) {
	exit, laptop, world, lan := newSpace(t), newSpace(t), newSpace(t), newSpace(t)
	wire(exit, "kry0", laptop, "kry0")
	wire(exit, "eth0", world, "eth0")
	wire(exit, "eth1", lan, "eth1")
	exit.sh("ip addr add 10.88.37.1/24 dev kry0", "ip addr add 203.0.113.2/26 dev eth0", "ip addr add 203.0.113.66/26 dev eth1", "ip route add default via 203.0.113.1", "sysctl -w net.ipv4.ip_forward=1")
	laptop.sh("ip addr add 10.88.37.9/24 dev kry0", "ip addr add 10.88.37.2/24 dev kry0", "ip route add default via 10.88.37.1")
	world.sh("ip addr add 203.0.113.1/26 dev eth0", "ip addr add 192.168.1.1/32 dev eth0", "ip addr add 169.254.169.254/32 dev eth0", "ip route add 10.88.37.0/24 via 203.0.113.2")
	lan.sh("ip addr add 203.0.113.65/26 dev eth1", "ip route add 10.88.37.0/24 via 203.0.113.66")
	world.serve(80)
	laptop.serve(80)
	type check struct {
		from     *space
		source   string
		to, what string
	}
	refused := []check{
		{laptop, "10.88.37.2", "203.0.113.1:80", "server-2 out the uplink"},
		{laptop, "10.88.37.9", "192.168.1.1:80", "the laptop to 192.168.1.1"},
		{laptop, "10.88.37.9", "169.254.169.254:80", "the laptop to 169.254.169.254"},
		{lan, "", "10.88.37.9:80", "a second LAN into kry0"},
		{world, "", "10.88.37.9:80", "the uplink into kry0"},
	}
	for _, entry := range append(refused, check{laptop, "10.88.37.9", "203.0.113.1:80", "the laptop out the uplink"}) {
		expect(t, entry.from, entry.source, entry.to, true, "before the rules: "+entry.what)
	}
	one := liveMember(liveOne, "server-1", "10.88.37.1")
	one.Exit = true
	carried := liveMember(liveLaptop, "laptop-1", "10.88.37.9")
	carried.Kind = "laptop"
	document := liveDocument(crew(one, liveMember(liveTwo, "server-2", "10.88.37.2"), carried), network.Rule{From: network.Side{Group: "laptops"}, To: network.Side{Group: "servers"}, Ports: network.Ports{All: true}})
	m := liveMesh(t, exit, liveOne)
	exitRoutes(t, m, 4)
	for _, krynodesOnTop := range []bool{false, true} {
		name := "exit jumps on top"
		if krynodesOnTop {
			name = "rule jumps on top"
		}
		t.Run(name, func(t *testing.T) {
			liveApply(t, m, document)
			if err := m.exit(t.Context(), document, one); err != nil {
				t.Fatal(err)
			}
			if krynodesOnTop {
				reorder(t, m, exit)
			}
			if listing := exit.sh("iptables -w -S FORWARD"); !strings.Contains(listing, "-P FORWARD DROP") {
				t.Fatalf("FORWARD policy is not DROP:\n%s", listing)
			}
			if nat := exit.sh("iptables -w -t nat -S POSTROUTING"); !strings.Contains(nat, "-A POSTROUTING -s 10.88.37.9/32 -o eth0 -j MASQUERADE") {
				t.Fatalf("no MASQUERADE for the laptop:\n%s", nat)
			}
			conn := laptop.open("10.88.37.9", "203.0.113.1:80")
			for range 3 {
				if !talks(conn) {
					t.Error("the laptop's connection out the uplink stopped after its first packet")
				}
			}
			for _, entry := range refused {
				expect(t, entry.from, entry.source, entry.to, false, entry.what)
			}
			liveApply(t, m, document, "10.88.37.9")
			if talks(conn) {
				t.Error("a dropped laptop's open connection still goes out the uplink")
			}
			expect(t, laptop, "10.88.37.9", "203.0.113.1:80", false, "a dropped laptop that is not cut")
			checkJumps(t, exit, "iptables", append(network.Jumps(), network.ExitJumps...))
		})
	}
}

func TestARemovedRuleKeepsOpenConnections(t *testing.T) {
	one, two := newSpace(t), newSpace(t)
	wire(one, "kry0", two, "kry0")
	one.sh("ip addr add 10.88.37.1/24 dev kry0")
	two.sh("ip addr add 10.88.37.2/24 dev kry0")
	two.serve(81)
	two.serve(82)
	members := crew(liveMember(liveOne, "server-1", "10.88.37.1"), liveMember(liveTwo, "server-2", "10.88.37.2"))
	m := liveMesh(t, two, liveTwo)
	liveApply(t, m, liveDocument(members, grant(liveOne, liveTwo, "81/tcp"), grant(liveOne, liveTwo, "82/tcp")))
	held := one.open("", "10.88.37.2:81")
	next := liveDocument(members, grant(liveOne, liveTwo, "82/tcp"))
	next.Version = 2
	liveApply(t, m, next)
	if !talks(held) {
		t.Error("the open connection to 81 broke when its rule went")
	}
	expect(t, one, "", "10.88.37.2:81", false, "a new connection to 81 after its rule went")
	expect(t, one, "", "10.88.37.2:82", true, "the rule that stayed")
}

func TestTheGuardPutsTheRulesBack(t *testing.T) {
	one, two := newSpace(t), newSpace(t)
	wire(one, "kry0", two, "kry0")
	one.sh("ip addr add 10.88.37.1/24 dev kry0")
	two.sh("ip addr add 10.88.37.2/24 dev kry0")
	two.serve(81)
	two.serve(82)
	document := liveDocument(crew(liveMember(liveOne, "server-1", "10.88.37.1"), liveMember(liveTwo, "server-2", "10.88.37.2")), grant(liveOne, liveTwo, "81/tcp"))
	m := liveMesh(t, two, liveTwo)
	liveApply(t, m, document)
	said := map[string]string{}
	steps := []struct {
		what   string
		opens  bool
		damage []string
	}{
		{"a jump deleted", true, []string{"iptables -w -D INPUT -i kry0 -j KRY-IN"}},
		{"KRY-IN flushed", true, []string{"iptables -w -F KRY-IN"}},
		{"KRY-EDGE deleted", false, []string{"iptables -w -D INPUT -j KRY-EDGE", "iptables -w -F KRY-EDGE", "iptables -w -X KRY-EDGE"}},
		{"KRY-FWD deleted", false, []string{"iptables -w -D FORWARD -i kry0 -j KRY-FWD", "iptables -w -D DOCKER-USER -i kry0 -j KRY-FWD", "iptables -w -F KRY-FWD", "iptables -w -X KRY-FWD"}},
		{"the IPv6 KRY-IN flushed", false, []string{"ip6tables -w -F KRY-IN"}},
		{"DOCKER-USER made again later", false, []string{"iptables -w -D DOCKER-USER -i kry0 -j KRY-FWD", "iptables -w -X DOCKER-USER", "iptables -w -N DOCKER-USER", "iptables -w -A DOCKER-USER -j RETURN"}},
	}
	for _, step := range steps {
		two.sh(step.damage...)
		if step.opens {
			expect(t, one, "", "10.88.37.2:82", true, step.what+", before the guard")
		}
		if _, ok := m.keep(t.Context(), said); !ok {
			t.Fatalf("%s: the guard pass did not run", step.what)
		}
		for _, entry := range families {
			body := network.RenderRules(document, liveTwo, nil, entry.family, "")
			if listing := two.sh(entry.tool + " -w -S"); !whole(listing, body) {
				t.Errorf("%s: %s is not back:\n%s", step.what, entry.tool, listing)
			}
			checkJumps(t, two, entry.tool, network.Jumps())
		}
		expect(t, one, "", "10.88.37.2:82", false, step.what+", after the guard")
		expect(t, one, "", "10.88.37.2:81", true, step.what+", the granted port after the guard")
	}
	if first := strings.Split(two.sh("iptables -w -S DOCKER-USER"), "\n")[1]; first != "-A DOCKER-USER -i kry0 -j KRY-FWD" {
		t.Errorf("the first DOCKER-USER rule is %q", first)
	}
}

func TestLeaveLeavesNoKrynodesChain(t *testing.T) {
	s := newSpace(t)
	s.sh("ip link add kry0 type veth peer name peer0",
		"iptables -w -t nat -A POSTROUTING -s 10.88.0.0/16 -o eth0 -j MASQUERADE",
		"iptables -w -A INPUT -p tcp --dport 22 -j ACCEPT",
		"ip6tables -w -N DOCKER-USER", "ip6tables -w -A DOCKER-USER -s fd00::/8 -j RETURN")
	m := liveMesh(t, s, liveOne)
	exitRoutes(t, m, 4, 6)
	document := wideDocument()
	liveApply(t, m, document)
	if err := m.exit(t.Context(), document, document.Members[0]); err != nil {
		t.Fatal(err)
	}
	if nat := s.sh("iptables -w -t nat -S POSTROUTING"); !strings.Contains(nat, "-s 10.88.37.9/32 -o eth0 -j MASQUERADE") {
		t.Fatalf("no laptop MASQUERADE before leaving:\n%s", nat)
	}
	for range 2 {
		if err := m.Leave(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range families {
		listing := s.sh(entry.tool + " -w -S")
		if strings.Contains(listing, "KRY-") {
			t.Errorf("%s still holds Krynodes rules:\n%s", entry.tool, listing)
		}
		nat := s.sh(entry.tool + " -w -t nat -S POSTROUTING")
		if strings.Contains(nat, "-s 10.88.37.9/32") || strings.Contains(nat, "fd88:88::25:9/128") {
			t.Errorf("%s still masquerades the laptop:\n%s", entry.tool, nat)
		}
	}
	if listing := s.sh("iptables -w -S"); strings.Contains(listing, "DOCKER-USER") || !strings.Contains(listing, "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT") {
		t.Errorf("iptables after leaving:\n%s", listing)
	}
	if listing := s.sh("ip6tables -w -S DOCKER-USER"); strings.TrimSpace(listing) != "-N DOCKER-USER\n-A DOCKER-USER -s fd00::/8 -j RETURN" {
		t.Errorf("the owner's IPv6 DOCKER-USER is not as it was:\n%s", listing)
	}
	if nat := s.sh("iptables -w -t nat -S POSTROUTING"); !strings.Contains(nat, "-A POSTROUTING -s 10.88.0.0/16 -o eth0 -j MASQUERADE") {
		t.Errorf("the owner's MASQUERADE is gone:\n%s", nat)
	}
}
