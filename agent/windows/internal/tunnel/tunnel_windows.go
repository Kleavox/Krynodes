//go:build windows

package tunnel

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	adapterName = "Krynodes"
	ruleName    = "Krynodes tunnel: refuse inbound"
	nrptKey     = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\Krynodes`
	defaultMTU  = 1420
)

var (
	families        = []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6}
	profileKeys     = []string{`SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile`, `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile`}
	dnsapi          = windows.NewLazySystemDLL("dnsapi.dll")
	flushResolver   = dnsapi.NewProc("DnsFlushResolverCache")
	iphlpapi        = windows.NewLazySystemDLL("iphlpapi.dll")
	icmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	icmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	icmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)

type Tunnel struct {
	guid      windows.GUID
	mu        sync.Mutex
	closed    bool
	config    Config
	native    *tun.NativeTun
	device    *device.Device
	applied   *Config
	mtu       int
	tuned     map[winipcfg.AddressFamily]bool
	addresses []netip.Prefix
	routes    []Route
	pins      []Route
	dns       []netip.Addr
	policy    *Policy
	rule      string
	warnings  []string
}

func New(node string) *Tunnel {
	sum := sha256.Sum256([]byte("krynodes adapter " + node))
	guid := windows.GUID{
		Data1: binary.BigEndian.Uint32(sum[0:4]),
		Data2: binary.BigEndian.Uint16(sum[4:6]),
		Data3: binary.BigEndian.Uint16(sum[6:8])&0x0fff | 0x5000,
	}
	copy(guid.Data4[:], sum[8:16])
	guid.Data4[0] = guid.Data4[0]&0x3f | 0x80
	return &Tunnel{guid: guid}
}

func (t *Tunnel) Apply(config Config) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.config = config
	return t.sync()
}

func (t *Tunnel) Refresh() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || (t.device == nil && t.config.Address == "") {
		return nil
	}
	return t.sync()
}

func (t *Tunnel) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed, t.config = true, Config{}
	t.down()
}

func (t *Tunnel) Warnings() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.warnings)
}

func (t *Tunnel) warn(lines ...string) {
	var next []string
	for _, line := range lines {
		if line == "" {
			continue
		}
		if !slices.Contains(t.warnings, line) {
			log.Print(line)
		}
		next = append(next, line)
	}
	t.warnings = next
}

func (t *Tunnel) sync() error {
	if t.config.Address == "" {
		t.down()
		return nil
	}
	firewall := firewallWarning()
	var held error
	if t.native == nil {
		tun.WintunTunnelType = adapterName
		created, err := tun.CreateTUNWithRequestedGUID(adapterName, &t.guid, mtuOf(t.config))
		if err != nil {
			return err
		}
		t.native = created.(*tun.NativeTun)
		t.device = device.NewDevice(created, conn.NewDefaultBind(), &device.Logger{Verbosef: device.DiscardLogf, Errorf: log.Printf})
		t.forget()
	}
	if t.applied == nil || !reflect.DeepEqual(*t.applied, t.config) {
		if err := t.configure(); err != nil {
			return err
		}
		applied := t.config
		t.applied = &applied
	} else {
		held = t.hold()
	}
	luid := winipcfg.LUID(t.native.LUID())
	six, err := hasIPv6(luid)
	if err != nil {
		return err
	}
	mtu := mtuOf(t.config)
	if mtu != t.mtu {
		t.native.ForceMTU(mtu)
		t.mtu, t.tuned = mtu, map[winipcfg.AddressFamily]bool{}
	}
	for _, family := range active(six) {
		if !t.tuned[family] {
			if err := tune(luid, family, mtu); err != nil {
				return err
			}
			t.tuned[family] = true
		}
	}
	system := System{NoIPv6: !six}
	if t.config.Exit {
		if system, err = snapshot(luid); err != nil {
			return err
		}
		system.NoIPv6 = !six
		t.pins = slices.DeleteFunc(t.pins, func(pin Route) bool { return !slices.Contains(system.Routes, pin) })
	}
	plan := Build(t.config, system)
	refused := ""
	if plan.ExitRefused {
		refused = "IPv6 is off on the Krynodes adapter but on for this laptop's network, so the exit node stays off."
	}
	t.warn(firewall, refused)
	return errors.Join(t.route(luid, plan, six), held)
}

func (t *Tunnel) forget() {
	t.applied, t.mtu, t.tuned = nil, 0, map[winipcfg.AddressFamily]bool{}
	t.addresses, t.routes, t.dns = nil, nil, nil
}

func active(six bool) []winipcfg.AddressFamily {
	if six {
		return families
	}
	return families[:1]
}

func hasIPv6(luid winipcfg.LUID) (bool, error) {
	if _, err := luid.IPInterface(windows.AF_INET); err != nil {
		return false, err
	}
	_, err := luid.IPInterface(windows.AF_INET6)
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return false, nil
	}
	return err == nil, err
}

func mtuOf(config Config) int {
	if config.MTU > 0 {
		return config.MTU
	}
	return defaultMTU
}

func (t *Tunnel) configure() error {
	uapi, err := settings(t.config, t.applied)
	if err != nil {
		return err
	}
	if err := t.device.IpcSet(uapi); err != nil {
		return err
	}
	return t.device.Up()
}

func (t *Tunnel) hold() error {
	dump, err := t.device.IpcGet()
	if err == nil {
		if uapi := reassert(t.config.Peers, dump); uapi != "" {
			err = t.device.IpcSet(uapi)
		}
	}
	if err != nil {
		return fmt.Errorf("put the members behind NAT back on the meeting point: %w", err)
	}
	return nil
}

func tune(luid winipcfg.LUID, family winipcfg.AddressFamily, mtu int) error {
	row, err := luid.IPInterface(family)
	if err != nil {
		return err
	}
	row.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	row.DadTransmits = 0
	row.ManagedAddressConfigurationSupported = false
	row.OtherStatefulConfigurationSupported = false
	row.NLMTU = uint32(mtu)
	row.UseAutomaticMetric = false
	row.Metric = 0
	return row.Set()
}

func nextHop(route Route) netip.Addr {
	if route.Via.IsValid() {
		return route.Via
	}
	if route.Prefix.Addr().Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

func (t *Tunnel) route(luid winipcfg.LUID, plan Plan, six bool) error {
	if err := t.guard(plan.Addresses); err != nil {
		return err
	}
	if !slices.Equal(t.addresses, plan.Addresses) {
		for _, family := range active(six) {
			if err := luid.SetIPAddressesForFamily(family, plan.Addresses); err != nil {
				return fmt.Errorf("set the tunnel's address: %w", err)
			}
		}
		t.addresses = slices.Clone(plan.Addresses)
	}
	var routes, pins []Route
	for _, route := range plan.Routes {
		if route.Interface == Inside {
			routes = append(routes, route)
		} else {
			pins = append(pins, route)
		}
	}
	if err := t.add(&t.pins, pins); err != nil {
		return err
	}
	if err := t.add(&t.routes, routes); err != nil {
		return err
	}
	if err := t.drop(&t.routes, routes); err != nil {
		return err
	}
	if err := t.drop(&t.pins, pins); err != nil {
		return err
	}
	if !slices.Equal(t.dns, plan.DNS) {
		for _, family := range active(six) {
			if err := luid.SetDNS(family, plan.DNS, nil); err != nil {
				return fmt.Errorf("set the tunnel's DNS: %w", err)
			}
		}
		t.dns = slices.Clone(plan.DNS)
	}
	policy, on := NRPT(plan)
	switch {
	case on && (t.policy == nil || !reflect.DeepEqual(*t.policy, policy)):
		if err := writeNRPT(policy); err != nil {
			return fmt.Errorf("send every name to the exit's DNS: %w", err)
		}
		t.policy = &policy
	case !on && t.policy != nil:
		if err := RemoveNRPT(); err != nil {
			return err
		}
		t.policy = nil
	}
	return nil
}

func (t *Tunnel) interfaceOf(route Route) winipcfg.LUID {
	if route.Interface == Inside {
		return winipcfg.LUID(t.native.LUID())
	}
	return winipcfg.LUID(route.Interface)
}

func (t *Tunnel) add(have *[]Route, want []Route) error {
	for _, route := range want {
		if slices.Contains(*have, route) {
			continue
		}
		if err := t.interfaceOf(route).AddRoute(route.Prefix, nextHop(route), 0); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			return fmt.Errorf("add the route to %s: %w", route.Prefix, err)
		}
		*have = append(*have, route)
	}
	return nil
}

func (t *Tunnel) drop(have *[]Route, want []Route) error {
	for _, route := range slices.Clone(*have) {
		if slices.Contains(want, route) {
			continue
		}
		if err := t.interfaceOf(route).DeleteRoute(route.Prefix, nextHop(route)); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			return fmt.Errorf("remove the route to %s: %w", route.Prefix, err)
		}
		*have = slices.DeleteFunc(*have, func(kept Route) bool { return kept == route })
	}
	return nil
}

func (t *Tunnel) guard(addresses []netip.Prefix) error {
	var local []string
	for _, address := range addresses {
		local = append(local, address.Addr().String())
	}
	rule := strings.Join(local, ",")
	if rule == t.rule || !firewallRunning() {
		return nil
	}
	if t.rule != "" {
		if err := netsh("set", "rule", quoted(ruleName), "new", "localip="+rule); err != nil {
			return err
		}
		t.rule = rule
		return nil
	}
	if err := RemoveFirewall(); err != nil {
		return err
	}
	if err := netsh("add", "rule", quoted(ruleName), "dir=in", "action=block", "profile=any", "localip="+rule); err != nil {
		return err
	}
	t.rule = rule
	return nil
}

func (t *Tunnel) down() {
	if err := t.drop(&t.pins, nil); err != nil {
		log.Printf("tunnel down: %v", err)
	}
	if t.policy != nil {
		if err := RemoveNRPT(); err != nil {
			log.Printf("tunnel down: %v", err)
		}
		t.policy = nil
	}
	if t.rule != "" {
		if err := RemoveFirewall(); err != nil {
			log.Printf("tunnel down: %v", err)
		}
		t.rule = ""
	}
	if t.device != nil {
		t.device.Close()
	}
	t.native, t.device, t.pins = nil, nil, nil
	t.forget()
	t.warn()
}

func snapshot(own winipcfg.LUID) (System, error) {
	type place struct {
		luid   winipcfg.LUID
		family winipcfg.AddressFamily
	}
	familyOf := func(address netip.Addr) winipcfg.AddressFamily {
		if address.Is4() {
			return windows.AF_INET
		}
		return windows.AF_INET6
	}
	plain := func(address netip.Addr) netip.Addr {
		if address.IsUnspecified() {
			return netip.Addr{}
		}
		return address
	}
	interfaces, err := winipcfg.GetIPInterfaceTable(windows.AF_UNSPEC)
	if err != nil {
		return System{}, err
	}
	var system System
	metrics := map[place]uint32{}
	for _, row := range interfaces {
		if row.Connected && row.InterfaceLUID != own {
			metrics[place{row.InterfaceLUID, row.Family}] = row.Metric
			if Virtual(uint64(row.InterfaceLUID)) && !slices.Contains(system.Virtual, uint64(row.InterfaceLUID)) {
				system.Virtual = append(system.Virtual, uint64(row.InterfaceLUID))
			}
		}
	}
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return System{}, err
	}
	addresses, err := winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
	if err != nil {
		return System{}, err
	}
	best := map[winipcfg.AddressFamily]uint32{}
	routed := map[winipcfg.LUID]bool{}
	for _, row := range routes {
		prefix := row.DestinationPrefix.Prefix()
		family := familyOf(prefix.Addr())
		metric, connected := metrics[place{row.InterfaceLUID, family}]
		if prefix.Bits() != 0 || !connected {
			continue
		}
		routed[row.InterfaceLUID] = true
		total := row.Metric + metric
		if lowest, found := best[family]; found && total >= lowest {
			continue
		}
		best[family] = total
		gateway := Gateway{Interface: uint64(row.InterfaceLUID), Via: plain(row.NextHop.Addr())}
		if family == windows.AF_INET {
			system.Default4 = gateway
		} else {
			system.Default6 = gateway
		}
	}
	owned := map[netip.Addr]bool{}
	for _, row := range addresses {
		address := row.Address.Addr().WithZone("")
		owned[address] = true
		if _, connected := metrics[place{row.InterfaceLUID, familyOf(address)}]; !connected || !routed[row.InterfaceLUID] || row.DadState != winipcfg.DadStatePreferred || !address.IsGlobalUnicast() {
			continue
		}
		link := Link{Interface: uint64(row.InterfaceLUID), Prefix: netip.PrefixFrom(address, int(row.OnLinkPrefixLength)).Masked()}
		if link.Prefix.Bits() > 0 && link.Prefix.Bits() < address.BitLen() && !slices.Contains(system.Links, link) {
			system.Links = append(system.Links, link)
		}
	}
	for _, row := range routes {
		prefix := row.DestinationPrefix.Prefix()
		if _, connected := metrics[place{row.InterfaceLUID, familyOf(prefix.Addr())}]; !connected || prefix.Bits() <= 1 || (prefix.IsSingleIP() && owned[prefix.Addr()]) {
			continue
		}
		system.Routes = append(system.Routes, Route{Prefix: prefix, Interface: uint64(row.InterfaceLUID), Via: plain(row.NextHop.Addr())})
	}
	for luid := range routed {
		system.Routed = append(system.Routed, uint64(luid))
	}
	slices.Sort(system.Routed)
	slices.Sort(system.Virtual)
	slices.SortFunc(system.Links, func(a, b Link) int {
		if a.Interface != b.Interface {
			return cmp.Compare(a.Interface, b.Interface)
		}
		return a.Prefix.Addr().Compare(b.Prefix.Addr())
	})
	return system, nil
}

func quoted(name string) string {
	return `name="` + name + `"`
}

func netsh(args ...string) error {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	path := filepath.Join(system, "netsh.exe")
	command := exec.Command(path)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW, CmdLine: syscall.EscapeArg(path) + " advfirewall firewall " + strings.Join(args, " ")}
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh advfirewall firewall %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func RemoveFirewall() error {
	err := netsh("delete", "rule", quoted(ruleName))
	if err == nil {
		return nil
	}
	if firewallRunning() && netsh("show", "rule", quoted(ruleName)) != nil {
		return nil
	}
	return err
}

func firewallRunning() bool {
	manager, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer manager.Disconnect()
	service, err := manager.OpenService("MpsSvc")
	if err != nil {
		return false
	}
	defer service.Close()
	status, err := service.Query()
	return err == nil && status.State == svc.Running
}

func FirewallOff() bool {
	return firewallWarning() != ""
}

func firewallWarning() string {
	if !firewallRunning() {
		return "Windows Firewall is not running, so other members can reach this laptop's services."
	}
	for _, path := range profileKeys {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		enabled, _, err := key.GetIntegerValue("EnableFirewall")
		key.Close()
		if err != nil {
			continue
		}
		if enabled == 0 {
			return "Windows Firewall is off for public networks, so other members can reach this laptop's services."
		}
		return ""
	}
	return ""
}

func writeNRPT(policy Policy) error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, nrptKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	for _, step := range []func() error{
		func() error { return key.SetDWordValue("Version", policy.Version) },
		func() error { return key.SetStringsValue("Name", policy.Name) },
		func() error { return key.SetStringValue("GenericDNSServers", policy.Servers) },
		func() error { return key.SetDWordValue("ConfigOptions", policy.ConfigOptions) },
		func() error { return key.SetStringValue("Comment", "") },
		func() error { return key.SetStringValue("DisplayName", "") },
		func() error { return key.SetStringValue("IPSECCARestriction", "") },
	} {
		if err := step(); err != nil {
			return err
		}
	}
	flushResolver.Call()
	return nil
}

func RemoveNRPT() error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptKey)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("remove the exit's DNS rule: %w", err)
	}
	flushResolver.Call()
	return nil
}

func Ping(address string, timeout time.Duration) (time.Duration, bool) {
	target, err := netip.ParseAddr(address)
	if err != nil || !target.Is4() {
		return 0, false
	}
	handle, _, _ := icmpCreateFile.Call()
	if windows.Handle(handle) == windows.InvalidHandle {
		return 0, false
	}
	defer icmpCloseHandle.Call(handle)
	request := []byte("krynodes")
	reply := make([]byte, 128)
	four := target.As4()
	started := time.Now()
	count, _, _ := icmpSendEcho.Call(handle, uintptr(binary.LittleEndian.Uint32(four[:])), uintptr(unsafe.Pointer(&request[0])), uintptr(len(request)), 0, uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout.Milliseconds()))
	elapsed := time.Since(started)
	from := netip.AddrFrom4([4]byte(reply[0:4]))
	return elapsed, count > 0 && binary.LittleEndian.Uint32(reply[4:8]) == 0 && from == target
}
