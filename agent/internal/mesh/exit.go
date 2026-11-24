package mesh

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/Kleavox/krynodes/agent/internal/network"
)

const laptopExitConf = "/etc/sysctl.d/99-krynodes-laptop-exit.conf"

var (
	pool       = netip.MustParsePrefix("10.88.0.0/16")
	forwarding = map[int]string{4: "/proc/sys/net/ipv4/ip_forward", 6: "/proc/sys/net/ipv6/conf/all/forwarding"}
)

func (m *Mesh) exit(ctx context.Context, document network.Document, me network.Member) error {
	var problems []error
	sysctl := ""
	for _, entry := range families {
		uplink := m.uplink(entry.family)
		forward, nat := network.Exit(me, document.Members, uplink, entry.family)
		ra, unread := "", error(nil)
		if forward != nil && entry.family == 6 {
			ra, unread = m.keepsRA(uplink)
		}
		problems = append(problems, m.syncNAT(ctx, entry.tool, nat, rangeOf(&document)))
		if forward == nil {
			problems = append(problems, m.unjump(ctx, entry.tool, network.ExitJumps))
			continue
		}
		if unread != nil {
			problems = append(problems, fmt.Errorf("read router advertisements on %s, so IPv6 forwarding stays as it was: %w", uplink, unread))
			continue
		}
		if ra != "" {
			key := "net.ipv6.conf." + ra + ".accept_ra"
			if strings.Contains(ra, ".") {
				key = "net/ipv6/conf/" + ra + "/accept_ra"
			}
			sysctl = key + " = 2\n"
			if err := m.acceptRA(ra); err != nil {
				problems = append(problems, fmt.Errorf("keep router advertisements on %s, so IPv6 forwarding stays as it was: %w", ra, err))
				continue
			}
		}
		problems = append(problems, m.forward(ctx, entry.tool, entry.family))
	}
	return errors.Join(append(problems, m.persist(ctx, sysctl))...)
}

func rangeOf(document *network.Document) netip.Prefix {
	if document != nil {
		if within, err := netip.ParsePrefix(document.Range); err == nil {
			return within
		}
	}
	return pool
}

func (m *Mesh) exitOff(ctx context.Context, within netip.Prefix) error {
	var problems []error
	for _, entry := range families {
		problems = append(problems, m.syncNAT(ctx, entry.tool, nil, within))
	}
	return errors.Join(append(problems, m.persist(ctx, ""))...)
}

func (m *Mesh) keepsRA(uplink string) (string, error) {
	current, err := os.ReadFile(m.path("/proc/sys/net/ipv6/conf/" + uplink + "/accept_ra"))
	if err != nil {
		return "", err
	}
	if value := strings.TrimSpace(string(current)); value == "1" || value == "2" {
		return uplink, nil
	}
	return "", nil
}

func (m *Mesh) acceptRA(uplink string) error {
	path := m.path("/proc/sys/net/ipv6/conf/" + uplink + "/accept_ra")
	current, err := os.ReadFile(path)
	if err == nil && strings.TrimSpace(string(current)) != "2" {
		err = os.WriteFile(path, []byte("2"), 0o644)
	}
	return err
}

func (m *Mesh) forward(ctx context.Context, tool string, family int) error {
	path := m.path(forwarding[family])
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(current)) == "1" {
		return nil
	}
	if err := m.command(ctx, tool, "-w", "-P", "FORWARD", "DROP"); err != nil {
		return fmt.Errorf("%s FORWARD policy: %w", tool, err)
	}
	return os.WriteFile(path, []byte("1"), 0o644)
}

func (m *Mesh) persist(ctx context.Context, content string) error {
	path := m.path(laptopExitConf)
	current, err := os.ReadFile(path)
	switch {
	case content == "" && errors.Is(err, os.ErrNotExist):
		return nil
	case content == "":
		return os.Remove(path)
	case err == nil && string(current) == content:
		return nil
	}
	if err := m.write(laptopExitConf, []byte(content), 0o644); err != nil {
		return err
	}
	return m.command(ctx, "sysctl", "-p", path)
}

func laptopMasquerade(line string, within netip.Prefix) bool {
	fields := strings.Fields(line)
	if len(fields) != 8 || fields[0] != "-A" || fields[1] != "POSTROUTING" || fields[2] != "-s" || fields[4] != "-o" || fields[6] != "-j" || fields[7] != "MASQUERADE" {
		return false
	}
	prefix, err := netip.ParsePrefix(fields[3])
	if err != nil || !prefix.IsSingleIP() {
		return false
	}
	address := prefix.Addr()
	if address.Is4() {
		return within.Contains(address)
	}
	raw := address.As16()
	four := netip.AddrFrom4([4]byte{10, 88, raw[13], raw[15]})
	return within.Contains(four) && network.Address6(four.String()) == address.String()
}

func (m *Mesh) syncNAT(ctx context.Context, tool string, wanted []string, within netip.Prefix) error {
	text, ok := m.output(ctx, tool, "-w", "-t", "nat", "-S", "POSTROUTING")
	if !ok {
		if len(wanted) == 0 {
			return nil
		}
		return fmt.Errorf("%s cannot list its NAT rules", tool)
	}
	var current []string
	var problems []error
	for line := range strings.SplitSeq(text, "\n") {
		if line = strings.TrimSpace(line); !laptopMasquerade(line, within) {
			continue
		}
		current = append(current, line)
		if !slices.Contains(wanted, line) {
			problems = append(problems, m.command(ctx, tool, append([]string{"-w", "-t", "nat", "-D"}, strings.Fields(line)[1:]...)...))
		}
	}
	for _, line := range wanted {
		if !slices.Contains(current, line) {
			problems = append(problems, m.command(ctx, tool, append([]string{"-w", "-t", "nat"}, strings.Fields(line)...)...))
		}
	}
	return errors.Join(problems...)
}
