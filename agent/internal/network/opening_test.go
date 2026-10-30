package network

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestAnOpeningIsAPortAndWhoMayReachIt(t *testing.T) {
	everyone, err := ParseOpening("443", "tcp", "everyone")
	if err != nil || everyone.String() != "443/tcp@everyone" {
		t.Fatalf("%+v %v", everyone, err)
	}
	addresses, err := ParseOpening("8443", "udp", "203.0.113.7, 198.51.100.0/24+2001:db8::1/32")
	want := Opening{Port: 8443, Protocol: "udp", From: FromAddresses, Addresses: []string{"203.0.113.7/32", "198.51.100.0/24", "2001:db8::/32"}}
	if err != nil || !reflect.DeepEqual(addresses, want) || addresses.String() != "8443/udp@203.0.113.7/32+198.51.100.0/24+2001:db8::/32" {
		t.Fatalf("%+v %v", addresses, err)
	}
	for _, c := range [][3]string{
		{"0", "tcp", "everyone"},
		{"65536", "tcp", "everyone"},
		{"443", "icmp", "everyone"},
		{"443", "tcp", "nobody"},
		{"443", "tcp", ""},
		{"443", "tcp", "203.0.113.0/33"},
		{"443", "tcp", "203.0.113.1,203.0.113.2,203.0.113.3,203.0.113.4,203.0.113.5,203.0.113.6,203.0.113.7,203.0.113.8,203.0.113.9"},
	} {
		if _, err := ParseOpening(c[0], c[1], c[2]); err == nil {
			t.Fatalf("%v must be refused", c)
		}
	}
	list, err := ParseOpenings("443/tcp@everyone, 8443/tcp@tailscale,9000/udp@203.0.113.0/24+198.51.100.9")
	if err != nil || len(list) != 3 || list[1].From != FromTailscale || list[2].Addresses[1] != "198.51.100.9/32" {
		t.Fatalf("%+v %v", list, err)
	}
	if empty, err := ParseOpenings(""); err != nil || len(empty) != 0 {
		t.Fatalf("%+v %v", empty, err)
	}
	for _, broken := range []string{"443/tcp", "443/tcp@everyone,443/tcp@tailscale", "a/tcp@everyone"} {
		if _, err := ParseOpenings(broken); err == nil {
			t.Fatalf("%q must be refused", broken)
		}
	}
}

func TestAnOpeningBecomesUfwAndFirewalldRules(t *testing.T) {
	cases := []struct {
		text      string
		ufw       []string
		firewalld []string
	}{
		{"443/tcp@everyone", []string{"allow 443/tcp"}, []string{"port:443/tcp"}},
		{"8443/tcp@tailscale", []string{"allow in on tailscale0 to any port 8443 proto tcp"}, []string{
			`rich:rule family="ipv4" source address="100.64.0.0/10" port port="8443" protocol="tcp" accept`,
			`rich:rule family="ipv6" source address="fd7a:115c:a1e0::/48" port port="8443" protocol="tcp" accept`,
		}},
		{"53/udp@203.0.113.0/24+2001:db8::/32", []string{
			"allow from 203.0.113.0/24 to any port 53 proto udp",
			"allow from 2001:db8::/32 to any port 53 proto udp",
		}, []string{
			`rich:rule family="ipv4" source address="203.0.113.0/24" port port="53" protocol="udp" accept`,
			`rich:rule family="ipv6" source address="2001:db8::/32" port port="53" protocol="udp" accept`,
		}},
	}
	for _, c := range cases {
		list, err := ParseOpenings(c.text)
		if err != nil {
			t.Fatal(err)
		}
		if got := list[0].UfwRules(); !reflect.DeepEqual(got, c.ufw) {
			t.Fatalf("%s ufw %q", c.text, got)
		}
		if got := list[0].FirewalldRules(); !reflect.DeepEqual(got, c.firewalld) {
			t.Fatalf("%s firewalld %q", c.text, got)
		}
	}
}

func TestPublishedPortsCloseExceptWhatIsOpen(t *testing.T) {
	open, _ := ParseOpenings("443/tcp@everyone,8443/tcp@tailscale,9000/tcp@203.0.113.0/24+2001:db8::/32")
	head := []string{
		"-A KRY-PUBLISH -m conntrack ! --ctstate NEW -j RETURN",
		"-A KRY-PUBLISH -m conntrack ! --ctstate DNAT -j RETURN",
		"-A KRY-PUBLISH -i docker0 -j RETURN",
		"-A KRY-PUBLISH -i br-+ -j RETURN",
		"-A KRY-PUBLISH -i krc+ -j RETURN",
		"-A KRY-PUBLISH -i kry0 -j RETURN",
	}
	v4 := append(slices.Clone(head),
		"-A KRY-PUBLISH -p tcp -m conntrack --ctorigdstport 443 -j RETURN",
		"-A KRY-PUBLISH -i tailscale0 -p tcp -m conntrack --ctorigdstport 8443 -j RETURN",
		"-A KRY-PUBLISH -s 203.0.113.0/24 -p tcp -m conntrack --ctorigdstport 9000 -j RETURN",
		"-A KRY-PUBLISH -j DROP",
	)
	if got := Publish(open, false); !reflect.DeepEqual(got, v4) {
		t.Fatalf("iptables\n%s", strings.Join(got, "\n"))
	}
	v6 := append(slices.Clone(head),
		"-A KRY-PUBLISH -p tcp -m conntrack --ctorigdstport 443 -j RETURN",
		"-A KRY-PUBLISH -i tailscale0 -p tcp -m conntrack --ctorigdstport 8443 -j RETURN",
		"-A KRY-PUBLISH -s 2001:db8::/32 -p tcp -m conntrack --ctorigdstport 9000 -j RETURN",
		"-A KRY-PUBLISH -j DROP",
	)
	if got := Publish(open, true); !reflect.DeepEqual(got, v6) {
		t.Fatalf("ip6tables\n%s", strings.Join(got, "\n"))
	}
	if got := Publish(nil, false); len(got) != len(head)+1 || got[len(got)-1] != "-A KRY-PUBLISH -j DROP" {
		t.Fatalf("nothing open %q", got)
	}
}
