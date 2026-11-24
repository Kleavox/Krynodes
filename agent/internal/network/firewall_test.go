package network

import (
	"fmt"
	"testing"
)

func TestTheFirewallGetsTwoNamedRules(t *testing.T) {
	ufw := fmt.Sprint(Open("ufw", 51821))
	if ufw != "[[ufw allow 51821/udp comment krynodes-network] [ufw allow in on kry0 comment krynodes-network]]" {
		t.Fatalf("ufw %s", ufw)
	}
	firewalld := fmt.Sprint(Open("firewalld", 51821))
	if firewalld != "[[firewall-cmd --permanent --add-port=51821/udp] [firewall-cmd --permanent --zone=trusted --add-interface=kry0] [firewall-cmd --reload]]" {
		t.Fatalf("firewalld %s", firewalld)
	}
	if len(Open("", 51821)) != 0 {
		t.Fatal("no firewall, no rules")
	}
}

func TestRemovalDeletesExactlyTheNamedRules(t *testing.T) {
	numbered := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 51821/udp                  ALLOW IN    Anywhere                   # krynodes-network
[ 3] Anywhere on kry0           ALLOW IN    Anywhere                   # krynodes-network
[ 4] 51820/udp                  ALLOW IN    Anywhere                   # wg0
[ 5] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 6] 51821/udp (v6)             ALLOW IN    Anywhere (v6)              # krynodes-network
`
	got := fmt.Sprint(Close("ufw", []int{51821}, numbered))
	if got != "[[ufw --force delete 6] [ufw --force delete 3] [ufw --force delete 2]]" {
		t.Fatalf("ufw %s", got)
	}
	firewalld := fmt.Sprint(Close("firewalld", []int{51821, 51920}, ""))
	if firewalld != "[[firewall-cmd --permanent --remove-port=51821/udp] [firewall-cmd --permanent --remove-port=51920/udp] [firewall-cmd --permanent --zone=trusted --remove-interface=kry0] [firewall-cmd --reload]]" {
		t.Fatalf("firewalld %s", firewalld)
	}
}

func TestRelayPortsOpenAndCloseOneByOne(t *testing.T) {
	if ufw := fmt.Sprint(OpenRelay("ufw", []int{51920, 51923})); ufw != "[[ufw allow 51920/udp comment krynodes-network] [ufw allow 51923/udp comment krynodes-network]]" {
		t.Fatalf("ufw %s", ufw)
	}
	if firewalld := fmt.Sprint(OpenRelay("firewalld", []int{51920})); firewalld != "[[firewall-cmd --add-port=51920/udp] [firewall-cmd --permanent --add-port=51920/udp]]" {
		t.Fatalf("firewalld %s", firewalld)
	}
	if len(OpenRelay("", []int{51920}))+len(OpenRelay("firewalld", nil))+len(CloseRelay("firewalld", nil, "")) != 0 {
		t.Fatal("no firewall or no port, no command")
	}
	numbered := `[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 51821/udp                  ALLOW IN    Anywhere                   # krynodes-network
[ 3] Anywhere on kry0           ALLOW IN    Anywhere                   # krynodes-network
[ 4] 51920/udp                  ALLOW IN    Anywhere                   # krynodes-network
[ 5] 51921/udp                  ALLOW IN    Anywhere                   # krynodes-network
[ 6] 51922/udp                  ALLOW IN    Anywhere
[ 7] 51920/udp (v6)             ALLOW IN    Anywhere (v6)              # krynodes-network
`
	if ufw := fmt.Sprint(CloseRelay("ufw", []int{51920, 51922}, numbered)); ufw != "[[ufw --force delete 7] [ufw --force delete 4]]" {
		t.Fatalf("ufw %s", ufw)
	}
	if firewalld := fmt.Sprint(CloseRelay("firewalld", []int{51920}, "")); firewalld != "[[firewall-cmd --remove-port=51920/udp] [firewall-cmd --permanent --remove-port=51920/udp]]" {
		t.Fatalf("firewalld %s", firewalld)
	}
}
