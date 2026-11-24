package network

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const Comment = "krynodes-network"

var (
	ufwNumber = regexp.MustCompile(`^\[\s*(\d+)\]\s.*#\s*` + Comment + `\s*$`)
	ufwPort   = regexp.MustCompile(`^\[\s*\d+\]\s+(\d+)/udp\s`)
)

func Open(firewall string, port int) [][]string {
	rule := strconv.Itoa(port) + "/udp"
	switch firewall {
	case "ufw":
		return [][]string{
			{"ufw", "allow", rule, "comment", Comment},
			{"ufw", "allow", "in", "on", Interface, "comment", Comment},
		}
	case "firewalld":
		return [][]string{
			{"firewall-cmd", "--permanent", "--add-port=" + rule},
			{"firewall-cmd", "--permanent", "--zone=trusted", "--add-interface=" + Interface},
			{"firewall-cmd", "--reload"},
		}
	}
	return nil
}

func OpenRelay(firewall string, ports []int) [][]string {
	var commands [][]string
	for _, port := range ports {
		rule := strconv.Itoa(port) + "/udp"
		switch firewall {
		case "ufw":
			commands = append(commands, []string{"ufw", "allow", rule, "comment", Comment})
		case "firewalld":
			commands = append(commands, []string{"firewall-cmd", "--add-port=" + rule}, []string{"firewall-cmd", "--permanent", "--add-port=" + rule})
		}
	}
	return commands
}

func ufwDeletes(ufwNumbered string, keep func(line string) bool) [][]string {
	var numbers []int
	for _, line := range strings.Split(ufwNumbered, "\n") {
		line = strings.TrimSpace(line)
		if found := ufwNumber.FindStringSubmatch(line); found != nil && keep(line) {
			number, _ := strconv.Atoi(found[1])
			numbers = append(numbers, number)
		}
	}
	slices.Sort(numbers)
	slices.Reverse(numbers)
	commands := [][]string{}
	for _, number := range numbers {
		commands = append(commands, []string{"ufw", "--force", "delete", strconv.Itoa(number)})
	}
	return commands
}

func CloseRelay(firewall string, ports []int, ufwNumbered string) [][]string {
	if len(ports) == 0 {
		return nil
	}
	switch firewall {
	case "ufw":
		return ufwDeletes(ufwNumbered, func(line string) bool {
			found := ufwPort.FindStringSubmatch(line)
			if found == nil {
				return false
			}
			port, _ := strconv.Atoi(found[1])
			return slices.Contains(ports, port)
		})
	case "firewalld":
		var commands [][]string
		for _, port := range ports {
			rule := "--remove-port=" + strconv.Itoa(port) + "/udp"
			commands = append(commands, []string{"firewall-cmd", rule}, []string{"firewall-cmd", "--permanent", rule})
		}
		return commands
	}
	return nil
}

func Close(firewall string, ports []int, ufwNumbered string) [][]string {
	switch firewall {
	case "ufw":
		return ufwDeletes(ufwNumbered, func(string) bool { return true })
	case "firewalld":
		var commands [][]string
		for _, port := range ports {
			commands = append(commands, []string{"firewall-cmd", "--permanent", "--remove-port=" + strconv.Itoa(port) + "/udp"})
		}
		return append(commands, []string{"firewall-cmd", "--permanent", "--zone=trusted", "--remove-interface=" + Interface}, []string{"firewall-cmd", "--reload"})
	}
	return nil
}
