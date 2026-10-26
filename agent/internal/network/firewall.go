package network

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const Comment = "krynodes-network"

var ufwNumber = regexp.MustCompile(`^\[\s*(\d+)\]\s.*#\s*` + Comment + `\s*$`)

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

func Close(firewall string, port int, ufwNumbered string) [][]string {
	switch firewall {
	case "ufw":
		var numbers []int
		for _, line := range strings.Split(ufwNumbered, "\n") {
			if found := ufwNumber.FindStringSubmatch(strings.TrimSpace(line)); found != nil {
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
	case "firewalld":
		rule := strconv.Itoa(port) + "/udp"
		return [][]string{
			{"firewall-cmd", "--permanent", "--remove-port=" + rule},
			{"firewall-cmd", "--permanent", "--zone=trusted", "--remove-interface=" + Interface},
			{"firewall-cmd", "--reload"},
		}
	}
	return nil
}
