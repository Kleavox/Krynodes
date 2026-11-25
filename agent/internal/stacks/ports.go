package stacks

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

const local = "127.0.0.1"

func Bind(config map[string]any, own string, network []int) error {
	if len(network) > 0 {
		if own == "" {
			return errors.New("this server is not in the private network, so no port can be served to it")
		}
		if ip := net.ParseIP(own); ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsLoopback() {
			return fmt.Errorf("%s is not a private network address", own)
		}
	}
	services := asMap(config["services"])
	for _, name := range sortedKeys(services) {
		service := asMap(services[name])
		listed := asList(service["ports"])
		if raw, set := service["ports"]; set && raw != nil && listed == nil {
			return fmt.Errorf("service %s lists its ports in a shape compose does not write", name)
		}
		if len(listed) == 0 {
			continue
		}
		ports := []any{}
		for _, raw := range listed {
			port := asMap(raw)
			if port == nil {
				return fmt.Errorf("service %s lists a port compose did not resolve", name)
			}
			port["host_ip"] = local
			ports = appendOnce(ports, port)
			for _, number := range network {
				if published(port, number) {
					private := maps.Clone(port)
					private["host_ip"], private["published"] = own, strconv.Itoa(number)
					ports = appendOnce(ports, private)
				}
			}
		}
		service["ports"] = ports
	}
	return nil
}

func appendOnce(ports []any, port map[string]any) []any {
	if slices.ContainsFunc(ports, func(kept any) bool { return reflect.DeepEqual(kept, port) }) {
		return ports
	}
	return append(ports, port)
}

func published(port map[string]any, number int) bool {
	text := asText(port["published"])
	if value, ok := port["published"].(float64); ok {
		text = strconv.Itoa(int(value))
	}
	first, last, ranged := strings.Cut(text, "-")
	if !ranged {
		last = first
	}
	low, lowErr := strconv.Atoi(first)
	high, highErr := strconv.Atoi(last)
	return lowErr == nil && highErr == nil && low <= number && number <= high
}
