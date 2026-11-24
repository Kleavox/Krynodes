package network

import (
	"regexp"
	"strconv"
	"strings"
)

type Link struct {
	Key       string   `json:"key"`
	Handshake *int64   `json:"handshake"`
	RX        int64    `json:"rx"`
	TX        int64    `json:"tx"`
	Endpoint  *string  `json:"endpoint"`
	MS        *float64 `json:"ms"`
}

var pingTime = regexp.MustCompile(`time[=<]([0-9.]+) ms`)

func ParseDump(output string) []Link {
	links := []Link{}
	for index, line := range strings.Split(strings.TrimSpace(output), "\n") {
		fields := strings.Split(line, "\t")
		if index == 0 || len(fields) != 8 || !validKey(fields[0]) {
			continue
		}
		link := Link{Key: fields[0]}
		if fields[2] != "(none)" {
			endpoint := fields[2]
			link.Endpoint = &endpoint
		}
		if at, err := strconv.ParseInt(fields[4], 10, 64); err == nil && at > 0 {
			link.Handshake = &at
		}
		link.RX, _ = strconv.ParseInt(fields[5], 10, 64)
		link.TX, _ = strconv.ParseInt(fields[6], 10, 64)
		links = append(links, link)
	}
	return links
}

func PingMS(output string) *float64 {
	found := pingTime.FindStringSubmatch(output)
	if found == nil {
		return nil
	}
	ms, err := strconv.ParseFloat(found[1], 64)
	if err != nil {
		return nil
	}
	return &ms
}
