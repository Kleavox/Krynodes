package network

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	probeMagic = "krynodes-probe-1"
	maxPeers   = 16
)

func ProbeArgs(args map[string]string) (int, []netip.AddrPort, error) {
	for name := range args {
		if name != "port" && name != "peers" {
			return 0, nil, errors.New("a probe takes a port and its peers only")
		}
	}
	port, err := strconv.Atoi(args["port"])
	if err != nil || !validPort(port) {
		return 0, nil, errors.New("a probe listens only on 51820 to 51919")
	}
	fields := strings.Fields(args["peers"])
	if len(fields) == 0 || len(fields) > maxPeers {
		return 0, nil, errors.New("a probe sends to 1 to 16 peers")
	}
	peers := make([]netip.AddrPort, 0, len(fields))
	for _, field := range fields {
		peer, err := netip.ParseAddrPort(field)
		if err != nil || !validPort(int(peer.Port())) {
			return 0, nil, errors.New("a probe sends only to an address on 51820 to 51919")
		}
		peers = append(peers, peer)
	}
	return port, peers, nil
}

func Probe(ctx context.Context, local netip.AddrPort, peers []netip.AddrPort, listen time.Duration) ([]string, bool) {
	var ip net.IP
	if !local.Addr().IsUnspecified() {
		ip = local.Addr().AsSlice()
	}
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: int(local.Port())})
	listened := err == nil
	if !listened {
		if socket, err = net.ListenUDP("udp", &net.UDPAddr{IP: ip}); err != nil {
			return []string{}, false
		}
	}
	defer socket.Close()
	wanted := map[netip.Addr]bool{}
	for _, peer := range peers {
		wanted[peer.Addr().Unmap()] = true
	}
	heard := map[string]bool{}
	var lock sync.Mutex
	done := make(chan struct{})
	socket.SetReadDeadline(time.Now().Add(listen))
	go func() {
		defer close(done)
		buffer := make([]byte, 64)
		for {
			count, from, err := socket.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			if listened && count == 32 && string(buffer[:len(probeMagic)]) == probeMagic && wanted[from.Addr().Unmap()] {
				lock.Lock()
				heard[from.Addr().Unmap().String()] = true
				lock.Unlock()
			}
		}
	}()
	payload := make([]byte, 32)
	copy(payload, probeMagic)
	rand.Read(payload[len(probeMagic):])
	for range 5 {
		for _, peer := range peers {
			socket.WriteToUDPAddrPort(payload, peer)
		}
		select {
		case <-ctx.Done():
		case <-time.After(listen / 10):
		}
	}
	<-done
	arrived := []string{}
	for address := range heard {
		arrived = append(arrived, address)
	}
	slices.Sort(arrived)
	return arrived, listened
}
