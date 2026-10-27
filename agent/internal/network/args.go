package network

import (
	"errors"
	"net/netip"
	"strconv"
)

func ValidRange(text string) bool {
	network, err := netip.ParsePrefix(text)
	return err == nil && network.Bits() == 24 && network.Masked() == network && pool.Contains(network.Addr())
}

func PrepareArgs(args map[string]string) (string, int, error) {
	port, err := strconv.Atoi(args["port"])
	if len(args) != 2 || !ValidRange(args["range"]) || err != nil || !validPort(port) {
		return "", 0, errors.New("prepare takes a /24 of 10.88.0.0/16 and a port of 51820 to 51919")
	}
	return args["range"], port, nil
}

func LinkTestArgs(args map[string]string) (string, string, int, error) {
	address, err := netip.ParseAddr(args["address"])
	mtu, mtuErr := strconv.Atoi(args["mtu"])
	if len(args) != 3 || !nodeID.MatchString(args["peer"]) || err != nil || !address.Is4() || address.String() != args["address"] || !pool.Contains(address) || mtuErr != nil || !validMTU(mtu) {
		return "", "", 0, errors.New("a test takes a member, its network address and an MTU of 1280 to 1500")
	}
	return args["peer"], args["address"], mtu, nil
}
