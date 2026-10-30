package actions

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/network"
	"github.com/Kleavox/krynodes/agent/internal/recipes"
	"github.com/Kleavox/krynodes/agent/internal/reporter"
	"github.com/Kleavox/krynodes/agent/internal/seal"
)

const (
	networkTools = "wireguard-tools"
	networkUnit  = "wg-quick@kry0.service"
	linksFile    = "network-links.json"
	linksFresh   = 2 * time.Minute
	resendEvery  = 10 * time.Minute
)

var (
	probeListen = 20 * time.Second
	probeOn     = netip.IPv6Unspecified()
)

var (
	pingSent    = regexp.MustCompile(`(\d+) packets transmitted, (\d+) (?:packets )?received`)
	pingAverage = regexp.MustCompile(`= [0-9.]+/([0-9.]+)/`)
	pointed     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-z0-9-]+\.kry\b`)
)

type preparedNetwork struct {
	Range string `json:"range"`
	Port  int    `json:"port"`
	MTU   *int   `json:"mtu"`
}

const probeFile = "probe.json"

type probeMark struct {
	Port  int       `json:"port"`
	PID   int       `json:"pid"`
	Until time.Time `json:"until"`
}

type networkRecord struct {
	Applied   network.Applied           `json:"applied"`
	Document  *network.Document         `json:"document,omitempty"`
	Announced map[string]string         `json:"announced,omitempty"`
	Announce  *reporter.NetworkAnnounce `json:"announce,omitempty"`
	Prepared  *preparedNetwork          `json:"prepared,omitempty"`
	Key       string                    `json:"key,omitempty"`
	Signer    string                    `json:"signer,omitempty"`
	Joined    bool                      `json:"joined,omitempty"`
	Port      int                       `json:"port,omitempty"`
	Firewall  string                    `json:"firewall,omitempty"`
	Tools     bool                      `json:"tools,omitempty"`
	Dropped   []string                  `json:"dropped,omitempty"`
	Tightened *network.Knocks           `json:"tightened,omitempty"`
}

type networkLinks struct {
	At    time.Time      `json:"at"`
	Links []network.Link `json:"links"`
}

func (e Executor) networkDir() string {
	return filepath.Join(e.StateDir, "network")
}

func (e Executor) readNetwork() networkRecord {
	record, _ := readState[networkRecord](e.StateDir, "network.json")
	return record
}

func (e Executor) saveNetwork(record networkRecord) error {
	return writeJSON(e.StateDir, "network.json", record, 0o640)
}

func (e Executor) network(ctx context.Context, request Request) (Result, bool) {
	if err := expired(request, e.Now()); err != nil {
		return e.refuse(request.ID, err), false
	}
	if !ValidTarget(request.Kind, request.Name) {
		return e.refuse(request.ID, errors.New("invalid target")), false
	}
	switch request.Action {
	case "inspect", "probe", "test", "endpoints":
		args, err := asked(request)
		if err != nil {
			return e.refuse(request.ID, err), false
		}
		return e.networkRead(ctx, request, args), false
	case "prepare", "unprepare", "rekey":
		if _, err := e.authorize(request); err != nil {
			return e.refuse(request.ID, err), false
		}
	case "apply", "announce", "drop", "tighten":
	default:
		return e.refuse(request.ID, fmt.Errorf("unknown action %q", request.Action)), false
	}
	if err := writeJSON(filepath.Join(e.StateDir, "host"), request.ID+".json", request, 0o600); err != nil {
		return e.failed(request, err, ""), false
	}
	return Result{}, true
}

func (e Executor) networkRead(ctx context.Context, request Request, args map[string]string) Result {
	switch request.Action {
	case "inspect":
		return e.answer(request, network.Read(ctx, e.Root, network.Runner(e.Run)), true)
	case "probe":
		port, peers, err := network.ProbeArgs(args)
		if err != nil {
			return e.refuse(request.ID, err)
		}
		if err := writeJSON(e.StateDir, probeFile, probeMark{Port: port, PID: os.Getpid(), Until: e.Now().Add(probeListen + 10*time.Second)}, 0o600); err != nil {
			return e.failed(request, err, "")
		}
		defer os.Remove(filepath.Join(e.StateDir, probeFile))
		arrived, listened := network.Probe(ctx, netip.AddrPortFrom(probeOn, uint16(port)), peers, probeListen)
		return e.answer(request, map[string]any{"listened": listened, "arrived": arrived}, true)
	case "test":
		return e.linkTest(ctx, request, args)
	}
	return e.setEndpoints(ctx, request, args)
}

func (e Executor) applyNetwork(ctx context.Context, request Request) Result {
	if err := expired(request, e.Now()); err != nil {
		return e.refuse(request.ID, err)
	}
	switch request.Action {
	case "apply":
		return e.applyDocument(ctx, request)
	case "announce", "drop", "tighten":
		args, err := asked(request)
		if err != nil {
			return e.refuse(request.ID, err)
		}
		switch request.Action {
		case "drop":
			return e.dropMember(ctx, request, args)
		case "tighten":
			return e.tighten(request, args)
		}
		return e.takeAnnouncement(ctx, request, args)
	}
	command, err := e.authorize(request)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	switch request.Action {
	case "prepare":
		networkRange, port, err := network.PrepareArgs(command.Args)
		if err != nil {
			return e.refuse(request.ID, err)
		}
		prepared, err := e.prepareNetwork(ctx, networkRange, port)
		if err != nil {
			return e.refuse(request.ID, err)
		}
		return e.answer(request, prepared, true)
	case "unprepare":
		if err := e.unprepareNetwork(ctx); err != nil {
			return e.refuse(request.ID, err)
		}
		return Result{ID: request.ID, OK: true, Output: "removed", FinishedAt: e.stamp()}
	case "rekey":
		return e.rekeyNetwork(ctx, request)
	}
	return e.refuse(request.ID, fmt.Errorf("unknown action %q", request.Action))
}

func (e Executor) prepareNetwork(ctx context.Context, networkRange string, port int) (reporter.NetworkPrepared, error) {
	record := e.readNetwork()
	if record.Joined {
		return reporter.NetworkPrepared{}, errors.New("this server is already in the private network")
	}
	found := network.Read(ctx, e.Root, network.Runner(e.Run))
	if port == 0 && found.Port != nil {
		port = *found.Port
	}
	switch {
	case !found.Kernel.OK && found.Kernel.Reason != nil && *found.Kernel.Reason == "container":
		return reporter.NetworkPrepared{}, errors.New("this server is a container that cannot load WireGuard; its host has to provide it")
	case !found.Kernel.OK:
		return reporter.NetworkPrepared{}, errors.New("this server's kernel has no WireGuard")
	case !found.Free(port):
		return reporter.NetworkPrepared{}, fmt.Errorf("%d/udp is taken on this server; check it again", port)
	case network.Clashes(networkRange, found.Used):
		return reporter.NetworkPrepared{}, fmt.Errorf("%s is already used on this server", networkRange)
	}
	if !found.Tools {
		installed, err := recipes.Install(ctx, e.recipeEnv(), networkTools)
		if err != nil {
			return reporter.NetworkPrepared{}, fmt.Errorf("install %s: %w", networkTools, err)
		}
		record.Tools = record.Tools || slices.Contains(strings.Fields(installed), networkTools)
	}
	keys, err := network.Load(e.networkDir(), true)
	if err != nil {
		return reporter.NetworkPrepared{}, err
	}
	record.Prepared = &preparedNetwork{Range: networkRange, Port: port, MTU: found.MTU}
	record.Key, record.Signer = keys.Public, keys.Signer
	if err := e.saveNetwork(record); err != nil {
		return reporter.NetworkPrepared{}, err
	}
	return reporter.NetworkPrepared{Key: keys.Public, Signer: keys.Signer, Port: port, MTU: found.MTU}, nil
}

func (e Executor) unprepareNetwork(ctx context.Context) error {
	record := e.readNetwork()
	if record.Joined {
		return errors.New("this server is in the private network; remove it from the network instead")
	}
	problems := e.takeDown(ctx, record)
	if err := e.saveNetwork(networkRecord{Applied: record.Applied}); err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func (e Executor) takeDown(ctx context.Context, record networkRecord) []string {
	var problems []string
	step := func(what string, err error) {
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			problems = append(problems, what+": "+err.Error())
		}
	}
	if record.Joined {
		step("stop kry0", e.networkCommand(ctx, "systemctl", "disable", "--now", networkUnit))
		step("remove kry0.conf", os.Remove(e.path(network.ConfigPath)))
		numbered := ""
		if record.Firewall == "ufw" {
			numbered, _ = e.output(ctx, "ufw", "status", "numbered")
		}
		for _, command := range network.Close(record.Firewall, record.Port, numbered) {
			step("firewall", e.networkCommand(ctx, command[0], command[1:]...))
		}
		e.dropRules(ctx)
		step("remove the Docker drop-in", os.Remove(e.path(network.DropInPath)))
		step("reload systemd", e.networkCommand(ctx, "systemctl", "daemon-reload"))
		step("hosts", e.writeHosts(nil))
	}
	step("remove the network key", network.Forget(e.networkDir()))
	if record.Tools && len(network.Read(ctx, e.Root, network.Runner(e.Run)).Others) == 0 {
		step("remove "+networkTools, recipes.Purge(ctx, e.recipeEnv(), networkTools))
	}
	return problems
}

func (e Executor) networkCommand(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	output, _, err := e.Run(ctx, name, args...)
	if err != nil {
		if text := clean(output); text != "" {
			return fmt.Errorf("%w: %s", err, text)
		}
	}
	return err
}

func (e Executor) writeHosts(members []network.Member) error {
	path := e.path(network.HostsPath)
	current, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	next := network.Hosts(string(current), members)
	if next == string(current) {
		return nil
	}
	return writeWhole(filepath.Dir(path), filepath.Base(path), []byte(next), 0o644)
}

func (e Executor) selfNode() (string, error) {
	trust, err := LoadTrust(e.StateDir)
	if err != nil {
		return "", err
	}
	if trust.NodeID == "" {
		return "", errors.New("no trusted devices")
	}
	return trust.NodeID, nil
}

func member(document network.Document, node string) (network.Member, bool) {
	index := slices.IndexFunc(document.Members, func(entry network.Member) bool { return entry.Node == node })
	if index < 0 {
		return network.Member{}, false
	}
	return document.Members[index], true
}

func (e Executor) presharedKeys(self network.Member, document network.Document) (map[string]string, error) {
	key, err := e.sealKey()
	if err != nil {
		return nil, err
	}
	keys := map[string]string{}
	for node, sealed := range self.PSK {
		plain, err := seal.Open(key, sealed)
		if err != nil || len(plain) != 32 {
			peer, _ := member(document, node)
			return nil, fmt.Errorf("the preshared key for %s cannot be opened on this server", peer.Name)
		}
		keys[node] = base64.StdEncoding.EncodeToString(plain)
	}
	return keys, nil
}

func withAnnounced(document network.Document, announced map[string]string) network.Document {
	document.Members = slices.Clone(document.Members)
	for index, entry := range document.Members {
		if key, ok := announced[entry.Node]; ok {
			document.Members[index].Key = key
		}
	}
	return document
}

func (e Executor) applyDocument(ctx context.Context, request Request) Result {
	trust, err := LoadTrust(e.StateDir)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	body, err := VerifyDocument(trust, request.Signed, e.Now())
	if err != nil {
		return e.refuse(request.ID, err)
	}
	document, err := network.Parse(body)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	record := e.readNetwork()
	hash := network.BodyHash(body)
	self, err := network.Accept(document, record.Applied, trust.NodeID, record.Joined)
	if errors.Is(err, network.ErrLeave) {
		return e.leaveNetwork(ctx, request, document, hash, record)
	}
	if err != nil {
		return e.refuse(request.ID, err)
	}
	keys, err := network.Load(e.networkDir(), false)
	if err != nil {
		return e.refuse(request.ID, errors.New("this server has no network key; get it ready first"))
	}
	rekey := self.Key == keys.Public && self.Rekey
	if self.Key != keys.Public && (record.Announce == nil || record.Announce.Key != keys.Public) {
		return e.refuse(request.ID, fmt.Errorf("the document names another key for %s", self.Name))
	}
	psk, err := e.presharedKeys(self, document)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	if self.Key == keys.Public && !rekey {
		record.Announce = nil
	}
	if rekey {
		if keys, err = network.Rekey(e.networkDir()); err != nil {
			return e.failed(request, err, "")
		}
		record.Key, record.Announce = keys.Public, &reporter.NetworkAnnounce{Key: keys.Public, Signature: keys.Announce(trust.NodeID)}
		if err := e.saveNetwork(record); err != nil {
			return e.failed(request, err, "")
		}
	}
	for node, key := range record.Announced {
		if entry, ok := member(document, node); !ok || entry.Key == key || slices.Contains(document.Blocked, key) {
			delete(record.Announced, node)
		}
	}
	if err := e.writeNetwork(ctx, &record, document, self, keys, psk); err != nil {
		return e.failed(request, err, "")
	}
	record.Applied = record.Applied.After(document, hash)
	record.Document, record.Key, record.Signer, record.Prepared = &document, keys.Public, keys.Signer, nil
	record.Tightened = nil
	record.Dropped = slices.DeleteFunc(record.Dropped, func(address string) bool {
		return slices.ContainsFunc(document.Members, func(entry network.Member) bool {
			return entry.Address == address && !entry.Cut && !slices.Contains(record.Applied.Blocked, entry.Key)
		})
	})
	if err := e.saveNetwork(record); err != nil {
		return e.failed(request, err, "")
	}
	e.syncRules(ctx)
	return Result{ID: request.ID, OK: true, Output: fmt.Sprintf("applied version %d", document.Version), FinishedAt: e.stamp()}
}

func (e Executor) writeNetwork(ctx context.Context, record *networkRecord, document network.Document, self network.Member, keys network.Keys, psk map[string]string) error {
	rendered := withAnnounced(document, record.Announced)
	config := network.Render(rendered, self, keys.Private, psk)
	path := e.path(network.ConfigPath)
	previous, _ := os.ReadFile(path)
	if err := writeWhole(filepath.Dir(path), filepath.Base(path), []byte(config), 0o600); err != nil {
		return err
	}
	if !record.Joined {
		state := e.firewallOf(ctx, recipes.Detect(e.recipeEnv()).Family)
		switch {
		case state.firewalld:
			record.Firewall = "firewalld"
		case state.active:
			record.Firewall = "ufw"
		}
		for _, command := range network.Open(record.Firewall, self.Port) {
			if err := e.networkCommand(ctx, command[0], command[1:]...); err != nil {
				return fmt.Errorf("open %d/udp: %w", self.Port, err)
			}
		}
		if err := e.networkCommand(ctx, "systemctl", "enable", "--now", networkUnit); err != nil {
			return fmt.Errorf("start kry0: %w", err)
		}
		dropIn := e.path(network.DropInPath)
		if err := writeWhole(filepath.Dir(dropIn), filepath.Base(dropIn), []byte(network.DropInBody), 0o644); err != nil {
			return err
		}
		if err := e.networkCommand(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		record.Joined, record.Port = true, self.Port
	} else if network.NeedsRestart(string(previous), config) {
		if err := e.networkCommand(ctx, "systemctl", "restart", networkUnit); err != nil {
			return fmt.Errorf("restart kry0: %w", err)
		}
	} else if err := e.syncNetwork(ctx, config); err != nil {
		return err
	}
	return e.writeHosts(rendered.Members)
}

func (e Executor) syncNetwork(ctx context.Context, config string) error {
	if err := writeWhole(e.networkDir(), "sync.conf", []byte(network.Strip(config)), 0o600); err != nil {
		return err
	}
	stripped := filepath.Join(e.networkDir(), "sync.conf")
	defer os.Remove(stripped)
	if err := e.networkCommand(ctx, "wg", "syncconf", network.Interface, stripped); err != nil {
		if again := e.networkCommand(ctx, "systemctl", "restart", networkUnit); again != nil {
			return fmt.Errorf("update kry0: %w; restarting it also failed: %v", err, again)
		}
	}
	return nil
}

func (e Executor) leaveNetwork(ctx context.Context, request Request, document network.Document, hash string, record networkRecord) Result {
	if !record.Joined {
		record.Applied = record.Applied.After(document, hash)
		if err := e.saveNetwork(record); err != nil {
			return e.failed(request, err, "")
		}
		return Result{ID: request.ID, OK: true, Output: "not in the private network", FinishedAt: e.stamp()}
	}
	_, own := e.ownAddress()
	problems := e.takeDown(ctx, record)
	if err := e.saveNetwork(networkRecord{Applied: record.Applied.After(document, hash)}); err != nil {
		problems = append(problems, err.Error())
	}
	problems = append(problems, e.unserve(ctx, own)...)
	if len(problems) > 0 {
		return Result{ID: request.ID, OK: false, Output: clean([]byte("left the private network, but: " + strings.Join(problems, "; "))), FinishedAt: e.stamp()}
	}
	return Result{ID: request.ID, OK: true, Output: "left the private network", FinishedAt: e.stamp()}
}

func (e Executor) joinedState() (networkRecord, network.Member, network.Keys, map[string]string, error) {
	record := e.readNetwork()
	if !record.Joined || record.Document == nil {
		return record, network.Member{}, network.Keys{}, nil, errors.New("this server is not in the private network")
	}
	node, err := e.selfNode()
	if err != nil {
		return record, network.Member{}, network.Keys{}, nil, err
	}
	self, ok := member(*record.Document, node)
	if !ok {
		return record, network.Member{}, network.Keys{}, nil, errors.New("this server is not in the private network")
	}
	keys, err := network.Load(e.networkDir(), false)
	if err != nil {
		return record, network.Member{}, network.Keys{}, nil, err
	}
	psk, err := e.presharedKeys(self, *record.Document)
	return record, self, keys, psk, err
}

func (e Executor) takeAnnouncement(ctx context.Context, request Request, args map[string]string) Result {
	record, self, keys, psk, err := e.joinedState()
	if err != nil {
		return e.refuse(request.ID, err)
	}
	node, key := args["node"], args["key"]
	peer, ok := member(*record.Document, node)
	switch {
	case !ok || node == self.Node:
		return e.refuse(request.ID, errors.New("the new key is for someone who is not another member"))
	case !network.Announced(peer.Signer, node, key, args["signature"]):
		return e.refuse(request.ID, fmt.Errorf("the new key is not signed by %s", peer.Name))
	case slices.Contains(record.Applied.Blocked, key):
		return e.refuse(request.ID, fmt.Errorf("%s's new key was taken out of the network", peer.Name))
	}
	current := peer.Key
	if announced, ok := record.Announced[node]; ok {
		current = announced
	}
	if current == key {
		return Result{ID: request.ID, OK: true, Output: peer.Name + " already uses this key", FinishedAt: e.stamp()}
	}
	if record.Announced == nil {
		record.Announced = map[string]string{}
	}
	record.Announced[node] = key
	if err := e.writeNetwork(ctx, &record, *record.Document, self, keys, psk); err != nil {
		return e.failed(request, err, "")
	}
	if err := e.saveNetwork(record); err != nil {
		return e.failed(request, err, "")
	}
	return Result{ID: request.ID, OK: true, Output: peer.Name + " has a new key", FinishedAt: e.stamp()}
}

func (e Executor) rekeyNetwork(ctx context.Context, request Request) Result {
	record := e.readNetwork()
	node, err := e.selfNode()
	if err != nil {
		return e.refuse(request.ID, err)
	}
	if record.Key == "" {
		return e.refuse(request.ID, errors.New("this server has no network key"))
	}
	var self network.Member
	var psk map[string]string
	if record.Joined {
		if record, self, _, psk, err = e.joinedState(); err != nil {
			return e.refuse(request.ID, err)
		}
	}
	keys, err := network.Rekey(e.networkDir())
	if err != nil {
		return e.failed(request, err, "")
	}
	announce := reporter.NetworkAnnounce{Key: keys.Public, Signature: keys.Announce(node)}
	record.Key, record.Announce = keys.Public, &announce
	if err := e.saveNetwork(record); err != nil {
		return e.failed(request, err, "")
	}
	if record.Joined {
		if err := e.writeNetwork(ctx, &record, *record.Document, self, keys, psk); err != nil {
			return e.failed(request, err, "")
		}
	}
	return e.answer(request, announce, true)
}

func (e Executor) dump(ctx context.Context) []network.Link {
	output, ok := e.output(ctx, "wg", "show", network.Interface, "dump")
	if !ok {
		return []network.Link{}
	}
	return network.ParseDump(output)
}

func linkOf(links []network.Link, key string) network.Link {
	for _, link := range links {
		if link.Key == key {
			return link
		}
	}
	return network.Link{}
}

type pingCount struct {
	sent, received int
	ms             *float64
}

func readPing(output string) pingCount {
	var count pingCount
	if found := pingSent.FindStringSubmatch(output); found != nil {
		count.sent, _ = strconv.Atoi(found[1])
		count.received, _ = strconv.Atoi(found[2])
	}
	if found := pingAverage.FindStringSubmatch(output); found != nil {
		if ms, err := strconv.ParseFloat(found[1], 64); err == nil {
			count.ms = &ms
		}
	}
	return count
}

func (e Executor) ping(ctx context.Context, args ...string) pingCount {
	output, _ := e.output(ctx, "ping", args...)
	return readPing(output)
}

type linkTest struct {
	Up            bool    `json:"up"`
	HasKey        bool    `json:"hasKey"`
	Version       *int    `json:"version"`
	Clock         int64   `json:"clock"`
	PublicAddress *string `json:"publicAddress"`
	Firewall      struct {
		Lets bool  `json:"lets"`
		Rule *bool `json:"rule"`
	} `json:"firewall"`
	Handshakes struct {
		Sent     int64 `json:"sent"`
		Received int64 `json:"received"`
		Answered int   `json:"answered"`
		Third    *bool `json:"third"`
	} `json:"handshakes"`
	Small struct {
		Sent int      `json:"sent"`
		Lost int      `json:"lost"`
		MS   *float64 `json:"ms"`
	} `json:"small"`
	Large struct {
		Passed *int  `json:"passed"`
		Tried  []int `json:"tried"`
	} `json:"large"`
}

func (e Executor) linkTest(ctx context.Context, request Request, args map[string]string) Result {
	peer, address, mtu, err := network.LinkTestArgs(args)
	if err != nil {
		return e.refuse(request.ID, err)
	}
	record := e.readNetwork()
	var found linkTest
	found.Clock = e.Now().Unix()
	found.Large.Tried = []int{}
	if record.Applied.Version > 0 {
		version := record.Applied.Version
		found.Version = &version
	}
	key, port := "", record.Port
	if record.Document != nil {
		if entry, ok := member(withAnnounced(*record.Document, record.Announced), peer); ok {
			key = entry.Key
		}
	}
	state, _ := e.output(ctx, "systemctl", "is-active", networkUnit)
	found.Up = strings.TrimSpace(state) == "active"
	e.firewallLets(ctx, port, &found)
	before := e.dump(ctx)
	first := linkOf(before, key)
	found.HasKey = key != "" && first.Key == key
	if first.Endpoint != nil {
		if endpoint, err := netip.ParseAddrPort(*first.Endpoint); err == nil {
			found.PublicAddress = e.sourceFor(ctx, endpoint.Addr().String())
		}
	}
	small := e.ping(ctx, "-n", "-c", "5", "-i", "0.2", "-W", "1", "-I", network.Interface, address)
	found.Small.Sent, found.Small.Lost, found.Small.MS = small.sent, small.sent-small.received, small.ms
	for size := mtu; size >= 1280 && len(found.Large.Tried) < 8; size -= 20 {
		found.Large.Tried = append(found.Large.Tried, size)
		if e.ping(ctx, "-n", "-c", "2", "-W", "1", "-M", "do", "-s", strconv.Itoa(size-28), "-I", network.Interface, address).received > 0 {
			passed := size
			found.Large.Passed = &passed
			break
		}
	}
	after := e.dump(ctx)
	last := linkOf(after, key)
	found.Handshakes.Sent, found.Handshakes.Received = max(last.TX-first.TX, 0), max(last.RX-first.RX, 0)
	if last.Handshake != nil && (first.Handshake == nil || *last.Handshake > *first.Handshake) {
		found.Handshakes.Answered = 1
	}
	for _, other := range after {
		if other.Key == key {
			continue
		}
		recent := other.Handshake != nil && e.Now().Unix()-*other.Handshake < network.AnswerSeconds
		found.Handshakes.Third = &recent
		if recent {
			break
		}
	}
	return e.answer(request, found, true)
}

func (e Executor) sourceFor(ctx context.Context, address string) *string {
	output, ok := e.output(ctx, "ip", "-j", "route", "get", address)
	if !ok {
		return nil
	}
	var routes []struct {
		Source string `json:"prefsrc"`
	}
	if json.Unmarshal([]byte(output), &routes) != nil || len(routes) == 0 || routes[0].Source == "" {
		return nil
	}
	return &routes[0].Source
}

func (e Executor) firewallLets(ctx context.Context, port int, found *linkTest) {
	state := e.firewallOf(ctx, recipes.Detect(e.recipeEnv()).Family)
	if !state.active {
		found.Firewall.Lets = true
		return
	}
	open := e.ufwOpen()
	rule := false
	if state.firewalld {
		open = e.firewalldOpen(ctx)
		_, rule = e.output(ctx, "firewall-cmd", "--query-port="+strconv.Itoa(port)+"/udp")
	} else {
		listed, _ := e.output(ctx, "ufw", "status")
		rule = slices.ContainsFunc(strings.Split(listed, "\n"), func(line string) bool {
			return strings.HasPrefix(strings.TrimSpace(line), strconv.Itoa(port)+"/udp") && strings.Contains(line, "# "+network.Comment)
		})
	}
	found.Firewall.Lets = slices.ContainsFunc(open, func(entry openPort) bool { return entry.lets(port, "udp") })
	found.Firewall.Rule = &rule
}

func (e Executor) setEndpoints(ctx context.Context, request Request, args map[string]string) Result {
	fields := strings.Fields(args["endpoints"])
	record := e.readNetwork()
	if len(args) != 1 || len(fields) == 0 || len(fields)%2 != 0 || len(fields) > 64 {
		return e.refuse(request.ID, errors.New("endpoints come as a key and an address for each member"))
	}
	if !record.Joined || record.Document == nil {
		return e.refuse(request.ID, errors.New("this server is not in the private network"))
	}
	listening := map[string]bool{}
	for _, entry := range withAnnounced(*record.Document, record.Announced).Members {
		listening[entry.Key] = !entry.NAT
	}
	changed := 0
	for index := 0; index < len(fields); index += 2 {
		key, endpoint := fields[index], fields[index+1]
		parsed, err := netip.ParseAddrPort(endpoint)
		if !listening[key] || key == record.Key || err != nil || parsed.Port() < network.FirstPort || parsed.Port() > network.LastPort {
			continue
		}
		if err := e.networkCommand(ctx, "wg", "set", network.Interface, "peer", key, "endpoint", parsed.String()); err != nil {
			return e.failed(request, err, "")
		}
		changed++
	}
	return Result{ID: request.ID, OK: true, Output: fmt.Sprintf("%d endpoints changed", changed), FinishedAt: e.stamp()}
}

func (e Executor) WriteLinks(ctx context.Context) {
	record := e.readNetwork()
	path := filepath.Join(e.StateDir, linksFile)
	if !record.Joined || record.Document == nil {
		os.Remove(path)
		return
	}
	addresses := map[string]string{}
	for _, entry := range withAnnounced(*record.Document, record.Announced).Members {
		addresses[entry.Key] = entry.Address
	}
	links := e.dump(ctx)
	for index, link := range links {
		address, known := addresses[link.Key]
		if known && link.Handshake != nil && e.Now().Unix()-*link.Handshake < network.AnswerSeconds {
			output, _ := e.output(ctx, "ping", "-n", "-c", "1", "-W", "1", "-I", network.Interface, address)
			links[index].MS = network.PingMS(output)
		}
	}
	writeJSON(e.StateDir, linksFile, networkLinks{At: e.Now(), Links: links}, 0o640)
}

func (e Executor) WatchLinks(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		e.WriteLinks(ctx)
		e.syncRules(ctx)
		e.watchKnocks(ctx)
		e.watchDenials(ctx)
		e.watchServer(ctx)
		e.syncTailnet(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (e Executor) networkInventory(snapshot Snapshot) *reporter.NetworkInventory {
	record := e.readNetwork()
	switch {
	case record.Joined && record.Document != nil:
		networkRange := netip.MustParsePrefix(record.Document.Range)
		points := []reporter.NetworkPoint{}
		for _, stack := range snapshot.Stacks {
			files, _ := e.composeFiles(stack)
			seen := map[string]bool{}
			if e.ownStack(stack.Directory) {
				files = []string{filepath.Join(stack.Directory, "compose.yaml")}
				for _, place := range e.metaOf(stack.Directory).Reaches {
					seen[place] = true
				}
			}
			for _, file := range append(files, filepath.Join(stack.Directory, ".env")) {
				body, _ := os.ReadFile(file)
				for _, target := range pointed.FindAllString(string(body), -1) {
					if address, err := netip.ParseAddr(target); err == nil && !networkRange.Contains(address) {
						continue
					}
					seen[target] = true
				}
			}
			for _, target := range slices.Sorted(maps.Keys(seen)) {
				if len(points) < 200 {
					points = append(points, reporter.NetworkPoint{Stack: stack.Project, Target: target})
				}
			}
		}
		return &reporter.NetworkInventory{Points: points}
	case record.Prepared != nil && record.Key != "":
		return &reporter.NetworkInventory{Prepared: &reporter.NetworkPrepared{Key: record.Key, Signer: record.Signer, Port: record.Prepared.Port, MTU: record.Prepared.MTU}, Points: []reporter.NetworkPoint{}}
	}
	return nil
}

func networkID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	text := hex.EncodeToString(sum[:16])
	return text[:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:]
}

func (r *Relay) readNetwork() networkRecord {
	var record networkRecord
	if err := readJSON(filepath.Join(r.StateDir, "network.json"), &record); err != nil {
		r.note(err)
	}
	return record
}

func (r *Relay) NetworkBeat() *reporter.NetworkBeat {
	record := r.readNetwork()
	if record.Key == "" && record.Applied.Version == 0 {
		return nil
	}
	beat := &reporter.NetworkBeat{Version: record.Applied.Version, Links: []network.Link{}, Announce: record.Announce}
	if record.Key != "" {
		key := record.Key
		beat.Key = &key
	}
	var links networkLinks
	if err := readJSON(filepath.Join(r.StateDir, linksFile), &links); err == nil && record.Joined && r.Now().Sub(links.At) < linksFresh && links.Links != nil {
		beat.Links = links.Links
	}
	return beat
}

func (r *Relay) NetworkReply(reply *reporter.NetworkReply) error {
	if reply == nil {
		return nil
	}
	record := r.readNetwork()
	now := r.Now()
	bucket := strconv.FormatInt(now.Truncate(resendEvery).Unix(), 10)
	expires := now.Add(time.Hour).UTC().Format(time.RFC3339Nano)
	var requests []Request
	asking := func(action string, args map[string]string, parts ...string) {
		encoded, err := json.Marshal(args)
		if err != nil {
			return
		}
		requests = append(requests, Request{ID: networkID(append([]string{action, bucket}, parts...)...), Kind: "network", Name: network.Interface, Action: action, ExpiresAt: expires, Attachment: base64.RawURLEncoding.EncodeToString(encoded)})
	}
	if len(reply.Document) > 0 {
		var signed SignedDocument
		var head struct {
			Version int `json:"version"`
		}
		if json.Unmarshal(reply.Document, &signed) == nil {
			if body, err := decode("document", signed.Document); err == nil && json.Unmarshal(body, &head) == nil && head.Version > record.Applied.Version {
				requests = append(requests, Request{ID: networkID("apply", bucket, signed.Document), Kind: "network", Name: network.Interface, Action: "apply", ExpiresAt: expires, Signed: reply.Document})
			}
		}
	}
	for _, announced := range reply.Announced {
		if record.Announced[announced.Node] != announced.Key {
			asking("announce", map[string]string{"node": announced.Node, "key": announced.Key, "signature": announced.Signature}, announced.Node, announced.Key)
		}
	}
	if len(reply.Endpoints) > 0 {
		var pairs []string
		for _, endpoint := range reply.Endpoints {
			pairs = append(pairs, endpoint.Key, endpoint.Endpoint)
		}
		joined := strings.Join(pairs, " ")
		asking("endpoints", map[string]string{"endpoints": joined}, joined)
	}
	r.mu.Lock()
	if r.queued == nil {
		r.queued = map[string]time.Time{}
	}
	for id, at := range r.queued {
		if now.Sub(at) > time.Hour {
			delete(r.queued, id)
		}
	}
	fresh := slices.DeleteFunc(requests, func(request Request) bool {
		_, seen := r.queued[request.ID]
		r.queued[request.ID] = now
		return seen
	})
	r.mu.Unlock()
	if len(fresh) == 0 {
		return nil
	}
	return r.Enqueue(fresh)
}
